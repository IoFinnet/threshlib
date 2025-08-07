// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	ecdsa_keygen "github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
	. "github.com/iofinnet/tss-lib/v3/tss/schnorr/resharing"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/signing"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
	testSetIdEdwards = "Edwards"
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrentEDDSA(t *testing.T) {
	t.Parallel()
	setUp("info")

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // // extra can be 0 to N-first
	oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, testSetIdEdwards, firstPartyIdx)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// init the new parties; re-use the fixture pre-params for speed
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan keygen.LocalPartySaveData, bothCommitteesPax)
	q := big.Wrap(edwards.Edwards().N)
	sessionId := common.MustGetRandomInt(q.BitLen() - 1)

	updater := test.SharedPartyUpdaterAsync

	// init the old parties first
	for j, pID := range oldPIDs {
		params, _ := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		tmp, _ := NewLocalParty(params, oldKeys[j], outCh, endCh, sessionId)
		P := tmp.(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}

	// init the new parties
	for _, pID := range newPIDs {
		params, _ := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		save := keygen.NewLocalPartySaveData(newPCount)
		tmp, _ := NewLocalParty(params, save, outCh, endCh, sessionId)
		P := tmp.(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				t.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest[:len(oldCommittee)] {
					go updater(oldCommittee[destP.Index], msg, errCh)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					go updater(newCommittee[destP.Index], msg, errCh)
				}
			}

		case save := <-endCh:
			// old committee members that aren't receiving a share have their Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
				newKeys[index] = save
			} else {
				endedOldCommittee++
			}
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
				assert.Equal(t, len(oldCommittee), endedOldCommittee)
				t.Logf("Resharing done. Reshared %d participants", reSharingEnded)

				// xj tests: BigXj == xj*G
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.Xi
					xj = big.ModInt(big.Wrap(tss.Edwards().Params().N)).Add(xj, big.NewInt(0))
					gXj, _ := crypto.ScalarBaseMult(tss.Edwards(), xj)
					BigXj := key.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signEndCh := make(chan *common.EndData, len(signPIDs))

	msg := []byte{1, 2, 3}

	for j, signPID := range signPIDs {
		params, _ := tss.NewParameters(tss.Edwards(), signP2pCtx, signPID, len(signPIDs), newThreshold)
		tmp, _ := signing.NewLocalParty(msg, params, signKeys[j], nil, signOutCh, signEndCh, sessionId)
		P := tmp.(*signing.LocalParty)
		signParties = append(signParties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				signErrCh <- err
			}
		}(P)
	}

	var signEnded int32
	for {
		select {
		case err := <-signErrCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, signErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signParties[dest[0].Index], msg, signErrCh)
			}

		case signData := <-signEndCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("EdDSA signing after reshare done. Received sign data from %d participants", signEnded)

				// BEGIN EdDSA verify
				pkX, pkY := signKeys[0].EDDSAPub.X(), signKeys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(signData.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, msg, newSig.R, newSig.S)

				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EdDSA reshare and signing test done.")
				// END EdDSA verify

				return
			}
		}
	}
}

func TestE2EConcurrent_MigrateFromECDSA(t *testing.T) {
	t.Parallel()
	setUp("info")

	threshold, newThreshold := testThreshold, testThreshold

	// PHASE: load keygen fixtures
	firstPartyIdx, extraParties := 0, 1 // // extra can be 0 to N-first
	oldKeysECDSA, oldPIDs, err := ecdsa_keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)

	oldKeys := make([]keygen.LocalPartySaveData, len(oldKeysECDSA))
	for i, key := range oldKeysECDSA {
		marshalled, err2 := json.Marshal(key)
		if !assert.NoError(t, err2, "should marshal keygen fixture") {
			return
		}
		var save keygen.LocalPartySaveData
		if err2 = json.Unmarshal(marshalled, &save); !assert.NoError(t, err2, "should unmarshal keygen fixture") {
			return
		}
		oldKeys[i] = save
		// In the migratory case where we are moving from ECDSA to EdDSA, the EDDSAPub is expected to be nil
		oldKeys[i].EDDSAPub = nil

		t.Logf("oldKeys[%d].ECDSAPub = %X %X", i, key.ECDSAPub.X(), key.ECDSAPub.Y())
	}

	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// init the new parties; re-use the fixture pre-params for speed
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan keygen.LocalPartySaveData, bothCommitteesPax)
	q := big.Wrap(edwards.Edwards().N)
	sessionId := common.MustGetRandomInt(q.BitLen() - 1)

	updater := test.SharedPartyUpdaterAsync

	// init the old parties first
	for j, pID := range oldPIDs {
		params, _ := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		tmp, _ := NewLocalParty(params, oldKeys[j], outCh, endCh, sessionId)
		P := tmp.(*LocalParty) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}

	// init the new parties
	for _, pID := range newPIDs {
		params, _ := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		save := keygen.NewLocalPartySaveData(newPCount)
		tmp, _ := NewLocalParty(params, save, outCh, endCh, sessionId)
		P := tmp.(*LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
	endedOldCommittee := 0
	var reSharingEnded int32
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				t.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest[:len(oldCommittee)] {
					go updater(oldCommittee[destP.Index], msg, errCh)
				}
			}
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					go updater(newCommittee[destP.Index], msg, errCh)
				}
			}

		case save := <-endCh:
			// old committee members that aren't receiving a share have their Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
				newKeys[index] = save
			} else {
				endedOldCommittee++
			}
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
				assert.Equal(t, len(oldCommittee), endedOldCommittee)
				t.Logf("EdDSA Resharing done. Reshared %d participants", reSharingEnded)

				// xj tests: BigXj == xj*G
				newEdDSAPubKey := newKeys[0].EDDSAPub
				for j, key := range newKeys {
					// xj test: BigXj == xj*G
					xj := key.Xi
					xj = big.ModInt(big.Wrap(tss.Edwards().Params().N)).Add(xj, big.NewInt(0))
					gXj, _ := crypto.ScalarBaseMult(tss.Edwards(), xj)
					BigXj := key.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					if !newEdDSAPubKey.Equals(key.EDDSAPub) {
						assert.FailNow(t, "newEdDSAPubKey != key.EDDSAPub")
						return
					}
					t.Logf("newKeys[%d].EDDSAPub = %X %X", j, key.EDDSAPub.X(), key.EDDSAPub.Y())
				}

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	signKeys, signPIDs := newKeys, newPIDs
	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signEndCh := make(chan *common.EndData, len(signPIDs))

	msg := []byte{1, 2, 3}

	for j, signPID := range signPIDs {
		params, _ := tss.NewParameters(tss.Edwards(), signP2pCtx, signPID, len(signPIDs), newThreshold)
		tmp, _ := signing.NewLocalParty(msg, params, signKeys[j], nil, signOutCh, signEndCh, sessionId)
		P := tmp.(*signing.LocalParty)
		signParties = append(signParties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				signErrCh <- err
			}
		}(P)
	}

	var signEnded int32
	for {
		select {
		case err := <-signErrCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, signErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signParties[dest[0].Index], msg, signErrCh)
			}

		case signData := <-signEndCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("EdDSA signing after resharing done. Received sign data from %d participants", signEnded)

				// BEGIN EdDSA verify
				pkX, pkY := signKeys[0].EDDSAPub.X(), signKeys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(signData.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, msg, newSig.R, newSig.S)

				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EdDSA reshare and signing test done.")
				// END EdDSA verify

				return
			}
		}
	}
}
