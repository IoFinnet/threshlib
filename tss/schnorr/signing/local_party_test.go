// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	ed "crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"

	"filippo.io/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}

}

func TestE2EConcurrentEdwards(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdEdwards)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))
	q := big.Wrap(edwards.Edwards().N)
	sessionId := common.MustGetRandomInt(q.BitLen() - 1)
	updater := test.SharedPartyUpdaterAsync

	msg := []byte{1, 2, 3}
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(edwards.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		tmp, _ := NewLocalParty(msg, params, keys[i], nil, outCh, endCh, sessionId)
		P := tmp.(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case end := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)

				// BEGIN check s correctness
				sumS, err := edwards25519.NewScalar().SetCanonicalBytes(ed25519.BigIntToLittleEndianBytes(parties[0].temp.si)[:])
				assert.NoError(t, err)
				scOne, err := edwards25519.NewScalar().SetCanonicalBytes((ed25519.BigIntToLittleEndianBytes(big.NewInt(1)))[:])
				assert.NoError(t, err)
				for i, p := range parties {
					if i == 0 {
						continue
					}
					sc := sumS
					sc2, err := edwards25519.NewScalar().SetCanonicalBytes(ed25519.BigIntToLittleEndianBytes(p.temp.si)[:])
					assert.NoError(t, err)
					sc = sc.MultiplyAdd(sc, scOne, sc2)
				}
				// END check s correctness

				// BEGIN EdDSA edwards verify
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()

				pkPt, err := ed25519.FromXYToEd25519Point(pkX, pkY)
				if err != nil {
					t.Errorf("edwards pubkey error %v", err.Error())
					t.FailNow()
				}

				if ok := ed.Verify(pkPt.Bytes(), msg, end.Signature); !assert.True(t, ok, "eddsa verify must pass") {
					t.Error("eddsa verify must pass")
					t.FailNow()
				}
				t.Log("EdDSA Edwards ORS test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}

func TestE2EConcurrentS256BIP340(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdS256BIP340)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))

	updater := test.SharedPartyUpdaterAsync

	msg, _ := hex.DecodeString("304502210088BE0644191B935DB1CD786B43FF27798006578D8C908906B49E89")
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)
	sessionId := common.GetBigRandomPositiveInt(q, q.BitLen())
	common.Logger.Warnf("t sessionId: %v, #: %v", common.FormatBigInt(sessionId), sessionId.BitLen())

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		tmp, _ := NewLocalParty(msg, params, keys[i], nil, outCh, endCh, sessionId)
		P := tmp.(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case end := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				R := parties[0].temp.r

				modN := int2.ModInt(big.Wrap(tss.S256().Params().N))

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.si)
				}
				fmt.Printf("S: %s\n", common.FormatBigInt(sumS))
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EdDSA verify
				r := new(big.Int).SetBytes(end.GetR())
				s := new(big.Int).SetBytes(end.GetS())

				if err2 := BIP340Verify(keys[0].EDDSAPub.ToBtcecPubKey(), msg, r, s); !assert.NoError(t, err2, "BIP-340 sig must verify") {
					return
				}
				t.Log("EdDSA BIP-340 interactive signing test done.")
				// END EdDSA verify

				break signing
			}
		}
	}
}
