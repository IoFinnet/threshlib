// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/vss"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants = TestParticipants
	testThreshold    = TestThreshold

	// eddsaSaveFixtureJSON is a mock JSON representation of the LocalPartySaveData struct used only in tests.
	eddsaSaveFixtureJSON = `{"Xi":5782289471710232184774556526888815564483945482990931900783078903380600134549,"ShareID":88936001176854392629344171587968117738873613378458846930024343693388278312766,"Ks":[88936001176854392629344171587968117738873613378458846930024343693388278312766,88936001176854392629344171587968117738873613378458846930024343693388278312767,88936001176854392629344171587968117738873613378458846930024343693388278312768,88936001176854392629344171587968117738873613378458846930024343693388278312769,88936001176854392629344171587968117738873613378458846930024343693388278312770],"BigXj":[{"Curve":"ed25519","Coords":[4933986389043529713612288990710525995902363010076932520329678210207630703374,41566287846385512796278185900507674908272976535724726164887198016899417779063]},{"Curve":"ed25519","Coords":[19930769991965148148573581771759373739050398644082800187315047616939929437406,46777663809918127553163055248179617131711712466610248636559115231239383314788]},{"Curve":"ed25519","Coords":[13591938651979958568066492204881968599067958037300330552590166998007619374862,25261940112218298671413058548538454200330247777316286476289314429398945112123]},{"Curve":"ed25519","Coords":[6613826993409320071991147605030013957589553108197584650611679896768065283078,24635922488328463733494386785525715867685335800037668596122540799475510390393]},{"Curve":"ed25519","Coords":[32703075032707582328120306841993915710489855392340535089259594769208952552807,47294320399670099879375895891329848070346324851650988123950895013787402329830]}],"EDDSAPub":{"Curve":"ed25519","Coords":[45372710830457731608454892684728274374819635356678897321562335663828958161563,16827269464280681361697775186867066832110563893495547028162847979750873775970]}}`
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrentAndSaveFixturesEdwards(t *testing.T) {
	t.Parallel()
	setUp("debug")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants, testSetIdEdwards)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))
	q := big.Wrap(tss.Edwards().Params().N)
	sessionId := common.MustGetRandomInt(q.BitLen() - 1)

	updater := test.SharedPartyUpdaterAsync

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params, _ := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			tmp, _ := NewLocalParty(params, outCh, endCh, sessionId)
			P = tmp.(*LocalParty)
		} else {
			tmp, _ := NewLocalParty(params, outCh, endCh, sessionId)
			P = tmp.(*LocalParty)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, testSetIdEdwards, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := big.NewInt(0)
				modQ := int2.ModInt(int2.Wrap(tss.Edwards().Params().N))
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						var share *int2.Int
						P.Lock()
						vssMsgs := P.temp.kgRound2Message1s
						if j2 == j {
							share = P.temp.shares[j].Share
						} else {
							share = new(big.Int).SetBytes(vssMsgs[j].Content().(*KGRound2Message1).Share)
						}

						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     share,
						}
						pShares = append(pShares, shareStruct)
						P.Unlock()
					}
					Pj.Lock()
					uj, err := pShares[:threshold+1].ReConstruct(tss.Edwards())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj.Cmp(Pj.temp.ui), 0)
					uG, _ := crypto.ScalarBaseMult(tss.Edwards(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj, _ := crypto.ScalarBaseMult(tss.Edwards(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold+1].ReConstruct(tss.Edwards())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.Edwards().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = modQ.Add(u, uj)
					Pj.Unlock()
				}

				// build eddsa key pair
				pkX, pkY := save.EDDSAPub.X(), save.EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}
				t.Logf("u len: %v", len(u.Bytes()))
				t.Logf("u: %v", common.FormatBigInt(u))
				uBytes := common.PadToLengthBytesInPlace(u.Bytes(), edwards.PrivScalarSize)
				sk, _, err := edwards.PrivKeyFromScalar(uBytes)
				assert.NoError(t, err, "error loading private key")
				// fmt.Println("err: ", err.Error())

				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, pk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				// uprime := new(big.Int).SetBytes(u.Bytes())
				ourPk, _ := crypto.ScalarBaseMult(tss.Edwards(), u)
				assert.Equal(t, pkX.Cmp(ourPk.X()), 0, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY.Cmp(ourPk.Y()), 0, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same EdDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.EDDSAPub.X())
					assert.Equal(t, pkY, Pj.data.EDDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := edwards.Sign(sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := edwards.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("EdDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func TestE2EConcurrentAndSaveFixturesS256BIP340(t *testing.T) {
	t.Parallel()
	setUp("info")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants, testSetIdS256BIP340)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	sessionId := common.GetBigRandomPositiveInt(q, q.BitLen())
	updater := test.SharedPartyUpdaterAsync

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			tmp, _ := NewLocalParty(params, outCh, endCh, sessionId)
			P = tmp.(*LocalParty)
		} else {
			tmp, _ := NewLocalParty(params, outCh, endCh, sessionId)
			P = tmp.(*LocalParty)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, testSetIdS256BIP340, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := big.NewInt(0)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						var share *int2.Int
						P.Lock()
						vssMsgs := P.temp.kgRound2Message1s
						if j2 == j {
							share = P.temp.shares[j].Share
						} else {
							share = new(big.Int).SetBytes(vssMsgs[j].Content().(*KGRound2Message1).Share)
						}
						P.Unlock()
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     share,
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					if eq := assert.Equal(t, uj.Int64(), Pj.temp.ui.Int64()); !eq {
						t.Logf("Pj: %v, uj: %v, ui: %v", Pj,
							common.FormatBigInt(uj), common.FormatBigInt(Pj.temp.ui))
						t.FailNow()
					}
					uG, _ := crypto.ScalarBaseMult(tss.S256(), uj)
					if eq := assert.Equal(t, uG, Pj.temp.vs[0], "ensure u*G[j] == V_0"); !eq {
						t.Logf("Pj: %v", Pj)
						t.FailNow()
					}

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj, _ := crypto.ScalarBaseMult(tss.S256(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.S256().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}
				u = new(big.Int).Mod(u, int2.Wrap(tss.S256().Params().N))
				t.Logf("u len: %v", len(u.Bytes()))

				// build eddsa key pair
				pkX, pkY := save.EDDSAPub.X(), save.EDDSAPub.Y()
				pk := save.EDDSAPub.ToBtcecPubKey()
				sk, _ := btcec.PrivKeyFromBytes(u.Bytes())
				// fmt.Println("err: ", err.Error())

				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, pk.IsOnCurve(), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPk, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), u)

				assert.Equal(t, pkX, ourPk.X(), "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPk.Y(), "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same EdDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.EDDSAPub.X())
					assert.Equal(t, pkY, Pj.data.EDDSAPub.Y())
				}
				t.Logf("Public key: X: %v, Y: %v", common.FormatBigInt(pkX), common.FormatBigInt(pkY))
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				signature, err := schnorr.Sign(sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := signature.Verify(data, save.EDDSAPub.ToBtcecPubKey())
				assert.True(t, ok, "signature should be ok")
				t.Log("EdDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func tryWriteTestFixtureFile(t *testing.T, index int, testSetId string, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(testSetId, index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func TestLocalPartySaveDataSerialization(t *testing.T) {
	t.Parallel()
	fixture := new(LocalPartySaveData)
	if err := json.Unmarshal([]byte(eddsaSaveFixtureJSON), fixture); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	// JSON serialization
	jsonData, err := json.Marshal(&fixture)
	assert.NoError(t, err)

	jsonDecoded := new(LocalPartySaveData)
	err = json.Unmarshal(jsonData, jsonDecoded)
	assert.NoError(t, err)

	assert.Equal(t, fixture, jsonDecoded, "JSON decoded data should be the same as the original fixture")

	// Gob serialization
	var gobBuffer bytes.Buffer
	gobEncoder := gob.NewEncoder(&gobBuffer)
	err = gobEncoder.Encode(&fixture)
	assert.NoError(t, err)

	gobEncodedLen := gobBuffer.Len()
	gobDecoder := gob.NewDecoder(&gobBuffer)
	gobDecoded := new(LocalPartySaveData)
	err = gobDecoder.Decode(gobDecoded)
	assert.NoError(t, err)

	assert.Equal(t, fixture, gobDecoded, "Gob decoded data should be the same as the original fixture")

	// Print sizes of original and encoded data
	t.Logf("JSON (original) size: %d bytes", len(eddsaSaveFixtureJSON))
	t.Logf("JSON (encoded) size: %d bytes", len(jsonData))
	t.Logf("Gob encoded size: %d bytes", gobEncodedLen)
}
