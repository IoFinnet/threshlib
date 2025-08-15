package signing

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	"github.com/stretchr/testify/assert"
)

// TestE2EConcurrent_OneRoundSignWithChannels runs in one-round signing mode. The signing steps described in figure 8 of the paper
// run as re-initialized Parties and the messages are exchanged via channels.
func TestE2EConcurrentECDSA_OneRoundSignWithChannels(t *testing.T) {
	t.Parallel()
	t.Skip("unsupported functionality - this test does not play well concurrently with other tests")

	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, errL := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, errL, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: pre-signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	preSignParties := make([]*LocalParty, 0, len(signPIDs))
	signParties := make([]*LocalParty, 0, len(signPIDs))
	preSignData := make([]*common.EndData_PreSignatureDataECDSA, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))
	dumpCh := make(chan tss.Message, len(signPIDs))
	// q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	// sessionId := common.GetBigRandomPositiveInt(q, q.BitLen())
	// try a small sessionId
	sessionId := new(big.Int).SetInt64(1)

	updater := test.SharedPartyUpdaterAsync

	// initialize the parties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		// nil in msg is important below
		// a nil msg runs the party in ORS mode
		P_, errP := NewLocalParty(nil, params, keys[i], keyDerivationDelta, outCh, endCh, sessionId)
		if errP != nil {
			t.Errorf("error %v", errP)
			t.FailNow()
		}
		P := P_.(*LocalParty)
		preSignParties = append(preSignParties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var endedPreSign, endedSigning int32
presigning:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presigning

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range preSignParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh, 250)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(preSignParties[dest[0].Index], msg, errCh, 250)
			}
		case preSignEnd := <-endCh:
			d := preSignEnd.GetPreSignDataEcdsa()
			preSignData = append(preSignData, d)
			atomic.AddInt32(&endedPreSign, 1)
			if atomic.LoadInt32(&endedPreSign) == int32(len(signPIDs)) {
				t.Logf("Done pre-signing. Received pre-sign data from %d participants", endedPreSign)
				break presigning
			}
		}
	}

	// initialize the parties again
	t.Logf("Peforming the signing phase starting from the final protocol round...")
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		// re-start at round 4 with message now
		P_, errP := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh, sessionId, 4)
		if errP != nil {
			t.Errorf("error %v", errP)
			t.Fail()
			return
		}
		P := P_.(*LocalParty)
		if err := P.LoadPreSignatureData(preSignData[i]); err != nil {
			t.Errorf("error %v", err)
			t.Fail()
			return
		}
		signParties = append(signParties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	t.Logf("Proceeding to sign the message...")
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh, 250)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signParties[dest[0].Index], msg, errCh, 250)
			}

		case dtemp := <-dumpCh:
			fmt.Println("got from dump")
			fmt.Println(dtemp)
			// P = ...... with dtemp
			// P.start
		case end := <-endCh:
			atomic.AddInt32(&endedSigning, 1)
			if atomic.LoadInt32(&endedSigning) == int32(len(signPIDs)) {
				t.Logf("Done signing. Received signature data from %d participants", endedSigning)
				R := signParties[0].temp.BigR
				// r := parties[0].temp.Rx
				// fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := int2.ModInt(big.Wrap(tss.S256().Params().N))

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range signParties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
				}
				// fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.S256(),
					X:     pkX,
					Y:     pkY,
				}

				r, s, v := end.R, end.S, end.SignatureRecovery
				sig := make([]byte, 65)
				subtle.ConstantTimeCopy(1, sig[32-len(r):32], r)
				subtle.ConstantTimeCopy(1, sig[64-len(s):64], s)
				sig[64] = v[0] & 0x01

				expPub := keys[0].ECDSAPub.ToBtcecPubKey().SerializeUncompressed()

				gotPub, err2 := crypto.Ecrecover(msg.Bytes(), sig)
				if !assert.NoError(t, err2) {
					return
				}
				if subtle.ConstantTimeCompare(expPub, gotPub) != 1 {
					t.Fatalf("recovered key did not match the expected one")
				}

				ok := ecdsa.Verify(&pk, msg.Bytes(), R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA S256 ORS signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}

// TestE2EConcurrent_OneRoundSignFinalize runs in one-round signing mode. The signing steps described in Figure 8 of the paper
// are the responsibility of the client. The parties are not re-initialized and no channels are used for the
// steps of Figure 8. The unit test calls FinalizeOneRoundSignAndVerify to calculate the final signature.
func TestE2EConcurrent_OneRoundSignFinalize(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, errL := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, errL, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: pre-signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	preSignParties := make([]*LocalParty, 0, len(signPIDs))
	preSignData := make([]*common.EndData_PreSignatureDataECDSA, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))
	// q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	// sessionId := common.GetBigRandomPositiveInt(q, q.BitLen())
	// try a small sessionId
	sessionId := new(big.Int).SetInt64(1)

	updater := test.SharedPartyUpdaterAsync

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		// nil in msg is important below
		// a nil msg runs the party in ORS mode
		P_, errP := NewLocalParty(nil, params, keys[i], keyDerivationDelta, outCh, endCh, sessionId)
		if errP != nil {
			t.Errorf("error %v", errP)
			t.FailNow()
		}
		P := P_.(*LocalParty)
		preSignParties = append(preSignParties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var endedPreSign int32
presigning:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presigning

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range preSignParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh, 250)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(preSignParties[dest[0].Index], msg, errCh, 250)
			}
		case preSignEnd := <-endCh:
			d := preSignEnd.GetPreSignDataEcdsa()
			preSignData = append(preSignData, d)
			atomic.AddInt32(&endedPreSign, 1)
			if atomic.LoadInt32(&endedPreSign) == int32(len(signPIDs)) {
				t.Logf("Done pre-signing. Received pre-sign data from %d participants", endedPreSign)
				break presigning
			}
		}
	}

	// Collect up ORS shares and finalize
	t.Logf("Collecting ORS shares and finalizing the signature...")
	𝜎js := make([]*big.Int, 0, len(preSignParties))
	modN := int2.ModInt(big.Wrap(tss.S256().Params().N))

	sumS := big.NewInt(0)
	for _, psd := range preSignData {
		𝜎j := FinalizeSigmaShare(
			tss.S256(),
			new(big.Int).SetBytes(psd.GetKI()),
			new(big.Int).SetBytes(psd.GetR().GetX()),
			new(big.Int).SetBytes(psd.GetChiI()),
			msg)
		𝜎js = append(𝜎js, 𝜎j)
		sumS = modN.Add(sumS, 𝜎j)
	}

	endData, errF := FinalizeOneRoundSignAndVerify(
		preSignParties[0].keys.ECDSAPub.Curve(),
		preSignParties[0].keys.ECDSAPub,
		crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(),
			new(big.Int).SetBytes(preSignData[0].GetR().GetX()),
			new(big.Int).SetBytes(preSignData[0].GetR().GetY())),
		𝜎js,
		msg)

	assert.NoError(t, errF, "no erro expected")

	R := preSignParties[0].temp.BigR

	// BEGIN ECDSA verify
	pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
	pk := ecdsa.PublicKey{
		Curve: tss.GetCurveForUnitTest(),
		X:     pkX,
		Y:     pkY,
	}

	r, s, v := endData.R, endData.S, endData.SignatureRecovery
	sig := make([]byte, 65)
	subtle.ConstantTimeCopy(1, sig[32-len(r):32], r)
	subtle.ConstantTimeCopy(1, sig[64-len(s):64], s)
	sig[64] = v[0] & 0x01

	expPub := keys[0].ECDSAPub.ToBtcecPubKey().SerializeUncompressed()

	gotPub, err2 := crypto.Ecrecover(msg.Bytes(), sig)
	if !assert.NoError(t, err2) {
		return
	}
	if subtle.ConstantTimeCompare(expPub, gotPub) != 1 {
		t.Fatalf("recovered key did not match the expected one")
	}

	ok := ecdsa.Verify(&pk, msg.Bytes(), R.X(), sumS)
	assert.True(t, ok, "ecdsa verify must pass")
	t.Log("ECDSA S256 ORS signing test done.")
	// END ECDSA verify
}
