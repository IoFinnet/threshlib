package signing

import (
	"crypto/ecdsa"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/common"
	int2 "github.com/binance-chain/tss-lib/common/int"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

func TestSaveState(t *testing.T) {
	setUp("debug")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalStatefulParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	// dumpCh := make(chan tss.Message, len(signPIDs))
	q := int2.Wrap(tss.EC().Params().N)
	sessionId := common.GetRandomPositiveInt(q)

	updater := test.SharedPartyUpdater
	keyDerivationDelta := int2.NewInt(0)
	partyHydratedInTest := false
	specialPartyToHydrate := 0

	// Just save
	saveAdvanceFunc := func(p LocalStatefulParty, msg tss.ParsedMessage) (bool, *tss.Error) {
		if errS := p.DehydrateAndSave(); errS != nil {
			common.Logger.Errorf("error: %v", errS)
			return false, p.WrapError(errS)
		}
		return false, nil
	}

	// Save and reload party 0
	preAdvanceReplacePartyFunc := func(p LocalStatefulParty, msg tss.ParsedMessage) (bool, *tss.Error) {
		if errF := p.DehydrateAndSave(); errF != nil {
			common.Logger.Errorf("error: %v", errF)
			return false, p.WrapError(errF)
		}

		// Hydrate party 0
		if p.Round().RoundNumber() == 3 && msg.GetFrom().Index == 1 && !partyHydratedInTest {
			time.Sleep(3 * time.Second)
			params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[specialPartyToHydrate], len(signPIDs), threshold)
			party_, _ := NewLocalStatefulParty(int2.NewInt(42), params, keys[specialPartyToHydrate],
				keyDerivationDelta, outCh, endCh, saveAdvanceFunc, sessionId)
			parties[specialPartyToHydrate] = party_.(*LocalStatefulParty)
			_, errH := parties[specialPartyToHydrate].HydrateIfNeeded(sessionId)
			if errH != nil {
				common.Logger.Errorf("Error: %s", errH)
				assert.FailNow(t, errH.Error())
			}
			partyHydratedInTest = true
			// common.Logger.Debugf("party:%v, post-update test intervention (end)", p.PartyID())
			return true, nil
		}
		return false, nil
	}

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		var advanceCallback func(p LocalStatefulParty, msg tss.ParsedMessage) (bool, *tss.Error)
		if i == specialPartyToHydrate {
			advanceCallback = preAdvanceReplacePartyFunc
		} else {
			advanceCallback = saveAdvanceFunc
		}
		P_, errP := NewLocalStatefulParty(int2.NewInt(42), params, keys[i], keyDerivationDelta, outCh, endCh,
			advanceCallback, sessionId)
		if errP != nil {
			t.Errorf("error %v", errP)
			t.FailNow()
		}
		P := P_.(*LocalStatefulParty)
		parties = append(parties, P)
		go func(P *LocalStatefulParty) {
			if errS := P.Start(); errS != nil {
				errCh <- errS
			}
		}(P)
	}

	var ended int32

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
		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.BigR
				// r := parties[0].temp.Rx
				// fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := int2.ModInt(int2.Wrap(tss.S256().Params().N))

				// BEGIN check s correctness
				sumS := int2.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
				}
				// fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX.Big(),
					Y:     pkY.Big(),
				}
				ok := ecdsa.Verify(&pk, int2.NewInt(42).Bytes(), R.X().Big(), sumS.Big())
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				// State file cleanup
				for _, p := range parties {
					errR := RemoveLocalStatefulPartyFile(p.PartyID().Index, sessionId)
					if errR != nil {
						assert.NoError(t, errR)
					}
				}
				break signing
			}
		}
	}

}
