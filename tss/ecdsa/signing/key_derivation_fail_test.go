// Copyright © 2021 io finnet group, inc

package signing

import (
	"strings"
	"sync/atomic"
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

// TestMismatchedKeyDerivationDelta verifies that signing fails when parties use different keyDerivationDeltas
func TestMismatchedKeyDerivationDelta(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// Create different keyDerivationDeltas for each party
	deltas := make([]*big.Int, len(signPIDs))
	for i := range deltas {
		// Use different deltas for each party
		deltas[i] = new(big.Int).SetUint64(uint64(i + 1))

		// Apply different delta to each party's keys
		keyCopies := make([]*keygen.LocalPartySaveData, 1)
		k := keys[i].Copy()
		keyCopies[0] = &k
		err = UpdatePublicKeyAndAdjustBigXj(deltas[i], keyCopies, nil, tss.S256())
		assert.NoError(t, err, "updating keys should not error")
		keys[i] = *keyCopies[0]
	}

	// PHASE: signing
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))

	updater := test.SharedPartyUpdaterAsync

	// init the parties with different key derivation deltas
	msg := common.GetRandomPrimeInt(256)
	sessionId := new(big.Int).SetInt64(1)

	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P_, _ := NewLocalParty(msg, params, keys[i], deltas[i], outCh, endCh, sessionId)
		P := P_.(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// Wait for result
	var ended, errored int32
signing:
	for {
		select {
		case err := <-errCh:
			// This is the expected path with different deltas
			common.Logger.Infof("Error received: %s", err)
			// With mismatched key derivation deltas, we expect errors
			atomic.AddInt32(&errored, 1)
			if atomic.LoadInt32(&errored) == int32(len(signPIDs)) {
				t.Logf("All parties produced errors as expected")
				break signing
			}
			// If we get even one error, that's good enough for the test
			if atomic.LoadInt32(&errored) > 0 {
				// We got an error related to inconsistent keys, which is what we want
				errMsg := err.Error()
				// Check if error is related to key inconsistency
				if strings.Contains(errMsg, "mismatched") || strings.Contains(errMsg, "inconsistent") {
					t.Logf("Key derivation error detected: %v", errMsg)
					break signing
				}
			}

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go func(P *LocalParty, msg tss.Message) {
						// No panic recovery - parties should properly error, not panic
						updater(P, msg, errCh)
					}(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *LocalParty, msg tss.Message) {
					// No panic recovery - parties should properly error, not panic
					updater(P, msg, errCh)
				}(parties[dest[0].Index], msg)
			}

		case <-endCh:
			// Count completions
			atomic.AddInt32(&ended, 1)

			// If all parties complete successfully, that's an error in our test
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Errorf("Signing unexpectedly succeeded with mismatched key derivation deltas")
				break signing
			}
		}
	}

	// Verify we didn't get a successful signing with different deltas
	assert.NotEqual(t, int32(len(signPIDs)), atomic.LoadInt32(&ended),
		"All parties should not have been able to complete signing with mismatched deltas")

	// We should have seen at least one error
	assert.Greater(t, atomic.LoadInt32(&errored), int32(0),
		"At least one party should have produced an error with mismatched deltas")

	t.Logf("Test successful - the ECDSA signing protocol failed as expected with mismatched deltas")
}
