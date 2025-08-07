// Copyright © 2021 io finnet group, inc

package signing

import (
	"crypto/ed25519"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	edcrypto "github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
)

// TestEDDSAPublicKeyRecovery tests EDDSA public key recovery when using HD wallet key derivation
func TestEDDSAPublicKeyRecovery(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// Load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdEdwards)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))
	assert.NotNil(t, keys[0].EDDSAPub, "the first EDDSA public key must not be null")

	// Save original public key for comparison later
	originalPubKey := keys[0].EDDSAPub
	originalPkX, originalPkY := originalPubKey.X(), originalPubKey.Y()
	originalEdPoint, err := edcrypto.FromXYToEd25519Point(originalPkX, originalPkY)
	assert.NoError(t, err, "should convert original key to Ed25519 point")
	originalEdPubKey := originalEdPoint.Bytes()

	// Create a key derivation delta
	keyDerivationDelta := common.GetRandomPositiveInt(big.Wrap(tss.Edwards().Params().N))

	// Compute the delta point: G * delta
	derivedPoint, err := crypto.ScalarBaseMult(tss.Edwards(), keyDerivationDelta)
	assert.NoError(t, err, "ScalarBaseMult should not error")

	// Manually derive the public key by adding the delta point to the original public key
	manuallyDerivedPub, err := originalPubKey.Add(derivedPoint)
	assert.NoError(t, err, "adding points should not error")
	manuallyDerivedPkX, manuallyDerivedPkY := manuallyDerivedPub.X(), manuallyDerivedPub.Y()
	manuallyDerivedEdPoint, err := edcrypto.FromXYToEd25519Point(manuallyDerivedPkX, manuallyDerivedPkY)
	assert.NoError(t, err, "should convert manually derived key to Ed25519 point")
	manuallyDerivedEdPubKey := manuallyDerivedEdPoint.Bytes()

	// Make a copy of the keys to avoid modifying the original
	keysCopy := make([]*keygen.LocalPartySaveData, len(keys))
	for i := range keys {
		k := keys[i].Copy()
		keysCopy[i] = &k
	}

	// Update keys with the key derivation delta using the library function
	err = UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keysCopy, nil, tss.Edwards())
	assert.NoError(t, err, "updating keys should not error")

	// Get the derived public key from the updated keys
	derivedPub := keysCopy[0].EDDSAPub
	derivedPkX, derivedPkY := derivedPub.X(), derivedPub.Y()
	derivedEdPoint, err := edcrypto.FromXYToEd25519Point(derivedPkX, derivedPkY)
	assert.NoError(t, err, "should convert to Ed25519 point")
	derivedEdPubKey := derivedEdPoint.Bytes()

	// Verify that the manually derived key matches the one derived by the function
	assert.True(t, derivedPub.Equals(manuallyDerivedPub),
		"derived public key should match manually derived public key")
	assert.Equal(t, manuallyDerivedEdPubKey, derivedEdPubKey,
		"derived Ed25519 public key should match manually derived Ed25519 public key")

	// PHASE: signing with derived keys
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))

	updater := test.SharedPartyUpdaterAsync

	msg, parties, errCh := initTheParties(signPIDs, p2pCtx, threshold, keysCopy, keyDerivationDelta, outCh, endCh, parties, errCh)

	var ended int32
	var signature []byte

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

		case data := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				signature = data.Signature

				// Test 1: Verify signature with derived public key
				// Should pass as we're using the correct derived key
				ok := ed25519.Verify(derivedEdPubKey, msg, signature)
				assert.True(t, ok, "signature should verify with the derived public key")

				// Test 2: Verify signature with original public key
				// Should fail as the signature was created with the derived key
				ok = ed25519.Verify(originalEdPubKey, msg, signature)
				assert.False(t, ok, "signature should NOT verify with the original public key")

				t.Log("EDDSA HD wallet public key recovery test completed successfully")
				break signing
			}
		}
	}
}
