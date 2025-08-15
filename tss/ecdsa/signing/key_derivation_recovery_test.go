// Copyright © 2021 io finnet group, inc

package signing

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	commonint "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

// TestECDSAPublicKeyRecovery tests ECDSA public key recovery when using HD wallet key derivation
func TestECDSAPublicKeyRecovery(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// Load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))
	assert.NotNil(t, keys[0].ECDSAPub, "the first ECDSA public key must not be null")

	// Save original public key for comparison later
	originalPubKey := keys[0].ECDSAPub
	originalEcdsaPubKey := &ecdsa.PublicKey{
		Curve: tss.GetCurveForUnitTest(),
		X:     new(big.Int).Set(originalPubKey.X()),
		Y:     new(big.Int).Set(originalPubKey.Y()),
	}

	// Create a key derivation delta
	keyDerivationDelta := common.GetRandomPositiveInt(commonint.Wrap(tss.GetCurveForUnitTest().Params().N))

	// Compute the delta point: G * delta
	derivedPoint, err := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), keyDerivationDelta)
	assert.NoError(t, err, "ScalarBaseMult should not error")

	// Manually derive the public key by adding the delta point to the original public key
	manuallyDerivedPub, err := originalPubKey.Add(derivedPoint)
	assert.NoError(t, err, "adding points should not error")
	manuallyDerivedEcdsaPubKey := &ecdsa.PublicKey{
		Curve: tss.GetCurveForUnitTest(),
		X:     new(big.Int).Set(manuallyDerivedPub.X()),
		Y:     new(big.Int).Set(manuallyDerivedPub.Y()),
	}

	// Make a copy of the keys to avoid modifying the original
	keysCopy := make([]*keygen.LocalPartySaveData, len(keys))
	for i := range keys {
		k := keys[i].Copy()
		keysCopy[i] = &k
	}

	// Update keys with the key derivation delta using the library function
	err = UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keysCopy, nil, tss.GetCurveForUnitTest())
	assert.NoError(t, err, "updating keys should not error")

	// Get the derived public key from the updated keys
	derivedPub := keysCopy[0].ECDSAPub
	derivedEcdsaPubKey := &ecdsa.PublicKey{
		Curve: tss.GetCurveForUnitTest(),
		X:     new(big.Int).Set(derivedPub.X()),
		Y:     new(big.Int).Set(derivedPub.Y()),
	}

	// Verify that the manually derived key matches the one derived by the function
	assert.True(t, derivedPub.Equals(manuallyDerivedPub),
		"derived public key should match manually derived public key")
	assert.Equal(t, 0, manuallyDerivedEcdsaPubKey.X.Cmp(derivedEcdsaPubKey.X),
		"derived ECDSA public key X should match manually derived ECDSA public key X")
	assert.Equal(t, 0, manuallyDerivedEcdsaPubKey.Y.Cmp(derivedEcdsaPubKey.Y),
		"derived ECDSA public key Y should match manually derived ECDSA public key Y")

	// PHASE: signing with derived keys
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))

	updater := test.SharedPartyUpdaterAsync

	msg, parties, errCh := initTheParties(signPIDs, p2pCtx, threshold, keysCopy, keyDerivationDelta, outCh, endCh, parties, errCh)

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

		case end := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)

				// Get the signature components
				bigRX := parties[0].temp.BigR.X()
				bigRY := parties[0].temp.BigR.Y()
				bigR := crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), bigRX, bigRY)

				// Get the s component of the signature
				modN := int2.ModInt(commonint.Wrap(tss.GetCurveForUnitTest().Params().N))
				sumS := commonint.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
				}

				// Test 1: Verify signature with derived public key
				ok := ecdsa.Verify(derivedEcdsaPubKey, msg.Bytes(), bigR.X(), sumS)
				assert.True(t, ok, "signature should verify with the derived public key")

				// Test 2: Verify signature with original public key
				ok = ecdsa.Verify(originalEcdsaPubKey, msg.Bytes(), bigR.X(), sumS)
				assert.False(t, ok, "signature should NOT verify with the original public key")

				// Test 3: Perform EC recovery to recover the public key using end data's SignatureRecovery byte

				// First, check which recovery ID works with our derived public key
				testSig := make([]byte, 65)
				copy(testSig[0:32], end.R)
				copy(testSig[32:64], end.S)

				var workingRecoveryID byte
				derivedUncompressed := derivedPub.ToBtcecPubKey().SerializeUncompressed()

				for v := byte(0); v <= 3; v++ {
					testSig[64] = v
					testRecoveredPub, testErr := crypto.Ecrecover(msg.Bytes(), testSig)
					if testErr == nil && bytes.Equal(testRecoveredPub, derivedUncompressed) {
						workingRecoveryID = v
						break
					}
				}

				// Assert that the end data's SignatureRecovery byte matches the one that works
				assert.Equal(t, workingRecoveryID, end.SignatureRecovery[0],
					"SignatureRecovery byte in end data should match the working recovery ID")

				// Create a properly formatted signature for recovery
				sig := make([]byte, 65)

				// Copy R and S from the end data (which already has them properly padded)
				copy(sig[0:32], end.R)
				copy(sig[32:64], end.S)

				// Use the recovery ID from the end data
				// The recovery ID should be in the range [0-3]
				recoveryID := end.SignatureRecovery[0]
				sig[64] = recoveryID

				// Perform the public key recovery
				recoveredPub, err := crypto.Ecrecover(msg.Bytes(), sig)
				assert.NoError(t, err, "ecrecover should not error with SignatureRecovery byte")

				// Log the recovery ID used
				t.Logf("Successfully used end data's SignatureRecovery byte (%d) to recover the public key",
					end.SignatureRecovery[0])

				// Test 4: Verify that the recovered key matches our derived key
				assert.True(t, bytes.Equal(recoveredPub, derivedUncompressed),
					"recovered key should match derived key")

				t.Log("ECDSA HD wallet public key recovery test completed successfully")
				break signing
			}
		}
	}
}
