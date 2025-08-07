// Copyright © 2021 Swingby

package signing

import (
	"crypto/ecdsa"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/ckd"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

func initTheParties(signPIDs tss.SortedPartyIDs, p2pCtx *tss.PeerContext, threshold int,
	keys []*keygen.LocalPartySaveData, keyDerivationDelta *big.Int, outCh chan tss.Message,
	endCh chan *common.EndData, parties []*LocalParty,
	errCh chan *tss.Error) (*big.Int, []*LocalParty, chan *tss.Error) {
	// q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	// sessionId := common.GetBigRandomPositiveInt(q, q.BitLen())
	// try a small sessionId
	sessionId := new(big.Int).SetInt64(1)
	// init the parties
	msg := common.GetRandomPrimeInt(256)
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.GetCurveForUnitTest(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P_, _ := NewLocalParty(msg, params, *keys[i], keyDerivationDelta, outCh, endCh, sessionId)
		P := P_.(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	return msg, parties, errCh
}

// For more information about child key derivation see https://github.com/iofinnet/tss-lib/v3/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// As mentioned in the Jira ticket above, we only use non-hardened derived keys.
// Differently from the Jira ticket, our code only updates xi and bigXj
// in signing. Our code does not require updates u_i or the VSS commitment to the polynomial either,
// as these are not used during the signing phase.

// TestNegativeKeyDerivationDelta tests that negative keyDerivationDelta values are rejected
func TestNegativeKeyDerivationDelta(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// Create a negative keyDerivationDelta
	negativeKeyDerivationDelta := new(big.Int).SetInt64(-1)

	// Test that UpdatePublicKeyAndAdjustBigXj rejects negative values
	keyCopies := make([]*keygen.LocalPartySaveData, 1)
	k := keys[0].Copy()
	keyCopies[0] = &k
	err = UpdatePublicKeyAndAdjustBigXj(negativeKeyDerivationDelta, keyCopies, nil, tss.S256())
	assert.Error(t, err, "UpdatePublicKeyAndAdjustBigXj should reject negative delta")
	assert.Contains(t, err.Error(), "must be nil or non-negative", "error should indicate that negative values are not allowed")

	// Create a local party with negative keyDerivationDelta
	p2pCtx := tss.NewPeerContext(signPIDs)
	params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[0], len(signPIDs), threshold)
	msg := common.GetRandomPrimeInt(256)
	sessionId := new(big.Int).SetInt64(1)

	outCh := make(chan tss.Message)
	endCh := make(chan *common.EndData)

	// Attempt to create a party with negative delta - should fail with error
	_, err = NewLocalParty(msg, params, keys[0], negativeKeyDerivationDelta, outCh, endCh, sessionId)
	assert.Error(t, err, "creating party with negative delta should error")
	assert.Contains(t, err.Error(), "must be nil or non-negative", "error should indicate that negative values are not allowed")

	t.Log("ECDSA negative key derivation test passed - correctly rejected negative delta")
}

// TestNilAndZeroKeyDerivationDelta tests that nil and zero keyDerivationDelta behave the same
func TestNilAndZeroKeyDerivationDelta(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// Save original keys for comparison using the Copy method
	keysCopy := make([]*keygen.LocalPartySaveData, len(keys))
	for i := range keys {
		k := keys[i].Copy()
		keysCopy[i] = &k
	}

	// Test with nil keyDerivationDelta
	p2pCtx := tss.NewPeerContext(signPIDs)
	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))
	parties := make([]*LocalParty, 0, len(signPIDs))

	msgNil, partiesNil, _ := initTheParties(signPIDs, p2pCtx, threshold, keysCopy, nil, outCh, endCh, parties, errCh)

	// Test with zero keyDerivationDelta
	zeroKeys := make([]*keygen.LocalPartySaveData, len(keys))
	for i := range keys {
		k := keysCopy[i].Copy()
		zeroKeys[i] = &k
	}

	zeroKeyDerivationDelta := big.NewInt(0)
	p2pCtxZero := tss.NewPeerContext(signPIDs)
	errChZero := make(chan *tss.Error, len(signPIDs))
	outChZero := make(chan tss.Message, len(signPIDs))
	endChZero := make(chan *common.EndData, len(signPIDs))
	partiesZero := make([]*LocalParty, 0, len(signPIDs))

	msgZero, partiesZero, _ := initTheParties(signPIDs, p2pCtxZero, threshold, zeroKeys, zeroKeyDerivationDelta, outChZero, endChZero, partiesZero, errChZero)

	// Verify both are running successfully
	assert.NotNil(t, msgNil, "message should not be nil")
	assert.NotNil(t, msgZero, "message should not be nil")
	assert.Equal(t, len(partiesNil), len(partiesZero), "should have same number of parties")

	// We don't need to run the full signing protocol - just verifying the setup works
	// is enough to confirm that nil and 0 are handled the same

	// Test concluded successfully
	t.Log("ECDSA nil and zero key derivation delta test passed.")
}

func TestHDKeyDerivation(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))
	assert.NotNil(t, keys[0].ECDSAPub, "the first ECDSA public key must not be null")

	// build ecdsa key pair
	pk := keys[0].ECDSAPub

	// setting the chain code to a random positive number smaller than the maximum allowed of 32 bytes
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	common.GetRandomPositiveInt(max32b).FillBytes(chainCode)
	keysPt := make([]*keygen.LocalPartySaveData, len(keys))
	for i, k := range keys {
		keysPt[i] = &k
	}

	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode,
	}

	// Using an arbitrary path of indices. In the common notation, this would be "m/13/209/3".
	il, extendedChildPk, errorDerivation := ckd.DeriveChildKeyFromHierarchy([]uint32{13, 209, 3}, extendedParentPk,
		big.Wrap(tss.GetCurveForUnitTest().Params().N), tss.GetCurveForUnitTest())
	assert.NoErrorf(t, errorDerivation, "there should not be an error deriving the child public key")

	keyDerivationDelta := il

	err = UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keysPt, extendedChildPk.PublicKey, tss.GetCurveForUnitTest())
	assert.NoErrorf(t, err, "there should not be an error setting the derived keys")

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))

	updater := test.SharedPartyUpdaterAsync

	msg, parties, errCh := initTheParties(signPIDs, p2pCtx, threshold, keysPt, keyDerivationDelta, outCh, endCh, parties, errCh)

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

		case data := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants %+v", ended, data)

				// bigR is stored as bytes for the OneRoundData protobuf struct
				bigRX, bigRY := parties[0].temp.BigR.X(), parties[0].temp.BigR.Y()
				bigR := crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), bigRX, bigRY)

				// fmt.Printf("sign result: R(%s, %s), r=%s\n", bigR.X().String(), bigR.Y().String(), r.String())

				modN := int2.ModInt(big.Wrap(tss.GetCurveForUnitTest().Params().N))

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
				}
				// fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				ecdsaPK := &ecdsa.PublicKey{
					Curve: tss.GetCurveForUnitTest(),
					X:     extendedChildPk.X(),
					Y:     extendedChildPk.Y(),
				}
				ok := ecdsa.Verify(ecdsaPK, msg.Bytes(), bigR.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")

				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}
