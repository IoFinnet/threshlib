// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch_test

import (
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	. "github.com/iofinnet/tss-lib/v3/crypto/zkp/sch"
	"github.com/iofinnet/tss-lib/v3/tss"
)

func TestBIP340ProofVerifyWithNonce(t *testing.T) {
	t.Parallel()
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	u := common.GetRandomPositiveInt(q)
	X, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), u)
	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())
	proof, err := NewProofWithNonce(X, u, nonce)
	assert.NoError(t, err, "there should be no error")

	res := proof.VerifyWithNonce(X, nonce)

	assert.True(t, res, "verify result must be true")
}

func TestBIP340ProofVerifyWithNonceEdwards(t *testing.T) {
	t.Parallel()
	if err := log.SetLogLevel("tss-lib", "debug"); err != nil {
		panic(err)
	}
	curve := tss.Edwards()

	u := big.NewInt(11)
	X, _ := crypto.ScalarBaseMult(curve, u)
	nonce := common.GetBigRandomPositiveInt(big.Wrap(curve.Params().N), big.Wrap(curve.Params().N).BitLen()-1)
	alpha := big.NewInt(90909)
	proof, err := NewProofWithNonceAndAlpha(X, u, alpha, nonce)

	assert.NoError(t, err, "there should be no error")

	res := proof.VerifyWithNonce(X, nonce)

	assert.True(t, res, "verify result must be true")
}

func TestBIP340ProofVerifyBadX(t *testing.T) {
	t.Parallel()
	curve := tss.S256()
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), u)
	X2, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), u2)

	nonce := common.GetBigRandomPositiveInt(big.Wrap(curve.Params().N), big.Wrap(curve.Params().N).BitLen()-1)

	proof, err := NewProofWithNonce(X2, u2, nonce)
	assert.NoError(t, err, "there should be no error")

	res := proof.VerifyWithNonce(X, nonce)

	assert.False(t, res, "verify result must be false")
}

func TestZeros(t *testing.T) {
	t.Parallel()
	curve := tss.S256()
	nonce := common.GetBigRandomPositiveInt(big.Wrap(curve.Params().N), big.Wrap(curve.Params().N).BitLen()-1)
	zero := big.NewInt(0)
	idG, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), big.NewInt(1))
	proof, err := NewProofWithNonce(idG, zero, nonce)
	assert.Error(t, err, "when x is zero there must be an error")
	assert.Nil(t, proof, "the proof must be nil with the error")

	p2, err2 := NewProofWithNonceAndAlpha(idG, zero, zero, zero)
	assert.Error(t, err2, "when alpha is zero there must be an error")
	assert.Nil(t, p2, "the proof must be nil with the error")
}

func TestBadVerify(t *testing.T) {
	t.Parallel()
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	u := common.GetRandomPositiveInt(q)
	X, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), u)
	nonce := common.GetRandomPositiveInt(q)
	proof, _ := NewProofWithNonce(X, u, nonce)
	proof.Z = big.NewInt(0)
	res := proof.VerifyWithNonce(X, nonce)
	assert.False(t, res, "verify result must be false")

	proof.Z = nil
	res2 := proof.VerifyWithNonce(X, nonce)
	assert.False(t, res2, "verify result must be false")
}
