// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)

	proof, err := NewProof(uG, u)

	assert.NoError(t, err, "there should be no error")

	assert.True(t, proof.A.IsOnCurve())
	assert.NotZero(t, proof.A.X())
	assert.NotZero(t, proof.A.Y())
	assert.NotZero(t, proof.Z)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	nonce := common.GetRandomPositiveInt(q)
	proof, err := NewProofGivenNonce(X, u, nonce)
	assert.NoError(t, err, "there should be no error")

	res := proof.VerifyWithNonce(X, nonce)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyWithNonce(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	nonce := common.GetRandomPositiveInt(q)
	proof, err := NewProofGivenNonce(X, u, nonce)
	assert.NoError(t, err, "there should be no error")

	res := proof.VerifyWithNonce(X, nonce)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof, err := NewProof(X2, u2)
	assert.NoError(t, err, "there should be no error")

	res := proof.Verify(X)

	assert.False(t, res, "verify result must be false")
}
