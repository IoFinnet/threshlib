// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpprm_test

import (
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"

	. "github.com/iofinnet/tss-lib/v3/crypto/zkp/prm"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

func TestPrmWithNonce(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute * 10)
	assert.NoError(test, err)
	nonce := common.GetBigRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N), big.Wrap(tss.GetCurveForUnitTest().Params().N).BitLen()-1)

	s, t, lambda, P, Q, N := preParams.H1i, preParams.H2i, preParams.Beta, preParams.P, preParams.Q, preParams.NTildei
	P2, Q2 := new(big.Int).Lsh(P, 1), new(big.Int).Lsh(Q, 1)
	Phi := new(big.Int).Mul(P2, Q2)

	proof, err := NewProofWithNonce(s, t, N, Phi, lambda, nonce)
	assert.NoError(test, err)

	ok := proof.VerifyWithNonce(s, t, N, nonce)
	assert.True(test, ok, "proof must verify")
}

func TestA1(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute * 10)
	assert.NoError(test, err)

	nonce := common.GetBigRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N), big.Wrap(tss.GetCurveForUnitTest().Params().N).BitLen()-1)

	s, t, lambda, P, Q, N := preParams.H1i, preParams.H2i, preParams.Beta, preParams.P, preParams.Q, preParams.NTildei
	P2, Q2 := new(big.Int).Lsh(P, 1), new(big.Int).Lsh(Q, 1)
	Phi := new(big.Int).Mul(P2, Q2)

	proof, err := NewProofWithNonce(s, t, N, Phi, lambda, nonce)
	assert.NoError(test, err)
	proof.A[1] = big.NewInt(1)

	ok := proof.VerifyWithNonce(s, t, N, nonce)
	assert.False(test, ok, "proof must verify")
}
