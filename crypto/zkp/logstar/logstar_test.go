// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkplogstar_test

import (
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	. "github.com/iofinnet/tss-lib/v3/crypto/zkp/logstar"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestLogstarWithNonce(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)

	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)

	x := common.GetRandomPositiveInt(q)
	C, rho, err := sk.EncryptAndReturnRandomness(x)
	assert.NoError(test, err)
	X, _ := crypto.ScalarBaseMult(ec, x)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)

	// with nonce
	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())
	g, _ := crypto.ScalarBaseMult(ec, big.NewInt(1))
	proof2, err := NewProofWithNonce(ec, pk, C, X, g, NCap, s, t, x, rho, nonce)
	assert.NoError(test, err)

	ok2 := proof2.VerifyWithNonce(ec, pk, C, X, g, NCap, s, t, nonce)
	assert.True(test, ok2, "proof must verify")
}
