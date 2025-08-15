// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpaffg_test

import (
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	. "github.com/iofinnet/tss-lib/v3/crypto/zkp/affg"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestAffgWithNonce(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	// q6 := new(big.Int).Mul(q3, q3)

	_, pk0, err := paillier.GenerateKeyPair(testPaillierKeyLength, 15*time.Minute)
	assert.NoError(test, err)
	_, pk1, err := paillier.GenerateKeyPair(testPaillierKeyLength, 15*time.Minute)
	assert.NoError(test, err)

	// a*b+w
	a := common.GetRandomPositiveInt(q)
	x := common.GetRandomPositiveInt(q)
	// x := q6
	y := common.GetRandomPositiveInt(q3)

	X, _ := crypto.ScalarBaseMult(ec, x)
	assert.NoError(test, err)

	Y, rhoy, err := pk1.EncryptAndReturnRandomness(y)
	assert.NoError(test, err)

	NCap, s, t, err := keygen.ConstantTestNTildeH1H2(1)
	assert.NoError(test, err)

	C, _, err := pk0.EncryptAndReturnRandomness(a)
	assert.NoError(test, err)

	cw, rho, err := pk0.EncryptAndReturnRandomness(y)
	assert.NoError(test, err)

	D, err := pk0.HomoMult(x, C)
	assert.NoError(test, err)
	D, err = pk0.HomoAdd(D, cw)
	assert.NoError(test, err)
	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())

	proof, err := NewProofWithNonce(ec, pk0, pk1, NCap, s, t, C, D, Y, X, x, y, rho, rhoy, nonce)
	assert.NoError(test, err)

	ok := proof.VerifyWithNonce(ec, pk0, pk1, NCap, s, t, C, D, Y, X, nonce)
	assert.True(test, ok, "proof must verify")
}
