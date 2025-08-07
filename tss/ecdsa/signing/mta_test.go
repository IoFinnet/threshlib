// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	zkpdec "github.com/iofinnet/tss-lib/v3/crypto/zkp/dec"
	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestAffg(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)
	// q3 := new(big.Int).Mul(q, q)
	// q3 = new(big.Int).Mul(q, q3)
	// q6 := new(big.Int).Mul(q3, q3)

	_, pki, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(test, err)
	skj, pkj, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(test, err)

	// gammai * kj == betai + alphaj
	kj := common.GetRandomPositiveInt(q)
	Kj, err := pkj.Encrypt(kj)
	assert.NoError(test, err)

	gammai := common.GetRandomPositiveInt(q)
	BigGammai, _ := crypto.ScalarBaseMult(ec, gammai)

	NCap, s, t, err := keygen.ConstantTestNTildeH1H2(1)
	assert.NoError(test, err)
	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())

	MtaOut, err := NewMtA(ec, Kj, gammai, BigGammai, pkj, pki, NCap, s, t, nonce)
	assert.NoError(test, err)

	alphaj, err := skj.Decrypt(MtaOut.Dji)
	assert.NoError(test, err)
	betai := MtaOut.Beta

	modN := int2.ModInt(big.Wrap(ec.Params().N))
	lhs := modN.Add(alphaj, betai)
	rhs := modN.Mul(kj, gammai)
	test.Log(lhs, rhs)
	assert.Equal(test, 0, lhs.Cmp(rhs))
	ok := MtaOut.Proofji.VerifyWithNonce(ec, pkj, pki, NCap, s, t, Kj, MtaOut.Dji, MtaOut.Fji, BigGammai, nonce)
	assert.True(test, ok)
}

func TestDec(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)
	q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
	modN := int2.ModInt(big.Wrap(ec.Params().N))
	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())

	_, pki, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(test, err)
	_, pkj, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(test, err)

	kj := common.GetRandomPositiveInt(q)
	Kj, 𝜌j, err := pkj.EncryptAndReturnRandomness(kj)
	assert.NoError(test, err)

	𝛾i := common.GetRandomPositiveInt(q)
	Γi, _ := crypto.ScalarBaseMult(ec, 𝛾i)

	NCap, s, t, err := keygen.ConstantTestNTildeH1H2(1)
	assert.NoError(test, err)

	N2 := pkj.NSquare()

	MtaOut, err := NewMtA(ec, Kj, 𝛾i, Γi, pkj, pki, NCap, s, t, nonce)
	assert.NoError(test, err)

	𝜌𝛾s := N2.Mul(big.NewInt(1).Exp(𝜌j, 𝛾i, N2), MtaOut.Sij)
	𝛾k𝛽ʹ := q3.Add(MtaOut.BetaNeg, q3.Mul(𝛾i, kj))

	proofD, err := zkpdec.NewProofWithNonce(ec, pkj, MtaOut.Dji, modN.Add(zero, 𝛾k𝛽ʹ), NCap, s, t, 𝛾k𝛽ʹ, 𝜌𝛾s, nonce)
	assert.NoError(test, err)
	okD := proofD.VerifyWithNonce(ec, pkj, MtaOut.Dji, modN.Add(zero, 𝛾k𝛽ʹ), NCap, s, t, nonce)
	assert.True(test, okD, "proof must verify")

}
