// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpdec_test

import (
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/ipfs/go-log"

	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	. "github.com/iofinnet/tss-lib/v3/crypto/zkp/dec"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestDecWithNonce(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)

	sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*15)
	assert.NoError(test, err)

	x := common.GetRandomPositiveInt(q)
	y := new(big.Int).Add(x, q)
	C, rho, err := sk.EncryptAndReturnRandomness(y)
	assert.NoError(test, err)
	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())

	proof, err := NewProofWithNonce(ec, pk, C, x, NCap, s, t, y, rho, nonce)
	assert.NoError(test, err)

	ok := proof.VerifyWithNonce(ec, pk, C, x, NCap, s, t, nonce)
	assert.True(test, ok, "proof must verify")
}

func TestDecWithCompositions(test *testing.T) {
	if err := log.SetLogLevel("tss-lib", "debug"); err != nil {
		panic(err)
	}
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)
	q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
	modQ3 := int2.ModInt(q3)
	modN := int2.ModInt(q)
	zero := big.NewInt(0)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)

	_, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
	assert.NoError(test, err)
	N2 := pk.NSquare()

	// Ki = enc(ki,𝜌i)
	𝛾i := common.GetRandomPositiveInt(q)
	ki := common.GetRandomPositiveInt(q)
	Ki, 𝜌i, err := pk.EncryptAndReturnRandomness(ki)

	nonce := common.GetBigRandomPositiveInt(q, q.BitLen())

	proof1, err := NewProofWithNonce(ec, pk, Ki, modN.Add(zero, ki), NCap, s, t, ki, 𝜌i, nonce)
	assert.NoError(test, err)
	ok1 := proof1.VerifyWithNonce(ec, pk, Ki, modN.Add(zero, ki), NCap, s, t, nonce)
	assert.True(test, ok1, "proof must verify")

	// 𝛾K = (𝛾i ⊗ Ki)
	𝛾K, err := pk.HomoMult(𝛾i, Ki)
	𝜌ʹ := big.NewInt(1).Exp(𝜌i, 𝛾i, N2)
	yʹ := modQ3.Mul(𝛾i, ki)
	proof2, err := NewProofWithNonce(ec, pk, 𝛾K, modN.Add(zero, yʹ), NCap, s, t, yʹ, 𝜌ʹ, nonce)
	assert.NoError(test, err)
	ok2 := proof2.VerifyWithNonce(ec, pk, 𝛾K, modN.Add(zero, yʹ), NCap, s, t, nonce)
	assert.True(test, ok2, "proof must verify")

	// Di = (𝛾i ⊗ Ki) ⊕ enc(-𝛽,si)
	x := common.GetRandomPositiveInt(q)
	𝛽ʹ := new(big.Int).Add(x, q)
	T, si, err := pk.EncryptAndReturnRandomness(𝛽ʹ)
	assert.NoError(test, err)
	Di, err := pk.HomoAdd(𝛾K, T)

	𝜌ʺ := N2.Mul(big.NewInt(1).Exp(𝜌i, 𝛾i, N2), si)
	yʺ := modQ3.Add(𝛽ʹ, modQ3.Mul(𝛾i, ki))
	proof3, err := NewProofWithNonce(ec, pk, Di, modN.Add(zero, yʺ), NCap, s, t, yʺ, 𝜌ʺ, nonce)
	assert.NoError(test, err)

	ok3 := proof3.VerifyWithNonce(ec, pk, Di, modN.Add(zero, yʺ), NCap, s, t, nonce)
	assert.True(test, ok3, "proof must verify")
}

func TestSmallMod(test *testing.T) {
	if err := log.SetLogLevel("tss-lib", "debug"); err != nil {
		panic(err)
	}
	ec := tss.GetCurveForUnitTest()
	q := big.Wrap(ec.Params().N)
	q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
	modQ3 := int2.ModInt(q3)
	x, _ := new(big.Int).SetString("64237ca0996e32e32523c31ad653d61744fd41042bba2e6e3981a848f7ecd6f5", 16)
	𝛾i, _ := new(big.Int).SetString("c7070cf90b032eb3c844411c918f51653659ea85d007e42fe9a2d29b2ac5a9c", 16)
	ki, _ := new(big.Int).SetString("64237ca0996e32e32523c31ad653d61744fd41042bba2e6e3981a848f7ecd6f5", 16)
	𝛽ʹ := new(big.Int).Add(x, q)
	// modQ3Mul𝛾iki := modQ3.Mul(𝛾i, ki)
	yʺ := modQ3.Add(𝛽ʹ, modQ3.Mul(𝛾i, ki))

	expectedyʺ, _ := new(big.Int).SetString("4dda57ec545360026cabe9eb31b6d7f74f103ea3d44081ab1d08be25747f17bd207522528b9379360160f810113713ff27bb3a4eaeb8e5b2302f949e6a43782", 16)

	assert.True(test, yʺ.Cmp(expectedyʺ) == 0)
}
