// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier_test

import (
	"testing"
	"time"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	. "github.com/iofinnet/tss-lib/v3/crypto/paillier"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var (
	privateKey *PrivateKey
	publicKey  *PublicKey
)

func init() {
	privateKey, publicKey, _ = GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
}

func setUp(t *testing.T) {
	t.Parallel()
	if privateKey != nil && publicKey != nil {
		return
	}
}

func TestGenerateKeyPair(t *testing.T) {
	setUp(t)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
}

func TestEncrypt(t *testing.T) {
	setUp(t)
	cipher, err := publicKey.Encrypt(big.NewInt(1))
	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptWithChosenRandomnessFailsBadRandom(t *testing.T) {
	setUp(t)
	_, err := publicKey.EncryptWithGivenRandomness(big.NewInt(1), big.NewInt(0))
	assert.Error(t, err, "must error")
}

func TestEncryptDecrypt(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, err := privateKey.Encrypt(exp)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)
	cypher = new(big.Int).Set(privateKey.N)
	_, err = privateKey.Decrypt(cypher)
	assert.Error(t, err)
}

func TestEncryptDecryptAndRecoverRandomness(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, rand, err := privateKey.EncryptAndReturnRandomness(exp)
	if err != nil {
		t.Error(err)
	}
	ret, rec, err := privateKey.DecryptAndRecoverRandomness(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)
	assert.Equal(t, rand, rec,
		"wrong randomness ", rand, " is not ", rec)
}

func TestEncryptDecryptAndRecoverRandomnessAndReEncrypt1(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, rand, _ := privateKey.EncryptAndReturnRandomness(exp)
	ret, err := privateKey.PublicKey.EncryptWithGivenRandomness(exp, rand)
	assert.NoError(t, err)
	assert.Equal(t, 0, cypher.Cmp(ret),
		"wrong encryption ", ret, " is not ", cypher)
}

func TestEncryptDecryptAndRecoverRandomnessAndReEncrypt2(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, _, _ := privateKey.EncryptAndReturnRandomness(exp)
	_, rand, _ := privateKey.DecryptAndRecoverRandomness(cypher)
	ret, err := privateKey.PublicKey.EncryptWithGivenRandomness(exp, rand)
	assert.NoError(t, err)
	assert.Equal(t, 0, cypher.Cmp(ret),
		"wrong encryption ", ret, " is not ", cypher)
}

func TestEncryptWithChosenRandomnessDecrypt(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	rnd := common.GetRandomPositiveInt(privateKey.N)
	cypher, err := privateKey.EncryptWithGivenRandomness(exp, rnd)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)
}

func TestHomoMul(t *testing.T) {
	setUp(t)
	three, err := privateKey.Encrypt(big.NewInt(3))
	assert.NoError(t, err)

	// for HomoMul, the first argument `m` is not ciphered
	six := big.NewInt(6)

	cm, err := privateKey.HomoMult(six, three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := uint64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestHomoAdd(t *testing.T) {
	setUp(t)
	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	one, _ := publicKey.Encrypt(num1)
	two, _ := publicKey.Encrypt(num2)

	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)
	assert.Equal(t, 0, plain.Cmp(new(big.Int).Add(num1, num2)))
}

func TestProofVerify(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(256)                                                // index
	ui := common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)) // ECDSA private
	y, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), ui)                      // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), y.X(), y.Y()))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), y.X(), y.Y()))
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestProofVerifyFail(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(256)                                                // index
	ui := common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)) // ECDSA private
	y, _ := crypto.ScalarBaseMult(tss.GetCurveForUnitTest(), ui)                      // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), y.X(), y.Y()))
	last := proof[len(proof)-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), y.X(), y.Y()))
	assert.NoError(t, err)
	assert.False(t, res, "proof verify result must be true")
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestGenerateXs(t *testing.T) {
	k := common.MustGetRandomInt(256)
	sX := common.MustGetRandomInt(256)
	sY := common.MustGetRandomInt(256)
	N := common.GetRandomPrimeInt(2048)

	xs := GenerateXs(13, k, N, crypto.NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), sX, sY))
	assert.Equal(t, 13, len(xs))
	for _, xi := range xs {
		assert.True(t, common.IsNumberInMultiplicativeGroup(N, xi))
	}
}
