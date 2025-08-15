// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	big2 "math/big"
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
)

const (
	randomIntBitLen = 1024
)

func TestGetRandomInt(t *testing.T) {
	t.Parallel()
	rnd := common.MustGetRandomInt(randomIntBitLen)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	t.Parallel()
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPos := common.GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	t.Parallel()
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPrimeInt(t *testing.T) {
	t.Parallel()
	prime := common.GetRandomPrimeInt(randomIntBitLen)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(common.PrimeTestN), "rand prime should be prime")
}

func TestGetRandomQuadraticNonResidue(t *testing.T) {
	t.Parallel()
	rnd := common.MustGetRandomInt(randomIntBitLen)
	N := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	// ensure N is odd
	for N.Bit(0) == 0 {
		N = common.GetRandomPositiveRelativelyPrimeInt(rnd)
	}
	w := common.GetRandomQuadraticNonResidue(N)
	assert.Equal(t, big2.Jacobi(w, N), -1, "must get quadratic non residue")
}
