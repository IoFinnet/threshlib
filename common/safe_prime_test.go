// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"runtime"
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/stretchr/testify/assert"
)

const (
	// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
	pQBitLenDifference = 3
)

func Test_getSafePrime(t *testing.T) {
	t.Parallel()
	prime := new(big.Int).SetInt64(5)
	sPrime := PrimeToSafePrime(prime)
	assert.True(t, sPrime.ProbablyPrime(PrimeTestN))
}

func Test_getSafePrime_Bad(t *testing.T) {
	t.Parallel()
	prime := new(big.Int).SetInt64(12)
	sPrime := PrimeToSafePrime(prime)
	assert.False(t, sPrime.ProbablyPrime(PrimeTestN))
}

func Test_Validate(t *testing.T) {
	t.Parallel()
	prime := new(big.Int).SetInt64(5)
	sPrime := PrimeToSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.True(t, sgp.Validate())
}

func Test_Validate_Bad(t *testing.T) {
	t.Parallel()
	prime := new(big.Int).SetInt64(12)
	sPrime := PrimeToSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.False(t, sgp.Validate())
}

func TestGetRandomGermainPrimeConcurrent(t *testing.T) {
	t.Parallel()
	// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
	modulusBitLen := 2048
	filter := func(p1, p2 *GermainSafePrime) bool {
		P, Q := p1.SafePrime(), p2.SafePrime()
		// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
		if new(big.Int).Sub(P, Q).BitLen() >= (modulusBitLen/2)-pQBitLenDifference {
			return true
		}
		return false
	}
	//
	sgps, err := GetRandomSafePrimesConcurrent(1024, 2, 20*time.Minute, runtime.NumCPU(), filter)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
	if sgps[0].p.Cmp(sgps[1].p) == 0 {
		t.Fatal("expected distinct prime p's")
	}
	if sgps[0].q.Cmp(sgps[1].q) == 0 {
		t.Fatal("expected distinct prime q's")
	}
	if sgps[0].p.Cmp(sgps[0].q) == 0 {
		t.Fatal("expected distinct prime p's and q's (1)")
	}
	if sgps[1].p.Cmp(sgps[1].q) == 0 {
		t.Fatal("expected distinct prime p's and q's (2)")
	}
	if new(big.Int).Sub(sgps[0].SafePrime(), sgps[1].SafePrime()).BitLen() < (modulusBitLen/2)-pQBitLenDifference {
		t.Fatal("expected safe prime to be more different than 2^(modulusBitLen/2)-3")
	}
}
