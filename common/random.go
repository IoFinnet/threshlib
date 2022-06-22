// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/rand"
	"fmt"
	big2 "math/big"

	int2 "github.com/binance-chain/tss-lib/common/int"
	"github.com/pkg/errors"
)

const (
	mustGetRandomIntMaxBits = 5000
)

var (
	zero = int2.NewInt(0)
	one  = int2.NewInt(1)
	two  = int2.NewInt(2)
)

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *int2.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big2.Int)
	max = max.Exp(two.Big(), big2.NewInt(int64(bits)), nil).Sub(max, one.Big())

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return int2.Wrap(n)
}

func GetRandomPositiveInt(upper *int2.Int) *int2.Int {
	if upper == nil || zero.Cmp(upper) != -1 {
		return nil
	}
	var try *int2.Int
	for {
		try = MustGetRandomInt(upper.BitLen())
		if try.Cmp(upper) < 0 && try.Cmp(zero) > 0 {
			break
		}
	}
	return try
}

func GetBigRandomPositiveInt(upper *int2.Int, minBitLen int) *int2.Int {
	if upper == nil || zero.Cmp(upper) != -1 || minBitLen < 8 || upper.BitLen() < minBitLen {
		return nil
	}
	var try *int2.Int
	maxRetries := 100
	ok := false
	for i := 0; i < maxRetries; i++ {
		try = MustGetRandomInt(upper.BitLen())
		if try.Cmp(upper) < 0 && try.Cmp(zero) >= 0 && try.BitLen() >= minBitLen {
			ok = true
			break
		}
	}
	if !ok {
		return nil
	}
	return try
}

func GetRandomPrimeInt(bits int) *int2.Int {
	if bits <= 0 {
		return nil
	}
	try, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
		try.Cmp(zero.Big()) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(bits).Big()
			if probablyPrime(int2.Wrap(try)) {
				break
			}
		}
	}
	return int2.Wrap(try)
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(n *int2.Int) *int2.Int {
	if n == nil || zero.Cmp(n) != -1 {
		return nil
	}
	var try *int2.Int
	for {
		try = MustGetRandomInt(n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

func IsNumberInMultiplicativeGroup(n, v *int2.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := int2.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//  Return a random generator of RQn with high probability.
//  THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(n *int2.Int) *int2.Int {
	f := GetRandomPositiveRelativelyPrimeInt(n)
	fSq := new(int2.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}

func GetRandomQuadraticNonResidue(n *int2.Int) *int2.Int {
	for {
		w := GetRandomPositiveInt(n)
		if big2.Jacobi(w.Big(), n.Big()) == -1 {
			return w
		}
	}
}
