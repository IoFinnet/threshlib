// Copyright © 2021 Io FinNet Group, Inc.

package common

import (
	big "github.com/iofinnet/tss-lib/v3/common/int"
)

// smallPrimes contains the first 15 odd primes (excluding 2).
// Used for rapid elimination of composite candidates in safe prime generation.
// Product fits in uint64 for efficient modular arithmetic.
var smallPrimes = []uint64{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of smallPrimes.
// Allows efficient coprimality testing via single modular reduction.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// GetFirstNPrimes returns the first n prime numbers.
// This is a lazy-initialized function that generates primes on first call
// and caches them for subsequent calls.
func GetFirstNPrimes(n int) []uint {
	if n <= 0 {
		return []uint{}
	}

	// For common cases, return pre-computed values
	if n <= 25 {
		// First 25 primes (up to 97)
		allPrimes := []uint{
			2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
			59, 61, 67, 71, 73, 79, 83, 89, 97,
		}
		if n <= len(allPrimes) {
			return allPrimes[:n]
		}
	}

	// For larger n, generate using sieve
	// Estimate upper bound using prime number theorem
	// For n >= 6: p_n < n * (ln(n) + ln(ln(n)))
	estimatedLimit := n * 20 // Simple overestimate that works well
	if n > 100 {
		estimatedLimit = n * 15
	}

	primes := GetPrimesUpTo(estimatedLimit)
	if len(primes) >= n {
		return primes[:n]
	}

	// If we didn't get enough primes, increase limit and try again
	for len(primes) < n {
		estimatedLimit *= 2
		primes = GetPrimesUpTo(estimatedLimit)
	}

	return primes[:n]
}

// GetPrimesUpTo generates all prime numbers up to the given limit
// using the Sieve of Eratosthenes algorithm.
func GetPrimesUpTo(limit int) []uint {
	if limit < 2 {
		return []uint{}
	}

	// Use sieve of Eratosthenes
	isComposite := make([]bool, limit+1)
	isComposite[0] = true
	isComposite[1] = true

	for p := 2; p*p <= limit; p++ {
		if !isComposite[p] {
			for i := p * p; i <= limit; i += p {
				isComposite[i] = true
			}
		}
	}

	// Collect the primes
	var primes []uint
	for i := 2; i <= limit; i++ {
		if !isComposite[i] {
			primes = append(primes, uint(i))
		}
	}
	return primes
}
