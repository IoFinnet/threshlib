// Copyright © 2021 Io FinNet Group, Inc.
// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Package common implements safe prime generation using the Combined Sieve algorithm.
//
// Combined Sieve Algorithm Overview:
// The Combined Sieve is an optimized algorithm for finding safe primes (primes of the form
// p = 2q + 1 where q is also prime). It combines multiple sieving techniques to efficiently
// eliminate non-prime candidates before expensive primality tests are performed.
//
// Key Components:
//
// 1. Small Prime Sieving:
//    - Tests candidates against a product of small primes (3, 5, 7, ..., 53)
//    - Quickly eliminates numbers divisible by these primes using modular arithmetic
//    - Much faster than individual divisibility tests or full primality testing
//
// 2. Modulo 3 Optimization:
//    - If q ≡ 1 (mod 3), then p = 2q + 1 ≡ 0 (mod 3), making p composite
//    - This single check eliminates 50% of candidates for p
//    - Mathematical proof: q = 3k + 1 → p = 2(3k + 1) + 1 = 6k + 3 = 3(2k + 1)
//
// 3. Incremental Search with Delta:
//    - Instead of generating new random numbers, adds small even deltas to candidates
//    - Preserves the odd property and high-bit characteristics
//    - Allows testing up to 2^20 variations from a single random start
//
// 4. Pocklington's Criterion:
//    - Once q is proven prime, we only need to verify 2^(p-1) ≡ 1 (mod p)
//    - Avoids expensive primality testing for p, using the fact that p = 2q + 1
//    - Provides mathematical certainty that p is prime given q is prime
//
// 5. Concurrent Generation:
//    - Multiple goroutines search for primes independently
//    - First valid result is accepted, others are cancelled
//    - Particularly effective for large bit sizes where generation time varies
//
// The algorithm's efficiency comes from eliminating candidates early in the pipeline,
// before expensive operations like modular exponentiation and probabilistic primality
// tests are performed. The combination of these techniques makes it significantly
// faster than naive approaches that test random numbers individually.

package common

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"
)

const (
	// InitialPrimeTestN = 1 runs a single BPSW (Baillie-PSW) test
	// BPSW combines Miller-Rabin base 2 + Lucas test, no known counterexamples
	InitialPrimeTestN = 1
	// PrimeTestN = 15 runs BPSW plus 14 additional Miller-Rabin rounds
	// This provides extremely high confidence for cryptographic use
	PrimeTestN = 15
	// maxDeltaSearch specifies the number of 2-increment steps to search from a random base.
	// 1<<20 provides over a million candidates.
	maxDeltaSearch = 1 << 20
)

type (
	GermainSafePrime struct {
		q,
		p *big.Int // p = 2q + 1
	}
)

func (sgp *GermainSafePrime) Prime() *big.Int {
	return sgp.q
}

func (sgp *GermainSafePrime) SafePrime() *big.Int {
	return sgp.p
}

func (sgp *GermainSafePrime) Validate() bool {
	// Create scratch variables for validation
	t1, t2 := new(big.Int), new(big.Int)

	// Check p = 2q + 1
	primeToSafePrime_nonAlloc(t1, sgp.q)
	if t1.Cmp(sgp.p) != 0 {
		return false
	}

	// Note: This validation is more stringent than the generation logic.
	// It performs a full probabilistic primality test on p, which is
	// mathematically redundant if q is prime and Pocklington's criterion is met,
	// but serves as a strong defense-in-depth verification for externally provided values.
	return isPocklingtonCriterionSatisfied_nonAlloc(sgp.p, t1, t2) &&
		probablyPrime(sgp.q) &&
		probablyPrime(sgp.p)
}

// ----- //

func PrimeToSafePrime(q *big.Int) *big.Int {
	// p = 2q + 1
	p := big.Int{}
	p.Mul(q, two)
	p.Add(&p, one)
	return &p
}

func probablyPrime(prime *big.Int) bool {
	return prime != nil && prime.ProbablyPrime(PrimeTestN)
}

// ----- //

// The following code is a modified copy of: https://github.com/didiercrunch/paillier/blob/753322e473bf8ee20267c7824e68ae47360cc69b/safe_prime_generator.go
// It is an implementation of the algorithm described in "Safe Prime Generation with a Combined Sieve" https://eprint.iacr.org/2003/186.pdf

// The code is the original Go implementation of rand.Prime optimized for
// generating safe (Sophie Germain) primes.
// A safe prime is a prime number of the form 2p + 1, where p is also a prime.

// Note from Author (https://github.com/pdyraga):
// I've adapted a Go code for generating random numbers by inserting some
// optimisations that will allow us to generate safe primes faster than
// with the previous, naive approach.
//
// First of all, having q which can be prime, we first check whether q%3=1.
// If that's true, there is no chance p=2q+1 is prime. It lets us to reject
// candidate numbers quicker without running an expensive primality tests.
//
// Also, before we run a primality test for q, we may check p=2q+1 against
// the primes between 3-53 (We are limited by Go's uint64 range).
//
// If all those conditions are met and we know p is prime, it's enough to
// check Pocklington criterion for q instead of running an expensive
// primality test for it.

// GetRandomSafePrimesConcurrent tries to find safe primes concurrently.
// The returned results are safe primes `p` and prime `q` such that `p=2q+1`.
// Concurrency level can be controlled with the `concurrencyLevel` parameter.
// If a safe prime could not be found in the specified `timeout`, the error
// is returned. Also, if at least one search process failed, error is returned
// as well.
//
// The safePrimeFilter parameter can be nil. If provided, it will be called
// to check each new prime candidate against all previously found primes.
// Note: This has O(n²) complexity with respect to numPrimes.
//
// NOTE: Requesting a large number of primes (numPrimes) will result in a
// proportionally large channel buffer, consuming more memory.
//
// How fast we generate a prime number is mostly a matter of luck and it depends
// on how lucky we are with drawing the first bytes.
// With today's multi-core processors, we can execute the process on multiple
// cores concurrently, accept the first valid result and cancel the rest of
// work. This way, with the same finding algorithm, we can get the result
// faster.
//
// Concurrency level should be set depending on what `bitLen` of prime is
// expected. For example, as of today, on a typical workstation, for 512-bit
// safe prime, `concurrencyLevel` should be set to `1` as generating the prime
// of this length is a matter of milliseconds for a single core.
// For 1024-bit safe prime, `concurrencyLevel` should be usually set to at least
// `2` and for 2048-bit safe prime, `concurrencyLevel` must be set to at least
// `4` to get the result in a reasonable time.
//
// This function generates safe primes of at least 6 `bitLen`. For every
// generated safe prime, the two most significant bits are always set to `1`
// - we don't want the generated number to be too small.
func GetRandomSafePrimesConcurrent(
	bitLen, numPrimes int, timeout time.Duration, concurrency int, safePrimeFilter func(p1, p2 *GermainSafePrime) bool) ([]*GermainSafePrime, error) {

	if bitLen < 6 {
		return nil, errors.New("safe prime size must be at least 6 bits")
	}
	if numPrimes < 1 {
		return nil, errors.New("numPrimes should be > 0")
	}

	errCh := make(chan error, concurrency*numPrimes*3)
	primes := make([]*GermainSafePrime, 0, numPrimes)
	primeCh := make(chan *GermainSafePrime, concurrency*numPrimes*3) // Large buffer to decouple workers from the consumer, preventing them from blocking on send

	wg := &sync.WaitGroup{}
	defer func() {
		wg.Wait()
		close(errCh)
		close(primeCh)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		runGenPrimeRoutine(
			ctx, primeCh, errCh, wg, rand.Reader, bitLen,
		)
	}

	needed := int32(numPrimes)
outer:
	for {
		select {
		case result := <-primeCh:
			// This filter check has O(n²) complexity with respect to numPrimes.
			// It is efficient for small n, but may become a bottleneck for large numbers of primes.
			if safePrimeFilter != nil {
				for _, prime := range primes {
					if !safePrimeFilter(prime, result) {
						continue outer
					}
				}
			}
			primes = append(primes, result)
			if atomic.AddInt32(&needed, -1) <= 0 {
				cancel()
				return primes[:numPrimes], nil
			}
		case err := <-errCh:
			cancel()
			return nil, err
		case <-ctx.Done():
			return nil, fmt.Errorf("generator timed out after %v", timeout)
		}
	}
}

// Starts a Goroutine searching for a safe prime of the specified `pBitLen`.
// If succeeds, writes prime `p` and prime `q` such that `p = 2q+1` to the
// `primeCh`. Prime `p` has a bit length equal to `pBitLen` and prime `q` has
// a bit length equal to `pBitLen-1`.
//
// The algorithm is as follows:
//  1. Generate a random odd number `q` of length `pBitLen-1` with two the most
//     significant bits set to `1`.
//  2. Execute preliminary primality test on `q` checking whether it is coprime
//     to all the elements of `smallPrimes`. It allows to eliminate trivial
//     cases quickly, when `q` is obviously no prime, without running an
//     expensive final primality tests.
//     If `q` is coprime to all of the `smallPrimes`, then go to the point 3.
//     If not, add `2` and try again, testing up to 2^20 candidates.
//  3. Check the potentially prime `q`, whether `q = 1 (mod 3)`. This will
//     happen for 50% of cases.
//     If it is, then `p = 2q+1` will be a multiple of 3, so it will be obviously
//     not a prime number. In this case, add `2` and try again (within the same
//     2^20 candidate search). If `q != 1 (mod 3)`, go to the point 4.
//  4. Now we know `q` is potentially prime and `p = 2q+1` is not a multiple of 3.
//     We execute a preliminary primality test on `p`, checking whether
//     it is coprime to all the elements of `smallPrimes` just like we did for
//     `q` in point 2. If `p` is not coprime to at least one element of the
//     `smallPrimes`, we try the next candidate by incrementing delta.
//     If `p` is coprime to all the elements of `smallPrimes`, go to point 5.
//  5. At this point, we know `q` is potentially prime, and `p=2q+1` is also
//     potentially prime. We first execute an initial, fast primality test for `q`
//     (Baillie-PSW). If it passes, we perform a full high-certainty primality test on `q`
//     (BPSW + 14 Miller-Rabin tests). If `q` is confirmed prime, we use Pocklington's
//     criterion to efficiently prove the primality of `p=2q+1`. As a final defense-in-depth
//     check, we run a single BPSW test on `p`. If all checks pass, we return the pair.
//     If not, go back to point 1.
func runGenPrimeRoutine(
	ctx context.Context,
	primeCh chan<- *GermainSafePrime,
	errCh chan<- error,
	waitGroup *sync.WaitGroup,
	rand io.Reader,
	pBitLen int,
) {
	qBitLen := pBitLen - 1
	b := uint(qBitLen % 8)
	if b == 0 {
		b = 8
	}

	bytesLen := (qBitLen + 7) / 8
	bytes := make([]byte, bytesLen)

	// Pre-allocate all big.Int objects once and reuse them
	p := new(big.Int)
	q := new(big.Int)
	qBase := new(big.Int) // Base value for delta calculations
	bigMod := new(big.Int)
	check := new(big.Int)
	// Scratch variables for non-allocating validation
	valT1 := new(big.Int)
	valT2 := new(big.Int)

	go func() {
		defer waitGroup.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, err := io.ReadFull(rand, bytes)
				if err != nil {
					errCh <- err
					return
				}

				// Clear bits in the first byte to make sure the candidate has
				// a size <= bits.
				bytes[0] &= uint8(int(1<<b) - 1)
				// Don't let the value be too small, i.e, set the most
				// significant two bits.
				// Setting the top two bits, rather than just the top bit,
				// means that when two of these values are multiplied together,
				// the result isn't ever one bit short.
				if b >= 2 {
					bytes[0] |= 3 << (b - 2)
				} else {
					// Here b==1, because b cannot be zero.
					bytes[0] |= 1
					if len(bytes) > 1 {
						bytes[1] |= 0x80
					}
				}
				// Make the value odd since an even number this large certainly
				// isn't prime.
				bytes[len(bytes)-1] |= 1

				q.SetBytes(bytes)

				// Calculate the value mod the product of smallPrimes. If it's
				// a multiple of any of these primes we add two until it isn't.
				// The probability of overflowing is minimal and can be ignored
				// because we still perform Miller-Rabin tests on the result.
				bigMod.Mod(q, smallPrimesProduct)
				mod := bigMod.Uint64()

				// Store the base q value to calculate offsets from
				qBase.Set(q)

				// Optimization: Instead of calculating q.Mod(q, 3) in each iteration, we
				// maintain the modulus in a simple integer counter. Since delta increments
				// by 2 each time, q's modulus 3 cycles through (X, X+2, X+1, X, X+2, X+1...).
				// This avoids an expensive big.Int operation in the loop's hot path.
				mod3State := new(big.Int).Mod(qBase, three).Int64()

				candidate := false
			NextDelta:
				for deltaVal := uint64(0); deltaVal < maxDeltaSearch; deltaVal += 2 {
					m := mod + deltaVal
					for _, prime := range smallPrimes {
						// Reject candidates divisible by a small prime.
						// The 'm != prime' check prevents rejecting a candidate that is one of the small primes itself.
						// This works because for small bit lengths (qBitLen <= 6), the candidate q is smaller than
						// smallPrimesProduct, so m (which is q mod smallPrimesProduct) equals q itself.
						// For qBitLen > 6, q is always larger than any small prime, so any divisibility implies it's composite.
						if m%prime == 0 && (m != prime || qBitLen > 6) {
							continue NextDelta
						}
					}

					if deltaVal > 0 {
						bigMod.SetUint64(deltaVal)
						q.Add(qBase, bigMod) // Calculate q = qBase + deltaVal
					}

					// If `q = 1 (mod 3)`, then `p` is a multiple of `3` so it's
					// obviously no prime and such `q` should be rejected.
					// This will happen in 50% of cases and we should detect
					// and eliminate them early.
					//
					// Explanation:
					// If q = 1 (mod 3) then there exists a q' such that:
					// q = 3q' + 1
					//
					// Since p = 2q + 1:
					// p = 2q + 1 = 2(3q' + 1) + 1 = 6q' + 2 + 1 = 6q' + 3 =
					//   = 3(2q' + 1)
					// So `p` is a multiple of `3`.
					if mod3State == 1 {
						// Update mod3State for next iteration: (1 + 2) % 3 = 0
						mod3State = (mod3State + 2) % 3
						continue
					}

					// p = 2q+1 - reuse existing p big.Int
					p.Mul(q, two)
					p.Add(p, one)

					// 1. Perform small primes test
					if q.BitLen() == qBitLen && isPrimeCandidate(p, check) {
						candidate = true
						break
					}

					// Update mod3State for next iteration
					mod3State = (mod3State + 2) % 3
				}

				// There is a tiny possibility that, by adding delta, we caused
				// the number to be one bit too long. Thus, we check BitLen here.

				// 2. Perform initial BPSW test on q as a quick filter
				// This uses ProbablyPrime(1) which runs a single BPSW test - fast but strong
				if candidate && q.BitLen() == qBitLen && q.ProbablyPrime(InitialPrimeTestN) {
					// Use non-allocating validation to avoid unnecessary allocations
					if validateGermainPair_nonAlloc(p, q, valT1, valT2) {
						// Validation passed. Now allocate and create the struct.
						pCopy := new(big.Int).Set(p)
						qCopy := new(big.Int).Set(q)
						sgp := &GermainSafePrime{p: pCopy, q: qCopy}

						select {
						case primeCh <- sgp:
							// Sent successfully
						case <-ctx.Done():
							// Context cancelled, discard the prime
						}
					}
				}
			}
		}
	}()
}

// isPocklingtonCriterionSatisfied_nonAlloc validates Pocklington's criterion.
// Pocklington's criterion can be used to prove the primality of `p = 2q + 1`
// once one has proven the primality of `q`.
// With `q` prime, `p = 2q + 1`, and `p` passing Fermat's primality test to base
// `2` that `2^{p-1} = 1 (mod p)` then `p` is prime as well.
// CAUTION: scratch1 and scratch2 are used for intermediate calculations and will be modified.
func isPocklingtonCriterionSatisfied_nonAlloc(p, scratch1, scratch2 *big.Int) bool {
	return scratch1.Exp(
		two,
		scratch2.Sub(p, one),
		p,
	).Cmp(one) == 0
}

func isPrimeCandidate(n, temp *big.Int) bool {
	m := temp.Mod(n, smallPrimesProduct).Uint64()
	for _, prime := range smallPrimes {
		if m != prime && m%prime == 0 {
			return false
		}
	}
	return true
}

// primeToSafePrime_nonAlloc computes p = 2q + 1 into dest without allocation.
// CAUTION: dest will be modified to contain the result.
func primeToSafePrime_nonAlloc(dest, q *big.Int) {
	dest.Mul(q, two)
	dest.Add(dest, one)
}

// validateGermainPair_nonAlloc performs validation without heap allocations.
// This function implements an optimized primality testing sequence:
// 1. Verifies p = 2q + 1
// 2. Performs full primality test on q (BPSW + additional Miller-Rabin rounds)
// 3. Uses Pocklington's criterion to verify p (fast, deterministic given q is prime)
// 4. Optionally performs a single BPSW test on p as defense-in-depth
//
// CAUTION: t1 and t2 are used for intermediate calculations and will be modified.
func validateGermainPair_nonAlloc(p, q, t1, t2 *big.Int) bool {
	// Check p = 2q + 1
	primeToSafePrime_nonAlloc(t1, q)
	if p.Cmp(t1) != 0 {
		return false
	}

	// Perform full primality test on q (BPSW + 14 additional Miller-Rabin rounds)
	// We already did an initial BPSW test, but now we do the full verification
	if !probablyPrime(q) {
		return false
	}

	// Use Pocklington's criterion to verify p
	// Mathematical theorem: If q is prime and 2^(p-1) ≡ 1 (mod p), then p is prime
	// This is much faster than running another full primality test
	if !isPocklingtonCriterionSatisfied_nonAlloc(p, t1, t2) {
		return false
	}

	// Defense-in-depth: Run a single BPSW test on p
	// This is mathematically redundant given Pocklington's criterion, but provides
	// protection against implementation bugs. Using ProbablyPrime(1) for just BPSW.
	return p.ProbablyPrime(1)
}
