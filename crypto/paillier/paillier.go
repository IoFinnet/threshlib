// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// The Paillier Crypto-system is an additive crypto-system. This means that given two ciphertexts, one can perform operations equivalent to adding the respective plain texts.
// Additionally, Paillier Crypto-system supports further computations:
//
// * Encrypted integers can be added together
// * Encrypted integers can be multiplied by an unencrypted integer
// * Encrypted integers and unencrypted integers can be added together
//
// Implementation adheres to GG18Spec (6)

package paillier

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	crypto2 "github.com/iofinnet/tss-lib/v3/crypto"
)

const (
	ProofIters        = 13
	verifyPrimesUntil = 1000 // Verify uses primes <1000
	// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
	pQBitLenDifference = 3 // >1020-bit P-Q
)

type (
	PublicKey struct {
		N *big.Int
	}

	PrivateKey struct {
		PublicKey
		LambdaN, // lcm(p-1, q-1)
		PhiN *big.Int // (p-1) * (q-1)
	}

	Proof [ProofIters]*big.Int
)

var (
	ErrMessageTooLong   = fmt.Errorf("the message is too large or < 0")
	ErrMessageMalFormed = fmt.Errorf("the message is mal-formed")

	zero = big.NewInt(0)
	one  = big.NewInt(1)

	smallPrimesForPerfectPower []uint
)

func init() {
	smallPrimesForPerfectPower = common.GetFirstNPrimes(25) // Primes up to 97
}

// len is the length of the modulus (each prime = len / 2)
func GenerateKeyPair(modulusBitLen int, timeout time.Duration, optionalConcurrency ...int) (privateKey *PrivateKey, publicKey *PublicKey, err error) {
	privateKey, publicKey, _, _, err = GenerateKeyPairAndPQ(modulusBitLen, timeout, optionalConcurrency...)
	return
}

// len is the length of the modulus (each prime = len / 2)
func GenerateKeyPairAndPQ(modulusBitLen int, timeout time.Duration, optionalConcurrency ...int) (privateKey *PrivateKey, publicKey *PublicKey, p, q *big.Int, err error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.GOMAXPROCS(0)
	}

	// KS-BTL-F-03: use two safe primes for P, Q
	var sgps []*common.GermainSafePrime
	var N, P, Q *big.Int
	{
		for {
			// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
			filter := func(p1, p2 *common.GermainSafePrime) bool {
				tmp := big.Int{}
				if tmp.Sub(p1.SafePrime(), p2.SafePrime()).BitLen() >= (modulusBitLen/2)-pQBitLenDifference {
					return true
				}
				return false
			}
			if sgps, err = common.GetRandomSafePrimesConcurrent(modulusBitLen/2, 2, timeout, concurrency, filter); err != nil {
				return
			}
			p, q = sgps[0].Prime(), sgps[1].Prime()
			P, Q = sgps[0].SafePrime(), sgps[1].SafePrime()
			break
		}
		tmp := big.Int{}
		N = tmp.Mul(P, Q)
	}

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN}
	return
}

// ----- //

func (publicKey *PublicKey) EncryptAndReturnRandomness(m *big.Int) (c *big.Int, x *big.Int, err error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageTooLong
	}
	x = common.GetRandomPositiveRelativelyPrimeInt(publicKey.N)
	N2 := publicKey.NSquare()
	// 1. gamma^m mod N2
	Gm := new(big.Int).Exp(publicKey.Gamma(), m, N2)
	// 2. x^N mod N2
	xN := new(big.Int).Exp(x, publicKey.N, N2)
	// 3. (1) * (2) mod N2
	c = int2.ModInt(N2).Mul(Gm, xN)
	return
}

func (pk *PublicKey) EncryptWithGivenRandomness(m, x *big.Int) (c *big.Int, err error) {
	if x == nil || x.Cmp(zero) == 0 {
		return nil, errors.New("EncryptWithGivenRandomness() requires non-zero randomness")
	}
	if m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageTooLong
	}
	// https://docs.rs/paillier/0.2.0/src/paillier/core.rs.html#236
	modNSq := int2.ModInt(pk.NSquare())
	// 1. gamma^m mod N2
	Gm := modNSq.Exp(pk.Gamma(), m)
	// 2. x^N mod N2
	xN := modNSq.Exp(x, pk.N)
	// 3. (1) * (2) mod N2
	c = modNSq.Mul(Gm, xN)
	return
}

func (publicKey *PublicKey) Encrypt(m *big.Int) (c *big.Int, err error) {
	c, _, err = publicKey.EncryptAndReturnRandomness(m)
	return
}

func (publicKey *PublicKey) HomoMult(m, c1 *big.Int) (*big.Int, error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageTooLong
	}
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// cipher^m mod N2
	return int2.ModInt(N2).Exp(c1, m), nil
}

func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	if c2.Cmp(zero) == -1 || c2.Cmp(N2) != -1 { // c2 < 0 || c2 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// c1 * c2 mod N2
	return int2.ModInt(N2).Mul(c1, c2), nil
}

func (publicKey *PublicKey) NSquare() *big.Int {
	return new(big.Int).Mul(publicKey.N, publicKey.N)
}

// AsInts returns the PublicKey serialised to a slice of *big.Int for hashing
func (publicKey *PublicKey) AsInts() []*big.Int {
	return []*big.Int{publicKey.N, publicKey.Gamma()}
}

// Gamma returns N+1
func (publicKey *PublicKey) Gamma() *big.Int {
	return new(big.Int).Add(publicKey.N, one)
}

// ----- //

func (privateKey *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
	N2 := privateKey.NSquare()
	if c.Cmp(zero) == -1 || c.Cmp(N2) != -1 { // c < 0 || c >= N2 ?
		return nil, ErrMessageTooLong
	}
	cg := new(big.Int).GCD(nil, nil, c, N2)
	if cg.Cmp(one) == 1 {
		return nil, ErrMessageMalFormed
	}
	// 1. L(u) = (c^LambdaN-1 mod N2) / N
	Lc := L(new(big.Int).Exp(c, privateKey.LambdaN, N2), privateKey.N)
	// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
	Lg := L(new(big.Int).Exp(privateKey.Gamma(), privateKey.LambdaN, N2), privateKey.N)
	// 3. (1) * modInv(2) mod N
	inv := new(big.Int).ModInverse(Lg, privateKey.N)
	m = int2.ModInt(privateKey.N).Mul(Lc, inv)
	return
}

func (sk *PrivateKey) DecryptAndRecoverRandomness(c *big.Int) (m, x *big.Int, err error) {
	if m, err = sk.Decrypt(c); err != nil {
		return
	}
	modN := int2.ModInt(sk.N)
	modNSq := int2.ModInt(sk.NSquare())
	modPhiN := int2.ModInt(sk.PhiN)
	// CDash = C * (1 - m*N) mod N2  (this is scalar subtraction)
	mN := modNSq.Mul(m, sk.N)
	cDash := modNSq.Mul(c, new(big.Int).Sub(one, mN))
	// M = N^-1 mod phi(N)
	M := modPhiN.Inverse(sk.N)
	// x = CDash^M mod N
	x = modN.Exp(cDash, M)
	return
}

// ----- //

// Proof is an implementation of Gennaro, R., Micciancio, D., Rabin, T.:
// An efficient non-interactive statistical zero-knowledge proof system for quasi-safe prime products.
// In: In Proc. of the 5th ACM Conference on Computer and Communications Security (CCS-98. Citeseer (1998)

func (privateKey *PrivateKey) Proof(k *big.Int, ecdsaPub *crypto2.ECPoint) *Proof {
	var pi Proof
	iters := ProofIters
	wg := new(sync.WaitGroup)
	wg.Add(1)
	xs := GenerateXs(iters, k, privateKey.N, ecdsaPub)
	for i := 0; i < iters; i++ {
		M := new(big.Int).ModInverse(privateKey.N, privateKey.PhiN)
		pi[i] = new(big.Int).Exp(xs[i], M, privateKey.N)
	}
	return &pi
}

func (pf *Proof) Verify(pkN, k *big.Int, ecdsaPub *crypto2.ECPoint) (bool, error) {
	if ecdsaPub == nil {
		return false, fmt.Errorf("ecdsaPub cannot be nil")
	}

	// Enhanced validation: Check for small factors up to 2^16 and verify modulus structure
	if !validateModulusStructure(pkN) {
		return false, nil
	}

	iters := ProofIters
	xs := GenerateXs(iters, k, pkN, ecdsaPub)
	for i, xi := range xs {
		xiModN := new(big.Int).Mod(xi, pkN)
		yiExpN := new(big.Int).Exp(pf[i], pkN, pkN)
		if xiModN.Cmp(yiExpN) != 0 {
			return false, nil
		}
	}
	return true, nil
}

// ----- utils

// validateModulusStructure performs comprehensive validation to ensure N is a valid RSA modulus
// that is resistant to small factor attacks (including the 6ix1een attack).
// The 2^16 (65536) bound was selected to mitigate the "6ix1een" attack - a modulus composed of
// sixteen primes all >1000 but <65536. Security tests cover primes near this boundary.
// It checks:
// 1. N has no small prime factors up to 2^16 (65536)
// 2. N passes probabilistic primality tests suggesting it's likely a semi-prime
// 3. N has appropriate size and structure
func validateModulusStructure(N *big.Int) bool {
	if N == nil || N.Sign() <= 0 {
		return false
	}

	// Check minimum size (at least 2040 bits for security, allowing some margin)
	if N.BitLen() < 2040 {
		return false
	}

	// Check N is odd (even N would have factor 2)
	if N.Bit(0) == 0 {
		return false
	}

	// Extended small prime check - check all primes up to 2^16
	// This prevents the 6ix1een attack with 16 factors > 1000
	if !checkNoSmallFactors(N, 65536) {
		return false
	}

	// Check that N is not prime itself (should be composite)
	if N.ProbablyPrime(10) {
		return false
	}

	// Check if N is a perfect power (now optimized with prime exponents only)
	if isPerfectPower(N) {
		return false
	}

	return true
}

// checkNoSmallFactors efficiently checks if N has any prime factors up to limit.
// Checking primes up to 2^16 (65536) is sufficient to detect the "6ix1een" attack and other
// small-factor constructions where attackers compose moduli from many small primes.
func checkNoSmallFactors(N *big.Int, limit uint64) bool {
	// Get all primes up to the limit using the shared utility
	// The 65536 cap ensures we check all primes needed to detect small-factor attacks
	primes := common.GetPrimesUpTo(int(min(limit, 65536)))

	// Check each prime factor
	for _, p := range primes {
		if new(big.Int).Mod(N, new(big.Int).SetUint64(uint64(p))).Sign() == 0 {
			return false
		}
	}

	return true
}

// isPerfectPower checks if N is a perfect power (n^k for k > 1)
// This helps detect if N has repeated factors.
// For performance with large cryptographic moduli, we only check small prime powers
// as the probability of a random RSA modulus being a perfect power is negligible
func isPerfectPower(N *big.Int) bool {
	// Numbers < 4 cannot be perfect powers b^k where b>1, k>1
	if N.Cmp(big.NewInt(4)) < 0 {
		return false
	}

	// For cryptographic moduli (2048+ bits), we only need to check small exponents
	// The probability that a random 2048-bit number is a perfect k-th power
	// for k > 20 is astronomically small (less than 2^(-100))
	maxExponentToCheck := 20
	if N.BitLen() < 1024 {
		maxExponentToCheck = 64 // For smaller numbers, check more exponents
	}

	// Check perfect square first (most common case)
	sqrt := new(big.Int).Sqrt(N)
	sqrtSquared := new(big.Int).Mul(sqrt, sqrt)
	if sqrtSquared.Cmp(N) == 0 {
		return true
	}

	// Check other small prime powers
	// Only check prime exponents up to our limit
	for _, p := range smallPrimesForPerfectPower {
		if p > uint(maxExponentToCheck) {
			break
		}
		if p == 2 {
			continue // Already checked squares above
		}

		// Use simple binary search for small exponents
		if isKthPowerSimple(N, p) {
			return true
		}
	}

	return false
}

// isKthPowerSimple checks if N is a perfect k-th power using optimized binary search
func isKthPowerSimple(N *big.Int, k uint) bool {
	bitLen := N.BitLen()
	// Quick bounds check: if k > bitLen(N), then N cannot be a k-th power > 1
	// since the smallest base (2) would give 2^k > 2^bitLen(N) > N
	if k > uint(bitLen) {
		return false
	}

	// Binary search for the k-th root
	// Upper bound: 2^(ceil(bitlen(N)/k))
	upperBound := new(big.Int).Lsh(big.NewInt(1), uint((bitLen+int(k)-1)/int(k)))

	low := big.NewInt(2) // Minimum base is 2
	high := upperBound
	kBig := new(big.Int).SetUint64(uint64(k))
	one := big.NewInt(1)

	// Pre-allocate big.Int variables to avoid repeated allocations in the loop
	mid := new(big.Int)
	midPower := new(big.Int)

	for low.Cmp(high) <= 0 {
		mid.Add(low, high)
		mid.Rsh(mid, 1) // Divide by 2

		// Compute mid^k
		midPower.Exp(mid, kBig, nil)

		switch midPower.Cmp(N) {
		case 0:
			return true
		case -1:
			low.Add(mid, one)
		case 1:
			high.Sub(mid, one)
		}
	}

	return false
}

func L(u, N *big.Int) *big.Int {
	t := new(big.Int).Sub(u, one)
	return new(big.Int).Div(t, N)
}

// GenerateXs generates the challenges used in Paillier key Proof
func GenerateXs(m int, k, N *big.Int, ecdsaPub *crypto2.ECPoint) []*big.Int {
	var i, n int
	ret := make([]*big.Int, m)
	sX, sY := ecdsaPub.X(), ecdsaPub.Y()
	kb, sXb, sYb, Nb := k.Bytes(), sX.Bytes(), sY.Bytes(), N.Bytes()
	bits := N.BitLen()
	blocks := (bits + 255) / 256 // Equivalent to Ceil(bits/256) without float
	chs := make([]chan []byte, blocks)
	for k := range chs {
		chs[k] = make(chan []byte)
	}
	for i < m {
		xi := make([]byte, 0, blocks*32)
		ib := []byte(strconv.Itoa(i))
		nb := []byte(strconv.Itoa(n))
		for j := 0; j < blocks; j++ {
			go func(j int) {
				jBz := []byte(strconv.Itoa(j))
				hash := hash.SHA256(ib, jBz, nb, kb, sXb, sYb, Nb)
				chs[j] <- hash
			}(j)
		}
		for _, ch := range chs { // must be in order
			rx := <-ch
			if rx == nil { // this should never happen. see: https://golang.org/pkg/hash/#Hash
				panic(errors.New("GenerateXs hash write error!"))
			}
			xi = append(xi, rx...) // xi1||···||xib
		}
		ret[i] = new(big.Int).SetBytes(xi)
		if common.IsNumberInMultiplicativeGroup(N, ret[i]) {
			i++
		} else {
			n++
		}
	}
	return ret
}

func (pf *Proof) String() string {
	if pf == nil {
		return "<nil>"
	}
	for _, v := range pf[:] {
		if v == nil {
			return "<*nil*>"
		}
	}
	return common.FormatBigInt(hash.SHA256i(pf[:]...))
}

// Clone creates a deep copy of the PublicKey
func (pk *PublicKey) Clone() *PublicKey {
	if pk == nil {
		return nil
	}
	newPK := &PublicKey{}
	if pk.N != nil {
		newPK.N = new(big.Int).Set(pk.N)
	}
	return newPK
}

// Clone creates a deep copy of the PrivateKey
func (sk *PrivateKey) Clone() *PrivateKey {
	if sk == nil {
		return nil
	}
	newSK := &PrivateKey{}

	// Clone the public key parts
	newSK.PublicKey = *sk.PublicKey.Clone()

	// Clone the private key parts
	if sk.LambdaN != nil {
		newSK.LambdaN = new(big.Int).Set(sk.LambdaN)
	}
	if sk.PhiN != nil {
		newSK.PhiN = new(big.Int).Set(sk.PhiN)
	}

	return newSK
}
