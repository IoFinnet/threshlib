// Copyright © 2021 Swingby

package zkpfac_test

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	. "github.com/iofinnet/tss-lib/v3/crypto/zkp/fac"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
	safePrimeBitLen   = 1024
)

var (
	one = big.NewInt(1)
)

type LocalPreParams struct {
	PaillierSK *paillier.PrivateKey // ski
	NTildei,
	H1i, H2i,
	Alpha, Beta,
	P, Q *big.Int
}

func generatePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.GOMAXPROCS(0)
	}

	common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
	start := time.Now()
	sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency, func(p1, p2 *common.GermainSafePrime) bool {
		// in the context of a unit test, we do not have to provide a filter function for the safe primes
		return true
	})
	if err != nil {
		// ch <- nil
		return nil, err
	}
	common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))

	if sgps == nil || sgps[0] == nil || sgps[1] == nil ||
		!sgps[0].Prime().ProbablyPrime(common.PrimeTestN) || !sgps[1].Prime().ProbablyPrime(common.PrimeTestN) ||
		!sgps[0].SafePrime().ProbablyPrime(common.PrimeTestN) || !sgps[1].SafePrime().ProbablyPrime(common.PrimeTestN) {
		return nil, errors.New("error while generating the safe primes")
	}

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	paiPK := &paillier.PublicKey{N: new(big.Int).Mul(P, Q)}
	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)
	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)
	paiSK := &paillier.PrivateKey{PublicKey: *paiPK, LambdaN: lambdaN, PhiN: phiN}
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := big.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	modPQ := big.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.Inverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}

func TestFacPQNoSmallFactor(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	nonce := common.GetBigRandomPositiveInt(big.Wrap(ec.Params().N), big.Wrap(ec.Params().N).BitLen()-1)
	Twol := big.Wrap(ec.Params().N)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	modNCap := int2.ModInt(NCap)

	pqOk := false

	var p, q *big.Int
	var pk *paillier.PublicKey

	for !pqOk {
		var err2 error
		_, pk, p, q, err2 = paillier.GenerateKeyPairAndPQ(testSafePrimeBits*2, time.Minute*10)
		p, q = common.PrimeToSafePrime(p), common.PrimeToSafePrime(q)
		assert.NoError(test, err2)
		sqrtNo := new(big.Int).Sqrt(pk.N)
		sqrtNoTwol := modNCap.Mul(sqrtNo, Twol)
		pUpperBound := p.Cmp(sqrtNoTwol) == -1
		qUpperBound := q.Cmp(sqrtNoTwol) == -1
		pLowerBound := p.Cmp(Twol) == +1
		qLowerBound := q.Cmp(Twol) == +1
		pqOk = pUpperBound && qUpperBound && pLowerBound && qLowerBound
	}

	proof, err := NewProofWithNonce(ec, pk, NCap, s, t, p, q, nonce)
	assert.NoError(test, err)

	ok := proof.VerifyWithNonce(ec, pk, NCap, s, t, nonce)
	assert.True(test, ok, "proof must verify")
}

func TestGeneral(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	nonce := common.GetBigRandomPositiveInt(big.Wrap(ec.Params().N), big.Wrap(ec.Params().N).BitLen()-1)

	preParams, err := generatePreParams(15 * time.Minute)
	if err != nil {
		test.Error("pre-params generation failed", err)
		test.Fail()
	}

	proof, err := NewProofWithNonce(ec, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i,
		common.PrimeToSafePrime(preParams.P), common.PrimeToSafePrime(preParams.Q), nonce)
	assert.NoError(test, err)

	ok := proof.VerifyWithNonce(ec, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i, nonce)
	assert.True(test, ok, "proof must verify")
}

func TestGeneralNonce(test *testing.T) {
	ec := tss.GetCurveForUnitTest()
	nonce := common.GetBigRandomPositiveInt(big.Wrap(ec.Params().N), big.Wrap(ec.Params().N).BitLen()-1)

	preParams, err := generatePreParams(15 * time.Minute)
	if err != nil {
		test.Error("pre-params generation failed")
		test.Fail()
	}

	proof, err := NewProofWithNonce(ec, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i,
		common.PrimeToSafePrime(preParams.P), common.PrimeToSafePrime(preParams.Q), nonce)
	assert.NoError(test, err)

	ok := proof.VerifyWithNonce(ec, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i,
		nonce)
	assert.True(test, ok, "proof must verify")
}
