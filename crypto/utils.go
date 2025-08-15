// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/elliptic"
	"fmt"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
)

func GenerateNTildei(safePrimes [2]*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if safePrimes[0] == nil || safePrimes[1] == nil {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %v", safePrimes)
	}
	// Do 20 rabin-miller tests to check if it's prime
	if !safePrimes[0].ProbablyPrime(common.PrimeTestN) || !safePrimes[1].ProbablyPrime(common.PrimeTestN) {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: expected two primes")
	}
	NTildei = new(big.Int).Mul(safePrimes[0], safePrimes[1])
	h1 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}

func moduloReduce(k []byte, curveParams *elliptic.CurveParams) []byte {
	// Since the order of G is curve.N, we can use a much smaller number by
	// doing modulo curve.N
	tmpK := big.Int{}
	if len(k) > (curveParams.BitSize / 8) {
		tmpK.SetBytes(k)
		tmpK.Mod(&tmpK, curveParams.N)
		return tmpK.Bytes()
	}
	return k
}
