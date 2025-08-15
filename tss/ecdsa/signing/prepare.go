// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"fmt"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
)

// PrepareForSigning(), GG18Spec (11) Fig. 14
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint, err error) {
	modQ := int2.ModInt(big.Wrap(ec.Params().N))
	if len(ks) != len(bigXs) {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs)))
	}
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	// 2-4.
	wi = new(big.Int).Set(xi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("index of two parties are equal"))
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.Inverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc, ksj := modQ.Add(ks[c], zero), modQ.Add(ks[j], zero)
			if ksj.Cmp(ksc) == 0 {
				err = fmt.Errorf("the indices of two parties are equal")
				return
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ksc, modQ.Inverse(new(big.Int).Sub(ksc, ksj)))
			bigWj, _ = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}

	// assertion: g^w_i == W_i
	pt, err := crypto.ScalarBaseMult(ec, wi)
	if err != nil {
		return
	}
	if !pt.Equals(bigWs[i]) {
		err = fmt.Errorf("assertion failed: g^w_i == W_i")
		return
	}
	return
}
