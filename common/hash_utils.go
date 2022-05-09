// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	big "github.com/binance-chain/tss-lib/common/int"
)

// RejectionSample implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	qGTZero := zero.Cmp(q) == -1
	// e = the first |q| bits of e'
	qBits := q.BitLen()
	e := firstBitsOf(qBits, eHash)
	// while e is not between 0-q
	for !(qGTZero && e.Cmp(q) == -1) {
		eHash := SHA512_256iOne(eHash)
		e = firstBitsOf(qBits, eHash)
	}
	return e
}

func firstBitsOf(bits int, v *big.Int) *big.Int {
	e := big.NewInt(0)
	for i := 0; i < bits; i++ {
		bit := v.Bit(i)
		if 0 < bit {
			e.SetBit(e, i, bit)
		}
	}
	return e
}
