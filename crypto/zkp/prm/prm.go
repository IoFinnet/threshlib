// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpprm

import (
	"errors"
	"fmt"

	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
)

const (
	Iterations         = 64
	ProofPrmBytesParts = Iterations * 2
	MinBitLen          = 254
)

type (
	ProofPrm struct {
		A [Iterations]*big.Int
		Z [Iterations]*big.Int
	}
)

// NewProofWithNonce implements zkpprm with a nonce
func NewProofWithNonce(s, t, N, Phi, lambda, nonce *big.Int) (*ProofPrm, error) {
	if s == nil || t == nil || N == nil || Phi == nil || lambda == nil ||
		nonce == nil || big.NewInt(0).Cmp(nonce) == 0 {
		return nil, errors.New("nil argument")
	}
	if nonce.BitLen() < MinBitLen {
		return nil, fmt.Errorf("invalid nonce")
	}
	modN, modPhi := big.ModInt(N), big.ModInt(Phi)

	// Fig 17.1
	a := make([]*big.Int, Iterations)
	A := [Iterations]*big.Int{}
	for i := range A {
		a[i] = common.GetRandomPositiveInt(Phi)
		A[i] = modN.Exp(t, a[i])
	}

	// Fig 17.2
	e := hash.SHA256i(append([]*big.Int{s, t, N, nonce}, A[:]...)...)

	// Fig 17.3
	Z := [Iterations]*big.Int{}
	for i := range Z {
		ei := big.NewInt(uint64(e.Bit(i)))
		Z[i] = modPhi.Add(a[i], modPhi.Mul(ei, lambda))
	}
	return &ProofPrm{A: A, Z: Z}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofPrm, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofPrmBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofPrm", ProofPrmBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	A := [Iterations]*big.Int{}
	copy(A[:], bis[:Iterations])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[Iterations:])

	return &ProofPrm{
		A: A,
		Z: Z,
	}, nil
}

func (pf *ProofPrm) VerifyWithNonce(s, t, N, nonce *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || !pf.ValidateANotOne() {
		return false
	}

	// Security check: Verify gcd(t, N) == 1 to ensure t is coprime to N.
	// This prevents malicious provers from using t=0 to bypass the Blum integer validation.
	if big.NewInt(1).Cmp(new(big.Int).GCD(nil, nil, t, N)) != 0 {
		return false
	}

	modN := big.ModInt(N)
	e := hash.SHA256i(append([]*big.Int{s, t, N, nonce}, pf.A[:]...)...)

	// Fig 17. Verification
	for i := 0; i < Iterations; i++ {
		ei := big.NewInt(uint64(e.Bit(i)))
		left := modN.Exp(t, pf.Z[i])
		right := modN.Exp(s, ei)
		right = modN.Mul(pf.A[i], right)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

func (pf *ProofPrm) ValidateBasic() bool {
	for i := range pf.A {
		if pf.A[i] == nil {
			return false
		}
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func (pf *ProofPrm) ValidateANotOne() bool {
	one := big.NewInt(1)
	for i := range pf.A {
		if pf.A[i] == nil || one.Cmp(pf.A[i]) == 0 {
			return false
		}
	}
	return true
}

func (pf *ProofPrm) Bytes() [ProofPrmBytesParts][]byte {
	bzs := [ProofPrmBytesParts][]byte{}
	for i := range pf.A {
		bzs[i] = pf.A[i].Bytes()
	}
	for i := range pf.Z {
		bzs[i+Iterations] = pf.Z[i].Bytes()
	}
	return bzs
}

func (pf *ProofPrm) ToIntArray() []*big.Int {
	array := make([]*big.Int, len(pf.A)+len(pf.Z))
	for k, a := range pf.A {
		array[k] = a
	}
	lA := len(pf.A)
	for k, z := range pf.Z {
		array[k+lA] = z
	}
	return array
}

func (pf *ProofPrm) String() string {
	a := pf.ToIntArray()
	return "(" + common.FormatBigInt(a[0]) + "..." + common.FormatBigInt(a[len(a)-1]) + ")"
}
