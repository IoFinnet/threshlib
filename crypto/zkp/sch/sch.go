// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
)

const (
	ProofSchBytesParts = 3
)

type (
	ProofSch struct {
		A *crypto.ECPoint
		Z *big.Int
	}
)

// NewProofWithNonce implements proofsch with a given nonce
func NewProofWithNonce(X *crypto.ECPoint, x *big.Int, nonce *big.Int) (*ProofSch, error) {
	if x == nil || X == nil || !X.ValidateBasic() || big.NewInt(0).Cmp(x) == 0 || nonce == nil ||
		big.NewInt(0).Cmp(nonce) == 0 {
		return nil, errors.New("zkpsch constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	if nonce.BitLen() < ec.Params().N.BitLen()-1 {
		return nil, errors.New("invalid nonce")
	}
	q := big.Wrap(ec.Params().N)
	g := crypto.NewECPointNoCurveCheck(ec, big.Wrap(ec.Params().Gx), big.Wrap(ec.Params().Gy)) // already on the curve.

	// Fig 22.1
	𝛼 := common.GetRandomPositiveInt(q)
	A, _ := crypto.ScalarBaseMult(ec, 𝛼)

	// Fig 22.2 e
	var e *big.Int
	{
		eHash := hash.SHA256i(X.X(), X.Y(), g.X(), g.Y(), A.X(), A.Y(), nonce)
		e = hash.HashToScalarQ(ec, eHash.Bytes())
	}

	// Fig 22.3
	z := new(big.Int).Mul(e, x)
	z = int2.ModInt(q).Add(𝛼, z)

	return &ProofSch{A: A, Z: z}, nil
}

// NewProof implements proofsch with a given nonce and 'alpha'
func NewProofWithNonceAndAlpha(X *crypto.ECPoint, x *big.Int, alpha *big.Int, nonce *big.Int) (*ProofSch, error) {
	if x == nil || X == nil || !X.ValidateBasic() || big.NewInt(0).Cmp(x) == 0 || big.NewInt(0).Cmp(alpha) == 0 ||
		nonce == nil || big.NewInt(0).Cmp(nonce) == 0 || alpha == nil {
		return nil, errors.New("zkpsch constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	if nonce.BitLen() < ec.Params().N.BitLen()-1 {
		return nil, errors.New("invalid nonce")
	}
	q := big.Wrap(ec.Params().N)
	g := crypto.NewECPointNoCurveCheck(ec, big.Wrap(ec.Params().Gx), big.Wrap(ec.Params().Gy)) // already on the curve.

	// Fig 22.1
	A, _ := crypto.ScalarBaseMult(ec, alpha)

	// Fig 22.2 e
	var e *big.Int
	{
		eHash := hash.SHA256i(X.X(), X.Y(), g.X(), g.Y(), A.X(), A.Y(), nonce)
		e = hash.HashToScalarQ(ec, eHash.Bytes())
	}

	// Fig 22.3
	z := new(big.Int).Mul(e, x)
	z = int2.ModInt(q).Add(alpha, z)

	return &ProofSch{A: A, Z: z}, nil
}

func NewProofCommitment(X *crypto.ECPoint, x *big.Int) (*crypto.ECPoint, *big.Int, error) {
	if x == nil || X == nil || !X.ValidateBasic() || big.NewInt(0).Cmp(x) == 0 {
		return nil, nil, errors.New("zkpsch constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	q := big.Wrap(ec.Params().N)

	// Fig 22.1
	alpha := common.GetRandomPositiveInt(q)
	A, _ := crypto.ScalarBaseMult(ec, alpha)
	return A, alpha, nil
}

func NewProofFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofSch, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofSchBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofSch", ProofSchBytesParts)
	}
	point, err := crypto.NewECPoint(ec,
		new(big.Int).SetBytes(bzs[0]),
		new(big.Int).SetBytes(bzs[1]))
	if err != nil {
		return nil, err
	}
	return &ProofSch{
		A: point,
		Z: new(big.Int).SetBytes(bzs[2]),
	}, nil
}

func (pf *ProofSch) VerifyWithNonce(X *crypto.ECPoint, nonce *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil || pf.Z == nil || big.NewInt(0).Cmp(pf.Z) == 0 || nonce == nil ||
		big.NewInt(0).Cmp(nonce) == 0 {
		return false
	}
	ec := X.Curve()
	g := crypto.NewECPointNoCurveCheck(ec, big.Wrap(ec.Params().Gx), big.Wrap(ec.Params().Gy))

	var e *big.Int
	{
		eHash := hash.SHA256i(X.X(), X.Y(), g.X(), g.Y(), pf.A.X(), pf.A.Y(), nonce)
		e = hash.HashToScalarQ(ec, eHash.Bytes())
	}

	// Fig 22. Verification
	left, _ := crypto.ScalarBaseMult(ec, pf.Z)
	XEXPe, _ := X.ScalarMult(e)
	right, err := pf.A.Add(XEXPe)
	if err != nil {
		return false
	}
	if right.X().Cmp(left.X()) != 0 || right.Y().Cmp(left.Y()) != 0 {
		return false
	}
	return true
}

func (pf *ProofSch) ValidateBasic() bool {
	return pf.Z != nil && pf.A != nil
}

func (pf *ProofSch) Bytes() [ProofSchBytesParts][]byte {
	return [...][]byte{
		pf.A.X().Bytes(),
		pf.A.Y().Bytes(),
		pf.Z.Bytes(),
	}
}

func (pf *ProofSch) String() string {
	return "(A:" + pf.A.String() + ", Z:" + common.FormatBigInt(pf.Z) + ")"
}
