// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkplogstar

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	"github.com/iofinnet/tss-lib/v3/crypto/zkp"
)

const (
	ProofLogstarBytesParts = 8
)

type (
	ProofLogstar struct {
		S, A          *big.Int
		Y             *crypto.ECPoint
		D, Z1, Z2, Z3 *big.Int
	}
)

// NewProofWithNonce implements prooflogstar with a given nonce
func NewProofWithNonce(ec elliptic.Curve, pk *paillier.PublicKey, C *big.Int, X *crypto.ECPoint, g *crypto.ECPoint,
	NCap, s, t, x, rho, nonce *big.Int) (*ProofLogstar, error) {
	if ec == nil || pk == nil || C == nil || X == nil || g == nil || NCap == nil || s == nil || t == nil || x == nil ||
		rho == nil || nonce == nil || big.NewInt(0).Cmp(nonce) == 0 {
		return nil, errors.New("ProveLogstar constructor received nil value(s)")
	}
	if nonce.BitLen() < ec.Params().N.BitLen()-1 {
		return nil, errors.New("invalid nonce")
	}
	q := big.Wrap(ec.Params().N)
	alpha, mu, r, gamma, S, A, Y, D := initProof(q, NCap, pk, s, x, t, g)

	// Fig 25.2 e
	var e *big.Int
	{
		eHash := hash.SHA256i(append(pk.AsInts(), S, Y.X(), Y.Y(), A, D, C, X.X(), X.Y(), g.X(), g.Y(), q, nonce)...)
		e = hash.HashToScalarQ(ec, eHash.Bytes())
	}

	z1, z2, z3 := coda(e, x, alpha, pk, rho, r, mu, gamma)

	return &ProofLogstar{S: S, A: A, Y: Y, D: D, Z1: z1, Z2: z2, Z3: z3}, nil
}

func coda(e *int2.Int, x *int2.Int, alpha *int2.Int, pk *paillier.PublicKey, rho *int2.Int, r *int2.Int, mu *int2.Int,
	gamma *int2.Int) (*int2.Int, *int2.Int, *int2.Int) {
	// Fig 25.3
	z1 := new(big.Int).Mul(e, x)
	z1 = new(big.Int).Add(z1, alpha)

	modN := int2.ModInt(pk.N)
	z2 := modN.Exp(rho, e)
	z2 = modN.Mul(z2, r)

	z3 := new(big.Int).Mul(e, mu)
	z3 = new(big.Int).Add(z3, gamma)
	return z1, z2, z3
}

func initProof(q *int2.Int, NCap *int2.Int, pk *paillier.PublicKey, s *int2.Int, x *int2.Int, t *int2.Int,
	g *crypto.ECPoint) (*int2.Int, *int2.Int, *int2.Int, *int2.Int, *int2.Int, *int2.Int, *crypto.ECPoint, *int2.Int) {
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNCap := new(big.Int).Mul(q, NCap)
	TwolPlus𝜀 := zkp.TwoTo768
	TwolPlus𝜀NCap := new(big.Int).Mul(TwolPlus𝜀, NCap)

	// Fig 25.1 sample
	alpha := common.GetRandomPositiveInt(q3)
	mu := common.GetRandomPositiveInt(qNCap)
	r := common.GetRandomPositiveRelativelyPrimeInt(pk.N)
	gamma := common.GetRandomPositiveInt(TwolPlus𝜀NCap)

	// Fig 25.1 compute
	modNCap := int2.ModInt(NCap)
	S := modNCap.Exp(s, x)
	S = modNCap.Mul(S, modNCap.Exp(t, mu))

	modNSquared := int2.ModInt(pk.NSquare())
	A := modNSquared.Exp(pk.Gamma(), alpha)
	A = modNSquared.Mul(A, modNSquared.Exp(r, pk.N))

	Y, _ := g.ScalarMult(alpha)

	D := modNCap.Exp(s, alpha)
	D = modNCap.Mul(D, modNCap.Exp(t, gamma))
	return alpha, mu, r, gamma, S, A, Y, D
}

func NewProofFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofLogstar, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofLogstarBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofLogstar", ProofLogstarBytesParts)
	}
	point, err := crypto.NewECPoint(ec,
		new(big.Int).SetBytes(bzs[2]),
		new(big.Int).SetBytes(bzs[3]))
	if err != nil {
		return nil, err
	}
	return &ProofLogstar{
		S:  new(big.Int).SetBytes(bzs[0]),
		A:  new(big.Int).SetBytes(bzs[1]),
		Y:  point,
		D:  new(big.Int).SetBytes(bzs[4]),
		Z1: new(big.Int).SetBytes(bzs[5]),
		Z2: new(big.Int).SetBytes(bzs[6]),
		Z3: new(big.Int).SetBytes(bzs[7]),
	}, nil
}

func (pf *ProofLogstar) VerifyWithNonce(ec elliptic.Curve, pk *paillier.PublicKey, C *big.Int, X *crypto.ECPoint,
	g *crypto.ECPoint, NCap, s, t, nonce *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || C == nil || X == nil || NCap == nil || s == nil || t == nil {
		return false
	}

	q := big.Wrap(ec.Params().N)
	TwolPlus𝜀 := zkp.TwoTo768

	// Fig 25. range check
	if pf.Z1.Cmp(TwolPlus𝜀) == 1 {
		return false
	}

	var e *big.Int
	{
		eHash := hash.SHA256i(append(pk.AsInts(), pf.S, pf.Y.X(), pf.Y.Y(), pf.A, pf.D, C, X.X(), X.Y(),
			g.X(), g.Y(), q, nonce)...)
		e = hash.HashToScalarQ(ec, eHash.Bytes())
	}

	return doVerify(ec, pk, C, X, g, NCap, s, t, pf, e)
}

func doVerify(ec elliptic.Curve, pk *paillier.PublicKey, C *int2.Int, X *crypto.ECPoint, g *crypto.ECPoint, NCap *int2.Int, s *int2.Int, t *int2.Int, pf *ProofLogstar, e *int2.Int) bool {
	// Fig 25. equality checks
	{
		modNSquared := int2.ModInt(pk.NSquare())

		Np1EXPz1 := modNSquared.Exp(pk.Gamma(), pf.Z1)
		z2EXPN := modNSquared.Exp(pf.Z2, pk.N)
		left := modNSquared.Mul(Np1EXPz1, z2EXPN)

		CEXPe := modNSquared.Exp(C, e)
		right := modNSquared.Mul(CEXPe, pf.A)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	{
		z1ModQ := new(big.Int).Mod(pf.Z1, big.Wrap(ec.Params().N))
		// left := crypto.ScalarBaseMult(ec, z1ModQ)
		left, err := g.ScalarMult(z1ModQ)
		if err != nil {
			return false
		}
		pt, err := X.ScalarMult(e)
		if err != nil {
			return false
		}
		if right, err := pt.Add(pf.Y); err != nil || !left.Equals(right) {
			return false
		}
	}
	{
		modNCap := int2.ModInt(NCap)
		sEXPz1 := modNCap.Exp(s, pf.Z1)
		tEXPz3 := modNCap.Exp(t, pf.Z3)
		left := modNCap.Mul(sEXPz1, tEXPz3)
		SEXPe := modNCap.Exp(pf.S, e)
		right := modNCap.Mul(pf.D, SEXPe)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

func (pf *ProofLogstar) ValidateBasic() bool {
	return pf.S != nil &&
		pf.A != nil &&
		pf.Y != nil &&
		pf.D != nil &&
		pf.Z1 != nil &&
		pf.Z2 != nil &&
		pf.Z3 != nil
}

func (pf *ProofLogstar) Bytes() [ProofLogstarBytesParts][]byte {
	return [...][]byte{
		pf.S.Bytes(),
		pf.A.Bytes(),
		pf.Y.X().Bytes(),
		pf.Y.Y().Bytes(),
		pf.D.Bytes(),
		pf.Z1.Bytes(),
		pf.Z2.Bytes(),
		pf.Z3.Bytes(),
	}
}
func (pf *ProofLogstar) String() string {
	return "(S:" + common.FormatBigInt(pf.S) + ", A:" + common.FormatBigInt(pf.A) +
		", Y:" + pf.Y.String() +
		", D:" + common.FormatBigInt(pf.D) + ", Z1:" + common.FormatBigInt(pf.Z1) +
		", Z2:" + common.FormatBigInt(pf.Z2) + ", Z3:" + common.FormatBigInt(pf.Z3) + ")"
}
