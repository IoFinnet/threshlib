// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	edcrypto "github.com/iofinnet/tss-lib/v3/crypto/ed25519"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

// Creates a new ECPoint and checks that the given coordinates are on the elliptic curve.
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

// Creates a new ECPoint without checking that the coordinates are on the elliptic curve.
// Only use this function when you are completely sure that the point is already on the curve.
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

func NewECPointFromBytes(ec elliptic.Curve, bzs [][]byte) (*ECPoint, error) {
	if !common.NonEmptyMultiBytes(bzs, 2) {
		return nil, fmt.Errorf("NewECPointFromBytes expects 2 points in bzs, got %d", len(bzs))
	}
	point, err := NewECPoint(ec,
		new(big.Int).SetBytes(bzs[0]),
		new(big.Int).SetBytes(bzs[1]))
	if err != nil {
		return nil, err
	}
	return point, nil
}

func (P *ECPoint) X() *big.Int {
	return new(big.Int).Set(P.coords[0])
}

func (P *ECPoint) Y() *big.Int {
	return new(big.Int).Set(P.coords[1])
}

func (P *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	x, y := P.curve.Add(P.X(), P.Y(), p1.X(), p1.Y())
	return NewECPoint(P.curve, big.Wrap(x), big.Wrap(y))
}

func (P *ECPoint) ToBtcecPubKey() *btcec.PublicKey {
	var x, y btcec.FieldVal
	x.SetByteSlice(P.X().Bytes())
	y.SetByteSlice(P.Y().Bytes())
	return btcec.NewPublicKey(&x, &y)
}

func (P *ECPoint) ToECDSA() *ecdsa.PublicKey {
	return P.ToBtcecPubKey().ToECDSA()
}

func (P *ECPoint) ToProtobufPoint() *common.ECPoint {
	return &common.ECPoint{
		X: P.X().Bytes(),
		Y: P.Y().Bytes(),
	}
}

func (P *ECPoint) ToEdwardsPubKey() *edwards.PublicKey {
	ecdsaPK := ecdsa.PublicKey{
		Curve: P.curve,
		X:     P.X(),
		Y:     P.Y(),
	}
	pk := edwards.PublicKey(ecdsaPK)
	return &pk
}

func (P *ECPoint) ToEd25519PublicKey() ([]byte, error) {
	// Convert to btcec public key first
	btcPk := P.ToBtcecPubKey()

	// Then convert to Ed25519 using utility function
	edPk := edcrypto.ToEd25519PublicKey(btcPk)
	if edPk == nil {
		return nil, errors.New("failed to convert to Ed25519 public key")
	}

	return edPk, nil
}

func (P *ECPoint) IsOnCurve() bool {
	return isOnCurve(P.curve, P.coords[0], P.coords[1])
}

func (P *ECPoint) Curve() elliptic.Curve {
	return P.curve
}

func (P *ECPoint) Equals(p2 *ECPoint) bool {
	if P == nil || p2 == nil {
		return false
	}
	return P.X().Cmp(p2.X()) == 0 && P.Y().Cmp(p2.Y()) == 0
}

func (P *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	P.curve = curve
	return P
}

// Copy creates a deep copy of the ECPoint
func (P *ECPoint) Copy() (*ECPoint, error) {
	if P == nil {
		return nil, nil
	}
	return NewECPoint(P.curve, P.X(), P.Y())
}

func (P *ECPoint) ValidateBasic() bool {
	return P != nil && P.coords[0] != nil && P.coords[1] != nil && P.IsOnCurve()
}

func (P *ECPoint) Bytes() [2][]byte {
	return [...][]byte{
		P.X().Bytes(),
		P.Y().Bytes(),
	}
}

func (p *ECPoint) String() string {
	if p == nil {
		return "<nil>"
	}
	x := common.FormatBigInt(p.X())
	y := common.FormatBigInt(p.Y())
	return "(" + x + "," + y + ")"
}

// ----- //

// ScalarMult returns k*P where P is a point on the curve. If a builtin constant-time implementation is not available for the curve,
// the function will fall back to our own constant-time implementation.
func (P *ECPoint) ScalarMult(k *big.Int) (*ECPoint, error) {
	return ScalarMult(P.curve, P, k)
}

// scalarMultConstantTime uses the Montgomery Ladder Point Multiplication to compute R0 = k * P
// Implementation based on https://asecuritysite.com/golang/go_bitcoin
func (P *ECPoint) scalarMultConstantTime(k *big.Int) *ECPoint {
	curve := P.curve
	k = big.NewInt(0).SetBytes(moduloReduce(k.Bytes(), curve.Params()))
	zero := big.NewInt(0)
	R0 := NewECPointNoCurveCheck(curve, zero, zero)
	R1 := NewECPointNoCurveCheck(curve, P.X(), P.Y())
	for i := P.curve.Params().N.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			x, y := curve.Add(R0.X(), R0.Y(), R1.X(), R1.Y())
			R1 = NewECPointNoCurveCheck(curve, big.Wrap(x), big.Wrap(y))

			x, y = curve.Add(R0.X(), R0.Y(), R0.X(), R0.Y())
			R0 = NewECPointNoCurveCheck(curve, big.Wrap(x), big.Wrap(y))
		} else {
			x, y := curve.Add(R0.X(), R0.Y(), R1.X(), R1.Y())
			R0 = NewECPointNoCurveCheck(curve, big.Wrap(x), big.Wrap(y))

			x, y = curve.Add(R1.X(), R1.Y(), R1.X(), R1.Y())
			R1 = NewECPointNoCurveCheck(curve, big.Wrap(x), big.Wrap(y))
		}
	}
	return R0
}

// ----- //

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	return c.IsOnCurve(x, y)
}

func matchesSpecificCurve(params *elliptic.CurveParams, available ...elliptic.Curve) (elliptic.Curve, bool) {
	for _, c := range available {
		if params == c.Params() {
			return c, true
		}
	}
	return nil, false
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in)*2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int, noCurveCheck ...bool) ([]*ECPoint, error) {
	if in == nil || len(in)%2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	var err error
	unFlat := make([]*ECPoint, len(in)/2)
	for i, j := 0, 0; i < len(in); i, j = i+2, j+1 {
		if len(noCurveCheck) == 0 || !noCurveCheck[0] {
			unFlat[j], err = NewECPoint(curve, in[i], in[i+1])
			if err != nil {
				return nil, err
			}
		} else {
			unFlat[j] = NewECPointNoCurveCheck(curve, in[i], in[i+1])
		}
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}
