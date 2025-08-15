package crypto

import (
	"crypto/elliptic"
	"errors"

	"filippo.io/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto/ed25519"
)

func ScalarBaseMult(curve elliptic.Curve, k *big.Int) (*ECPoint, error) {
	G := NewECPointNoCurveCheck(curve, big.Wrap(curve.Params().Gx), big.Wrap(curve.Params().Gy))
	return ScalarMult(curve, G, k)
}

// ScalarMult returns k*P where P is a point on the curve. If a builtin constant-time implementation is not available for the curve,
// the function will fall back to our own constant-time implementation.
func ScalarMult(curve elliptic.Curve, P *ECPoint, k *big.Int) (Q *ECPoint, err error) {
	// use the curve's function only if it is a constant-time implementation
	if specificCurve, match := matchesSpecificCurve(curve.Params(), elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()); match {
		x, y := specificCurve.ScalarBaseMult(k.Bytes())
		if Q, err = NewECPoint(curve, big.Wrap(x), big.Wrap(y)); err != nil {
			return
		}
		return Q, err
	}
	if _, isEdwards := curve.(*edwards.TwistedEdwardsCurve); isEdwards {
		var Pʹ *edwards25519.Point
		if Pʹ, err = ed25519.FromXYToEd25519Point(P.X(), P.Y()); err != nil {
			return
		}
		if curve.Params().N.Cmp(k) == -1 {
			return nil, errors.New("ScalarMult: scalar is out of range")
		}
		kBytes := ed25519.BigIntToLittleEndianBytes(k)
		scalar := edwards25519.NewScalar()
		if scalar, err = scalar.SetCanonicalBytes(kBytes[:]); err != nil {
			return
		}
		if err != nil {
			common.Logger.Errorf("error %v", err)
		}
		x, y := ed25519.FromEd25519PointToXY(Pʹ.ScalarMult(scalar, Pʹ))
		if Q, err = NewECPoint(curve, x, y); err != nil {
			return
		}
		return
	}
	return P.scalarMultConstantTime(k), err
}
