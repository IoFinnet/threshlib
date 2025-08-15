package crypto

import (
	"encoding/json"
	"fmt"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// ECPoint supports various marshaling formats implemented as custom encoder/decoders.
var (
	_ json.Marshaler   = (*ECPoint)(nil)
	_ json.Unmarshaler = (*ECPoint)(nil)
)

// crypto.ECPoint is not inherently json marshal-able
func (P *ECPoint) MarshalJSON() ([]byte, error) {
	ecName, ok := tss.GetCurveName(P.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry, please call tss.RegisterCurve(name, curve) to register it first", P.curve)
	}

	return json.Marshal(&struct {
		Curve  string
		Coords [2]*big.Int
	}{
		Curve:  string(ecName),
		Coords: P.coords,
	})
}

func (P *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve  string
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	P.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}

	if len(aux.Curve) > 0 {
		ec, ok := tss.GetCurveByName(tss.CurveName(aux.Curve))
		if !ok {
			return fmt.Errorf("cannot find curve named with %s in curve registry, please call tss.RegisterCurve(name, curve) to register it first", aux.Curve)
		}
		P.curve = ec
	} else {
		// forward compatible, use global ec as default value
		P.curve = tss.S256()
	}

	if !P.IsOnCurve() {
		return fmt.Errorf("ECPoint.UnmarshalJSON: the point is not on the elliptic curve (%T) ", P.curve)
	}

	return nil
}
