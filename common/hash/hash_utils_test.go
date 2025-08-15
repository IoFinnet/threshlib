package hash_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/armfazh/h2c-go-ref"
	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/tss"
)

func TestHashToScalarQ(t *testing.T) {
	t.Parallel()
	tests := []struct {
		curve        elliptic.Curve
		hashToScalar h2c.HashToScalar
	}{
		{
			curve:        tss.Edwards(),
			hashToScalar: hash.HToScalarEdwards25519,
		},
		{
			curve:        tss.S256(),
			hashToScalar: hash.HToScalarSecp256k1,
		},
		{
			curve:        elliptic.P256(),
			hashToScalar: hash.HToScalarP256,
		},
	}

	hs := hash.SHA256iOne(big.NewInt(123))
	for _, test := range tests {
		h := hash.HashToScalarQ(test.curve, hs.Bytes())
		maxScalar := test.hashToScalar.GetScalarField().Order()
		if h.Sign() < 0 || h.Cmp(maxScalar) >= 0 {
			t.Fatal("invalid hash")
		}
	}
}
