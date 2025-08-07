package hash

import (
	"crypto/elliptic"

	"github.com/armfazh/h2c-go-ref"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	big "github.com/iofinnet/tss-lib/v3/common/int"
)

var (
	hToPointSecp256k1, _    = h2c.Secp256k1_XMDSHA256_SSWU_RO_.Get([]byte("QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"))
	hToPointP256, _         = h2c.P256_XMDSHA256_SSWU_RO_.Get([]byte("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"))
	hToPointEdwards25519, _ = h2c.Edwards25519_XMDSHA512_ELL2_RO_.Get([]byte("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"))
	HToScalarSecp256k1      = hToPointSecp256k1.GetHashToScalar()
	HToScalarP256           = hToPointP256.GetHashToScalar()
	HToScalarEdwards25519   = hToPointEdwards25519.GetHashToScalar()
)

func HashToScalarQ(ec elliptic.Curve, in []byte) *big.Int {
	switch ec.Params().Name {
	case "secp256k1":
		return HToScalarSecp256k1.Hash(in).Polynomial()[0]
	case "P-256":
		return HToScalarP256.Hash(in).Polynomial()[0]
	case "ed25519":
		return HToScalarEdwards25519.Hash(in).Polynomial()[0]
	case "":
		_, cast := ec.(*edwards.TwistedEdwardsCurve)
		if cast {
			return HToScalarEdwards25519.Hash(in).Polynomial()[0]
		}
	}
	return nil
}
