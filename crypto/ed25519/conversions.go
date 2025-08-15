package ed25519

import (
	"crypto/ed25519"
	"errors"
	mathbig "math/big"
	"math/bits"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
)

// BigIntToLittleEndianBytes converts a big integer to a LE byte string such as the ones used in ed25519 Scalar.
func BigIntToLittleEndianBytes(a *big.Int) []byte {
	aBz := a.Bytes()
	s := make([]byte, len(aBz))
	if a == nil {
		return s
	}

	// Caveat: a can be longer than 32 bytes.
	s = CopyBytes(aBz)

	// reverse the byte string --> little endian after
	// encoding.
	reverse(s)
	return s
}

// BigIntToFieldElement converts a big endian integer into its corresponding
// 40 byte field representation.
func BigIntToFieldElement(a *big.Int) *field.Element {
	return fromBig(new(field.Element), a)
}

func FromEd25519PointToXY(P *edwards25519.Point) (xt, yt *big.Int) {
	var zInv, x, y field.Element
	X, Y, Z, _ := P.ExtendedCoordinates()
	zInv.Invert(Z)       // zInv = 1 / Z
	x.Multiply(X, &zInv) // x = X / Z
	y.Multiply(Y, &zInv) // y = Y / Z
	xt = big.Wrap(elementToBigInt(&x))
	yt = big.Wrap(elementToBigInt(&y))
	return
}

func FromXYToEd25519Point(xt, yt *big.Int) (P *edwards25519.Point, err error) {
	X := BigIntToFieldElement(xt)
	Y := BigIntToFieldElement(yt)
	Z := BigIntToFieldElement(big.NewInt(1))
	T := BigIntToFieldElement(big.NewInt(1))
	T.Multiply(X, Y)
	P = edwards25519.NewIdentityPoint()
	if P, err = P.SetExtendedCoordinates(X, Y, Z, T); err != nil {
		return
	}
	return
}

func AddExtendedElements(p, q *edwards25519.Point) *edwards25519.Point {
	return p.Add(p, q)
}

// CopyBytes copies a byte string into a new byte string.
func CopyBytes(aB []byte) []byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}

	return s[:]
}

// elementToBigInt returns v as a big.Int.
func elementToBigInt(v *field.Element) *mathbig.Int {
	buf := v.Bytes()

	words := make([]mathbig.Word, 32*8/bits.UintSize)
	for n := range words {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) == 0 {
				break
			}
			words[n] |= mathbig.Word(buf[0]) << mathbig.Word(i)
			buf = buf[1:]
		}
	}
	return new(mathbig.Int).SetBits(words)
}

// fromBig sets v = n, and returns v. The bit length of n must not exceed 256.
func fromBig(v *field.Element, n *big.Int) *field.Element {
	if n.BitLen() > 32*8 {
		panic("edwards25519: invalid field element input size")
	}

	buf := make([]byte, 0, 32)
	for _, word := range n.Bits() {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) >= cap(buf) {
				break
			}
			buf = append(buf, byte(word))
			word >>= 8
		}
	}

	v.SetBytes(buf[:32])
	return v
}

// reverse reverses a byte string
func reverse(s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// FromPointToEd25519PublicKey converts big.Int point coordinates to ed25519.PublicKey
func FromPointToEd25519PublicKey(x, y *big.Int) (ed25519.PublicKey, error) {
	if x == nil || y == nil {
		return nil, errors.New("invalid point coordinates")
	}

	// Use the existing FromXYToEd25519Point function
	edPoint, err := FromXYToEd25519Point(x, y)
	if err != nil {
		return nil, err
	}

	// Get the bytes representation of the Ed25519 point
	return edPoint.Bytes(), nil
}

// ToEd25519PublicKey converts a btcec.PublicKey to ed25519.PublicKey
func ToEd25519PublicKey(pk *btcec.PublicKey) ed25519.PublicKey {
	if pk == nil {
		common.Logger.Error("nil public key")
		return nil
	}

	// Convert FieldVal to big.Int
	x := new(mathbig.Int).SetBytes(pk.X().Bytes()[:])
	y := new(mathbig.Int).SetBytes(pk.Y().Bytes()[:])

	edPubKey, err := FromPointToEd25519PublicKey(big.Wrap(x), big.Wrap(y))
	if err != nil {
		common.Logger.Errorf("error converting to Ed25519: %v", err)
		return nil
	}

	return edPubKey
}
