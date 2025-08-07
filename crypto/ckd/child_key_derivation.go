// Copyright © Swingby

package ckd

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	mathbig "math/big"
	"strings"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	edcrypto "github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	"golang.org/x/crypto/ripemd160"
)

type ExtendedKey struct {
	PublicKey  *crypto.ECPoint // Changed from embedded *btcec.PublicKey
	Depth      uint8
	ChildIndex uint32
	ChainCode  []byte // 32 bytes
	ParentFP   []byte // parent fingerprint
	Version    []byte
}

// For more information about child key derivation see https://github.com/iofinnet/tss-lib/v3/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// The functions below do not implement the full BIP-32 specification. As mentioned in the Jira ticket above,
// we only use non-hardened derived keys.

const (
	// HardenedKeyStart hardened key starts.
	HardenedKeyStart = 0x80000000 // 2^31

	// max Depth
	maxDepth = 1<<8 - 1

	PubKeyBytesLenCompressed = 33

	pubKeyCompressed byte = 0x2

	serializedKeyLen = 78

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits
)

// X returns the X coordinate of the public key
func (k *ExtendedKey) X() *mathbig.Int {
	return k.PublicKey.X()
}

// Y returns the Y coordinate of the public key
func (k *ExtendedKey) Y() *mathbig.Int {
	return k.PublicKey.Y()
}

// ToEd25519PublicKey converts the ExtendedKey to Ed25519 public key format
func (k *ExtendedKey) ToEd25519PublicKey() ed25519.PublicKey {
	// Convert ECPoint to Ed25519 format
	x, y := k.PublicKey.X(), k.PublicKey.Y()
	edPoint, err := edcrypto.FromXYToEd25519Point(x, y)
	if err != nil {
		return nil
	}
	return edPoint.Bytes()
}

// Extended public key serialization, defined in BIP32
func (k *ExtendedKey) String() string {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.ChildIndex)

	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.Version...)
	serializedBytes = append(serializedBytes, k.Depth)
	serializedBytes = append(serializedBytes, k.ParentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.ChainCode...)
	pubKeyBytes := serializeCompressed(big.Wrap(k.PublicKey.X()), big.Wrap(k.PublicKey.Y()))
	serializedBytes = append(serializedBytes, pubKeyBytes...)

	checkSum := doubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// NewExtendedKeyFromString returns a new extended key from a base58-encoded extended key
func NewExtendedKeyFromString(key string, curve elliptic.Curve) (*ExtendedKey, error) {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)

	decoded := base58.Decode(key)
	// Ensure we have at least the minimum bytes for checksum validation
	if len(decoded) < 4 {
		return nil, errors.New("extended key too short")
	}

	// Split the payload and checksum up and ensure the checksum matches.
	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := doubleHashB(payload)[:4]
	if subtle.ConstantTimeCompare(checkSum, expectedCheckSum) != 1 {
		return nil, errors.New("invalid extended key")
	}

	// Ensure we have enough bytes for all fields up to the key data
	if len(payload) < 45 {
		return nil, errors.New("extended key payload too short")
	}

	// Deserialize each of the payload fields.
	version := payload[:4]
	depth := payload[4:5][0]
	parentFP := payload[5:9]
	childNum := binary.BigEndian.Uint32(payload[9:13])
	chainCode := payload[13:45]
	keyData := payload[45:] // This will be either 32 or 33 bytes

	var pubKey *crypto.ECPoint
	if _, ok := curve.(*btcec.KoblitzCurve); ok {
		// Ensure the public key parses correctly and is actually on the
		// secp256k1 curve.
		pk, err := btcec.ParsePubKey(keyData)
		if err != nil {
			return nil, err
		}
		if pubKey, err = crypto.NewECPoint(curve, big.Wrap(pk.X()), big.Wrap(pk.Y())); err != nil {
			return nil, err
		}
	} else if curve.Params().Name == edwards.Edwards().Params().Name {
		// This is an Edwards curve (Ed25519)
		// Ed25519 public keys are always 32 bytes
		var ed25519PubKey []byte
		if len(keyData) == 33 {
			// Skip the first byte (prefix) and use the remaining 32 bytes
			ed25519PubKey = keyData[1:]
		} else if len(keyData) == 32 {
			// Use all 32 bytes as the Ed25519 public key
			ed25519PubKey = keyData
		} else {
			return nil, fmt.Errorf("Ed25519 key data must be 32 or 33 bytes, got %d", len(keyData))
		}

		// Decompress the Ed25519 public key using filippo.io/edwards25519
		ed25519Point := edwards25519.NewIdentityPoint()
		_, err := ed25519Point.SetBytes(ed25519PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress Ed25519 public key: %v", err)
		}

		// Get extended coordinates and convert to affine
		X, Y, Z, _ := ed25519Point.ExtendedCoordinates()
		zInv := new(field.Element).Invert(Z)
		x := new(field.Element).Multiply(X, zInv)
		y := new(field.Element).Multiply(Y, zInv)

		// Convert field elements to big.Int
		// Note: field.Element.Bytes() returns little-endian, but big.Int expects big-endian
		xBytes := x.Bytes()
		yBytes := y.Bytes()

		// Reverse for big-endian
		reverseBytes(xBytes[:])
		reverseBytes(yBytes[:])

		xBig := new(mathbig.Int).SetBytes(xBytes[:])
		yBig := new(mathbig.Int).SetBytes(yBytes[:])

		// Create ECPoint for Edwards curve
		if pubKey, err = crypto.NewECPoint(curve, big.Wrap(xBig), big.Wrap(yBig)); err != nil {
			return nil, fmt.Errorf("failed to create ECPoint for Ed25519: %v", err)
		}
	} else {
		// Standard elliptic curve unmarshaling for other curves
		px, py := elliptic.Unmarshal(curve, keyData)
		if px == nil || py == nil {
			return nil, errors.New("failed to unmarshal public key")
		}
		var err error
		if pubKey, err = crypto.NewECPoint(curve, big.Wrap(px), big.Wrap(py)); err != nil {
			return nil, err
		}
	}

	return &ExtendedKey{
		PublicKey:  pubKey,
		Depth:      depth,
		ChildIndex: childNum,
		ChainCode:  chainCode,
		ParentFP:   parentFP,
		Version:    version,
	}, nil
}

func doubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// reverseBytes reverses a byte slice in place
func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// PaddedAppend append src to dst, if less than size padding 0 at start
func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

// PaddedBytes padding byte array to size length
func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		subtle.ConstantTimeCopy(1, tmp[offset:], src)
	}
	return tmp
}

// SerializeCompressed serializes a public key 33-byte compressed format
func serializeCompressed(publicKeyX *big.Int, publicKeyY *big.Int) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubKeyCompressed
	if isOdd(publicKeyY) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(b, 32, publicKeyX.Bytes())
}

func DeriveChildKeyFromHierarchy(indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	// Use Edwards-specific derivation for Ed25519
	if IsEdwardsCurve(curve) {
		return DeriveChildKeyFromHierarchyEdwards(indicesHierarchy, pk, curve)
	}

	// Original implementation for ECDSA curves
	var k = pk
	var err error
	var childKey *ExtendedKey
	if pk == nil {
		return nil, nil, errors.New("pubkey cannot be nil")
	}
	mod_ := int2.ModInt(mod)
	ilNum := big.NewInt(0)
	for index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = DeriveChildKey(indicesHierarchy[index], k, curve)
		if err != nil {
			return nil, nil, err
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}
	return ilNum, k, nil
}

// DeriveChildKey Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKey(index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	// Use Edwards-specific derivation for Ed25519
	if IsEdwardsCurve(curve) {
		return deriveChildKeyEdwards(index, pk, curve)
	}

	// Original implementation for ECDSA curves
	return deriveChildKeyECDSA(index, pk, curve)
}

// deriveChildKeyECDSA implements the original ECDSA child key derivation
func deriveChildKeyECDSA(index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk == nil {
		return nil, nil, errors.New("pubkey cannot be nil")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cryptoPk, err := crypto.NewECPoint(curve, big.Wrap(pk.X()), big.Wrap(pk.Y()))
	if err != nil {
		common.Logger.Error("error getting pubkey from extendedkey")
		return nil, nil, err
	}

	pkPublicKeyBytes := serializeCompressed(big.Wrap(pk.X()), big.Wrap(pk.Y()))

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	binary.BigEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	if ilNum.Cmp(big.Wrap(curve.Params().N)) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		err = errors.New("invalid derived key")
		common.Logger.Error("error deriving child key")
		return nil, nil, err
	}

	deltaG, err := crypto.ScalarBaseMult(curve, ilNum)
	if err != nil {
		return nil, nil, err
	}
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err = errors.New("invalid child")
		common.Logger.Error("error invalid child")
		return nil, nil, err
	}
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}

	childPk := &ExtendedKey{
		PublicKey:  childCryptoPk,
		Depth:      pk.Depth + 1,
		ChildIndex: index,
		ChainCode:  childChainCode,
		ParentFP:   hash160(pkPublicKeyBytes)[:4],
		Version:    pk.Version,
	}
	return ilNum, childPk, nil
}

// ParseHDPath parses a BIP32 derivation path string into a slice of uint32 indices
// Format: "m/44/0/0/0/0" (without hardened indices)
// M is argument to the CKDpub function in BIP32, whereas m is argument to CKDpriv.
// The DeriveChildKey function in tss-lib implements CKDpub.
func ParseHDPath(pathStr string) ([]uint32, error) {
	if pathStr == "" {
		return nil, errors.New("empty HD path")
	}

	// Special case for "m/" (root path) - return empty indices array (zero delta)
	if pathStr == "M/" || pathStr == "m/" {
		return []uint32{}, nil
	}

	// Split the path by "/"
	parts := strings.Split(pathStr, "/")

	// Check if the path starts with "M" or "m"
	if len(parts) == 0 || (parts[0] != "M" && parts[0] != "m") {
		return nil, errors.New("HD path must start with 'm/' or 'M/'")
	}

	// Parse each index after "m"
	indices := make([]uint32, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue // Skip empty parts (e.g., "m//1" -> would skip the empty part)
		}

		// Check if it contains hardened indicator (')
		if strings.Contains(parts[i], "'") || strings.Contains(parts[i], "h") || strings.Contains(parts[i], "H") {
			return nil, errors.New("hardened indices (with ', h, or H) are not supported")
		}

		// Parse the index as uint32
		var index uint64
		_, err := fmt.Sscanf(parts[i], "%d", &index)
		if err != nil {
			return nil, fmt.Errorf("invalid index '%s' at position %d: %v", parts[i], i, err)
		}

		// Validate index range
		if index >= 0x80000000 {
			return nil, fmt.Errorf("index %d at position %d exceeds max allowed value (0x80000000)", index, i)
		}

		indices = append(indices, uint32(index))
	}

	// Check depth limit
	if len(indices) > maxDepth {
		return nil, fmt.Errorf("HD path too deep: %d levels (max %d)", len(indices), maxDepth)
	}

	// For paths with no indices (e.g., just "m"), we're okay with returning an empty slice
	// This allows paths like "m" or "m/" to be treated as root paths (zero delta)
	return indices, nil
}

// GenerateSeed
// TODO: Is this being used?
func GenerateSeed(length uint8) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, errors.New("invalid seed length")
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
