// Copyright © 2025 io finnet group, inc

package ckd

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	ed "github.com/iofinnet/tss-lib/v3/crypto/ed25519"
)

// deriveChildKeyEdwards derives a child key for Edwards curves (Ed25519)
// This implementation properly handles Ed25519 point serialization and little-endian scalar interpretation
func deriveChildKeyEdwards(index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk == nil {
		return nil, nil, errors.New("pubkey cannot be nil")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	// Get the ECPoint from the public key
	cryptoPk := pk.PublicKey

	// For Ed25519, we need to serialize the public key properly (32 bytes)
	edPoint, err := ed.FromXYToEd25519Point(cryptoPk.X(), cryptoPk.Y())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to Ed25519 point: %v", err)
	}
	pkPublicKeyBytes := edPoint.Bytes()

	// Create data for HMAC: serialized public key + index
	data := make([]byte, len(pkPublicKeyBytes)+4)
	copy(data, pkPublicKeyBytes)
	binary.BigEndian.PutUint32(data[len(pkPublicKeyBytes):], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]

	// Ed25519 uses little-endian scalar representation internally.
	// BIP32 HMAC output (IL) is in big-endian format, so we reverse bytes to convert
	// from big-endian to little-endian to match Ed25519's scalar format.
	// This ensures compatibility with other Ed25519 HD wallet implementations.
	ilReversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		ilReversed[31-i] = il[i]
	}
	ilNum := new(big.Int).SetBytes(ilReversed)

	// Always reduce modulo N to ensure valid scalar
	ilNum.Mod(ilNum, big.Wrap(curve.Params().N))

	// Check if the result is zero (invalid)
	if ilNum.Sign() == 0 {
		return nil, nil, errors.New("invalid derived key: zero scalar")
	}

	// Calculate delta * G
	deltaG, err := crypto.ScalarBaseMult(curve, ilNum)
	if err != nil {
		return nil, nil, err
	}

	// Add delta * G to parent public key
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		return nil, nil, err
	}

	// Create child extended key
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

// DeriveChildKeyFromHierarchyEdwards derives a child key from a hierarchy of indices for Edwards curves
func DeriveChildKeyFromHierarchyEdwards(indicesHierarchy []uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if pk == nil {
		return nil, nil, errors.New("pubkey cannot be nil")
	}

	// Verify we have an Edwards curve
	if _, ok := curve.(*edwards.TwistedEdwardsCurve); !ok {
		return nil, nil, errors.New("curve must be an Edwards curve for EdDSA derivation")
	}

	var k = pk
	var err error
	var childKey *ExtendedKey
	mod_ := big.ModInt(big.Wrap(curve.Params().N))
	ilNum := big.NewInt(0)

	for _, index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = deriveChildKeyEdwards(index, k, curve)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive HD child key at index %d: %v", index, err)
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}

	return ilNum, k, nil
}

// IsEdwardsCurve checks if the given curve is an Edwards curve
func IsEdwardsCurve(curve elliptic.Curve) bool {
	_, ok := curve.(*edwards.TwistedEdwardsCurve)
	return ok
}
