// Copyright © 2021 io finnet group, inc

package signing

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/ckd"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
)

var (
	// xPubVersionBytes is the version bytes for extended public keys (xpub)
	xPubVersionBytes = []byte{0x04, 0x88, 0xB2, 0x1E}
)

// UpdatePublicKeyAndAdjustBigXj updates the public key and BigXj values for EDDSA
// when using HD wallet key derivation. This version accepts an ECPoint directly, avoiding
// unnecessary conversions through btcec format for EdDSA keys.
func UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta *big.Int, keys []*keygen.LocalPartySaveData,
	childECPoint *crypto.ECPoint, ec elliptic.Curve) error {
	// Reject negative keyDerivationDelta values
	if keyDerivationDelta != nil && keyDerivationDelta.Sign() < 0 {
		return fmt.Errorf("keyDerivationDelta must be nil or non-negative")
	}
	gDelta, err := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	if err != nil {
		return fmt.Errorf("failed to compute g^delta: %w", err)
	}

	for k := range keys {
		// If childECPoint is provided, use it directly
		if childECPoint != nil {
			keys[k].EDDSAPub = childECPoint
		} else {
			// Otherwise, update the existing public key by adding delta
			keys[k].EDDSAPub, err = keys[k].EDDSAPub.Add(gDelta)
			if err != nil {
				common.Logger.Errorf("error updating public key with delta")
				return err
			}
		}

		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				common.Logger.Errorf("error in delta operation")
				return err
			}
		}
	}
	return nil
}

// DeriveEdDSAHDChildKey derives HD child key for EdDSA using BIP32-style chain codes
// Returns the derived delta and child key
// This properly handles Ed25519 point serialization and little-endian scalar interpretation
func DeriveEdDSAHDChildKey(keyData *keygen.LocalPartySaveData, chainCodeHex string, hdPath []uint32) (hdDelta *big.Int, childKey *ckd.ExtendedKey, err error) {
	// Convert hex chain code to bytes
	chainCode, err := hex.DecodeString(strings.TrimPrefix(chainCodeHex, "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid chain code hex: %v", err)
	}

	if len(chainCode) != 32 {
		return nil, nil, fmt.Errorf("chain code must be 32 bytes (64 hex characters), got %d bytes", len(chainCode))
	}

	// Get the EdDSA public key
	masterPub := keyData.EDDSAPub
	if masterPub == nil {
		return nil, nil, errors.New("no EdDSA public key found in key data")
	}

	// Create extended key from master pub and chain code
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  masterPub,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode,
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    xPubVersionBytes,
	}

	// Use Edwards curve for EdDSA
	ec := edwards.Edwards()

	// Derive child key using the updated crypto/ckd implementation
	return ckd.DeriveChildKeyFromHierarchy(hdPath, extendedParentPk, big.Wrap(ec.Params().N), ec)
}

// DeriveEdDSAHDChildKeyFromPath is a convenience function that takes a string path
func DeriveEdDSAHDChildKeyFromPath(keyData *keygen.LocalPartySaveData, chainCodeHex string, hdPathStr string) (hdDelta *big.Int, childKey *ckd.ExtendedKey, err error) {
	hdPath, err := ckd.ParseHDPath(hdPathStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse HD path: %v", err)
	}

	return DeriveEdDSAHDChildKey(keyData, chainCodeHex, hdPath)
}

// VerifyEdDSAHDDerivation verifies that the derived public key matches expected values
// This is useful for testing against known test vectors
func VerifyEdDSAHDDerivation(originalPub *crypto.ECPoint, hdDelta *big.Int, expectedChildPub *crypto.ECPoint) error {
	// Calculate delta * G
	deltaG, err := crypto.ScalarBaseMult(edwards.Edwards(), hdDelta)
	if err != nil {
		return fmt.Errorf("failed to compute delta * G: %v", err)
	}

	// Add delta * G to original public key
	derivedPub, err := originalPub.Add(deltaG)
	if err != nil {
		return fmt.Errorf("failed to add delta to public key: %v", err)
	}

	// Compare with expected
	if !derivedPub.Equals(expectedChildPub) {
		return fmt.Errorf("derived public key does not match expected")
	}

	return nil
}
