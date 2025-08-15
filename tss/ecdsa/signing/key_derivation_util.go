// Copyright © 2021 io finnet group, inc

package signing

import (
	"crypto/elliptic"
	"fmt"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/ckd"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

func UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta *big.Int, keys []*keygen.LocalPartySaveData,
	childECPoint *crypto.ECPoint, ec elliptic.Curve) error {
	// Reject negative keyDerivationDelta values
	if keyDerivationDelta != nil && keyDerivationDelta.Sign() < 0 {
		return fmt.Errorf("keyDerivationDelta must be nil or non-negative")
	}
	var err error
	gDelta, _ := crypto.ScalarBaseMult(ec, keyDerivationDelta)

	for k := range keys {
		// If childECPoint is provided, update the public key
		if childECPoint != nil {
			keys[k].ECDSAPub = childECPoint
		} else {
			// Otherwise, update the existing public key by adding delta
			keys[k].ECDSAPub, err = keys[k].ECDSAPub.Add(gDelta)
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

func derivingPubkeyFromPath(masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  masterPub,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}
	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, big.Wrap(ec.Params().N), ec)
}
