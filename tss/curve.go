// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"reflect"
	"sync"

	s256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

type CurveName string

const (
	Secp256k1 CurveName = "secp256k1"
	Nist256p1 CurveName = "nist256p1" // a.k.a secp256r1
	Ed25519   CurveName = "ed25519"
)

var (
	s256     elliptic.Curve
	registry sync.Map
)

// Init default curve (secp256k1)
func init() {
	s256 = s256k1.S256()
	registry.Store(Secp256k1, s256)
	registry.Store(Nist256p1, elliptic.P256())
	registry.Store(Ed25519, edwards.Edwards())
}

func RegisterCurve(name CurveName, curve elliptic.Curve) {
	registry.Store(name, curve)
}

// return curve, exist(bool)
func GetCurveByName(name CurveName) (elliptic.Curve, bool) {
	if val, exist := registry.Load(name); exist {
		return val.(elliptic.Curve), true
	}
	return nil, false
}

// return name, exist(bool)
func GetCurveName(curve elliptic.Curve) (CurveName, bool) {
	match := CurveName("")
	registry.Range(func(name, value interface{}) bool {
		if reflect.TypeOf(curve) == reflect.TypeOf(value) {
			match = name.(CurveName)
			return false
		}
		return true
	})
	if match != "" {
		return match, true
	}
	return "", false
}

// GetCurveForUnitTest returns an elliptic curve for unit tests ONLY. The default is secp256k1.
// Deprecated: Use ONLY in tests. Use GetCurveByName instead.
func GetCurveForUnitTest() elliptic.Curve {
	return s256
}

// secp256k1
func S256() elliptic.Curve {
	return s256
}

func Edwards() elliptic.Curve {
	return edwards.Edwards()
}
