// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/stretchr/testify/assert"

	. "github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/tss"
)

func TestFlattenECPoints(t *testing.T) {
	t.Parallel()
	type args struct {
		in []*ECPoint
	}
	tests := []struct {
		name    string
		args    args
		want    []*big.Int
		wantErr bool
	}{{
		name: "flatten with 2 points (happy)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(3), big.NewInt(4)),
		}},
		want: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)},
	}, {
		name: "flatten with nil point (expects err)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(1), big.NewInt(2)),
			nil,
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(3), big.NewInt(4))},
		},
		want:    nil,
		wantErr: true,
	}, {
		name: "flatten with nil coordinate (expects err)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), nil, big.NewInt(4))},
		},
		want:    nil,
		wantErr: true,
	}, {
		name:    "flatten with nil `in` slice",
		args:    args{nil},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := FlattenECPoints(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("FlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnFlattenECPoints(t *testing.T) {
	t.Parallel()
	type args struct {
		in []*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    []*ECPoint
		wantErr bool
	}{{
		name: "un-flatten 2 points (happy)",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}},
		want: []*ECPoint{
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.GetCurveForUnitTest(), big.NewInt(3), big.NewInt(4)),
		},
	}, {
		name:    "un-flatten uneven len(points) (expects err)",
		args:    args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}},
		want:    nil,
		wantErr: true,
	}, {
		name:    "un-flatten with nil coordinate (expects err)",
		args:    args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), nil}},
		want:    nil,
		wantErr: true,
	}, {
		name:    "flatten with nil `in` slice",
		args:    args{nil},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := UnFlattenECPoints(tss.GetCurveForUnitTest(), tt.args.in, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnFlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnFlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestS256EcpointJsonSerialization(t *testing.T) {
	t.Parallel()
	ec := tss.S256()
	tss.RegisterCurve("secp256k1", ec)

	pubKeyBytes, err := hex.DecodeString("03935336acb03b2b801d8f8ac5e92c56c4f6e93319901fdfffba9d340a874e2879")
	assert.NoError(t, err)
	pbk, err := btcec.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	point, err := NewECPoint(ec, big.Wrap(pbk.X()), big.Wrap(pbk.Y()))
	assert.NoError(t, err)
	bz, err := json.Marshal(point)
	assert.NoError(t, err)
	assert.True(t, len(bz) > 0)

	var umpoint ECPoint
	err = json.Unmarshal(bz, &umpoint)
	assert.NoError(t, err)

	assert.True(t, point.Equals(&umpoint))
	assert.True(t, reflect.TypeOf(point.Curve()) == reflect.TypeOf(umpoint.Curve()))
}

func TestEdwardsEcpointJsonSerialization(t *testing.T) {
	t.Parallel()
	ec := tss.Edwards()
	tss.RegisterCurve("ed25519", ec)

	pubKeyBytes, err := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f249")
	assert.NoError(t, err)
	pbk, err := edwards.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	point, err := NewECPoint(ec, big.Wrap(pbk.X), big.Wrap(pbk.Y))
	assert.NoError(t, err)
	bz, err := json.Marshal(point)
	assert.NoError(t, err)
	assert.True(t, len(bz) > 0)

	var umpoint ECPoint
	err = json.Unmarshal(bz, &umpoint)
	assert.NoError(t, err)

	assert.True(t, point.Equals(&umpoint))
	assert.True(t, reflect.TypeOf(point.Curve()) == reflect.TypeOf(umpoint.Curve()))
}

func TestECPointMult(t *testing.T) {
	t.Parallel()
	curves := []elliptic.Curve{tss.S256(), tss.Edwards()}
	one := big.NewInt(1)
	for _, ec := range curves {
		{
			gen := NewECPointNoCurveCheck(ec, big.Wrap(ec.Params().Gx), big.Wrap(ec.Params().Gy))
			gen1, _ := gen.ScalarMult(one)

			assert.True(t, gen.Equals(gen1), "current implementation - must be the same generator point "+ec.Params().Name)
			// t.Logf("G: %v, G1 (after mult): %v", common.FormatBigInt(gen.X()), common.FormatBigInt(gen1.X()))

			gen2, _ := ScalarBaseMult(ec, one)
			assert.True(t, gen.Equals(gen2), "ScalarBaseMult in ecpoint.go - must be the same generator point "+ec.Params().Name)
			// t.Logf("G: %v, G2 (after custom mult): %v", common.FormatBigInt(gen.X()), common.FormatBigInt(gen2.X()))
		}

		{
			for a := 0; a < 50; a++ {
				rand := common.GetRandomPositiveInt(big.Wrap(ec.Params().N))
				Q, _ := ScalarBaseMult(ec, rand)
				x, y := ec.ScalarBaseMult(rand.Bytes())
				Qʹ, err := NewECPoint(ec, big.Wrap(x), big.Wrap(y))
				assert.NoError(t, err, "there should be no error")
				assert.True(t, Q.Equals(Qʹ), "must be the same point")
			}
			var Q *ECPoint
			rand := common.GetRandomPositiveInt(big.Wrap(ec.Params().N))
			Q, _ = ScalarBaseMult(ec, rand)
			x, y := ec.ScalarBaseMult(rand.Bytes())
			Qʹ, err := NewECPoint(ec, big.Wrap(x), big.Wrap(y))
			assert.True(t, Q.Equals(Qʹ), "must be the same point")
			for a := 0; a < 50 && rand.Cmp(big.NewInt(1)) == +1; rand = big.NewInt(0).Sub(rand, big.NewInt(1)) {
				Q, _ = ScalarMult(ec, Q, rand)
				Qʹ, _ = Qʹ.ScalarMult(rand)

				assert.NoError(t, err, "there should be no error")
				if !assert.True(t, Q.Equals(Qʹ), "must be the same point") {
					t.FailNow()
				}
				a = a + 1
			}
		}

		for _, k := range []uint64{2, 10, 21, 101, 1003} {
			P, _ := ScalarBaseMult(ec, big.NewInt(k))
			x, y := ec.ScalarBaseMult(big.NewInt(k).Bytes())
			Pʹ, err := NewECPoint(ec, big.Wrap(x), big.Wrap(y))
			assert.NoError(t, err, "there should be no error")
			assert.EqualValues(t, P.X(), Pʹ.X(), "must be the same point")
			assert.EqualValues(t, P.Y(), Pʹ.Y(), "must be the same point")
		}
	}
}

func TestECPointMultEd(t *testing.T) {
	t.Parallel()
	curve := tss.Edwards()
	xx, _ := new(big.Int).SetString("14e528b1154be417b6cf078dd6712438d381a5b2c593d552ff2fd2c1207cf3cb", 16)
	xy, _ := new(big.Int).SetString("2d9082313f21ab975a6f7ce340ff0fce1258591c3c9c58d4308f2dc36a033713", 16)
	X, _ := NewECPoint(curve, xx, xy)
	e, _ := new(big.Int).SetString("fad46d13fe8ce132c7f55c3caf1c2254217ce7538db37ef6cd058aec825c094", 16)
	XEXPeNew, _ := X.ScalarMult(e)
	multOld := func(p *ECPoint, k *big.Int) *ECPoint {
		x, y := p.Curve().ScalarMult(p.X(), p.Y(), k.Bytes())
		newP, err := NewECPoint(curve, big.Wrap(x), big.Wrap(y))
		assert.NoError(t, err)
		return newP
	}

	XEXPeOld := multOld(X, e)
	t.Logf("XEXPeOld: %v, XEXPeNew: %v", XEXPeOld, XEXPeNew)
	assert.True(t, XEXPeOld.Equals(XEXPeNew), "must be the same point")
}

func TestECPointEncodingDecoding(t *testing.T) {
	t.Parallel()
	// Create a new ECPoint
	curve := tss.Edwards()
	xx, _ := new(big.Int).SetString("14e528b1154be417b6cf078dd6712438d381a5b2c593d552ff2fd2c1207cf3cb", 16)
	xy, _ := new(big.Int).SetString("2d9082313f21ab975a6f7ce340ff0fce1258591c3c9c58d4308f2dc36a033713", 16)
	ecPoint, _ := NewECPoint(curve, xx, xy)

	// Helper function to measure execution time
	timeOperation := func(name string, f func()) {
		start := time.Now()
		f()
		duration := time.Since(start)
		t.Logf("%s took %v", name, duration)
	}

	// Test JSON encoding and decoding
	var jsonData []byte
	var jsonDecoded ECPoint
	timeOperation("JSON Marshal", func() {
		jsonData, _ = json.Marshal(ecPoint)
	})
	timeOperation("JSON Unmarshal", func() {
		_ = json.Unmarshal(jsonData, &jsonDecoded)
	})
	assert.Equal(t, ecPoint, &jsonDecoded)
	t.Log()

	// Test Gob encoding and decoding
	var gobBuffer bytes.Buffer
	var gobDecoded ECPoint
	var gobSize int
	timeOperation("Gob Encode", func() {
		gobEncoder := gob.NewEncoder(&gobBuffer)
		_ = gobEncoder.Encode(ecPoint)
		gobSize = gobBuffer.Len() // Measure size immediately after encoding
	})
	timeOperation("Gob Decode", func() {
		gobDecoder := gob.NewDecoder(&gobBuffer)
		_ = gobDecoder.Decode(&gobDecoded)
	})
	assert.Equal(t, ecPoint, &gobDecoded)
	t.Log()

	// Print sizes of encoded data
	t.Logf("JSON encoded size: %d bytes", len(jsonData))
	t.Logf("Gob encoded size: %d bytes", gobSize)
}
