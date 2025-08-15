// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	. "github.com/iofinnet/tss-lib/v3/crypto/vss"
	"github.com/iofinnet/tss-lib/v3/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	t.Parallel()
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)))
	}
	_, e := CheckIndexes(tss.GetCurveForUnitTest(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, indexes[99])
	_, e = CheckIndexes(tss.GetCurveForUnitTest(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	t.Parallel()
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)))
	}
	_, e := CheckIndexes(tss.GetCurveForUnitTest(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, big.Wrap(tss.GetCurveForUnitTest().Params().N))
	_, e = CheckIndexes(tss.GetCurveForUnitTest(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	t.Parallel()
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N))

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)))
	}

	vs, _, err := Create(tss.GetCurveForUnitTest(), threshold, secret, ids)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}
func TestCreateZeroSumRandomArray(t *testing.T) {
	t.Parallel()
	array := CreateZeroSumRandomArray(big.Wrap(tss.GetCurveForUnitTest().Params().N), 100)
	sum := big.NewInt(0)
	modN := big.ModInt(big.Wrap(tss.GetCurveForUnitTest().Params().N))
	for _, a := range array {
		sum = modN.Add(sum, a)
	}
	assert.Equal(t, int64(0), sum.Int64(), "must be zero")
}

func TestVerify(t *testing.T) {
	t.Parallel()
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N))

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)))
	}

	vs, shares, err := Create(tss.GetCurveForUnitTest(), threshold, secret, ids)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.GetCurveForUnitTest(), threshold, vs))
	}
}

func TestReconstruct(t *testing.T) {
	t.Parallel()
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N))

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(big.Wrap(tss.GetCurveForUnitTest().Params().N)))
	}

	_, shares, err := Create(tss.GetCurveForUnitTest(), threshold, secret, ids)
	assert.NoError(t, err)

	secretError2, err2 := shares[:threshold-1].ReConstruct(tss.GetCurveForUnitTest())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secretError2)

	secretError3, err3 := shares[:threshold].ReConstruct(tss.GetCurveForUnitTest())
	assert.Error(t, err3)
	assert.Nil(t, secretError3)

	secret4, err4 := shares[:threshold+1].ReConstruct(tss.GetCurveForUnitTest())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)

	secret5, err5 := shares[:num].ReConstruct(tss.GetCurveForUnitTest())
	assert.NoError(t, err5)
	assert.NotZero(t, secret5)

	assert.Equal(t, secret.Int64(), secret4.Int64(), "secrets must be the same")
	assert.Equal(t, secret4.Int64(), secret5.Int64(), "secrets must be the same")
}
