// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments_test

import (
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/stretchr/testify/assert"

	. "github.com/iofinnet/tss-lib/v3/crypto/commitments"
)

func TestCreateVerify(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(zero, one)
	pass := commitment.Verify()

	assert.True(t, pass, "must pass")
}

func TestDeCommit(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(zero, one)
	pass, secrets := commitment.DeCommit()

	assert.True(t, pass, "must pass")

	assert.NotZero(t, len(secrets), "len(secrets) must be non-zero")
}
