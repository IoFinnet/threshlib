// Copyright © 2025 IO Finnet Group, Inc.
//
// This file is part of IO Finnet Group, Inc. The full IO Finnet Group, Inc. copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"github.com/iofinnet/tss-lib/v3/tss"
)

// Terminate implements the Party interface, providing a way to forcibly stop protocol execution
// and cancel any running goroutines in the EdDSA keygen process.
func (p *LocalParty) Terminate() *tss.Error {
	return tss.BaseTerminate(p)
}
