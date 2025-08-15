package tss

import (
	big "github.com/iofinnet/tss-lib/v3/common/int"
)

type SaveData interface {
	GetShareID() *big.Int

	// It returns byte arrays to avoid an import cycle on crypto.ECPoint :(
	GetPubKeyBz() [2][]byte
}
