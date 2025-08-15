package tss

import (
	"crypto"

	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"
)

func ExpandSessionID(sessionId *big.Int, byteLen int) *big.Int {
	if byteLen < len(sessionId.Bytes()) {
		return sessionId
	}
	// add +1 byte to make sure we're covering the required nonce bit len
	expanded := hash.ExpandXMD(crypto.SHA256, sessionId.Bytes(), sessionId.Bytes(), byteLen+1)
	return new(big.Int).SetBytes(expanded)
}
