package signing

import (
	"crypto/subtle"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/iofinnet/tss-lib/v3/crypto"
)

func selfTestECRecovery(msg, r, s, v []byte, pk *btcec.PublicKey) ([]byte, []byte, error) {
	sig := make([]byte, 65)
	subtle.ConstantTimeCopy(1, sig[32-len(r):32], r)
	subtle.ConstantTimeCopy(1, sig[64-len(s):64], s)
	// The recovery ID should be in the range [0-3]
	sig[64] = v[0] & 0x01
	expPub := pk.SerializeUncompressed()
	gotPub, err := crypto.Ecrecover(msg, sig)
	return expPub, gotPub, err
}
