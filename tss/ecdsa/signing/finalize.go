package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/crypto"
)

// FinalizeSigmaShare calculates 𝜎i, the sigma share of a party for one-round signing mode.
// This becomes this party's 𝜎_i share passed into the FinalizeOneRoundSignAndVerify, and other 𝜎_j should be collected via messaging from other parties.
// It is defined in Figure 8 Round 1 of the paper.
func FinalizeSigmaShare(ec elliptic.Curve, ki, rX, chii, msg *big.Int) *big.Int {
	if ec == nil || ki == nil || rX == nil || chii == nil || msg == nil {
		return nil
	}
	modN := big.ModInt(ec.Params().N)
	return modN.Add(modN.Mul(ki, msg), modN.Mul(rX, chii))
}

// FinalizeSigmaShareFromEndData calculates 𝜎i, the sigma share of a party for one-round signing mode, with an EndData protobuf message as an input.
// This becomes this party's 𝜎_i share passed into the FinalizeOneRoundSignAndVerify, and other 𝜎_j should be collected via messaging from other parties.
// It is defined in Figure 8 Round 1 of the paper.
// keyDerivationDelta must be provided (can be nil for non-HD) and validates that the presignature was created with the same delta.
func FinalizeSigmaShareFromEndData(ec elliptic.Curve, data *common.EndData_PreSignatureDataECDSA, msg *big.Int, keyDerivationDelta *big.Int) *big.Int {
	if ec == nil || data == nil || msg == nil || len(data.KI) == 0 || len(data.ChiI) == 0 || data.R == nil || !data.R.ValidateBasic(ec) {
		return nil
	}

	// Check HD delta validation
	hasStoredDelta := len(data.GetHdDelta()) > 0
	hasProvidedDelta := keyDerivationDelta != nil && keyDerivationDelta.Sign() != 0

	if hasStoredDelta && !hasProvidedDelta {
		// Presignature has HD delta but none provided
		return nil
	} else if !hasStoredDelta && hasProvidedDelta {
		// Presignature is non-HD but HD delta provided
		return nil
	} else if hasStoredDelta && hasProvidedDelta {
		// Both have deltas, compare them
		storedDelta := new(big.Int).SetBytes(data.GetHdDelta())
		if subtle.ConstantTimeCompare(storedDelta.Bytes(), keyDerivationDelta.Bytes()) != 1 {
			// Stored delta doesn't match expected
			return nil
		}
	}

	modN := big.ModInt(ec.Params().N)
	ki := new(big.Int).SetBytes(data.GetKI())
	rX := new(big.Int).SetBytes(data.R.X)
	𝜒i := new(big.Int).SetBytes(data.ChiI)
	return modN.Add(modN.Mul(ki, msg), modN.Mul(rX, 𝜒i))
}

// FinalizeOneRoundSignAndVerify is called in one-round signing mode to build a final signature given others' 𝜎i shares (𝜎js) and a msg.
// Note: each P in 𝜎js should correspond with that P's 𝜎i at the same index in 𝜎js.
func FinalizeOneRoundSignAndVerify(
	ec elliptic.Curve,
	ourPubKey *crypto.ECPoint,
	ourBigR *crypto.ECPoint,
	𝜎js []*big.Int,
	msg *big.Int,
) (*common.EndData, error) {
	out := common.EndData{}
	if ec == nil || ourPubKey == nil || ourBigR == nil || !ourBigR.ValidateBasic() || msg == nil {
		return nil, fmt.Errorf("FinalizeOneRoundSignAndVerify: invalid arguments")
	}
	𝜎 := 𝜎js[0]
	// Fig 8. Output. combine signature shares verify and output
	N := big.Wrap(ec.Params().N)
	modN := big.ModInt(N)
	for idx, 𝜎j := range 𝜎js {
		if idx == 0 {
			continue
		}
		𝜎 = modN.Add(𝜎, 𝜎j)
	}

	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if ourBigR.X().Cmp(N) > 0 {
		recid = 2
	}
	if ourBigR.Y().Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	halfN := new(big.Int).Rsh(N, 1)
	if 𝜎.Cmp(halfN) > 0 {
		𝜎.Sub(N, 𝜎)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := ec.Params().BitSize / 8
	out.R = common.PadToLengthBytesInPlace(ourBigR.X().Bytes(), bitSizeInBytes)
	out.S = common.PadToLengthBytesInPlace(𝜎.Bytes(), bitSizeInBytes)
	out.Signature = append(out.R, out.S...)
	out.SignatureRecovery = []byte{byte(recid)}
	out.M = msg.Bytes()

	ourBtcEcPk := ourPubKey.ToBtcecPubKey()
	ok := ecdsa.Verify(ourBtcEcPk.ToECDSA(), msg.Bytes(), ourBigR.X(), 𝜎)
	if !ok {
		return nil, fmt.Errorf("signature verification failed")
	}

	// self-test EC recovery
	m, r, s, v := msg.Bytes(), out.R, out.S, out.SignatureRecovery
	expPub, gotPub, err := selfTestECRecovery(m, r, s, v, ourBtcEcPk)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(expPub, gotPub) != 1 {
		return nil, fmt.Errorf("EC recovery self-test failed")
	}
	return &out, nil
}

func FinalizeOneRoundSignAndVerifyFromEndData(
	ec elliptic.Curve,
	data *common.EndData_PreSignatureDataECDSA,
	𝜎js []*big.Int,
	msg *big.Int,
) (*common.EndData, error) {
	if ec == nil || data == nil || msg == nil {
		return nil, fmt.Errorf("FinalizeOneRoundSignAndVerifyFromEndData: invalid arguments")
	}
	pk, err := crypto.NewECPoint(ec, new(big.Int).SetBytes(data.Pk.GetX()), new(big.Int).SetBytes(data.Pk.GetY()))
	if err != nil {
		return nil, err
	}
	bigR, err := crypto.NewECPoint(ec, new(big.Int).SetBytes(data.R.GetX()), new(big.Int).SetBytes(data.R.GetY()))
	if err != nil {
		return nil, err
	}
	return FinalizeOneRoundSignAndVerify(ec, pk, bigR, 𝜎js, msg)
}
