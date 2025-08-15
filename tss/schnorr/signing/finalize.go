package signing

import (
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	errors2 "github.com/pkg/errors"
)

func FinalizeSigShare(ec elliptic.Curve, pk *crypto.ECPoint, encR, rI, wI []byte, msg []byte) (*big.Int, error) {
	if ec == nil || len(encR) == 0 || len(rI) == 0 || len(wI) == 0 || msg == nil || pk == nil || !pk.ValidateBasic() {
		return nil, errors.New("invalid or nil arguments")
	}
	_, isTwistedEdwardsCurve := ec.(*edwards.TwistedEdwardsCurve)
	isSecp256k1Curve := strings.Compare("secp256k1", ec.Params().Name) == 0

	var encodedPK []byte
	if isTwistedEdwardsCurve {
		encodedPubKeyPt, err := ed25519.FromXYToEd25519Point(pk.X(), pk.Y())
		if err != nil {
			return nil, err
		}
		encodedPubKeyBz := encodedPubKeyPt.Bytes()
		if len(encodedPubKeyBz) != 32 {
			return nil, errors.New("error with ed25519 encoded bytes conversion: not 32 bytes")
		}
		encodedPK = encodedPubKeyBz[:32]
	} else if isSecp256k1Curve {
		var s [32]byte
		pk.X().FillBytes(s[:])
		encodedPK = s[:]
	}

	// 7. compute lambda - signature share with message m applied
	// h = hash512(k || A || M)
	var lambdaReduced *edwards25519.Scalar
	var 𝜆 *chainhash.Hash
	if isTwistedEdwardsCurve {
		var lambda [64]byte

		h := sha512.New()
		h.Reset()
		h.Write(encR)
		h.Write(encodedPK)
		h.Write(msg)
		h.Sum(lambda[:0])

		var err error
		if lambdaReduced, err = edwards25519.NewScalar().SetUniformBytes(lambda[:]); err != nil {
			return nil, errors2.Wrapf(err, "NewScalar(lambda)")
		}
	} else if isSecp256k1Curve {
		𝜆 = chainhash.TaggedHash(
			[]byte("BIP0340/challenge"), encR, encodedPK, msg,
		)
		var e btcec.ModNScalar
		if overflow := e.SetBytes((*[32]byte)(𝜆.CloneBytes())); overflow != 0 {
			str := "hash of (r || P || m) too big"
			return nil, errors.New(str)
		}
	}

	// 8. compute s_i
	var localS *edwards25519.Scalar
	var si *big.Int
	wII := new(big.Int).SetBytes(wI)
	if isTwistedEdwardsCurve {
		wiS, err := edwards25519.NewScalar().SetCanonicalBytes(ed25519.BigIntToLittleEndianBytes(wII)[:])
		if err != nil {
			return nil, errors2.Wrapf(err, "NewScalar(wi)")
		}
		riS, err := edwards25519.NewScalar().SetCanonicalBytes(rI)
		if err != nil {
			return nil, errors2.Wrapf(err, "NewScalar(ri)")
		}
		localS = edwards25519.NewScalar().MultiplyAdd(lambdaReduced, wiS, riS)
		// si = new(big.Int).SetBytes(ReverselocalS.Bytes())
		si = littleEndianBytesToBigInt(localS.Bytes())
	} else if isSecp256k1Curve {
		𝜆wi := big.NewInt(0).Mul(big.NewInt(0).SetBytes(𝜆.CloneBytes()), wII)
		si = new(big.Int).Add(new(big.Int).SetBytes(rI), 𝜆wi)
	}

	// return s_i as the sig share
	return si, nil
}

func FinalizeSigShareFromEndData(ec elliptic.Curve, data *common.EndData_PreSignatureDataEdDSA, msg []byte, keyDerivationDelta *big.Int) (*big.Int, error) {
	if ec == nil || data == nil || msg == nil || len(data.WI) == 0 {
		return nil, errors.New("invalid or nil arguments")
	}

	// Check HD delta validation
	hasStoredDelta := len(data.GetHdDelta()) > 0
	hasProvidedDelta := keyDerivationDelta != nil && keyDerivationDelta.Sign() != 0

	if hasStoredDelta && !hasProvidedDelta {
		// Presignature has HD delta but none provided
		return nil, fmt.Errorf("presignature has HD delta but none expected")
	} else if !hasStoredDelta && hasProvidedDelta {
		// Presignature is non-HD but HD delta provided
		return nil, fmt.Errorf("presignature is non-HD but HD derivation expected")
	} else if hasStoredDelta && hasProvidedDelta {
		// Both have deltas, compare them
		storedDelta := new(big.Int).SetBytes(data.GetHdDelta())
		if subtle.ConstantTimeCompare(storedDelta.Bytes(), keyDerivationDelta.Bytes()) != 1 {
			// Stored delta doesn't match expected
			return nil, fmt.Errorf("presignature was created with different HD derivation path")
		}
	}

	pkPt, err := crypto.NewECPoint(ec, new(big.Int).SetBytes(data.Pk.GetX()), new(big.Int).SetBytes(data.Pk.GetY()))
	if err != nil {
		return nil, err
	}
	return FinalizeSigShare(ec, pkPt, data.GetEncodedR(), data.GetRI(), data.GetWI(), msg)
}

func FinalizeOneRoundSignAndVerify(
	ec elliptic.Curve,
	ourPubKey *crypto.ECPoint,
	sjs []*big.Int,
	r *big.Int, a uint64,
	msg []byte) (*common.EndData, error) {

	out := common.EndData{}

	var s *big.Int
	var sumS *edwards25519.Scalar

	_, isTwistedEdwardsCurve := ec.(*edwards.TwistedEdwardsCurve)
	isSecp256k1Curve := strings.Compare("secp256k1", ec.Params().Name) == 0

	si := sjs[0]
	if isTwistedEdwardsCurve {
		var err error
		if sumS, err = edwards25519.NewScalar().SetCanonicalBytes(ed25519.BigIntToLittleEndianBytes(si)[:]); err != nil {
			return nil, errors2.Wrapf(err, "NewScalar(si)")
		}
		oneS, err := edwards25519.NewScalar().SetCanonicalBytes(ed25519.BigIntToLittleEndianBytes(big.NewInt(1))[:])
		if err != nil {
			return nil, errors2.Wrapf(err, "NewScalar(1)")
		}
		for j, sj := range sjs {
			if j == 0 {
				continue
			}
			sjS, err2 := edwards25519.NewScalar().SetCanonicalBytes(ed25519.BigIntToLittleEndianBytes(sj))
			if err2 != nil {
				return nil, errors2.Wrapf(err2, "NewScalar(sj)")
			}
			sumS = sumS.MultiplyAdd(sumS, oneS, sjS)
		}
		s = littleEndianBytesToBigInt(sumS.Bytes())
	} else if isSecp256k1Curve {
		sumSInt := si
		modN := big.ModInt(big.Wrap(ec.Params().N))
		for j, sj := range sjs {
			if j == 0 {
				continue
			}
			sumSInt = modN.Add(sumSInt, sj)
		}
		// if we adjusted R by adding aG to find R with an even Y coordinate, add a to s also.
		s = modN.Add(sumSInt, big.NewInt(a))
	}

	// save the signature for final output
	signature := new(common.ECSignature)
	if isTwistedEdwardsCurve {
		signature.Signature = append(ed25519.BigIntToLittleEndianBytes(r), sumS.Bytes()...)
		signature.R = ed25519.BigIntToLittleEndianBytes(r)
		signature.S = ed25519.BigIntToLittleEndianBytes(s)
	} else if isSecp256k1Curve {
		var r32b, s32b [32]byte
		encode32bytes(r, r32b[:])
		encode32bytes(s, s32b[:])
		signature.Signature = append(r32b[:], s32b[:]...)
		signature.R = r32b[:]
		signature.S = s32b[:]
	}

	signature.M = msg
	out.R = signature.R
	out.S = signature.S
	out.Signature = append(out.R, out.S...)

	if isTwistedEdwardsCurve {
		common.Logger.Debugf("finalize - r: %v, s:%v", hex.EncodeToString(r.Bytes()),
			hex.EncodeToString(s.Bytes()))
		if ok := edwards.Verify(ourPubKey.ToEdwardsPubKey(), msg, r, s); !ok {
			return nil, fmt.Errorf("edwards signature verification failed")
		}
	} else if isSecp256k1Curve {
		if err := BIP340Verify(ourPubKey.ToBtcecPubKey(), msg, r, s); err != nil {
			return nil, errors2.Wrapf(err, "BIP-340 signature verification failed")
		}
	}
	return &out, nil
}

func FinalizeOneRoundSignAndVerifyFromEndData(
	ec elliptic.Curve,
	data *common.EndData_PreSignatureDataEdDSA,
	sjs []*big.Int,
	msg []byte,
) (*common.EndData, error) {
	if ec == nil || data == nil || msg == nil {
		return nil, errors.New("invalid or nil arguments")
	}
	r := new(big.Int).SetBytes(data.R)
	pk, err := crypto.NewECPoint(ec, new(big.Int).SetBytes(data.Pk.GetX()), new(big.Int).SetBytes(data.Pk.GetY()))
	if err != nil {
		return nil, err
	}
	return FinalizeOneRoundSignAndVerify(ec, pk, sjs, r, data.A, msg)
}
