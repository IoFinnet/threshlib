// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"strings"

	"filippo.io/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/commitments"
	"github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	"github.com/iofinnet/tss-lib/v3/tss"
	errors2 "github.com/pkg/errors"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	// 1. init R
	var Rsecp256k1 *crypto.ECPoint
	var Redwards *edwards25519.Point

	var riBytes []byte
	_, isTwistedEdwardsCurve := round.Params().EC().(*edwards.TwistedEdwardsCurve)
	isSecp256k1Curve := strings.Compare("secp256k1", round.Params().EC().Params().Name) == 0
	if isTwistedEdwardsCurve {
		riBytes = ed25519.BigIntToLittleEndianBytes(round.temp.ri)
		riSc, err := edwards25519.NewScalar().SetCanonicalBytes(riBytes[:])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewScalar(ri)"))
		}
		Redwards = edwards25519.NewIdentityPoint().ScalarBaseMult(riSc)
	} else if isSecp256k1Curve {
		riBytes = round.temp.ri.Bytes()
		Rsecp256k1, _ = crypto.ScalarBaseMult(round.Params().EC(), round.temp.ri)
	}

	// 2-6. compute R
	i := round.PartyID().Index
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*PreSignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		if round.temp.sessionId == nil {
			return round.WrapError(errors.New("sessionId not set"))
		}
		ok = proof.VerifyWithNonce(Rj, round.temp.sessionId)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		if isTwistedEdwardsCurve {
			extendedRj, _ := ed25519.FromXYToEd25519Point(Rj.X(), Rj.Y())
			if err != nil {
				return round.WrapError(errors2.Wrapf(err, "error with ed25519 extended element conversion"), Pj)
			}
			if Redwards = ed25519.AddExtendedElements(Redwards, extendedRj); err != nil {
				return round.WrapError(errors2.Wrapf(err, "error with ed25519 extended element addition"), Pj)
			}
		} else if isSecp256k1Curve {
			Rsecp256k1, err = Rsecp256k1.Add(Rj)
			if err != nil {
				return round.WrapError(errors2.Wrapf(err, "error with addition"), Pj)
			}
		}
	}

	var encodedR []byte
	a := uint64(0)
	if isTwistedEdwardsCurve {
		if len(Redwards.Bytes()) < 32 {
			return round.WrapError(errors.New("error with ed25519 encoded bytes conversion: too short"))
		}
		encodedR = Redwards.Bytes()[:]
		encodedPubKeyPt, err := ed25519.FromXYToEd25519Point(round.key.EDDSAPub.X(), round.key.EDDSAPub.Y())
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "error with ed25519 public key conversion"))
		}
		encodedPubKeyBz := encodedPubKeyPt.Bytes()
		if len(encodedPubKeyBz) < 32 {
			return round.WrapError(errors.New("error with ed25519 encoded bytes conversion: too short"))
		}
	} else if isSecp256k1Curve {
		var s [32]byte
		round.key.EDDSAPub.X().FillBytes(s[:])
		encodedR = make([]byte, 32)
		{
			G, _ := crypto.ScalarBaseMult(round.Params().EC(), big.NewInt(1))
			for ; oddY(Rsecp256k1); a++ { // Y cannot be odd in BIP340
				Rsecp256k1, _ = Rsecp256k1.Add(G)
			}
			round.temp.a = a
			encode32bytes(Rsecp256k1.X(), encodedR[:])
		}
	}

	// 9. store r3 message pieces
	if isTwistedEdwardsCurve {
		round.temp.r = littleEndianBytesToBigInt(encodedR)
	} else if isSecp256k1Curve {
		round.temp.r = Rsecp256k1.X()
	}

	// One-Round Signing Shortcut Exit
	if round.temp.m == nil {
		preSignData := &common.EndData_PreSignatureDataEdDSA{
			Ssid:     round.temp.sessionId.Bytes(),
			Pk:       round.key.EDDSAPub.ToProtobufPoint(),
			EncodedR: encodedR,
			RI:       riBytes,
			R:        round.temp.r.Bytes(),
			WI:       round.temp.wi.Bytes(),
			A:        a,
		}
		// Add HD delta if present
		if round.temp.keyDerivationDelta != nil && round.temp.keyDerivationDelta.Sign() != 0 {
			preSignData.HdDelta = round.temp.keyDerivationDelta.Bytes()
		}
		round.data.PreSignDataEddsa = preSignData
		common.Logger.Debugf("EdDSA party %v, one-round data is going out", round.PartyID())
		round.end <- round.data
		return nil
	}

	// 7. compute lambda - signature share with message m applied
	// h = hash512(k || A || M)
	// 8. compute s_i
	si, err := FinalizeSigShare(
		round.Params().EC(), round.key.EDDSAPub, encodedR, riBytes, round.temp.wi.Bytes(), round.temp.m)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "FinalizeSigShare"))
	}
	round.temp.si = si

	// 10. broadcast s_i to other parties
	r3msg := NewSignRound3Message(round.temp.sessionId, round.PartyID(), si)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false

	// One-Round Signing Shortcut Exit
	if round.temp.m == nil {
		return nil
	}

	return &signout{round}
}
