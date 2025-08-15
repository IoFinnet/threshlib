// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	cmt "github.com/iofinnet/tss-lib/v3/crypto/commitments"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	"github.com/iofinnet/tss-lib/v3/crypto/vss"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message1)(nil),
		(*DGRound2Message2)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
		(*DGRound4Message)(nil),
	}
)

// ----- //

func NewDGRound1Message(
	sessionId *big.Int,
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldCommittee:        false,
		IsToOldAndNewCommittees: false,
	}
	content := &DGRound1Message{
		EcdsaPubX:   ecdsaPub.X().Bytes(),
		EcdsaPubY:   ecdsaPub.Y().Bytes(),
		VCommitment: vct.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment)
}

func (m *DGRound1Message) UnmarshalECDSAPub(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.EcdsaPubX),
		new(big.Int).SetBytes(m.EcdsaPubY))
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// ----- //

func NewDGRound2Message1(
	sessionId *big.Int,
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	paillierPf *paillier.Proof,
	NTildei,
	H1i,
	H2i *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf[:])
	content := &DGRound2Message1{
		PaillierN:     paillierPK.N.Bytes(),
		PaillierProof: paiPfBzs,
		NTilde:        NTildei.Bytes(),
		H1:            H1i.Bytes(),
		H2:            H2i.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message1) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.PaillierProof) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2)
}

func (m *DGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

func (m *DGRound2Message1) UnmarshalPaillierProof() *paillier.Proof {
	var pf paillier.Proof
	if m.PaillierProof == nil {
		return nil
	}
	ints := common.ByteSlicesToBigInts(m.PaillierProof)
	copy(pf[:], ints[:paillier.ProofIters])
	return &pf
}

// ----- //

func NewDGRound2Message2(
	sessionId *big.Int,
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldCommittee:        true,
		IsToOldAndNewCommittees: false,
	}
	content := &DGRound2Message2{}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message2) ValidateBasic(_ elliptic.Curve) bool {
	return true
}

// ----- //

func NewDGRound3Message1(
	sessionId *big.Int,
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

// ----- //

func NewDGRound3Message2(
	sessionId *big.Int,
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewDGRound4Message(
	sessionId *big.Int,
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message{}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message) ValidateBasic(_ elliptic.Curve) bool {
	return true
}
