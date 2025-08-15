// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	cmt "github.com/iofinnet/tss-lib/v3/crypto/commitments"
	zkpsch "github.com/iofinnet/tss-lib/v3/crypto/zkp/sch"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*PreSignRound1Message)(nil),
		(*PreSignRound2Message)(nil),
		(*SignRound3Message)(nil),
	}
)

// ----- //

func NewPreSignRound1Message(
	sessionId *big.Int,
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &PreSignRound1Message{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound1Message) ValidateBasic(_ elliptic.Curve) bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *PreSignRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewPreSignRound2Message(
	sessionId *big.Int,
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *zkpsch.ProofSch,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	proofBzs := proof.Bytes()
	content := &PreSignRound2Message{
		DeCommitment: dcBzs,
		Proof:        proofBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound2Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3) &&
		common.NonEmptyMultiBytes(m.Proof, zkpsch.ProofSchBytesParts)
}

func (m *PreSignRound2Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *PreSignRound2Message) UnmarshalZKProof(ec elliptic.Curve) (*zkpsch.ProofSch, error) {
	return zkpsch.NewProofFromBytes(ec, m.GetProof())
}

// ----- //

func NewSignRound3Message(
	sessionId *big.Int,
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		S: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.S)
}

func (m *SignRound3Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}
