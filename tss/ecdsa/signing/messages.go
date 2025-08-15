// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	zkpaffg "github.com/iofinnet/tss-lib/v3/crypto/zkp/affg"
	zkpdec "github.com/iofinnet/tss-lib/v3/crypto/zkp/dec"
	zkpenc "github.com/iofinnet/tss-lib/v3/crypto/zkp/enc"
	zkplogstar "github.com/iofinnet/tss-lib/v3/crypto/zkp/logstar"
	zkpmul "github.com/iofinnet/tss-lib/v3/crypto/zkp/mul"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*PreSignRound1Message)(nil),
		(*PreSignRound2Message)(nil),
		(*PreSignRound3Message)(nil),
		(*SignRound4Message)(nil),
	}
)

// ----- //

func NewPreSignRound1Message(
	sessionId *big.Int,
	to, from *tss.PartyID,
	K *big.Int,
	G *big.Int,
	𝜓0ji *zkpenc.ProofEnc,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := 𝜓0ji.Bytes()
	content := &PreSignRound1Message{
		K:        K.Bytes(),
		G:        G.Bytes(),
		EncProof: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound1Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.K) &&
		common.NonEmptyBytes(m.G) &&
		common.NonEmptyMultiBytes(m.EncProof, zkpenc.ProofEncBytesParts)
}

func (m *PreSignRound1Message) UnmarshalK() *big.Int {
	return new(big.Int).SetBytes(m.GetK())
}

func (m *PreSignRound1Message) UnmarshalG() *big.Int {
	return new(big.Int).SetBytes(m.GetG())
}

func (m *PreSignRound1Message) Unmarshal𝜓0ij() (*zkpenc.ProofEnc, error) {
	return zkpenc.NewProofFromBytes(m.GetEncProof())
}

// ----- //

func NewPreSignRound2Message(
	sessionId *big.Int,
	to, from *tss.PartyID,
	Γi *crypto.ECPoint,
	DjiDelta *big.Int,
	FjiDelta *big.Int,
	DjiChi *big.Int,
	FjiChi *big.Int,
	AffgProofDelta *zkpaffg.ProofAffg,
	AffgProofChi *zkpaffg.ProofAffg,
	ψʹji *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigGammaBytes := Γi.Bytes()
	AffgDeltaBz := AffgProofDelta.Bytes()
	AffgChiBz := AffgProofChi.Bytes()
	LogstarBz := ψʹji.Bytes()
	content := &PreSignRound2Message{
		BigGammaShare:  BigGammaBytes[:],
		DjiDelta:       DjiDelta.Bytes(),
		FjiDelta:       FjiDelta.Bytes(),
		DjiChi:         DjiChi.Bytes(),
		FjiChi:         FjiChi.Bytes(),
		AffgProofDelta: AffgDeltaBz[:],
		AffgProofChi:   AffgChiBz[:],
		LogstarProof:   LogstarBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound2Message) ValidateBasic(ec elliptic.Curve) bool {
	if _, err := m.UnmarshalBigGammaShare(ec); err != nil {
		return false
	}
	return m != nil &&
		common.NonEmptyMultiBytes(m.BigGammaShare, 2) &&
		common.NonEmptyBytes(m.DjiDelta) &&
		common.NonEmptyBytes(m.FjiDelta) &&
		common.NonEmptyBytes(m.DjiChi) &&
		common.NonEmptyBytes(m.FjiChi) &&
		common.NonEmptyMultiBytes(m.AffgProofDelta, zkpaffg.ProofAffgBytesParts) &&
		common.NonEmptyMultiBytes(m.AffgProofChi, zkpaffg.ProofAffgBytesParts) &&
		common.NonEmptyMultiBytes(m.LogstarProof, zkplogstar.ProofLogstarBytesParts)
}

func (m *PreSignRound2Message) UnmarshalBigGammaShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigGammaShare())
}

func (m *PreSignRound2Message) UnmarshalDjiDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetDjiDelta())
}

func (m *PreSignRound2Message) UnmarshalFjiDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetFjiDelta())
}

func (m *PreSignRound2Message) UnmarshalDjiChi() *big.Int {
	return new(big.Int).SetBytes(m.GetDjiChi())
}

func (m *PreSignRound2Message) UnmarshalFjiChi() *big.Int {
	return new(big.Int).SetBytes(m.GetFjiChi())
}

func (m *PreSignRound2Message) UnmarshalAffgProofDelta(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
	return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofDelta())
}

func (m *PreSignRound2Message) UnmarshalAffgProofChi(ec elliptic.Curve) (*zkpaffg.ProofAffg, error) {
	return zkpaffg.NewProofFromBytes(ec, m.GetAffgProofChi())
}

func (m *PreSignRound2Message) UnmarshalLogstarProof(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetLogstarProof())
}

// ----- //

func NewPreSignRound3Message(
	sessionId *big.Int,
	to, from *tss.PartyID,
	𝛿i *big.Int,
	Δi *crypto.ECPoint,
	ProofLogstar *zkplogstar.ProofLogstar,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	BigDeltaShareBzs := Δi.Bytes()
	ProofBz := ProofLogstar.Bytes()
	content := &PreSignRound3Message{
		DeltaShare:    𝛿i.Bytes(),
		BigDeltaShare: BigDeltaShareBzs[:],
		ProofLogstar:  ProofBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *PreSignRound3Message) ValidateBasic(ec elliptic.Curve) bool {
	if _, err := m.UnmarshalBigDeltaShare(ec); err != nil {
		return false
	}
	return m != nil &&
		common.NonEmptyBytes(m.DeltaShare) &&
		common.NonEmptyMultiBytes(m.BigDeltaShare, 2) &&
		common.NonEmptyMultiBytes(m.ProofLogstar, zkplogstar.ProofLogstarBytesParts)
}

func (m *PreSignRound3Message) UnmarshalDeltaShare() *big.Int {
	return new(big.Int).SetBytes(m.GetDeltaShare())
}

func (m *PreSignRound3Message) UnmarshalBigDeltaShare(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPointFromBytes(ec, m.GetBigDeltaShare())
}

func (m *PreSignRound3Message) UnmarshalProofLogstar(ec elliptic.Curve) (*zkplogstar.ProofLogstar, error) {
	return zkplogstar.NewProofFromBytes(ec, m.GetProofLogstar())
}

// ----- //

func NewSignRound4AbortingMessage(
	sessionId *big.Int,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound4AbortingMessage{}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4AbortingMessage) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil
}

func NewSignRound4Message(
	sessionId *big.Int,
	from *tss.PartyID,
	SigmaShare *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound4Message{
		SigmaShare: SigmaShare.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.SigmaShare)
}

func (m *SignRound4Message) UnmarshalSigmaShare() *big.Int {
	return new(big.Int).SetBytes(m.GetSigmaShare())
}

func NewIdentificationPrepRound5Message(
	sessionId *big.Int,
	to, from *tss.PartyID,
	𝛾i *big.Int,
	sji *big.Int,
	𝛽ʹji *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &IdentificationPrepRound5Message{
		Gamma:     𝛾i.Bytes(),
		Sji:       sji.Bytes(),
		BetaNegji: 𝛽ʹji.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationPrepRound5Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.Gamma) &&
		common.NonEmptyBytes(m.Sji) &&
		common.NonEmptyBytes(m.BetaNegji)
}

func (m *IdentificationPrepRound5Message) UnmarshalGamma() *big.Int {
	return new(big.Int).SetBytes(m.GetGamma())
}

func (m *IdentificationPrepRound5Message) UnmarshalSji() *big.Int {
	return new(big.Int).SetBytes(m.GetSji())
}

func (m *IdentificationPrepRound5Message) UnmarshalBetaNegji() *big.Int {
	return new(big.Int).SetBytes(m.GetBetaNegji())
}

// ----- //

func NewIdentificationRound6Message(
	sessionId *big.Int,
	from *tss.PartyID,
	H *big.Int,
	MulProof *zkpmul.ProofMul,
	deltaShareEnc, encryptedValueSum *big.Int,
	proofDeltaShare *zkpdec.ProofDec,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	MulProofBzs := MulProof.Bytes()
	proofDeltaShareBzs := proofDeltaShare.Bytes()
	content := &IdentificationRound6Message{
		H:                 H.Bytes(),
		MulProof:          MulProofBzs[:],
		DeltaShareEnc:     deltaShareEnc.Bytes(),
		EncryptedValueSum: encryptedValueSum.Bytes(),
		DecProof:          proofDeltaShareBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *IdentificationRound6Message) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.H) &&
		common.NonEmptyBytes(m.DeltaShareEnc) &&
		common.NonEmptyBytes(m.EncryptedValueSum) &&
		common.NonEmptyMultiBytes(m.MulProof, zkpmul.ProofMulBytesParts) &&
		common.NonEmptyMultiBytes(m.DecProof, zkpdec.ProofDecBytesParts)
}

func (m *IdentificationRound6Message) UnmarshalH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *IdentificationRound6Message) UnmarshalDeltaShareEnc() *big.Int {
	return new(big.Int).SetBytes(m.GetDeltaShareEnc())
}

func (m *IdentificationRound6Message) UnmarshalEncryptedValueSum() *big.Int {
	return new(big.Int).SetBytes(m.GetEncryptedValueSum())
}

func (m *IdentificationRound6Message) UnmarshalProofMul() (*zkpmul.ProofMul, error) {
	return zkpmul.NewProofFromBytes(m.GetMulProof())
}

func (m *IdentificationRound6Message) UnmarshalProofDec() (*zkpdec.ProofDec, error) {
	return zkpdec.NewProofFromBytes(m.GetDecProof())
}

// ----- //

func NewTempDataDumpMessage(
	sessionId *big.Int,
	from *tss.PartyID,
	tempDump localTempData,
	roundNum int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: false,
	}
	var buffer bytes.Buffer
	dataEnc := gob.NewEncoder(&buffer)
	err := dataEnc.Encode(tempDump)
	if err != nil {
		return nil
	}
	content := &TempDataDumpMessage{
		DataDump: buffer.Bytes(),
		RoundNum: int32(roundNum),
	}
	msg := tss.NewMessageWrapper(meta, content, sessionId)
	return tss.NewMessage(meta, content, msg)
}

func (m *TempDataDumpMessage) ValidateBasic(_ elliptic.Curve) bool {
	return m != nil &&
		common.NonEmptyBytes(m.DataDump)
}

func (m *TempDataDumpMessage) UnmarshalTempDump() (*localTempData, error) {
	dataDec := gob.NewDecoder(bytes.NewReader(m.GetDataDump()))
	var tempData localTempData
	err := dataDec.Decode(&tempData)
	if err != nil {
		return nil, err
	}
	return &tempData, nil
}
