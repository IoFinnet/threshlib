// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
//
// Package signing implements threshold signing for both EdDSA and BIP-340.
// This unified approach is possible because:
// 1. Both are Schnorr-based signature schemes
// 2. The threshold signing protocol (nonce generation, share combination) is identical
// 3. Only the final signature verification step differs between the schemes
//
// The BIP340Verify function handles BIP-340 specific verification, while
// standard EdDSA verification is used for Ed25519 signatures.

package signing

import (
	"errors"
	"fmt"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/crypto"
	cmt "github.com/iofinnet/tss-lib/v3/crypto/commitments"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

const MaxParties = 10000

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.EndData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *common.EndData
	}

	localMessageStore struct {
		signRound1Messages,
		signRound2Messages,
		signRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		m []byte
		wi,
		ri *big.Int
		pointRi            *crypto.ECPoint
		deCommit           cmt.HashDeCommitment
		keyDerivationDelta *big.Int

		// round 2
		cjs       []*big.Int
		si        *big.Int
		sessionId *big.Int

		// round 3
		r *big.Int
		a uint64 // aG, ensuring R with even Y
	}
)

// NewLocalParty returns a new local party for EdDSA signing. Use a nil msg to enable one-round signing mode.
func NewLocalParty(
	msg []byte,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- *common.EndData,
	sessionId *big.Int,
) (tss.Party, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	partyCount := len(params.Parties().IDs())
	if partyCount > MaxParties {
		return nil, fmt.Errorf("signing.NewLocalParty expected at most %d parties", MaxParties)
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.EndData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.m = msg
	p.temp.cjs = make([]*big.Int, partyCount)
	// Initialize keyDerivationDelta to 0 if it's nil
	if keyDerivationDelta == nil {
		p.temp.keyDerivationDelta = big.NewInt(0)
	} else if keyDerivationDelta.Sign() < 0 {
		// Reject negative keyDerivationDelta values
		return nil, fmt.Errorf("keyDerivationDelta must be nil or non-negative")
	} else {
		p.temp.keyDerivationDelta = keyDerivationDelta
	}

	// hash the sessionID to make sure it's of the expected length when used as a nonce
	p.temp.sessionId = tss.ExpandSessionID(sessionId, len(p.params.EC().Params().N.Bytes())+1)
	return p, nil
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool, sessionId *big.Int) (bool, *tss.Error) {
	sessionId = tss.ExpandSessionID(sessionId, len(p.params.EC().Params().N.Bytes())+1)
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast, sessionId)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return p.BaseParty.ValidateMessage(msg)
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *PreSignRound1Message:
		p.temp.signRound1Messages[fromPIdx] = msg

	case *PreSignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg

	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) Params() *tss.Parameters {
	return p.params
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
