// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	big "github.com/binance-chain/tss-lib/common/int"
)

type (
	Party interface {
		Start() *Error
		// The main entry point when updating a party's state from the wire.
		// isBroadcast should represent whether the message was received via a reliable broadcast
		UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool, sessionId *big.Int) (ok bool, err *Error)
		// You may use this entry point to update a party's state when running locally or in tests
		Update(msg ParsedMessage) (ok bool, err *Error)
		ValidateMessage(msg ParsedMessage) (bool, *Error)
		StoreMessage(msg ParsedMessage) (bool, *Error)
		FirstRound() Round
		WrapError(err error, culprits ...*PartyID) *Error
		Running() bool
		WaitingFor() []*PartyID
		Params() *Parameters
		PartyID() *PartyID
		String() string

		// Private lifecycle methods
		setRound(Round) *Error
		Round() Round
		advance()
		Lock()
		Unlock()
	}

	StatefulParty interface {
		Party
		Hydrate(marshalledPartyState string) (bool, *Error)
		Dehydrate() (marshalledPartyState string, err *Error)
		Restart(roundNumber int, marshalledPartyState string) *Error
	}

	BaseParty struct {
		mtx        sync.Mutex
		rndMtx     sync.RWMutex
		rnd        Round
		FirstRound Round
	}
)

func (p *BaseParty) Running() bool {
	return p.rnd != nil
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.Lock()
	defer p.Unlock()
	if p.rnd == nil {
		return []*PartyID{}
	}
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	if p.rnd == nil {
		return NewError(err, "", -1, nil, culprits...)
	}
	return p.rnd.WrapError(err, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	var curve elliptic.Curve
	round := p.Round()
	if round == nil {
		round = p.FirstRound
	}
	if round == nil {
		curve = EC()
	} else {
		curve = round.Params().EC()
	}
	if !msg.ValidateBasic(curve) {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) String() string {
	return fmt.Sprintf("round: %d", p.Round().RoundNumber())
}

// -----
// Private lifecycle methods

func (p *BaseParty) advance() {
	p.rndMtx.Lock()
	defer p.rndMtx.Unlock()
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) setRound(round Round) *Error {
	p.rndMtx.Lock()
	defer p.rndMtx.Unlock()
	if p.rnd != nil {
		return p.WrapError(errors.New("a round is already set on this party"))
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) SetRound(round Round) *Error {
	return p.setRound(round)
}

func (p *BaseParty) Round() Round {
	p.rndMtx.RLock()
	defer p.rndMtx.RUnlock()
	return p.rnd
}

func (p *BaseParty) Lock() {
	p.mtx.Lock()
}

func (p *BaseParty) Unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p Party, task string, prepare ...func(Round) *Error) *Error {
	p.Lock()
	defer p.Unlock()
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
	}
	if p.Round() != nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	if err := p.setRound(round); err != nil {
		return err
	}
	if 1 < len(prepare) {
		return p.WrapError(errors.New("too many prepare functions given to Start(); 1 allowed"))
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return err
		}
	}
	roundNumber := round.RoundNumber()
	common.Logger.Infof("party %s: %s round %d starting", p.Round().Params().PartyID(), task, roundNumber)
	defer func() {
		common.Logger.Debugf("party %s: %s round %d finished", p.Round().Params().PartyID(), task, roundNumber)
	}()
	return p.Round().Start()
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, task string, advanceCallback ...func(Party) (bool, *Error)) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// lock the mutex. need this mtx unlock hook; L108 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.Unlock()
		return ok, err
	}
	p.Lock() // data is written to P state below
	if p.Round() != nil {
		common.Logger.Debugf("party %s BaseUpdate round %d update. msg: %s", p.PartyID(), p.Round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.Round() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.Round().Params().PartyID(), task, p.Round().RoundNumber())
		if _, err := p.Round().Update(); err != nil {
			return r(false, err)
		}
		if p.Round().CanProceed() {
			if len(advanceCallback) > 0 {
				_, err2 := advanceCallback[0](p)
				if err2 != nil {
					return r(false, err2)
				}
			}
			p.advance()
			if p.Round() != nil {
				rndNum := p.Round().RoundNumber()
				common.Logger.Infof("party %s: %s round %d WILL start", p.Round().Params().PartyID(), task, rndNum+1)
				if err := p.Round().Start(); err != nil {
					return r(false, err)
				}
				common.Logger.Infof("party %s: %s round %d started", p.Round().Params().PartyID(), task, rndNum+1)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			}
			p.Unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish)
		}
		return r(true, nil)
	}
	return r(true, nil)
}
