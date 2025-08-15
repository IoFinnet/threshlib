// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/tss"
	errors2 "github.com/pkg/errors"
)

func (round *signout) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	// collect up s_j's
	sjs := make([]*big.Int, len(round.Parties().IDs()))
	for j := range round.Parties().IDs() {
		sjs[j] = round.temp.signRound3Messages[j].Content().(*SignRound3Message).UnmarshalS()
	}

	var err error
	if round.data, err = FinalizeOneRoundSignAndVerify(
		round.EC(), round.key.EDDSAPub, sjs, round.temp.r, round.temp.a, round.temp.m); err != nil {
		return round.WrapError(errors2.Wrapf(err, "FinalizeOneRoundSignAndVerify failed"))
	}

	for j := range round.temp.signRound3Messages {
		round.ok[j] = true
	}
	round.end <- round.data
	return nil
}

func (round *signout) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *signout) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *signout) NextRound() tss.Round {
	return nil // finished!
}
