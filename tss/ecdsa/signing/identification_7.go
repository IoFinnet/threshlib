// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"sync"

	big "github.com/iofinnet/tss-lib/v3/common/int"

	"github.com/iofinnet/tss-lib/v3/common"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

func newRound7(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.EndData, temp *localTempData, out chan<- tss.Message, end chan<- *common.EndData) tss.Round {
	return &identification7{&identification6{&identificationPrep{&sign4{&presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}, false}}}}
}

func (round *identification7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
	modN := int2.ModInt(big.Wrap(round.EC().Params().N))

	// Fig 7. Output.2
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)

	wg := sync.WaitGroup{}
	wg.Add((round.PartyCount() - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			proofMul := round.temp.r6msgProofMul[j]
			ok := proofMul.VerifyWithNonce(round.EC(), round.key.PaillierPKs[j], round.temp.r1msgK[j],
				round.temp.r1msgG[j], round.temp.r6msgH[j], round.temp.sessionId)
			if !ok {
				common.Logger.Errorf("round7: proofmul verify failed. Current party(i): %v, culprit(j): %v", round.PartyID(), Pj)
				errChs <- round.WrapError(errors.New("round7: proofmul verify failed"), Pj)
				return
			}
		}(j, Pj)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			proofDec := round.temp.r6msgProofDec[j]
			okDec := proofDec.VerifyWithNonce(round.EC(), round.key.PaillierPKs[j], round.temp.r6msgDeltaShareEnc[j],
				modN.Add(zero, round.temp.r6msgEncryptedValueSum[j]), round.key.NTildej[j], round.key.H1j[j],
				round.key.H2j[j], round.temp.sessionId)
			if !okDec {
				common.Logger.Errorf("round7: proofdec verify failed. Current party(i): %v, culprit(j): %v", round.PartyID(), Pj)
				errChs <- round.WrapError(errors.New("round7: proofdec verify failed"), Pj)
				return
			}
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("round7: identification verify failed"), culprits...)
	} else {
		common.Logger.Errorf("party %v - abort triggered but no culprit was identified", round.PartyID())
		// or when running a unit test where messages are tainted, the current party (i) may be the culprit
	}

	// clear unused variables
	round.temp.𝛾i = nil
	round.temp.DeltaShareBetas = nil
	round.temp.DeltaShareBetaNegs = nil

	clear(round.temp.DeltaMtASij)
	clear(round.temp.DeltaMtARij)
	clear(round.temp.DeltaMtAFji)
	clear(round.temp.r1msgG)
	clear(round.temp.r1msgK)
	clear(round.temp.r3msg𝛿j)
	return nil
}

func (round *identification7) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *identification7) CanAccept(_ tss.ParsedMessage) bool {
	return true
}

func (round *identification7) NextRound() tss.Round {
	round.started = false
	return nil
}
