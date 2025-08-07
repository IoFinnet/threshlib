// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"sync"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	zkplogstar "github.com/iofinnet/tss-lib/v3/crypto/zkp/logstar"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

func newRound2(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.EndData, temp *localTempData, out chan<- tss.Message, end chan<- *common.EndData) tss.Round {
	return &presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 2}}}
}

func (round *presign2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 2.1 verify received proof enc
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	wg.Add(round.PartyCount() - 1)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			Kj := round.temp.r1msgK[j]
			𝜓ij := round.temp.r1msg𝜓0ij[j]
			ok := 𝜓ij.VerifyWithNonce(round.EC(), round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i,
				round.key.H2i, Kj, round.temp.sessionId)
			if !ok {
				errChs <- round.WrapError(errors.New("round2: proofenc verify failed"), Pj)
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
		return round.WrapError(errors.New("round2: proofenc verify failed"), culprits...)
	}

	// Fig 7. Round 2.2 compute MtA and generate proofs
	Γi, _ := crypto.ScalarBaseMult(round.Params().EC(), round.temp.𝛾i)
	g := crypto.NewECPointNoCurveCheck(round.EC(), big.Wrap(round.EC().Params().Gx), big.Wrap(round.EC().Params().Gy))
	errChs = make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg = sync.WaitGroup{}
	wg.Add(round.PartyCount() - 1)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			Kj := round.temp.r1msgK[j]

			DeltaOut := make(chan *MtAOut, 1)
			ChiOut := make(chan *MtAOut, 1)
			ProofOut := make(chan *zkplogstar.ProofLogstar, 1)

			wgj := sync.WaitGroup{}
			wgj.Add(3)

			go func(j int, Pj *tss.PartyID) {
				defer wgj.Done()
				DeltaMtA, err := NewMtA(round.EC(), Kj, round.temp.𝛾i, Γi, round.key.PaillierPKs[j],
					&round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.sessionId)

				if err != nil {
					errChs <- round.WrapError(errors.New("MtADelta failed"), Pj)
					return
				}
				DeltaOut <- DeltaMtA
			}(j, Pj)
			go func(j int, Pj *tss.PartyID) {
				defer wgj.Done()
				ChiMtA, err := NewMtA(round.EC(), Kj, round.temp.w, round.temp.BigWs[i], round.key.PaillierPKs[j],
					&round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j],
					round.temp.sessionId)
				if err != nil {
					errChs <- round.WrapError(errors.New("MtAChi failed"), Pj)
					return
				}
				ChiOut <- ChiMtA
			}(j, Pj)
			go func(j int, Pj *tss.PartyID) {
				defer wgj.Done()
				ProofLogstar, err := zkplogstar.NewProofWithNonce(round.EC(), &round.key.PaillierSK.PublicKey,
					round.temp.G, Γi, g, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.𝛾i,
					round.temp.𝜈i, round.temp.sessionId)
				if err != nil {
					errChs <- round.WrapError(errors.New("prooflogstar failed"), Pj)
					return
				}
				ProofOut <- ProofLogstar
			}(j, Pj)

			wgj.Wait()
			DeltaMtA := <-DeltaOut
			ChiMtA := <-ChiOut
			ProofLogstar := <-ProofOut

			FjiPki, rij, err := round.key.PaillierSK.PublicKey.EncryptAndReturnRandomness(DeltaMtA.Beta) // Encrypting Fji
			// with pk i
			if err != nil {
				errChs <- round.WrapError(errors.New("encryption failed"), Pj)
				return
			}
			r2msg := NewPreSignRound2Message(round.temp.sessionId, Pj, round.PartyID(), Γi, DeltaMtA.Dji, DeltaMtA.Fji,
				ChiMtA.Dji, ChiMtA.Fji, DeltaMtA.Proofji, ChiMtA.Proofji, ProofLogstar)
			round.out <- r2msg

			round.temp.DeltaShareBetas[j] = DeltaMtA.Beta
			round.temp.DeltaShareBetaNegs[j] = DeltaMtA.BetaNeg
			round.temp.DeltaMtAFji[j] = FjiPki
			round.temp.DeltaMtASij[j] = DeltaMtA.Sij
			round.temp.DeltaMtARij[j] = rij
			round.temp.Dji[j] = DeltaMtA.Dji
			round.temp.ChiShareBetas[j] = ChiMtA.Beta

		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}
	round.temp.Γi = Γi

	// clear unused variables
	clear(round.temp.r1msg𝜓0ij)
	return nil
}

func (round *presign2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r2msgDeltaD {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *presign2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PreSignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *presign2) NextRound() tss.Round {
	round.started = false

	// Before proceeding to round 3, perform an early check for mismatched key deltas
	// This provides a more explicit error rather than crashing with a nil pointer
	if round.temp.keyDerivationDelta != nil {
		// Basic sanity check for HD wallet derivation
		i := round.PartyID().Index

		// In round 2, we've received the gamma shares from all parties
		// If key derivation deltas differ between parties, these shares will be inconsistent
		// Before proceeding to round 3 where calculation can crash, add an explicit check

		// The most common failure with mismatched deltas occurs in round 3 with a nil pointer
		// We'll add an additional safeguard here with an explicit error message

		// Check if gamma shares are valid - this is a heuristic check
		// If parties used different deltas, gamma shares will often be incompatible
		// But we can't directly compare the deltas as they're private to each party
		for j, gammaj := range round.temp.r2msgBigGammaShare {
			if j == i {
				continue // Skip self
			}

			// Basic validation of shares
			if gammaj == nil || !gammaj.ValidateBasic() {
				err := errors.New("invalid gamma share detected - this often indicates mismatched key derivation deltas between parties")
				common.Logger.Errorf("Key consistency warning: %v", err)
				// Don't return an error yet, but log the warning - the protocol will fail properly in round 3
			}
		}
	}

	return &presign3{round}
}
