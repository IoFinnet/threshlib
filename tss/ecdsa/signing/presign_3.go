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
	"github.com/iofinnet/tss-lib/v3/crypto"
	zkplogstar "github.com/iofinnet/tss-lib/v3/crypto/zkp/logstar"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
)

func newRound3(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.EndData, temp *localTempData, out chan<- tss.Message, end chan<- *common.EndData) tss.Round {
	return &presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}
}

func (round *presign3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 3.1 verify proofs received and decrypt alpha share of MtA output
	g := crypto.NewECPointNoCurveCheck(round.EC(), big.Wrap(round.EC().Params().Gx), big.Wrap(round.EC().Params().Gy))
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	wg.Add((round.PartyCount() - 1) * 3)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		Γj := round.temp.r2msgBigGammaShare[j]

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			DeltaD := round.temp.r2msgDeltaD[j]
			DeltaF := round.temp.r2msgDeltaF[j]
			proofAffgDelta := round.temp.r2msgDeltaProof[j]
			ok := proofAffgDelta.VerifyWithNonce(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j],
				round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, DeltaD, DeltaF, Γj, round.temp.sessionId)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg delta"))
				return
			}
			AlphaDelta, err := round.key.PaillierSK.Decrypt(DeltaD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"))
				return
			}
			round.temp.DeltaShareAlphas[j] = AlphaDelta
		}(j, Pj)

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ChiD := round.temp.r2msgChiD[j]
			ChiF := round.temp.r2msgChiF[j]
			proofAffgChi := round.temp.r2msgChiProof[j]
			ok := proofAffgChi.VerifyWithNonce(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j],
				round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, ChiD, ChiF, round.temp.BigWs[j],
				round.temp.sessionId)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify affg chi"))
				return
			}
			AlphaChi, err := round.key.PaillierSK.Decrypt(ChiD)
			if err != nil {
				errChs <- round.WrapError(errors.New("failed to do mta"))
				return
			}
			round.temp.ChiShareAlphas[j] = AlphaChi
		}(j, Pj)

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ψʹij := round.temp.r2msgProofLogstar[j]
			Gj := round.temp.r1msgG[j]
			ok := ψʹij.VerifyWithNonce(round.EC(), round.key.PaillierPKs[j], Gj, Γj, g, round.key.NTildei,
				round.key.H1i, round.key.H2i, round.temp.sessionId)
			if !ok {
				errChs <- round.WrapError(errors.New("failed to verify logstar"))
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
		return round.WrapError(errors.New("round3: failed to verify proofs"), culprits...)
	}

	// Fig 7. Round 3.2 accumulate results from MtA
	Γ := round.temp.Γi
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		BigGammaShare := round.temp.r2msgBigGammaShare[j]
		var err error
		Γ, err = Γ.Add(BigGammaShare)
		if err != nil {
			return round.WrapError(errors.New("round3: failed to collect Γ"))
		}
	}
	Δi, _ := Γ.ScalarMult(round.temp.ki)

	modN := int2.ModInt(big.Wrap(round.EC().Params().N))
	𝛿i := modN.Mul(round.temp.ki, round.temp.𝛾i)
	𝜒i := modN.Mul(round.temp.ki, round.temp.w)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}

		// Add explicit nil checks to provide better error messages when using mismatched deltas
		if round.temp.DeltaShareAlphas[j] == nil {
			return round.WrapError(errors.New("mismatched key derivation deltas detected: DeltaShareAlphas is nil"))
		}
		if round.temp.DeltaShareBetas[j] == nil {
			return round.WrapError(errors.New("mismatched key derivation deltas detected: DeltaShareBetas is nil"))
		}
		if round.temp.ChiShareAlphas[j] == nil {
			return round.WrapError(errors.New("mismatched key derivation deltas detected: ChiShareAlphas is nil"))
		}
		if round.temp.ChiShareBetas[j] == nil {
			return round.WrapError(errors.New("mismatched key derivation deltas detected: ChiShareBetas is nil"))
		}

		𝛿i = modN.Add(𝛿i, round.temp.DeltaShareAlphas[j])
		𝛿i = modN.Add(𝛿i, round.temp.DeltaShareBetas[j])

		𝜒i = modN.Add(𝜒i, round.temp.ChiShareAlphas[j])
		𝜒i = modN.Add(𝜒i, round.temp.ChiShareBetas[j])
	}

	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	round.temp.𝛿i = 𝛿i
	round.temp.𝜒i = 𝜒i
	round.temp.Δi = Δi
	round.temp.Γ = Γ

	wg = sync.WaitGroup{}
	wg.Add(round.PartyCount() - 1)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ProofOut := make(chan *zkplogstar.ProofLogstar, 1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			ψʺji, err := zkplogstar.NewProofWithNonce(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, Δi, Γ,
				round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.ki, round.temp.𝜌i, round.temp.sessionId)
			if err != nil {
				errChs <- round.WrapError(errors.New("proof generation failed"))
			}
			ProofOut <- ψʺji
		}(j, Pj)

		ψDoublePrimeji := <-ProofOut
		r3msg := NewPreSignRound3Message(round.temp.sessionId, Pj, round.PartyID(), 𝛿i, Δi, ψDoublePrimeji)
		common.Logger.Debugf("party %v r3, NewPreSignRound3Message is going out to Pj %v", round.PartyID(), Pj)
		round.out <- r3msg
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	// clear unused variables
	round.temp.w = nil
	round.temp.BigWs = nil
	round.temp.Γi = nil

	round.temp.ChiShareBetas = nil
	round.temp.DeltaShareAlphas = nil
	round.temp.ChiShareAlphas = nil

	clear(round.temp.r2msgChiD)
	clear(round.temp.r2msgChiF)
	clear(round.temp.r2msgDeltaProof)
	clear(round.temp.r2msgChiProof)
	clear(round.temp.r2msgProofLogstar)
	return nil
}

func (round *presign3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r3msg𝛿j {
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

func (round *presign3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PreSignRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *presign3) NextRound() tss.Round {
	round.started = false
	return &sign4{round, false}
}
