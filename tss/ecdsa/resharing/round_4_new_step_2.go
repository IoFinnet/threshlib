// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"sync"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	int2 "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/commitments"
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	"github.com/iofinnet/tss-lib/v3/crypto/vss"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	errors2 "github.com/pkg/errors"
)

var (
	one = big.NewInt(1)
)

func newRound4(params *tss.ReSharingParameters, input, save *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- keygen.LocalPartySaveData) tss.Round {
	return &round4{&round3{&round2{&round1{
		&base{params, temp, input, save, out, end, make([]bool, len(params.OldParties().IDs())), make([]bool, len(params.NewParties().IDs())), false, 4}}}}}
}

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK

	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		// both committees proceed to round 5 after receiving "ACK" messages from the new committee
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	// 1-3. verify paillier key proofs
	culprits := make([]*tss.PartyID, 0, len(round.NewParties().IDs())) // who caused the error(s)
	for _, msg := range round.temp.dgRound2Message1s {
		if Pi.Index == msg.GetFrom().Index { // skipping myself
			continue
		}
		r2msg1 := msg.Content().(*DGRound2Message1)

		// [TOB-BIN-8] mitigation
		paiPK, proof := r2msg1.UnmarshalPaillierPK(), r2msg1.UnmarshalPaillierProof()
		H1j := new(big.Int).SetBytes(r2msg1.H1)
		H2j := new(big.Int).SetBytes(r2msg1.H2)
		if err := checkTobBin8(paiPK.N, H1j, H2j, proof); err != nil {
			culprits = append(culprits, msg.GetFrom())
			continue
		}

		// verify standard proof
		if ok, err := proof.Verify(paiPK.N, msg.GetFrom().KeyInt(), round.save.ECDSAPub); !ok || err != nil {
			culprits = append(culprits, msg.GetFrom())
			continue
		}
		common.Logger.Debugf("paillier verify passed for party %s", msg.GetFrom())
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}

	// save NTilde_j, h1_j, h2_j received in NewCommitteeStep1 here
	for j, msg := range round.temp.dgRound2Message1s {
		if j == i {
			continue
		}
		r2msg1 := msg.Content().(*DGRound2Message1)
		round.save.NTildej[j] = new(big.Int).SetBytes(r2msg1.NTilde)
		round.save.H1j[j] = new(big.Int).SetBytes(r2msg1.H1)
		round.save.H2j[j] = new(big.Int).SetBytes(r2msg1.H2)
	}

	// 4.
	newXi := big.NewInt(0)
	newXiMtx := sync.Mutex{}

	// 5-9.
	wg := sync.WaitGroup{}
	modQ := int2.ModInt(big.Wrap(round.Params().EC().Params().N))
	vjc := make([][]*crypto.ECPoint, len(round.OldParties().IDs()))
	culprits = make([]*tss.PartyID, 0, 1) // who caused the error(s)
	wg.Add(len(vjc))
	for j := 0; j <= len(vjc)-1; j++ { // P1..P_t+1. Ps are indexed from 0 here
		go func(j int) {
			defer wg.Done()
			Pj := round.Parties().IDs()[j]

			// 6-7.
			r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
			r3msg2 := round.temp.dgRound3Message2s[j].Content().(*DGRound3Message2)

			vCj, vDj := r1msg.UnmarshalVCommitment(), r3msg2.UnmarshalVDeCommitment()

			if len(vDj) == 0 {
				culprits = append(culprits, Pj)
				return
			}
			// 6. unpack flat "v" commitment content
			vCmtDeCmt := commitments.HashCommitDecommit{C: vCj, D: vDj}
			ok, flatVs := vCmtDeCmt.DeCommit()
			if !ok || len(flatVs) != (round.NewThreshold()+1)*2 { // they're points so * 2
				culprits = append(culprits, Pj)
				return
			}
			vj, err := crypto.UnFlattenECPoints(round.Params().EC(), flatVs)
			if err != nil {
				culprits = append(culprits, Pj)
				return
			}
			vjc[j] = vj

			// 8.
			r3msg1 := round.temp.dgRound3Message1s[j].Content().(*DGRound3Message1)
			sharej := &vss.Share{
				Threshold: round.NewThreshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     new(big.Int).SetBytes(r3msg1.Share),
			}
			if verified := sharej.Verify(round.Params().EC(), round.NewThreshold(), vj); !verified {
				culprits = append(culprits, Pj)
				return
			}

			// 9.
			newXiMtx.Lock()
			newXi.Add(newXi, sharej.Share)
			newXiMtx.Unlock()
		}(j)
	}
	wg.Wait()
	if len(culprits) > 0 {
		return round.WrapError(errors.New("ECDSA VSS verification failed"), culprits...)
	}

	// 10-13.
	var err error
	Vc := make([]*crypto.ECPoint, round.NewThreshold()+1)
	for c := 0; c <= round.NewThreshold(); c++ {
		Vc[c] = vjc[0][c]
		for j := 1; j <= len(vjc)-1; j++ {
			Vc[c], err = Vc[c].Add(vjc[j][c])
			if err != nil {
				return round.WrapError(errors2.Wrapf(err, "Vc[c].Add(vjc[j][c])"))
			}
		}
	}

	// 14.
	if !Vc[0].Equals(round.save.ECDSAPub) {
		return round.WrapError(errors.New("assertion failed: V_0 != y"), round.PartyID())
	}

	// 15-19.
	newKs := make([]*big.Int, 0, round.NewPartyCount())
	newBigXjs := make([]*crypto.ECPoint, round.NewPartyCount())
	culprits = make([]*tss.PartyID, 0, round.NewPartyCount()) // who caused the error(s)
	wg = sync.WaitGroup{}
	wg.Add(round.NewPartyCount())
	for j := 0; j < round.NewPartyCount(); j++ {
		Pj := round.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newKs = append(newKs, kj)
		go func(j int, Pj *tss.PartyID, kj *big.Int) {
			defer wg.Done()
			var errA error
			newBigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.NewThreshold(); c++ {
				z = modQ.Mul(z, kj)
				VccG, errB := Vc[c].ScalarMult(z)
				if errB != nil {
					culprits = append(culprits, Pj)
					return
				}
				if newBigXj, errA = newBigXj.Add(VccG); errA != nil {
					culprits = append(culprits, Pj)
					return
				}
			}
			newBigXjs[j] = newBigXj
		}(j, Pj, kj)
	}
	wg.Wait()
	if len(culprits) > 0 {
		return round.WrapError(errors2.Wrapf(err, "newBigXj.Add(Vc[c].ScalarMult(z))"), culprits...)
	}

	round.temp.newXi = newXi
	round.temp.newKs = newKs
	round.temp.newBigXjs = newBigXjs

	// Send an "ACK" message to both committees to signal that we're ready to save our data
	r4msg := NewDGRound4Message(round.temp.sessionId, round.OldAndNewParties(), Pi)
	round.temp.dgRound4Messages[i] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// accept messages from new -> old&new committees
	for j, msg := range round.temp.dgRound4Messages {
		if round.newOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.newOK[j] = true
	}
	return true, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}

// [TOB-BIN-8] mitigation
func checkTobBin8(N, h1, h2 *big.Int, T *paillier.Proof) error {
	if N.Sign() != 1 {
		return errors.New("failed BIN8 check")
	}
	h1_ := new(big.Int).Mod(h1, N)
	if h1_.Cmp(one) != 1 || h1_.Cmp(N) != -1 {
		return errors.New("failed BIN8 check")
	}
	h2_ := new(big.Int).Mod(h2, N)
	if h2_.Cmp(one) != 1 || h2_.Cmp(N) != -1 {
		return errors.New("failed BIN8 check")
	}
	if h1_.Cmp(h2_) == 0 {
		return errors.New("failed BIN8 check")
	}
	for i := range T {
		a := new(big.Int).Mod(T[i], N)
		if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
			return errors.New("failed BIN8 check")
		}
	}
	return nil
}
