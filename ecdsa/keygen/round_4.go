// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"sync"

	big "github.com/binance-chain/tss-lib/common/int"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	//
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)

	wg := sync.WaitGroup{}
	modQ := big.ModInt(big.Wrap(round.EC().Params().N))
	sid := common.SHA512_256i(append(round.Parties().IDs().Keys(), big.Wrap(tss.EC().Params().N),
		big.Wrap(tss.EC().Params().P), big.Wrap(tss.EC().Params().B),
		big.Wrap(tss.EC().Params().Gx), big.Wrap(tss.EC().Params().Gy))...)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Keygen: Fig 5. Output 1.
		noncej := modQ.Add(modQ.Add(round.temp.rref3msgSsid[j], round.temp.𝜌), big.NewInt(uint64(j)))
		/* common.Logger.Debugf("party %v r4 j: %v, ssid[%v]: %v, 𝜌: %v, nonce[j=%v]: %v", round.PartyID(),
			j, j, common.FormatBigInt(round.temp.rref3msgSsid[j]), common.FormatBigInt(round.temp.𝜌),
			j, common.FormatBigInt(noncej),
		) */

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			if sameAj := round.temp.r2msgAKeygenj[j].Equals(round.temp.r3msgpf𝜓j[j].A); !sameAj {
				errChs <- round.WrapError(errors.New("verification of Aj failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			sidjrid := modQ.Add(modQ.Add(sid, big.NewInt(uint64(j))), round.temp.rid)
			nonceKG := modQ.Add(sidjrid, round.temp.sessionId)
			if ok := round.temp.r3msgpf𝜓j[j].VerifyWithNonce(round.temp.r2msgXKeygenj[j], nonceKG); !ok {
				/* common.Logger.Debugf("party %v r4 KG err sch 𝜓[j=%v]: %v, nonceKG: %v", round.PartyID(),
					j, zkpsch.FormatProofSch(round.temp.r3msgpf𝜓j[j]), common.FormatBigInt(nonceKG),
				) */
				errChs <- round.WrapError(errors.New("verification of 𝜓j failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			share := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     round.temp.r3msgxij[j],
			}
			if ok := share.Verify(round.EC(), round.Threshold(), round.temp.r2msgVss[j]); !ok {
				errChs <- round.WrapError(errors.New("vss verify failed"), Pj)
			}
		}(j, Pj)

		// refresh:
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			xⁱⱼ, randomnessCⁱⱼ, err := round.save.PaillierSK.DecryptAndRecoverRandomness(round.temp.rref3msgCzeroji[j])
			if err != nil {
				errChs <- round.WrapError(errors.New("error decrypting C"), Pj)
			}

			if same := round.temp.rref3msgRandomnessCzeroji[j].Cmp(randomnessCⁱⱼ) == 0; !same {
				errChs <- round.WrapError(errors.New("error decrypting C"), Pj)
			}
			Xⁱⱼ := crypto.ScalarBaseMult(round.EC(), xⁱⱼ)
			if !round.temp.rref2msgXj[j][i].Equals(Xⁱⱼ) {
				// errChs <- round.WrapError(errors.New("different X"), Pj)
				N := big.Wrap(round.EC().Params().N)
				onePlusNi := big.NewInt(0).Add(big.NewInt(1), round.save.LocalPreParams.NTildei)
				minusxⁱⱼ := big.NewInt(0).Neg(xⁱⱼ)
				a := big.NewInt(0).Exp(onePlusNi, minusxⁱⱼ, nil)
				oneOverN := big.NewInt(0).Div(big.NewInt(1), N)
				N2 := big.NewInt(0).Mul(N, N)
				𝜇 := big.NewInt(0).Exp(big.NewInt(0).Mul(round.temp.rref3msgCzeroji[j], a), oneOverN, N2)
				common.Logger.Error("g^(x^i_j) != X^i_j, equality required -- verify 𝜇.")
				common.Logger.Errorf("Reporting party:%v, culprit: %v", round.PartyID(), Pj)
				r4msg := NewKGRound4Message(round.temp.sessionId, round.PartyID(), sid, true, 𝜇, Pj.Index,
					round.temp.rref3msgCzeroji[j], xⁱⱼ)
				round.out <- r4msg
				return
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			if !round.temp.rref3msgpf𝜓j[j].VerifyWithNonce(round.temp.rref2msgNj[j], noncej) {
				/* common.Logger.Debugf("party %v r4 KR err mod 𝜓[j=%v]: %v, noncej: %v", round.PartyID(),
					j, zkpmod.FormatProofMod(round.temp.rref3msgpf𝜓j[j]), common.FormatBigInt(noncej),
				)
				*/
				errChs <- round.WrapError(errors.New("failed mod proof"), Pj)
				return
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			Nj, sj, tj := round.temp.rref2msgNj[j], round.temp.rref2msgsj[j], round.temp.rref2msgtj[j]
			if !round.temp.rref3msgpf𝜙ji[j].VerifyWithNonce(round.EC(), round.save.PaillierPKs[j],
				Nj, sj, tj, noncej) {
				/* common.Logger.Debugf("party:%v r4, Pj: %v, 𝜙_[j=%v],[i=%v]: %v, nonce[%v]: %v, ssid: %v, 𝜌: %v",
				round.PartyID(), Pj,
				j, i, zkpfac.FormatProofFac(round.temp.rref3msgpf𝜙ji[j]),
				j, common.FormatBigInt(noncej),
				common.FormatBigInt(round.temp.ssid), common.FormatBigInt(round.temp.𝜌))

				*/
				errChs <- round.WrapError(errors.New("failed mod proof"), Pj)
				return
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			BCapj := round.temp.rref3msgpfᴨᵢ[j].A
			if !BCapj.Equals(round.temp.rref2msgBj[j]) {
				errChs <- round.WrapError(errors.New("different B"), Pj)
				return
			}

			if ok := round.temp.rref3msgpfᴨᵢ[j].VerifyWithNonce(round.temp.rref2msgYj[j], noncej); !ok {
				/* common.Logger.Debugf("party %v r4 err, Pj: %v, ᴨ[j=%v]: %v, nonce: %v", round.PartyID(),
					Pj, j, zkpsch.FormatProofSch(round.temp.rref3msgpfᴨᵢ[j]), common.FormatBigInt(noncej),
				) */
				errChs <- round.WrapError(errors.New("failed sch proof"), Pj)
				return
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			𝜓ⁱⱼ := round.temp.rref3msgpf𝜓ⁱⱼ[j]
			if !𝜓ⁱⱼ.A.Equals(round.temp.rref2msgAj[j][i]) {
				errChs <- round.WrapError(errors.New("different A"), Pj)
				return
			}

			if ok := 𝜓ⁱⱼ.VerifyWithNonce(round.temp.rref2msgXj[j][i], noncej); !ok {
				/* common.Logger.Debugf("party:%v r4, Pj: %v, 𝜓^[i=%v]_[j=%v]: %v, X^[i=%v]_[j=%v]: %v, nonce[%v]: %v"+
				", ssid: %v, 𝜌: %v",
				round.PartyID(), Pj,
				i, j, zkpsch.FormatProofSch(𝜓ⁱⱼ),
				i, j, crypto.FormatECPoint(round.temp.rref2msgXj[j][i]),
				j, common.FormatBigInt(noncej),
				common.FormatBigInt(round.temp.rref3msgSsid[j]), common.FormatBigInt(round.temp.𝜌))
				*/
				errChs <- round.WrapError(errors.New("failed sch proof"), Pj)
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
		return round.WrapError(errors.New("round4: failed to verify proofs"), culprits...)
	}

	xi := new(big.Int).Set(round.temp.shares[i].Share)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		xi = new(big.Int).Add(xi, round.temp.r3msgxij[j])
	}
	round.save.Xi = new(big.Int).Mod(xi, big.Wrap(round.EC().Params().N))

	Vc := make([]*crypto.ECPoint, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c]
	}

	{
		var err error
		culpritsV := make([]*tss.PartyID, 0)
		for j, Pj := range round.Parties().IDs() {
			if j == i {
				continue
			}
			PjVs := round.temp.r2msgVss[j]
			for c := 0; c <= round.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					culpritsV = append(culpritsV, Pj)
				}
			}
		}
		if len(culpritsV) > 0 {
			return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), culpritsV...)
		}
	}

	{
		var err error
		culpritsB := make([]*tss.PartyID, 0)
		for j, Pj := range round.Parties().IDs() {
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := big.NewInt(1)
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					culpritsB = append(culpritsB, Pj)
				}
			}
			round.save.BigXj[j] = BigXj
		}
		if len(culpritsB) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culpritsB...)
		}
	}

	// Compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(err)
	}

	if round.temp.sessionId == nil {
		return round.WrapError(errors.New("sessionId not set"))
	}
	round.temp.ecdsaPubKey = ecdsaPubKey
	r4msg := NewKGRound4Message(round.temp.sessionId, round.PartyID(), sid, false, big.NewInt(1),
		-1, big.NewInt(1), big.NewInt(1))
	round.out <- r4msg

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r4msg𝜇j {
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

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &roundout{round}
}
