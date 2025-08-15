// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/common/hash"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/vss"
	zkpprm "github.com/iofinnet/tss-lib/v3/crypto/zkp/prm"
	zkpsch "github.com/iofinnet/tss-lib/v3/crypto/zkp/sch"
	"github.com/iofinnet/tss-lib/v3/tss"
	errors2 "github.com/pkg/errors"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	𝜅 := uint(256)
	twoTo256 := new(big.Int).Lsh(big.NewInt(1), 𝜅)

	// Fig 5. Round 1. private key part
	ridi := common.GetRandomPositiveInt(twoTo256)
	ui := common.GetRandomPositiveInt(twoTo256)

	// Secret for VSS - sampled from curve order N (distinct from ui which is a public nonce)
	secretXi := common.GetRandomPositiveInt(big.Wrap(round.EC().Params().N))

	// Fig 5. Round 1. pub key part, vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), secretXi, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	xi := new(big.Int).Set(shares[i].Share)
	XiKeygen, _ := crypto.ScalarBaseMult(round.EC(), xi)
	AiKeygen, τKeygen, err := zkpsch.NewProofCommitment(XiKeygen, xi)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// Fig 6. Round 1.
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	Ni, si, ti := preParams.NTildei, preParams.H1i, preParams.H2i
	sid := hash.SHA256i(append(ids, big.Wrap(round.EC().Params().N),
		big.Wrap(round.EC().Params().P), big.Wrap(round.EC().Params().B),
		big.Wrap(round.EC().Params().Gx), big.Wrap(round.EC().Params().Gy))...)

	𝜑Nᵢ := preParams.PaillierSK.PhiN
	𝜆 := preParams.Beta
	yi := common.GetRandomPositiveInt(big.Wrap(round.EC().Params().N))
	Yi, _ := crypto.ScalarBaseMult(round.EC(), yi)

	Bᵢ, 𝜏KeyRefresh, err := zkpsch.NewProofCommitment(Yi, yi) // Bᵢ, 𝜏
	if err != nil {
		return round.WrapError(errors.New("zkpsch failed"), Pi)
	}
	xⁿᵢ := vss.CreateZeroSumRandomArray(big.Wrap(round.EC().Params().N), len(round.Parties().IDs()))
	XᵢKeyRefresh := make([]*crypto.ECPoint, len(round.Parties().IDs()))
	𝜌ᵢ := common.GetRandomPositiveInt(twoTo256)

	for j := 0; j < len(round.Parties().IDs()); j++ {
		XᵢKeyRefresh[j], _ = crypto.ScalarBaseMult(round.EC(), xⁿᵢ[j])
	}

	XiPoints, err := crypto.FlattenECPoints(XᵢKeyRefresh)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "flattening error"))
	}

	var nonce *big.Int
	ssid := hash.SHA256i([]*big.Int{sid /* round.temp.rid,*/, Ni, si, ti, round.temp.sessionId}...)
	nonce = big.NewInt(0).Add(ssid, big.NewInt(uint64(i)))
	if nonce.BitLen() < zkpprm.MinBitLen {
		nonce = new(big.Int).Lsh(nonce, uint(zkpprm.MinBitLen-nonce.BitLen()))
	}

	𝜓ᵢ, err := zkpprm.NewProofWithNonce(si, ti, Ni, 𝜑Nᵢ, 𝜆, nonce)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	/* common.Logger.Debugf("party %v r1 𝜓ᵢ proof[%v]: %v, Ni: %v, si: %v, ti: %v, nonce: %v"+
		", ssid: %v, sid: %v, sessionId: %v", round.PartyID(),
		i, zkpprm.FormatProofPrm(𝜓ᵢ), common.FormatBigInt(Ni), common.FormatBigInt(si), common.FormatBigInt(ti),
		common.FormatBigInt(nonce), common.FormatBigInt(ssid), common.FormatBigInt(sid),
		common.FormatBigInt(round.temp.sessionId),
	) */

	AᵢKeyrefresh := make([]*crypto.ECPoint, len(round.Parties().IDs()))
	𝜏js := make([]*big.Int, len(round.Parties().IDs()))
	for j := 0; j < len(round.Parties().IDs()); j++ {
		Ajᵢ, 𝜏ⱼ, err2 := zkpsch.NewProofCommitment(XᵢKeyRefresh[j], xⁿᵢ[j])
		if err2 != nil {
			return round.WrapError(errors2.Wrapf(err, "zkpsch error"))
		}
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "point addition error"))
		}
		AᵢKeyrefresh[j] = Ajᵢ
		𝜏js[j] = 𝜏ⱼ
	}
	AiPoints, err := crypto.FlattenECPoints(AᵢKeyrefresh)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "flattening error"))
	}

	keygenListToHash, errF := crypto.FlattenECPoints(vs)
	if errF != nil {
		return round.WrapError(errF, Pi)
	}
	keygenListToHash = append(keygenListToHash, []*big.Int{sid, big.NewInt(uint64(i)), ridi, XiKeygen.X(), XiKeygen.Y(), AiKeygen.X(), AiKeygen.Y(), ui}...)

	𝜓array := 𝜓ᵢ.ToIntArray()
	keyRefreshListToHash := append([]*big.Int{ssid, big.NewInt(uint64(i)), Yi.X(), Yi.Y(),
		Bᵢ.X(), Bᵢ.Y(), Ni, si, ti, 𝜌ᵢ, ui}, 𝜓array...)
	keyRefreshListToHash = append(keyRefreshListToHash, XiPoints...)
	keyRefreshListToHash = append(keyRefreshListToHash, AiPoints...)

	ViKeygen := hash.SHA256i(keygenListToHash...)
	ViKeyRefresh := hash.SHA256i(keyRefreshListToHash...)
	{
		msg := NewKGRound1Message(round.temp.sessionId, round.PartyID(), sid, ViKeygen,
			// refresh:
			ssid,
			ViKeyRefresh)
		round.out <- msg
	}

	round.temp.𝜓ᵢ = 𝜓ᵢ
	round.temp.vs = vs
	round.temp.ridi = ridi
	round.temp.sid = sid
	round.temp.ui = ui
	round.temp.Yᵢ, round.temp.yᵢ = Yi, yi
	round.temp.AiKeygen = AiKeygen
	round.temp.τKeygen = τKeygen
	round.temp.xⁿᵢ = xⁿᵢ
	round.temp.𝜏KeyRefresh = 𝜏KeyRefresh
	round.save.Ks = ids
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i
	round.save.ShareID = ids[i]
	round.temp.shares = shares
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey

	round.temp.𝜌ᵢ = 𝜌ᵢ
	round.temp.𝜏js = 𝜏js
	round.temp.ssid = ssid
	round.temp.Bᵢ = Bᵢ
	round.temp.XiRefreshList = XᵢKeyRefresh
	round.temp.AiRefreshList = AᵢKeyrefresh

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.rref1msgSsid {
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

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
