package signing

import (
	ed "crypto/ed25519"
	"encoding/hex"
	"sync/atomic"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	"github.com/iofinnet/tss-lib/v3/test"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
	"github.com/stretchr/testify/assert"
)

const (
	testSetIdS256BIP340 = "S256"
	testSetIdEdwards    = "Edwards"
)

var (
	// The test message is zero-prefixed because it matters to keep preceding zero-bytes for a message, but not for a hash.
	// See: https://github.com/bnb-chain/tss-lib/pull/284
	testMsg, _ = hex.DecodeString("00225472616e73616374696f6e54797065223a225061796d656e74222c224163636f756e74223a22724e325578357838514a37533741696d6d7874654b4b6b703545546173624e526178222c2244657374696e6174696f6e223a22724b3476626f583256593461335a70686d32347845456647396a655958716f366e4b222c22416d6f756e74223a2231303030303030222c22466c616773223a302c2253657175656e6365223a323137393537372c22466565223a223132222c224c6173744c656467657253657175656e6365223a3232343038350000")
)

func TestE2EConcurrentEdwards_OneRoundSign(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdEdwards)
	assert.NoError(t, err, "should load edwards keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: pre-signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	preSignParties := make([]*LocalParty, 0, len(signPIDs))
	preSignData := make([]*common.EndData_PreSignatureDataEdDSA, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))
	q := big.Wrap(edwards.Edwards().N)
	sessionId := common.MustGetRandomInt(q.BitLen() - 1)
	updater := test.SharedPartyUpdaterAsync

	// init the preSignParties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(edwards.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		// a nil msg runs the party in ORS mode
		tmp, _ := NewLocalParty(nil, params, keys[i], nil, outCh, endCh, sessionId)
		P := tmp.(*LocalParty)
		preSignParties = append(preSignParties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var endedPreSign int32
presigning:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presigning

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range preSignParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(preSignParties[dest[0].Index], msg, errCh)
			}

		case preSignEnd := <-endCh:
			d := preSignEnd.GetPreSignDataEddsa()
			preSignData = append(preSignData, d)
			atomic.AddInt32(&endedPreSign, 1)
			if atomic.LoadInt32(&endedPreSign) == int32(len(signPIDs)) {
				t.Logf("Done pre-signing. Received pre-sign data from %d participants", endedPreSign)
				break presigning
			}
		}
	}

	// Collect up ORS shares and finalize
	t.Logf("Collecting ORS shares and finalizing the signature...")
	sjs := make([]*big.Int, len(preSignParties))

	// Use the real message for the finalization
	for _, party := range signPIDs {
		psd := preSignData[party.Index]
		sj, err2 := FinalizeSigShare(
			tss.Edwards(),
			keys[0].EDDSAPub,
			psd.GetEncodedR(),
			psd.GetRI(),
			psd.GetWI(),
			testMsg)
		if !assert.NoError(t, err2, "FinalizeSigShare must not error") {
			return
		}
		sjs[party.Index] = sj
	}

	end, err := FinalizeOneRoundSignAndVerify(
		tss.Edwards(), keys[0].EDDSAPub, sjs, new(big.Int).SetBytes(preSignData[0].GetR()), preSignData[0].A, testMsg)

	// BEGIN EdDSA edwards verify
	pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()

	pkPt, err := ed25519.FromXYToEd25519Point(pkX, pkY)
	if err != nil {
		t.Errorf("edwards pubkey error %v", err.Error())
		t.FailNow()
	}

	if ok := ed.Verify(pkPt.Bytes(), testMsg, end.Signature); !assert.True(t, ok, "eddsa verify must pass") {
		t.Error("eddsa verify must pass")
		t.FailNow()
	}
	t.Log("EdDSA Edwards ORS test done.")
	// END EDDSA verify
}

func TestE2EConcurrentBIP340S256_OneRoundSign(t *testing.T) {
	t.Parallel()
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdS256BIP340)
	assert.NoError(t, err, "should load BIP-340 keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: pre-signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	preSignParties := make([]*LocalParty, 0, len(signPIDs))
	preSignData := make([]*common.EndData_PreSignatureDataEdDSA, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.EndData, len(signPIDs))
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	sessionId := common.MustGetRandomInt(q.BitLen() - 1)
	updater := test.SharedPartyUpdaterAsync

	// init the preSignParties
	for i := 0; i < len(signPIDs); i++ {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		// a nil msg runs the party in ORS mode
		tmp, _ := NewLocalParty(nil, params, keys[i], nil, outCh, endCh, sessionId)
		P := tmp.(*LocalParty)
		preSignParties = append(preSignParties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var endedPreSign int32
presigning:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break presigning

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range preSignParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(preSignParties[dest[0].Index], msg, errCh)
			}

		case preSignEnd := <-endCh:
			d := preSignEnd.GetPreSignDataEddsa()
			preSignData = append(preSignData, d)
			atomic.AddInt32(&endedPreSign, 1)
			if atomic.LoadInt32(&endedPreSign) == int32(len(signPIDs)) {
				t.Logf("Done pre-signing. Received pre-sign data from %d participants", endedPreSign)
				break presigning
			}
		}
	}

	// Collect up ORS shares and finalize
	t.Logf("Collecting ORS shares and finalizing the signature...")
	sjs := make([]*big.Int, len(preSignParties))

	// Use the real message for the finalization
	msg, _ := hex.DecodeString("304502210088BE0644191B935DB1CD786B43FF27798006578D8C908906B49E89")
	for _, party := range signPIDs {
		psd := preSignData[party.Index]
		sj, err2 := FinalizeSigShare(
			tss.S256(),
			keys[0].EDDSAPub,
			psd.GetEncodedR(),
			psd.GetRI(),
			psd.GetWI(),
			msg)
		if !assert.NoError(t, err2, "FinalizeSigShare must not error") {
			return
		}
		sjs[party.Index] = sj
	}

	end, err := FinalizeOneRoundSignAndVerify(
		tss.S256(), keys[0].EDDSAPub, sjs, new(big.Int).SetBytes(preSignData[0].GetR()), preSignData[0].A, msg)

	// BEGIN EdDSA verify
	r := new(big.Int).SetBytes(end.GetR())
	s := new(big.Int).SetBytes(end.GetS())

	errV := BIP340Verify(keys[0].EDDSAPub.ToBtcecPubKey(), msg, r, s)
	if !assert.NoError(t, errV, "EdDSA sig must verify") {
		return
	}
	t.Log("EdDSA BIP-340 ORS test done.")
	// END EdDSA verify
}
