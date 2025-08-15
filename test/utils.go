// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package test

import (
	"time"

	"github.com/iofinnet/tss-lib/v3/common"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// SharedPartyUpdaterAsync is a helper function for updating a party with a message.
// It optionally simulates network delay for all parties except the first one and removes 50ms of delay per round.
func SharedPartyUpdaterAsync(party tss.Party, msg tss.Message, errCh chan<- *tss.Error, optSimNetDelayRangeMS ...int) {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}
	go func() {
		bz, _, err := msg.WireBytes()
		if err != nil {
			errCh <- party.WrapError(err)
			return
		}
		pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast(), msg.GetSessionId())
		if err != nil {
			errCh <- party.WrapError(err)
			return
		}
		// we simulate network delay for parties with index > 0 and remove 50ms per round
		if 0 < len(optSimNetDelayRangeMS) {
			party.Lock()
			partyIdx := party.PartyID().Index
			if party.Round() != nil {
				roundNum := party.Round().RoundNumber()
				party.Unlock()
				if partyIdx > 0 {
					simNetDelayRangeMS := max(0, optSimNetDelayRangeMS[0]-(roundNum*50))
					common.Logger.Debugf("party %v simulating network delay of %vms", partyIdx, simNetDelayRangeMS)
					// Sleep a random time between 0-Nms
					time.Sleep(time.Duration(simNetDelayRangeMS) * time.Millisecond)
				}
			}
		}
		if _, err := party.Update(pMsg); err != nil {
			errCh <- err
		}
	}()
}
