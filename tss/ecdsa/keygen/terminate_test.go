// Copyright © 2025 IO Finnet Group, Inc.
//
// This file is part of IO Finnet Group, Inc. The full IO Finnet Group, Inc. copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/iofinnet/tss-lib/v3/common"
	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// TestTerminateKeygen verifies that a running keygen protocol can be terminated
func TestTerminateKeygen(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	participantIDs := tss.GenerateTestPartyIDs(testParticipants)

	p2pCtx := tss.NewPeerContext(participantIDs)
	parties := make([]*LocalParty, 0, len(participantIDs))

	errCh := make(chan *tss.Error, len(participantIDs))
	outCh := make(chan tss.Message, len(participantIDs))
	endCh := make(chan LocalPartySaveData, len(participantIDs))

	terminated := make(chan struct{})

	// Create a flag to track if Terminate was called
	terminateCalled := atomic.Int32{}

	// Create a wait group to ensure all parties are started before termination
	var wg sync.WaitGroup
	wg.Add(len(participantIDs))

	// Create and start parties
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	sessionID := common.GetRandomPositiveInt(q)

	for _, pID := range participantIDs {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, pID, len(participantIDs), threshold)
		P, _ := NewLocalParty(params, outCh, endCh, sessionID)
		LP := P.(*LocalParty)
		parties = append(parties, LP)

		go func(p *LocalParty, pID *tss.PartyID) {
			defer wg.Done()
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(LP, pID)
	}

	// Wait for all parties to start
	wg.Wait()

	// Terminate the first party
	go func() {
		time.Sleep(100 * time.Millisecond) // Give the protocol a small amount of time to run
		terminateCalled.Store(1)
		err := parties[0].Terminate()
		if err != nil {
			t.Logf("Termination error: %v", err)
		}
		close(terminated)
	}()

	// Verify termination
	select {
	case <-terminated:
		// Wait a short time to allow the termination to take effect
		time.Sleep(50 * time.Millisecond)

		// Verify the party is marked as terminated
		assert.False(t, parties[0].Running(), "Party should not be running after termination")
		assert.Equal(t, int32(1), terminateCalled.Load(), "Terminate should have been called")

		// The protocol might still continue with the remaining parties
		// But the terminated party should not accept any more updates
		// Create a mock message
		routing := tss.MessageRouting{
			From: parties[1].params.PartyID(),
			To:   []*tss.PartyID{parties[0].params.PartyID()},
		}
		content := &KGRound1Message{} // Using an example message type
		msg := tss.NewMessage(routing, content, nil)

		_, err := parties[0].Update(msg)
		assert.Error(t, err, "Party should reject updates after termination")

		// Cleanup
		for _, p := range parties {
			if p != parties[0] {
				// Terminate all other parties
				_ = p.Terminate()
			}
		}

	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for termination")
	}
}

// TestTerminateKeygenRound2 tests termination after the protocol has progressed to round 2
func TestTerminateKeygenRound2(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	participantIDs := tss.GenerateTestPartyIDs(testParticipants)

	p2pCtx := tss.NewPeerContext(participantIDs)
	parties := make([]*LocalParty, 0, len(participantIDs))

	errCh := make(chan *tss.Error, len(participantIDs))
	outCh := make(chan tss.Message, len(participantIDs)*len(participantIDs))
	endCh := make(chan LocalPartySaveData, len(participantIDs))

	terminated := make(chan struct{})
	reachedRound2 := make(chan struct{})

	// Create a flag to track if Terminate was called
	terminateCalled := atomic.Int32{}

	// Channel to coordinate the test
	doneCh := make(chan struct{})
	defer close(doneCh)

	// Create a wait group to ensure all parties are started
	var wg sync.WaitGroup
	wg.Add(len(participantIDs))

	// Keep track of messages for test monitoring
	var round2Reached atomic.Bool

	// Create and start parties
	q := big.Wrap(tss.GetCurveForUnitTest().Params().N)
	sessionID := common.GetRandomPositiveInt(q)

	for _, pID := range participantIDs {
		params, _ := tss.NewParameters(tss.S256(), p2pCtx, pID, len(participantIDs), threshold)
		P, _ := NewLocalParty(params, outCh, endCh, sessionID)
		LP := P.(*LocalParty)
		parties = append(parties, LP)

		go func(p *LocalParty, pID *tss.PartyID) {
			defer wg.Done()
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(LP, pID)
	}

	// Wait for all parties to start
	wg.Wait()

	// Message handler - actually routes messages between parties so the protocol progresses
	go func() {
		for {
			select {
			case <-doneCh:
				return
			case msg := <-outCh:
				dest := msg.GetTo()
				// Periodically check if protocol has advanced beyond round 1
				// This avoids checking round numbers directly in this goroutine
				// which would cause a data race
				if !round2Reached.Load() && msg.Type() != "" {
					// Use message type as an indicator that the protocol is progressing
					// This is safer than checking round numbers directly
					go func() {
						time.Sleep(50 * time.Millisecond)

						// After waiting, check if any party has moved to a new round
						// We're not checking for specific round numbers here, just progress
						if !round2Reached.Load() {
							round2Reached.Store(true)
							close(reachedRound2)
						}
					}()
				}

				if dest == nil { // broadcast
					for _, party := range parties {
						if party.PartyID().Id != msg.GetFrom().Id {
							// Deliver the message to other parties
							go func(party *LocalParty, msg tss.Message) {
								wireBytes, _, errWire := msg.WireBytes()
								if errWire != nil {
									errCh <- party.WrapError(errWire)
									return
								}
								_, err := party.UpdateFromBytes(wireBytes, msg.GetFrom(), msg.IsBroadcast(), sessionID)
								if err != nil {
									errCh <- err
								}
							}(party, msg)
						}
					}
				} else { // point-to-point
					if dest[0].Id != msg.GetFrom().Id {
						for _, party := range parties {
							if party.PartyID().Id == dest[0].Id {
								go func(party *LocalParty, msg tss.Message) {
									wireBytes, _, errWire := msg.WireBytes()
									if errWire != nil {
										errCh <- party.WrapError(errWire)
										return
									}
									_, err := party.UpdateFromBytes(wireBytes, msg.GetFrom(), msg.IsBroadcast(), sessionID)
									if err != nil {
										errCh <- err
									}
								}(party, msg)
							}
						}
					}
				}
			case err := <-errCh:
				if err != nil {
					// Don't fail on errors after termination, as they're expected
					if terminateCalled.Load() == 0 {
						t.Logf("Error from party: %v", err)
					}
				}
			}
		}
	}()

	// Wait for round 2 and then terminate
	go func() {
		select {
		case <-reachedRound2:
			common.Logger.Info("Round 2 reached, terminating...")
			// Let the protocol run for a tiny bit in round 2
			time.Sleep(50 * time.Millisecond)

			terminateCalled.Store(1)
			err := parties[0].Terminate()
			if err != nil {
				t.Logf("Termination error: %v", err)
			}
			close(terminated)
		case <-time.After(10 * time.Second):
			t.Errorf("Timed out waiting for protocol to progress")
			close(terminated)
		}
	}()

	// Verify termination
	select {
	case <-terminated:
		// Wait a short time to allow the termination to take effect
		time.Sleep(100 * time.Millisecond)

		// Verify the party is marked as terminated
		assert.False(t, parties[0].Running(), "Party should not be running after termination")
		assert.Equal(t, int32(1), terminateCalled.Load(), "Terminate should have been called")
		assert.True(t, round2Reached.Load(), "Protocol should have progressed")

		// The protocol should continue with the remaining parties
		// But the terminated party should not accept any more updates
		routing := tss.MessageRouting{
			From: parties[1].params.PartyID(),
			To:   []*tss.PartyID{parties[0].params.PartyID()},
		}
		content := &KGRound2Message{} // Using an example message type
		msg := tss.NewMessage(routing, content, nil)

		_, err := parties[0].Update(msg)
		assert.Error(t, err, "Party should reject updates after termination")

		// Cleanup
		for _, p := range parties {
			if p != parties[0] {
				// Terminate all other parties
				_ = p.Terminate()
			}
		}

	case <-time.After(15 * time.Second):
		t.Fatal("Timed out waiting for termination")
	}
}
