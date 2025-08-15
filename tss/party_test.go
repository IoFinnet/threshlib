// Copyright © 2025 IO Finnet Group, Inc.
//
// This file is part of IO Finnet Group, Inc. The full IO Finnet Group, Inc. copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	big "github.com/iofinnet/tss-lib/v3/common/int"
)

// mockParty is a minimal implementation of Party for testing
type mockParty struct {
	BaseParty
	params  *Parameters
	partyID *PartyID
}

func (p *mockParty) Start() *Error {
	return nil
}

func (p *mockParty) UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool, sessionId *big.Int) (bool, *Error) {
	return true, nil
}

func (p *mockParty) Update(msg ParsedMessage) (bool, *Error) {
	return true, nil
}

func (p *mockParty) StoreMessage(msg ParsedMessage) (bool, *Error) {
	return true, nil
}

func (p *mockParty) PartyID() *PartyID {
	return p.partyID
}

func (p *mockParty) Params() *Parameters {
	return p.params
}

func (p *mockParty) FirstRound() Round {
	return p.BaseParty.FirstRound
}

func (p *mockParty) Terminate() *Error {
	return BaseTerminate(p)
}

// Mock round implementation for testing
type mockRound struct {
	params *Parameters
}

func (r *mockRound) Start() *Error {
	return nil
}

func (r *mockRound) Update() (bool, *Error) {
	return true, nil
}

func (r *mockRound) CanAccept(msg ParsedMessage) bool {
	return true
}

func (r *mockRound) RoundNumber() int {
	return 1
}

func (r *mockRound) CanProceed() bool {
	return false
}

func (r *mockRound) NextRound() Round {
	return nil
}

func (r *mockRound) WaitingFor() []*PartyID {
	return []*PartyID{}
}

func (r *mockRound) WrapError(err error, culprits ...*PartyID) *Error {
	return NewError(err, "mock", 1, nil, culprits...)
}

func (r *mockRound) Params() *Parameters {
	return r.params
}

// TestPartyTermination tests the Terminate functionality
func TestPartyTermination(t *testing.T) {
	// Setup
	key := big.NewInt(123456789)
	pid := NewPartyID("test", "test", key)
	params, _ := NewParameters(S256(), NewPeerContext([]*PartyID{pid}), pid, 1, 1)

	// Create mock party
	party := &mockParty{
		params:  params,
		partyID: pid,
	}

	// Create mock round with context
	round := &mockRound{
		params: params,
	}

	// Set the round in the party
	err := party.setRound(round)
	assert.Nil(t, err, "setRound should not return an error")

	// Test initial state
	assert.True(t, party.Running(), "Party should be running")
	assert.False(t, party.terminated, "Party should not be terminated")

	// Test termination
	err = party.Terminate()
	assert.Nil(t, err, "Terminate should not return an error")
	assert.True(t, party.terminated, "Party should be marked as terminated")
	assert.False(t, party.Running(), "Party should not be running after termination")

	// Test that WaitingFor returns empty after termination
	waitingFor := party.WaitingFor()
	assert.Empty(t, waitingFor, "WaitingFor should return empty array after termination")

	// Test terminating an already terminated party
	err = party.Terminate()
	assert.NotNil(t, err, "Terminating an already terminated party should return an error")
	assert.Contains(t, err.Error(), "already terminated", "Error should mention party is already terminated")
}

// TestPartySetRoundAfterTermination tests that a terminated party cannot set a new round
func TestPartySetRoundAfterTermination(t *testing.T) {
	// Setup
	key := big.NewInt(123456789)
	pid := NewPartyID("test", "test", key)
	params, _ := NewParameters(S256(), NewPeerContext([]*PartyID{pid}), pid, 1, 1)

	// Create mock party
	party := &mockParty{
		params:  params,
		partyID: pid,
	}

	// Create mock round with context
	round := &mockRound{
		params: params,
	}

	// Set the round in the party
	err := party.setRound(round)
	assert.Nil(t, err, "setRound should not return an error")

	// Terminate the party
	err = party.Terminate()
	assert.Nil(t, err, "Terminate should not return an error")

	// Clear the round to allow setting a new one
	party.rndMtx.Lock()
	party.rnd = nil
	party.rndMtx.Unlock()

	// Attempt to run BaseStart on a terminated party (this would normally be called by implementations)
	err = BaseStart(party, "test")
	assert.NotNil(t, err, "BaseStart should fail on terminated party")
	assert.Contains(t, err.Error(), "terminated", "Error should mention party is terminated")
}

// TestContextCancellation tests that context cancellation works
func TestContextCancellation(t *testing.T) {
	// Create a RoundContext with a short timeout
	ctx := NewRoundContext(10 * time.Millisecond)

	// Test that context is valid initially
	select {
	case <-ctx.Done():
		t.Fatal("Context should not be done initially")
	default:
		// Expected
	}

	// Test explicit cancellation
	ctx.Cancel()

	// Context should be done
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Fatal("Context should be done after cancellation")
	}

	// Test reset
	ctx.Reset()

	// Context should be valid again
	select {
	case <-ctx.Done():
		t.Fatal("Context should not be done after reset")
	default:
		// Expected
	}
}
