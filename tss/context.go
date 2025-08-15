// Copyright © 2025 IO Finnet Group, Inc.
//
// This file is part of IO Finnet Group, Inc. The full IO Finnet Group, Inc. copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"context"
	"sync"
	"time"
)

// RoundContext provides a context-aware wrapper for goroutines in round implementations
// to allow for proper cancellation and cleanup
type RoundContext struct {
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
}

// NewRoundContext creates a new context for managing goroutines in TSS rounds
func NewRoundContext(timeout time.Duration) *RoundContext {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return &RoundContext{
		ctx:     ctx,
		cancel:  cancel,
		timeout: timeout,
	}
}

// Context returns the underlying context
func (rc *RoundContext) Context() context.Context {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ctx
}

// Cancel explicitly cancels the context
func (rc *RoundContext) Cancel() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.cancel != nil {
		rc.cancel()
	}
}

// Reset recreates the context with the same timeout
func (rc *RoundContext) Reset() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Cancel the existing context if it exists
	if rc.cancel != nil {
		rc.cancel()
	}

	// Create a new context
	ctx, cancel := context.WithTimeout(context.Background(), rc.timeout)
	rc.ctx = ctx
	rc.cancel = cancel
}

// WithValue returns a new context with the provided key-value pair
func (rc *RoundContext) WithValue(key, val interface{}) context.Context {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return context.WithValue(rc.ctx, key, val)
}

// Done returns the done channel from the context
func (rc *RoundContext) Done() <-chan struct{} {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ctx.Done()
}

// Err returns the context error
func (rc *RoundContext) Err() error {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ctx.Err()
}

// Deadline returns the context deadline
func (rc *RoundContext) Deadline() (time.Time, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ctx.Deadline()
}

// Value returns the value for the key from the context
func (rc *RoundContext) Value(key interface{}) interface{} {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.ctx.Value(key)
}
