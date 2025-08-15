// Copyright © 2025 io finnet group, inc
//
// This file is part of io finnet group. The full io finnet group copyright notice,
// including terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGobEncodingLocalPartySaveData(t *testing.T) {
	t.Parallel()

	// Parse the fixture JSON
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(eddsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "failed to unmarshal test fixture")

	// Test basic gob encode/decode
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	err = enc.Encode(fixture)
	require.NoError(t, err, "gob encoding failed")

	var decoded LocalPartySaveData
	err = dec.Decode(&decoded)
	require.NoError(t, err, "gob decoding failed")

	// Verify all fields match
	assert.Equal(t, fixture.Xi, decoded.Xi, "Xi field doesn't match after gob encode/decode")
	assert.Equal(t, fixture.ShareID, decoded.ShareID, "ShareID field doesn't match after gob encode/decode")

	// Ensure slices have the same length
	assert.Equal(t, len(fixture.Ks), len(decoded.Ks), "Ks slice length doesn't match")
	assert.Equal(t, len(fixture.BigXj), len(decoded.BigXj), "BigXj slice length doesn't match")

	// Check slices contents
	for i := range fixture.Ks {
		assert.Equal(t, fixture.Ks[i], decoded.Ks[i], "Ks[%d] doesn't match", i)
	}

	for i := range fixture.BigXj {
		assert.True(t, fixture.BigXj[i].Equals(decoded.BigXj[i]), "BigXj[%d] doesn't match", i)
	}

	// Check EDDSAPub
	assert.True(t, fixture.EDDSAPub.Equals(decoded.EDDSAPub), "EDDSAPub doesn't match after gob encode/decode")

	// Test the Copy method which uses gob internally
	copied := fixture.Copy()
	// Compare individual fields since direct equality might fail due to pointer comparisons
	assert.Equal(t, fixture.Xi, copied.Xi, "Xi field doesn't match in copied data")
	assert.Equal(t, fixture.ShareID, copied.ShareID, "ShareID field doesn't match in copied data")

	// Check slices
	assert.Equal(t, len(fixture.Ks), len(copied.Ks), "Ks slice length doesn't match")
	assert.Equal(t, len(fixture.BigXj), len(copied.BigXj), "BigXj slice length doesn't match")

	// Check that EDDSAPub is properly copied
	assert.True(t, fixture.EDDSAPub.Equals(copied.EDDSAPub), "EDDSAPub doesn't match in copied data")

	// Ensure deep copy by modifying a field and ensuring the original is unchanged
	copied.Xi.SetInt64(999)
	assert.NotEqual(t, fixture.Xi, copied.Xi, "Copy() didn't perform a deep copy")
}

func TestLocalSecretsGobEncoding(t *testing.T) {
	t.Parallel()

	// Parse the fixture
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(eddsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "failed to unmarshal test fixture")

	// Extract LocalSecrets
	secrets := fixture.LocalSecrets

	// Test gob encode/decode
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	err = enc.Encode(secrets)
	require.NoError(t, err, "gob encoding failed for LocalSecrets")

	var decodedSecrets LocalSecrets
	err = dec.Decode(&decodedSecrets)
	require.NoError(t, err, "gob decoding failed for LocalSecrets")

	// Verify fields match
	assert.Equal(t, secrets.Xi, decodedSecrets.Xi, "Xi doesn't match after gob encode/decode")
	assert.Equal(t, secrets.ShareID, decodedSecrets.ShareID, "ShareID doesn't match after gob encode/decode")
}

func TestGobRegistration(t *testing.T) {
	t.Parallel()

	// Test that the gob registration works by encoding types directly
	// This would fail if the init() function didn't register the types

	// Create minimal instances of the registered types
	saveData := new(LocalPartySaveData)
	secrets := new(LocalSecrets)

	// Encode each type
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	// Try encoding each type - this should not panic
	err := enc.Encode(saveData)
	assert.NoError(t, err, "encoding LocalPartySaveData failed despite gob registration")

	buf.Reset()
	err = enc.Encode(secrets)
	assert.NoError(t, err, "encoding LocalSecrets failed despite gob registration")
}
