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
	err := json.Unmarshal([]byte(ecdsaSaveFixtureJSON), fixture)
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
	assert.Equal(t, fixture.PaillierSK.LambdaN, decoded.PaillierSK.LambdaN, "PaillierSK.LambdaN doesn't match after gob encode/decode")
	assert.Equal(t, fixture.PaillierSK.PublicKey.N, decoded.PaillierSK.PublicKey.N, "PaillierSK.PublicKey.N doesn't match after gob encode/decode")
	assert.Equal(t, fixture.NTildei, decoded.NTildei, "NTildei field doesn't match after gob encode/decode")
	assert.Equal(t, fixture.H1i, decoded.H1i, "H1i field doesn't match after gob encode/decode")
	assert.Equal(t, fixture.H2i, decoded.H2i, "H2i field doesn't match after gob encode/decode")

	// Ensure slices have the same length
	assert.Equal(t, len(fixture.Ks), len(decoded.Ks), "Ks slice length doesn't match")
	assert.Equal(t, len(fixture.NTildej), len(decoded.NTildej), "NTildej slice length doesn't match")
	assert.Equal(t, len(fixture.H1j), len(decoded.H1j), "H1j slice length doesn't match")
	assert.Equal(t, len(fixture.H2j), len(decoded.H2j), "H2j slice length doesn't match")
	assert.Equal(t, len(fixture.BigXj), len(decoded.BigXj), "BigXj slice length doesn't match")
	assert.Equal(t, len(fixture.PaillierPKs), len(decoded.PaillierPKs), "PaillierPKs slice length doesn't match")

	// Test the Copy method which uses gob internally
	copied := fixture.Copy()
	// Compare individual fields since Direct equality might fail due to pointer comparisons
	assert.Equal(t, fixture.Xi, copied.Xi, "Xi field doesn't match in copied data")
	assert.Equal(t, fixture.ShareID, copied.ShareID, "ShareID field doesn't match in copied data")
	assert.Equal(t, fixture.PaillierSK.LambdaN, copied.PaillierSK.LambdaN, "PaillierSK.LambdaN doesn't match in copied data")
	assert.Equal(t, fixture.NTildei, copied.NTildei, "NTildei field doesn't match in copied data")
	assert.Equal(t, fixture.H1i, copied.H1i, "H1i field doesn't match in copied data")
	assert.Equal(t, fixture.H2i, copied.H2i, "H2i field doesn't match in copied data")

	// Ensure deep copy by modifying a field and ensuring the original is unchanged
	copied.Xi.SetInt64(999)
	assert.NotEqual(t, fixture.Xi, copied.Xi, "Copy() didn't perform a deep copy")
}

func TestLocalPreParamsGobEncoding(t *testing.T) {
	t.Parallel()

	// Parse the fixture
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(ecdsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "failed to unmarshal test fixture")

	// Extract LocalPreParams
	preParams := fixture.LocalPreParams

	// Test gob encode/decode
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	err = enc.Encode(preParams)
	require.NoError(t, err, "gob encoding failed for LocalPreParams")

	var decodedParams LocalPreParams
	err = dec.Decode(&decodedParams)
	require.NoError(t, err, "gob decoding failed for LocalPreParams")

	// Verify fields match
	assert.Equal(t, preParams.PaillierSK.LambdaN, decodedParams.PaillierSK.LambdaN, "PaillierSK doesn't match after gob encode/decode")
	assert.Equal(t, preParams.NTildei, decodedParams.NTildei, "NTildei doesn't match after gob encode/decode")
	assert.Equal(t, preParams.H1i, decodedParams.H1i, "H1i doesn't match after gob encode/decode")
	assert.Equal(t, preParams.H2i, decodedParams.H2i, "H2i doesn't match after gob encode/decode")
	assert.Equal(t, preParams.Alpha, decodedParams.Alpha, "Alpha doesn't match after gob encode/decode")
	assert.Equal(t, preParams.Beta, decodedParams.Beta, "Beta doesn't match after gob encode/decode")
	assert.Equal(t, preParams.P, decodedParams.P, "P doesn't match after gob encode/decode")
	assert.Equal(t, preParams.Q, decodedParams.Q, "Q doesn't match after gob encode/decode")
}

func TestLocalSecretsGobEncoding(t *testing.T) {
	t.Parallel()

	// Parse the fixture
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(ecdsaSaveFixtureJSON), fixture)
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
