// Copyright © 2025 io finnet group, inc
//
// This file is part of io finnet group. The full io finnet group copyright notice,
// including terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/json"
	"testing"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonEncodingLocalPartySaveData(t *testing.T) {
	t.Parallel()

	// Parse the fixture JSON
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(eddsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "failed to unmarshal test fixture")

	// Test basic JSON encode/decode cycle
	jsonData, err := json.Marshal(fixture)
	require.NoError(t, err, "JSON marshaling failed")

	var decoded LocalPartySaveData
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err, "JSON unmarshaling failed")

	// Verify all fields match
	assert.Equal(t, fixture.Xi, decoded.Xi, "Xi field doesn't match after JSON encode/decode")
	assert.Equal(t, fixture.ShareID, decoded.ShareID, "ShareID field doesn't match after JSON encode/decode")

	// Output bit lengths to verify we're handling large numbers
	t.Logf("Xi bit length: %d", fixture.Xi.BitLen())
	t.Logf("ShareID bit length: %d", fixture.ShareID.BitLen())

	// Ensure slices have the same length
	assert.Equal(t, len(fixture.Ks), len(decoded.Ks), "Ks slice length doesn't match")
	assert.Equal(t, len(fixture.BigXj), len(decoded.BigXj), "BigXj slice length doesn't match")

	// Check slice contents
	for i := range fixture.Ks {
		assert.Equal(t, fixture.Ks[i], decoded.Ks[i], "Ks[%d] doesn't match", i)
	}

	for i := range fixture.BigXj {
		assert.True(t, fixture.BigXj[i].Equals(decoded.BigXj[i]), "BigXj[%d] doesn't match", i)
	}

	// Check EDDSAPub
	assert.True(t, fixture.EDDSAPub.Equals(decoded.EDDSAPub), "EDDSAPub doesn't match after JSON encode/decode")

	// Test JSON encode/decode with pretty printing
	prettyJson, err := json.MarshalIndent(fixture, "", "  ")
	require.NoError(t, err, "JSON marshaling with indentation failed")

	var prettyDecoded LocalPartySaveData
	err = json.Unmarshal(prettyJson, &prettyDecoded)
	require.NoError(t, err, "JSON unmarshaling of pretty JSON failed")

	assert.Equal(t, fixture.Xi, prettyDecoded.Xi, "Xi doesn't match after pretty JSON encode/decode")
	assert.Equal(t, fixture.ShareID, prettyDecoded.ShareID, "ShareID doesn't match after pretty JSON encode/decode")
}

func TestJsonLocalSecrets(t *testing.T) {
	t.Parallel()

	// Parse the fixture
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(eddsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "failed to unmarshal test fixture")

	// Extract LocalSecrets
	secrets := fixture.LocalSecrets

	// Test JSON encode/decode
	jsonData, err := json.Marshal(secrets)
	require.NoError(t, err, "JSON marshaling of LocalSecrets failed")

	var decodedSecrets LocalSecrets
	err = json.Unmarshal(jsonData, &decodedSecrets)
	require.NoError(t, err, "JSON unmarshaling of LocalSecrets failed")

	// Verify fields match
	assert.Equal(t, secrets.Xi, decodedSecrets.Xi, "Xi doesn't match after JSON encode/decode")
	assert.Equal(t, secrets.ShareID, decodedSecrets.ShareID, "ShareID doesn't match after JSON encode/decode")
}

func TestLocalPartySaveDataCustomJson(t *testing.T) {
	t.Parallel()

	// Create a minimal test instance with non-nil fields using large numbers
	saveData := NewLocalPartySaveData(2)

	// Use very large integers to test JSON encoding of big numbers
	xiHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF42"
	xi, _ := new(big.Int).SetString(xiHex, 16)
	saveData.Xi = xi

	shareIDHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"
	shareID, _ := new(big.Int).SetString(shareIDHex, 16)
	saveData.ShareID = shareID

	// Use ScalarBaseMult to generate valid points on the curve
	x1, y1 := tss.Edwards().ScalarBaseMult(big.NewInt(123).Bytes())
	eddsaPub, err := crypto.NewECPoint(tss.Edwards(), big.Wrap(x1), big.Wrap(y1))
	require.NoError(t, err)
	saveData.EDDSAPub = eddsaPub

	// Very large values for Ks
	ks0Hex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF49"
	ks0, _ := new(big.Int).SetString(ks0Hex, 16)
	saveData.Ks[0] = ks0

	ks1Hex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF50"
	ks1, _ := new(big.Int).SetString(ks1Hex, 16)
	saveData.Ks[1] = ks1

	// Generate valid points for BigXj
	x2, y2 := tss.Edwards().ScalarBaseMult(big.NewInt(456).Bytes())
	bigXj0, err := crypto.NewECPoint(tss.Edwards(), big.Wrap(x2), big.Wrap(y2))
	require.NoError(t, err)
	saveData.BigXj[0] = bigXj0

	x3, y3 := tss.Edwards().ScalarBaseMult(big.NewInt(789).Bytes())
	bigXj1, err := crypto.NewECPoint(tss.Edwards(), big.Wrap(x3), big.Wrap(y3))
	require.NoError(t, err)
	saveData.BigXj[1] = bigXj1

	// Test JSON encode/decode of the custom structure
	jsonData, err := json.Marshal(saveData)
	require.NoError(t, err, "JSON marshaling failed for custom test instance")

	var decoded LocalPartySaveData
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err, "JSON unmarshaling failed for custom test instance")

	// Verify the fields after roundtrip
	assert.Equal(t, saveData.Xi, decoded.Xi, "Xi doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.ShareID, decoded.ShareID, "ShareID doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.Ks[0], decoded.Ks[0], "Ks[0] doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.Ks[1], decoded.Ks[1], "Ks[1] doesn't match after JSON encode/decode")
	assert.True(t, saveData.EDDSAPub.Equals(decoded.EDDSAPub), "EDDSAPub doesn't match after JSON encode/decode")
	assert.True(t, saveData.BigXj[0].Equals(decoded.BigXj[0]), "BigXj[0] doesn't match after JSON encode/decode")
	assert.True(t, saveData.BigXj[1].Equals(decoded.BigXj[1]), "BigXj[1] doesn't match after JSON encode/decode")
}

func TestFixtureJsonFormat(t *testing.T) {
	t.Parallel()

	// Verify that the fixture JSON string is valid and can be parsed
	var rawJson map[string]interface{}
	err := json.Unmarshal([]byte(eddsaSaveFixtureJSON), &rawJson)
	require.NoError(t, err, "Fixture JSON is not valid JSON format")

	// Check that we can parse into our struct
	fixture := new(LocalPartySaveData)
	err = json.Unmarshal([]byte(eddsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "Failed to unmarshal fixture JSON into LocalPartySaveData")

	// Verify a few important fields
	assert.NotNil(t, fixture.Xi, "Xi should not be nil in fixture")
	assert.NotNil(t, fixture.ShareID, "ShareID should not be nil in fixture")
	assert.NotNil(t, fixture.EDDSAPub, "EDDSAPub should not be nil in fixture")
	assert.NotEmpty(t, fixture.Ks, "Ks should not be empty in fixture")
	assert.NotEmpty(t, fixture.BigXj, "BigXj should not be empty in fixture")

	// Verify that the fixture contains large integers
	t.Logf("Fixture Xi bit length: %d", fixture.Xi.BitLen())
	t.Logf("Fixture ShareID bit length: %d", fixture.ShareID.BitLen())

	// Re-encode the fixture to JSON and verify we can decode it again
	jsonData, err := json.Marshal(fixture)
	require.NoError(t, err, "Failed to marshal fixture to JSON")

	var reloadedFixture LocalPartySaveData
	err = json.Unmarshal(jsonData, &reloadedFixture)
	require.NoError(t, err, "Failed to unmarshal re-encoded fixture")

	// Verify large numbers roundtrip correctly
	assert.Equal(t, fixture.Xi, reloadedFixture.Xi, "Xi didn't match after JSON roundtrip")
	assert.Equal(t, fixture.ShareID, reloadedFixture.ShareID, "ShareID didn't match after JSON roundtrip")
	assert.True(t, fixture.EDDSAPub.Equals(reloadedFixture.EDDSAPub), "EDDSAPub didn't match after JSON roundtrip")
}
