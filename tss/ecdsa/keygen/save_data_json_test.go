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
	"github.com/iofinnet/tss-lib/v3/crypto/paillier"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonEncodingLocalPartySaveData(t *testing.T) {
	t.Parallel()

	// Parse the fixture JSON
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(ecdsaSaveFixtureJSON), fixture)
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
	assert.Equal(t, fixture.PaillierSK.LambdaN, decoded.PaillierSK.LambdaN, "PaillierSK.LambdaN doesn't match after JSON encode/decode")
	assert.Equal(t, fixture.PaillierSK.PublicKey.N, decoded.PaillierSK.PublicKey.N, "PaillierSK.PublicKey.N doesn't match after JSON encode/decode")
	assert.Equal(t, fixture.NTildei, decoded.NTildei, "NTildei field doesn't match after JSON encode/decode")
	assert.Equal(t, fixture.H1i, decoded.H1i, "H1i field doesn't match after JSON encode/decode")
	assert.Equal(t, fixture.H2i, decoded.H2i, "H2i field doesn't match after JSON encode/decode")

	// Output bit lengths to verify we're handling large numbers
	t.Logf("Xi bit length: %d", fixture.Xi.BitLen())
	t.Logf("ShareID bit length: %d", fixture.ShareID.BitLen())
	t.Logf("PaillierSK.LambdaN bit length: %d", fixture.PaillierSK.LambdaN.BitLen())
	t.Logf("PaillierSK.PublicKey.N bit length: %d", fixture.PaillierSK.PublicKey.N.BitLen())
	t.Logf("NTildei bit length: %d", fixture.NTildei.BitLen())
	t.Logf("H1i bit length: %d", fixture.H1i.BitLen())
	t.Logf("H2i bit length: %d", fixture.H2i.BitLen())

	// Ensure slices have the same length
	assert.Equal(t, len(fixture.Ks), len(decoded.Ks), "Ks slice length doesn't match")
	assert.Equal(t, len(fixture.NTildej), len(decoded.NTildej), "NTildej slice length doesn't match")
	assert.Equal(t, len(fixture.H1j), len(decoded.H1j), "H1j slice length doesn't match")
	assert.Equal(t, len(fixture.H2j), len(decoded.H2j), "H2j slice length doesn't match")
	assert.Equal(t, len(fixture.BigXj), len(decoded.BigXj), "BigXj slice length doesn't match")
	assert.Equal(t, len(fixture.PaillierPKs), len(decoded.PaillierPKs), "PaillierPKs slice length doesn't match")

	// Check a few slice elements
	if len(fixture.Ks) > 0 {
		assert.Equal(t, fixture.Ks[0], decoded.Ks[0], "Ks[0] doesn't match")
	}
	if len(fixture.BigXj) > 0 {
		assert.True(t, fixture.BigXj[0].Equals(decoded.BigXj[0]), "BigXj[0] doesn't match")
	}

	// Check ECDSAPub
	assert.True(t, fixture.ECDSAPub.Equals(decoded.ECDSAPub), "ECDSAPub doesn't match after JSON encode/decode")

	// Test that the provided fixture matches JSON roundtrip
	fixtureJson, err := json.Marshal(fixture)
	require.NoError(t, err, "JSON marshaling of fixture failed")

	roundtripFixture := new(LocalPartySaveData)
	err = json.Unmarshal(fixtureJson, roundtripFixture)
	require.NoError(t, err, "JSON unmarshaling of fixture failed")

	assert.Equal(t, fixture.Xi, roundtripFixture.Xi, "Xi doesn't match after fixture JSON roundtrip")
	assert.Equal(t, fixture.ShareID, roundtripFixture.ShareID, "ShareID doesn't match after fixture JSON roundtrip")
}

func TestJsonLocalPreParams(t *testing.T) {
	t.Parallel()

	// Parse the fixture
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(ecdsaSaveFixtureJSON), fixture)
	require.NoError(t, err, "failed to unmarshal test fixture")

	// Extract LocalPreParams
	preParams := fixture.LocalPreParams

	// Test JSON encode/decode
	jsonData, err := json.Marshal(preParams)
	require.NoError(t, err, "JSON marshaling of LocalPreParams failed")

	var decodedParams LocalPreParams
	err = json.Unmarshal(jsonData, &decodedParams)
	require.NoError(t, err, "JSON unmarshaling of LocalPreParams failed")

	// Verify fields match
	assert.Equal(t, preParams.PaillierSK.LambdaN, decodedParams.PaillierSK.LambdaN, "PaillierSK doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.NTildei, decodedParams.NTildei, "NTildei doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.H1i, decodedParams.H1i, "H1i doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.H2i, decodedParams.H2i, "H2i doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.Alpha, decodedParams.Alpha, "Alpha doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.Beta, decodedParams.Beta, "Beta doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.P, decodedParams.P, "P doesn't match after JSON encode/decode")
	assert.Equal(t, preParams.Q, decodedParams.Q, "Q doesn't match after JSON encode/decode")
}

func TestJsonLocalSecrets(t *testing.T) {
	t.Parallel()

	// Parse the fixture
	fixture := new(LocalPartySaveData)
	err := json.Unmarshal([]byte(ecdsaSaveFixtureJSON), fixture)
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

	saveData.PaillierSK = &paillier.PrivateKey{}
	lambdaNHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF44"
	lambdaN, _ := new(big.Int).SetString(lambdaNHex, 16)
	saveData.PaillierSK.LambdaN = lambdaN

	nHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45"
	n, _ := new(big.Int).SetString(nHex, 16)
	saveData.PaillierSK.PublicKey.N = n

	nTildeiHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF46"
	nTildei, _ := new(big.Int).SetString(nTildeiHex, 16)
	saveData.NTildei = nTildei

	h1iHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF47"
	h1i, _ := new(big.Int).SetString(h1iHex, 16)
	saveData.H1i = h1i

	h2iHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF48"
	h2i, _ := new(big.Int).SetString(h2iHex, 16)
	saveData.H2i = h2i

	// Use ScalarBaseMult to generate a valid point on the curve
	x, y := tss.S256().ScalarBaseMult(big.NewInt(555).Bytes())
	ecdsaPub, err := crypto.NewECPoint(tss.S256(), big.Wrap(x), big.Wrap(y))
	require.NoError(t, err)
	saveData.ECDSAPub = ecdsaPub

	ks0Hex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF49"
	ks0, _ := new(big.Int).SetString(ks0Hex, 16)
	saveData.Ks[0] = ks0

	ks1Hex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF50"
	ks1, _ := new(big.Int).SetString(ks1Hex, 16)
	saveData.Ks[1] = ks1

	// Test JSON encode/decode of the custom structure
	jsonData, err := json.Marshal(saveData)
	require.NoError(t, err, "JSON marshaling failed for custom test instance")

	var decoded LocalPartySaveData
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err, "JSON unmarshaling failed for custom test instance")

	// Verify the fields after roundtrip
	assert.Equal(t, saveData.Xi, decoded.Xi, "Xi doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.ShareID, decoded.ShareID, "ShareID doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.NTildei, decoded.NTildei, "NTildei doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.Ks[0], decoded.Ks[0], "Ks[0] doesn't match after JSON encode/decode")
	assert.Equal(t, saveData.Ks[1], decoded.Ks[1], "Ks[1] doesn't match after JSON encode/decode")
	assert.True(t, saveData.ECDSAPub.Equals(decoded.ECDSAPub), "ECDSAPub doesn't match after JSON encode/decode")
}
