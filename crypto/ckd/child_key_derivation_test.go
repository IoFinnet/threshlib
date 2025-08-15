package ckd

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	tss_int "github.com/iofinnet/tss-lib/v3/common/int"
	tss_crypto "github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/ed25519"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicDerivation(t *testing.T) {
	t.Parallel()
	// port from https://github.com/btcsuite/btcutil/blob/master/hdkeychain/extendedkey_test.go
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	testVec2MasterPubKey := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	tests := []struct {
		name    string
		master  string
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewExtendedKeyFromString(test.master, tss.S256())
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			_, extKey, err = DeriveChildKey(childNum, extKey, tss.S256())
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		pubStr := extKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Derive #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

// TestNewExtendedKeyFromStringEdwards tests parsing Edwards curve extended keys
func TestNewExtendedKeyFromStringEdwards(t *testing.T) {
	// Test data - Edwards curve xpub with 0x00 prefix (33 bytes)
	xpubStr := "xpub661MyMwAqRbcFBtY9TCYf6EALRfLpq7X3kwftLsD7tv7oFQB8iXBEz5UAczJisMMzfKoinRPMivNSFLLse7vtaxWSvoGdvn6CLUSnXsS9c5"
	expectedChainCodeHex := "40dcf32d882459f808aa9412667630a64e58367849b50e9421513700755b4469"

	curve := tss.Edwards()

	// Parse the extended key
	extKey, err := NewExtendedKeyFromString(xpubStr, curve)
	require.NoError(t, err)
	require.NotNil(t, extKey)

	// Verify basic properties
	assert.Equal(t, uint8(0), extKey.Depth)
	assert.Equal(t, uint32(0), extKey.ChildIndex)
	assert.Equal(t, expectedChainCodeHex, hex.EncodeToString(extKey.ChainCode))
	assert.NotNil(t, extKey.PublicKey)

	// The public key should have valid X,Y coordinates
	assert.NotNil(t, extKey.PublicKey.X())
	assert.NotNil(t, extKey.PublicKey.Y())
}

// TestNewExtendedKeyFromStringEdwards32Bytes tests parsing Edwards curve extended keys with 32-byte format
func TestNewExtendedKeyFromStringEdwards32Bytes(t *testing.T) {
	// Create a custom xpub with 32-byte Ed25519 key (no 0x00 prefix)
	// This is a synthetic test since real extended keys typically use 33 bytes
	// But we want to ensure the code handles both formats

	// For this test, we'll manually construct an extended key payload
	// version(4) || depth(1) || parentFP(4) || childIndex(4) || chainCode(32) || key(32) || checksum(4)

	// Use a valid Ed25519 public key (this is the derived key from the test fixture at path m/0)
	ed25519PubKey, _ := hex.DecodeString("F9C7707A6A3C2C7834ABB0DE4D154F281FCE3F51565D38126FC23FE71535AEFD")

	// Construct payload
	version := []byte{0x04, 0x88, 0xB2, 0x1E} // xpub version
	depth := byte(0)
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	childIndex := []byte{0x00, 0x00, 0x00, 0x00}
	chainCode, _ := hex.DecodeString("40dcf32d882459f808aa9412667630a64e58367849b50e9421513700755b4469")

	// Build payload with 32-byte key
	payload := append(version, depth)
	payload = append(payload, parentFP...)
	payload = append(payload, childIndex...)
	payload = append(payload, chainCode...)
	payload = append(payload, ed25519PubKey...) // 32 bytes, no prefix

	// Calculate checksum
	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Complete serialized key
	serialized := append(payload, checksum...)
	xpubStr := base58.Encode(serialized)

	curve := tss.Edwards()

	// Parse the extended key with 32-byte format
	extKey, err := NewExtendedKeyFromString(xpubStr, curve)
	require.NoError(t, err)
	require.NotNil(t, extKey)

	// Verify it parsed correctly
	assert.Equal(t, uint8(0), extKey.Depth)
	assert.NotNil(t, extKey.PublicKey)
}

// TestNewExtendedKeyFromStringEdwardsWithEDPrefix tests parsing Edwards curve extended keys with 0xED prefix
func TestNewExtendedKeyFromStringEdwardsWithEDPrefix(t *testing.T) {
	// Create a custom xpub with 0xED prefix + 32-byte Ed25519 key (XRPL format)
	// version(4) || depth(1) || parentFP(4) || childIndex(4) || chainCode(32) || key(33) || checksum(4)

	// Use a valid Ed25519 public key with 0xED prefix
	ed25519PubKey, _ := hex.DecodeString("F9C7707A6A3C2C7834ABB0DE4D154F281FCE3F51565D38126FC23FE71535AEFD")

	// Construct payload
	version := []byte{0x04, 0x88, 0xB2, 0x1E} // xpub version
	depth := byte(0)
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	childIndex := []byte{0x00, 0x00, 0x00, 0x00}
	chainCode, _ := hex.DecodeString("40dcf32d882459f808aa9412667630a64e58367849b50e9421513700755b4469")

	// Build key data with 0xED prefix
	keyData := append([]byte{0xED}, ed25519PubKey...)

	// Build payload
	payload := append(version, depth)
	payload = append(payload, parentFP...)
	payload = append(payload, childIndex...)
	payload = append(payload, chainCode...)
	payload = append(payload, keyData...) // 33 bytes with 0xED prefix

	// Calculate checksum
	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Complete serialized key
	serialized := append(payload, checksum...)
	xpubStr := base58.Encode(serialized)

	curve := tss.Edwards()

	// Parse the extended key with 0xED prefix format
	extKey, err := NewExtendedKeyFromString(xpubStr, curve)
	require.NoError(t, err)
	require.NotNil(t, extKey)

	// Verify it parsed correctly
	assert.Equal(t, uint8(0), extKey.Depth)
	assert.NotNil(t, extKey.PublicKey)
}

// TestEdwardsHDDerivation tests HD key derivation for Edwards curves
func TestEdwardsHDDerivation(t *testing.T) {
	xpubStr := "xpub661MyMwAqRbcFBtY9TCYf6EALRfLpq7X3kwftLsD7tv7oFQB8iXBEz5UAczJisMMzfKoinRPMivNSFLLse7vtaxWSvoGdvn6CLUSnXsS9c5"
	expectedPubKeyHex := "F9C7707A6A3C2C7834ABB0DE4D154F281FCE3F51565D38126FC23FE71535AEFD"

	curve := tss.Edwards()

	// Parse the extended key
	extKey, err := NewExtendedKeyFromString(xpubStr, curve)
	require.NoError(t, err)

	// Derive child key for path m/0
	hdPath := []uint32{0}
	hdDelta, childKey, err := DeriveChildKeyFromHierarchy(hdPath, extKey, tss_int.Wrap(curve.Params().N), curve)
	require.NoError(t, err)
	require.NotNil(t, hdDelta)
	require.NotNil(t, childKey)

	// Convert child public key to Ed25519 format
	childECPoint, err := tss_crypto.NewECPoint(curve,
		tss_int.Wrap(childKey.PublicKey.X()),
		tss_int.Wrap(childKey.PublicKey.Y()))
	require.NoError(t, err)

	ed25519Point, err := ed25519.FromXYToEd25519Point(childECPoint.X(), childECPoint.Y())
	require.NoError(t, err)

	derivedPubKey := ed25519Point.Bytes()
	derivedPubKeyHex := strings.ToUpper(hex.EncodeToString(derivedPubKey))

	assert.Equal(t, expectedPubKeyHex, derivedPubKeyHex, "Derived public key should match expected")
}

// TestEdwardsHDDerivationXRPL tests Edwards curve HD derivation with XRPL test vectors
func TestEdwardsHDDerivationXRPL(t *testing.T) {
	// Test vectors from XRPL transaction
	xpubStr := "xpub661MyMwAqRbcG9aErp1paHxw5LYRQd4t24d7CBReN2EeqynEr3uSSjfP6Jr1RgMYqEFzNPTGKsS96dAALutAnFpdhmVCgNxXW7cB5GVAWse"
	expectedSigningPubKeyHex := "DA65F1ED202CFF9216443248FABE11F48AC0B816CF049E557C059E806204BDEB"
	// expectedTxnSignature := "6445D66394A163D2FE73054969EA8F92927DD873B79F45CA9D5A27D3CADB95DDF5E8ECD922E7FF62535844C6FDA0BF359BE4CE4E11F5CB4211DBF8B8F1F8A007"
	// expectedAccount := "rUtF1DGU2iioZEpfPVSQWbZhBY3jwEGvBj"
	// expectedDestination := "rUbt82cnFDjcet7MybRZ9NhN1istJ3qYbm"

	curve := tss.Edwards()

	// Parse the extended key
	extKey, err := NewExtendedKeyFromString(xpubStr, curve)
	require.NoError(t, err)
	require.NotNil(t, extKey)

	// Derive child key for path m/0
	hdPath := []uint32{0}
	hdDelta, childKey, err := DeriveChildKeyFromHierarchy(hdPath, extKey, tss_int.Wrap(curve.Params().N), curve)
	require.NoError(t, err)
	require.NotNil(t, hdDelta)
	require.NotNil(t, childKey)

	// Convert child public key to Ed25519 format
	childECPoint, err := tss_crypto.NewECPoint(curve,
		tss_int.Wrap(childKey.PublicKey.X()),
		tss_int.Wrap(childKey.PublicKey.Y()))
	require.NoError(t, err)

	ed25519Point, err := ed25519.FromXYToEd25519Point(childECPoint.X(), childECPoint.Y())
	require.NoError(t, err)

	derivedPubKey := ed25519Point.Bytes()
	derivedPubKeyHex := strings.ToUpper(hex.EncodeToString(derivedPubKey))

	// Verify the derived signing public key matches the XRPL transaction
	assert.Equal(t, expectedSigningPubKeyHex, derivedPubKeyHex, "Derived signing public key should match XRPL transaction")

	// Log the results for verification
	t.Logf("xpub: %s", xpubStr)
	t.Logf("path: m/0")
	t.Logf("Derived SigningPubKey: %s", derivedPubKeyHex)
	t.Logf("Expected SigningPubKey: %s", expectedSigningPubKeyHex)
}
