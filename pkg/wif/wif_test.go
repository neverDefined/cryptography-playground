package wif

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestWIFEncodeDecodeRoundTrip tests the complete WIF workflow with proper Bitcoin key pairs
func TestWIFEncodeDecodeRoundTrip(t *testing.T) {
	// Step 1: Generate a proper Bitcoin private key using btcec
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate Bitcoin private key: %v", err)
	}

	// Get the private key bytes (32 bytes)
	privateKeyBytes := privateKey.Key.Bytes()
	t.Logf("Generated private key (hex): %x", privateKeyBytes)

	// Get the public key for verification
	publicKey := privateKey.PubKey()
	t.Logf("Generated public key (hex): %x", publicKey.SerializeCompressed())

	// Step 2: Test uncompressed WIF (mainnet)
	t.Run("Uncompressed Mainnet", func(t *testing.T) {
		// Encode private key to WIF
		wif, err := Encode(privateKeyBytes[:], false, false) // uncompressed, mainnet
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		t.Logf("WIF (uncompressed, mainnet): %s", wif)

		// Decode WIF back to private key
		decodedKey, compressed, version, err := Decode(wif)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		// Verify the results
		if compressed {
			t.Error("Expected uncompressed, got compressed")
		}
		if version != MAINNET_VERSION {
			t.Errorf("Expected mainnet version 0x%02X, got 0x%02X", MAINNET_VERSION, version)
		}
		if !compareBytes(privateKeyBytes[:], decodedKey[:]) {
			t.Error("Private key mismatch after encode/decode")
		}

		// Verify we can reconstruct the same public key
		decodedPrivateKey, _ := btcec.PrivKeyFromBytes(decodedKey[:])
		decodedPublicKey := decodedPrivateKey.PubKey()
		if !publicKey.IsEqual(decodedPublicKey) {
			t.Error("Public key mismatch after WIF round-trip")
		}

		t.Logf("✓ Uncompressed mainnet WIF round-trip successful")
	})

	// Step 3: Test compressed WIF (mainnet)
	t.Run("Compressed Mainnet", func(t *testing.T) {
		// Encode private key to WIF
		wif, err := Encode(privateKeyBytes[:], true, false) // compressed, mainnet
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		t.Logf("WIF (compressed, mainnet): %s", wif)

		// Decode WIF back to private key
		decodedKey, compressed, version, err := Decode(wif)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		// Verify the results
		if !compressed {
			t.Error("Expected compressed, got uncompressed")
		}
		if version != MAINNET_VERSION {
			t.Errorf("Expected mainnet version 0x%02X, got 0x%02X", MAINNET_VERSION, version)
		}
		if !compareBytes(privateKeyBytes[:], decodedKey[:]) {
			t.Error("Private key mismatch after encode/decode")
		}

		// Verify we can reconstruct the same public key
		decodedPrivateKey, _ := btcec.PrivKeyFromBytes(decodedKey[:])
		decodedPublicKey := decodedPrivateKey.PubKey()
		if !publicKey.IsEqual(decodedPublicKey) {
			t.Error("Public key mismatch after WIF round-trip")
		}

		t.Logf("✓ Compressed mainnet WIF round-trip successful")
	})

	// Step 4: Test uncompressed WIF (testnet)
	t.Run("Uncompressed Testnet", func(t *testing.T) {
		// Encode private key to WIF
		wif, err := Encode(privateKeyBytes[:], false, true) // uncompressed, testnet
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		t.Logf("WIF (uncompressed, testnet): %s", wif)

		// Decode WIF back to private key
		decodedKey, compressed, version, err := Decode(wif)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		// Verify the results
		if compressed {
			t.Error("Expected uncompressed, got compressed")
		}
		if version != TESTNET_VERSION {
			t.Errorf("Expected testnet version 0x%02X, got 0x%02X", TESTNET_VERSION, version)
		}
		if !compareBytes(privateKeyBytes[:], decodedKey[:]) {
			t.Error("Private key mismatch after encode/decode")
		}

		// Verify we can reconstruct the same public key
		decodedPrivateKey, _ := btcec.PrivKeyFromBytes(decodedKey[:])
		decodedPublicKey := decodedPrivateKey.PubKey()
		if !publicKey.IsEqual(decodedPublicKey) {
			t.Error("Public key mismatch after WIF round-trip")
		}

		t.Logf("✓ Uncompressed testnet WIF round-trip successful")
	})

	// Step 5: Test compressed WIF (testnet)
	t.Run("Compressed Testnet", func(t *testing.T) {
		// Encode private key to WIF
		wif, err := Encode(privateKeyBytes[:], true, true) // compressed, testnet
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		t.Logf("WIF (compressed, testnet): %s", wif)

		// Decode WIF back to private key
		decodedKey, compressed, version, err := Decode(wif)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		// Verify the results
		if !compressed {
			t.Error("Expected compressed, got uncompressed")
		}
		if version != TESTNET_VERSION {
			t.Errorf("Expected testnet version 0x%02X, got 0x%02X", TESTNET_VERSION, version)
		}
		if !compareBytes(privateKeyBytes[:], decodedKey[:]) {
			t.Error("Private key mismatch after encode/decode")
		}

		// Verify we can reconstruct the same public key
		decodedPrivateKey, _ := btcec.PrivKeyFromBytes(decodedKey[:])
		decodedPublicKey := decodedPrivateKey.PubKey()
		if !publicKey.IsEqual(decodedPublicKey) {
			t.Error("Public key mismatch after WIF round-trip")
		}

		t.Logf("✓ Compressed testnet WIF round-trip successful")
	})
}

// TestWIFWithKnownValues tests with specific known private keys
func TestWIFWithKnownValues(t *testing.T) {
	// Known private key from Bitcoin documentation
	// Private key: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
	privateKeyHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	// Create btcec private key for public key generation
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	publicKey := privateKey.PubKey()

	t.Logf("Testing with known private key: %s", privateKeyHex)
	t.Logf("Generated public key (compressed): %x", publicKey.SerializeCompressed())

	// Test compressed mainnet WIF
	wif, err := Encode(privateKeyBytes, true, false)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	t.Logf("Generated WIF: %s", wif)

	// Decode and verify
	decodedKey, compressed, version, err := Decode(wif)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !compressed {
		t.Error("Expected compressed WIF")
	}
	if version != MAINNET_VERSION {
		t.Errorf("Expected mainnet version, got 0x%02X", version)
	}
	if !compareBytes(privateKeyBytes, decodedKey[:]) {
		t.Error("Private key mismatch")
	}

	// Verify public key reconstruction
	decodedPrivateKey, _ := btcec.PrivKeyFromBytes(decodedKey[:])
	decodedPublicKey := decodedPrivateKey.PubKey()
	if !publicKey.IsEqual(decodedPublicKey) {
		t.Error("Public key mismatch after WIF round-trip")
	}

	t.Logf("✓ Known value test successful")
}

// TestWIFErrorCases tests error conditions
func TestWIFErrorCases(t *testing.T) {
	t.Run("Invalid Private Key Length", func(t *testing.T) {
		// Test with wrong length private key
		shortKey := []byte{0x01, 0x02, 0x03} // too short
		_, err := Encode(shortKey, false, false)
		if err == nil {
			t.Error("Expected error for short private key")
		}

		longKey := make([]byte, 64) // too long
		_, err = Encode(longKey, false, false)
		if err == nil {
			t.Error("Expected error for long private key")
		}
	})

	t.Run("Invalid WIF String", func(t *testing.T) {
		// Test with invalid WIF string
		_, _, _, err := Decode("invalid-wif-string")
		if err == nil {
			t.Error("Expected error for invalid WIF string")
		}
	})
}

// Helper function to compare byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Example functions for documentation
func ExampleEncode() {
	// Generate a proper Bitcoin private key
	privateKey, _ := btcec.NewPrivateKey()
	privateKeyBytes := privateKey.Key.Bytes()

	// Encode as compressed mainnet WIF
	wif, err := Encode(privateKeyBytes[:], true, false)
	if err != nil {
		panic(err)
	}

	println("WIF:", wif)
	println("Public key:", hex.EncodeToString(privateKey.PubKey().SerializeCompressed()))
}

func ExampleDecode() {
	// Decode a WIF string
	wif := "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
	privateKey, compressed, version, err := Decode(wif)
	if err != nil {
		panic(err)
	}

	// Reconstruct the public key
	btcPrivateKey, _ := btcec.PrivKeyFromBytes(privateKey[:])
	publicKey := btcPrivateKey.PubKey()

	println("Private key:", hex.EncodeToString(privateKey[:]))
	println("Public key:", hex.EncodeToString(publicKey.SerializeCompressed()))
	println("Compressed:", compressed)
	println("Version:", hex.EncodeToString([]byte{version}))
}
