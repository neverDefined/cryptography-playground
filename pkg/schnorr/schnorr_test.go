package schnorr

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestSchnorrSignAndVerify tests the complete Schnorr signature workflow
func TestSchnorrSignAndVerify(t *testing.T) {
	// Step 1: Generate a proper Bitcoin private key
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	publicKey := privateKey.PubKey()
	t.Logf("Generated private key (hex): %x", privateKey.Key.Bytes())
	t.Logf("Generated public key (compressed): %x", publicKey.SerializeCompressed())

	// Step 2: Test with various messages
	testMessages := []string{
		"Hello, Bitcoin!",
		"Test message for Schnorr signature",
		"",
		"Very long message that tests the signature algorithm with a lot of data to process and verify that it works correctly with different message lengths",
	}

	for i, message := range testMessages {
		t.Run("Message_"+string(rune('A'+i)), func(t *testing.T) {
			msg := []byte(message)
			if len(msg) == 0 {
				msg = []byte("empty message") // Use placeholder for empty string test
			}

			// Sign the message
			signature, err := SignBIP340(msg, privateKey)
			if err != nil {
				t.Fatalf("SignBIP340 failed: %v", err)
			}

			t.Logf("Message: %q", string(msg))
			t.Logf("Signature (hex): %x", signature)

			// Verify the signature
			isValid := VerifyBIP340(msg, publicKey, signature)
			if !isValid {
				t.Error("Signature verification failed")
			}

			// Test that modified message fails verification
			modifiedMsg := append([]byte("modified"), msg...)
			isValidModified := VerifyBIP340(modifiedMsg, publicKey, signature)
			if isValidModified {
				t.Error("Signature verification should fail with modified message")
			}

			// Test that wrong public key fails verification
			wrongPrivateKey, _ := btcec.NewPrivateKey()
			wrongPublicKey := wrongPrivateKey.PubKey()
			isValidWrongKey := VerifyBIP340(msg, wrongPublicKey, signature)
			if isValidWrongKey {
				t.Error("Signature verification should fail with wrong public key")
			}

			t.Logf("✓ Message %d signature test successful", i+1)
		})
	}
}

// TestSchnorrSignAndVerifyFunction tests the convenience function
func TestSchnorrSignAndVerifyFunction(t *testing.T) {
	// Test with a simple message
	message := []byte("Test message for SignAndVerify function")
	success, err := SignAndVerify(message)
	if err != nil {
		t.Fatalf("SignAndVerify failed: %v", err)
	}
	if !success {
		t.Error("SignAndVerify should return true for valid signature")
	}

	t.Logf("✓ SignAndVerify function test successful")
}

// TestSchnorrErrorCases tests error conditions
func TestSchnorrErrorCases(t *testing.T) {
	t.Run("Empty Message", func(t *testing.T) {
		privateKey, _ := btcec.NewPrivateKey()
		_, err := SignBIP340([]byte{}, privateKey)
		if err == nil {
			t.Error("Expected error for empty message")
		}
	})

	t.Run("Nil Private Key", func(t *testing.T) {
		_, err := SignBIP340([]byte("test"), nil)
		if err == nil {
			t.Error("Expected error for nil private key")
		}
	})

	t.Run("Nil Public Key", func(t *testing.T) {
		isValid := VerifyBIP340([]byte("test"), nil, [64]byte{})
		if isValid {
			t.Error("Expected false for nil public key")
		}
	})

	t.Run("Empty Message Verification", func(t *testing.T) {
		privateKey, _ := btcec.NewPrivateKey()
		publicKey := privateKey.PubKey()
		isValid := VerifyBIP340([]byte{}, publicKey, [64]byte{})
		if isValid {
			t.Error("Expected false for empty message")
		}
	})

	t.Run("Invalid Signature Format", func(t *testing.T) {
		privateKey, _ := btcec.NewPrivateKey()
		publicKey := privateKey.PubKey()
		// Create an invalid signature (all zeros)
		invalidSig := [64]byte{}
		isValid := VerifyBIP340([]byte("test"), publicKey, invalidSig)
		if isValid {
			t.Error("Expected false for invalid signature")
		}
	})
}

// TestSchnorrDeterministic tests that signatures are deterministic
func TestSchnorrDeterministic(t *testing.T) {
	privateKey, _ := btcec.NewPrivateKey()
	message := []byte("Deterministic test message")

	// Sign the same message twice
	sig1, err := SignBIP340(message, privateKey)
	if err != nil {
		t.Fatalf("First signature failed: %v", err)
	}

	sig2, err := SignBIP340(message, privateKey)
	if err != nil {
		t.Fatalf("Second signature failed: %v", err)
	}

	// Signatures should be identical (deterministic)
	if sig1 != sig2 {
		t.Error("Schnorr signatures should be deterministic")
		t.Logf("Signature 1: %x", sig1)
		t.Logf("Signature 2: %x", sig2)
	}

	t.Logf("✓ Deterministic signature test successful")
}

// TestSchnorrWithKnownValues tests with specific known values
func TestSchnorrWithKnownValues(t *testing.T) {
	// Create a private key from known bytes
	privateKeyHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	privateKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	publicKey := privateKey.PubKey()

	message := []byte("Known value test")
	signature, err := SignBIP340(message, privateKey)
	if err != nil {
		t.Fatalf("SignBIP340 failed: %v", err)
	}

	t.Logf("Private key: %s", privateKeyHex)
	t.Logf("Public key: %x", publicKey.SerializeCompressed())
	t.Logf("Message: %q", string(message))
	t.Logf("Signature: %x", signature)

	// Verify the signature
	isValid := VerifyBIP340(message, publicKey, signature)
	if !isValid {
		t.Error("Signature verification failed for known values")
	}

	t.Logf("✓ Known values test successful")
}

// TestSchnorrExamples demonstrates the example usage patterns
func TestSchnorrExamples(t *testing.T) {
	t.Run("SignBIP340 Example", func(t *testing.T) {
		// Generate a private key
		privateKey, _ := btcec.NewPrivateKey()

		// Sign a message
		message := []byte("Hello, Bitcoin!")
		signature, err := SignBIP340(message, privateKey)
		if err != nil {
			t.Fatalf("SignBIP340 failed: %v", err)
		}

		t.Logf("Message: %s", string(message))
		t.Logf("Signature: %x", signature)
		t.Logf("✓ SignBIP340 example successful")
	})

	t.Run("VerifyBIP340 Example", func(t *testing.T) {
		// Generate a key pair
		privateKey, _ := btcec.NewPrivateKey()
		publicKey := privateKey.PubKey()

		// Sign a message
		message := []byte("Hello, Bitcoin!")
		signature, _ := SignBIP340(message, privateKey)

		// Verify the signature
		isValid := VerifyBIP340(message, publicKey, signature)
		if !isValid {
			t.Error("Signature verification failed")
		}

		t.Logf("Signature valid: %t", isValid)
		t.Logf("✓ VerifyBIP340 example successful")
	})

	t.Run("SignAndVerify Example", func(t *testing.T) {
		// Test the complete workflow
		message := []byte("Test message")
		success, err := SignAndVerify(message)
		if err != nil {
			t.Fatalf("SignAndVerify failed: %v", err)
		}
		if !success {
			t.Error("SignAndVerify should return true")
		}

		t.Logf("Sign and verify successful: %t", success)
		t.Logf("✓ SignAndVerify example successful")
	})
}

// TestTaprootWorkflow demonstrates the complete Taproot Schnorr workflow
func TestTaprootWorkflow(t *testing.T) {
	// Step 1: Key generation
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	pub := priv.PubKey()

	t.Logf("Generated private key (hex): %x", priv.Key.Bytes())
	t.Logf("Generated public key (compressed): %x", pub.SerializeCompressed())

	// Step 2: Extract x-only public key (BIP340 uses 32-byte x)
	xonly := XOnlyFromPub(pub)
	t.Logf("X-only public key: %x", xonly)

	// Step 3: Sign arbitrary message bytes (BIP340 takes arbitrary-length msg)
	msg := []byte("Taproot says hello")
	sig, err := SignBIP340(msg, priv)
	if err != nil {
		t.Fatalf("SignBIP340 failed: %v", err)
	}
	t.Logf("Signature (64B): %x", sig[:])

	// Step 4: Verify using full public key
	ok := VerifyBIP340(msg, pub, sig)
	if !ok {
		t.Error("Verification with full public key failed")
	}
	t.Logf("Verify w/ full pub: %v", ok)

	// Step 5: Verify using x-only public key
	ok2, err := VerifyWithXOnly(msg, sig, xonly)
	if err != nil {
		t.Fatalf("VerifyWithXOnly failed: %v", err)
	}
	if !ok2 {
		t.Error("Verification with x-only public key failed")
	}
	t.Logf("Verify w/ x-only pub: %v", ok2)

	// Step 6: Negative test (tamper message)
	ok3, _ := VerifyWithXOnly([]byte("Taproot says hELlo"), sig, xonly)
	if ok3 {
		t.Error("Verification should fail with tampered message")
	}
	t.Logf("Verify tampered msg: %v", ok3)

	// Step 7: Test round-trip conversion
	reconstructedPub, err := ParseXOnly(xonly)
	if err != nil {
		t.Fatalf("ParseXOnly failed: %v", err)
	}

	// Verify the reconstructed public key has the same x-coordinate
	// Note: ParseXOnly uses even-Y lift, so it may not match the original exactly
	reconstructedXOnly := XOnlyFromPub(reconstructedPub)
	if !compareBytes(xonly[:], reconstructedXOnly[:]) {
		t.Error("Reconstructed public key x-coordinate doesn't match original")
	}
	t.Logf("✓ Round-trip conversion successful")

	// Step 8: Test signature parsing and joining
	_, err = ParseSignature(sig)
	if err != nil {
		t.Fatalf("ParseSignature failed: %v", err)
	}

	// Extract r and s components from the original signature
	r := [32]byte{}
	s := [32]byte{}
	copy(r[:], sig[:32]) // First 32 bytes: r component
	copy(s[:], sig[32:]) // Second 32 bytes: s component

	// Reconstruct signature
	reconstructedSig := JoinSig(r, s)
	if reconstructedSig != sig {
		t.Error("Reconstructed signature doesn't match original")
	}
	t.Logf("✓ Signature parsing and joining successful")

	t.Logf("✓ Complete Taproot workflow test successful")
}

// TestXOnlyPublicKey demonstrates x-only public key operations
func TestXOnlyPublicKey(t *testing.T) {
	// Generate a key pair
	privateKey, _ := btcec.NewPrivateKey()
	publicKey := privateKey.PubKey()

	// Test x-only extraction
	xOnly := XOnlyFromPub(publicKey)
	t.Logf("Full public key (compressed): %x", publicKey.SerializeCompressed())
	t.Logf("X-only public key: %x", xOnly)

	// Verify the x-only key is 32 bytes
	if len(xOnly) != 32 {
		t.Errorf("X-only key should be 32 bytes, got %d", len(xOnly))
	}

	// Test round-trip conversion
	reconstructedPub, err := ParseXOnly(xOnly)
	if err != nil {
		t.Fatalf("ParseXOnly failed: %v", err)
	}

	// The reconstructed key should have the same x-coordinate
	// Note: ParseXOnly uses even-Y lift, so it may not match the original exactly
	// but the x-coordinate should be the same
	reconstructedXOnly := XOnlyFromPub(reconstructedPub)
	if !compareBytes(xOnly[:], reconstructedXOnly[:]) {
		t.Error("Reconstructed public key x-coordinate doesn't match original")
	}

	// Test that the x-only key is indeed just the x-coordinate
	compressed := publicKey.SerializeCompressed()
	expectedXOnly := compressed[1:] // Skip the prefix byte
	if !compareBytes(xOnly[:], expectedXOnly) {
		t.Error("X-only key doesn't match expected x-coordinate")
	}

	t.Logf("✓ X-only public key operations successful")
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
