package schnorr

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// SignBIP340 produces a 64-byte BIP340 Schnorr signature over a message using a private key
//
// BIP340 Schnorr signatures are deterministic and provide better security properties
// than ECDSA. They are used in Bitcoin Taproot and other modern Bitcoin features.
//
// The signature format is: [r (32 bytes)][s (32 bytes)] where r and s are field elements
// The message is hashed to 32 bytes using SHA256 before signing (BIP340 requirement)
//
// Example:
//
//	privateKey, _ := btcec.NewPrivateKey()
//	message := []byte("Hello, Bitcoin!")
//	signature, err := SignBIP340(message, privateKey)
//	// Result: [64]byte{0x12, 0x34, 0x56, ...} (64-byte signature)
func SignBIP340(msg []byte, priv *btcec.PrivateKey) ([64]byte, error) {
	// Step 1: Validate inputs
	if len(msg) == 0 {
		return [64]byte{}, errors.New("message cannot be empty")
	}
	if priv == nil {
		return [64]byte{}, errors.New("private key cannot be nil")
	}

	// Step 2: Hash the message to 32 bytes (BIP340 requirement)
	// BIP340 Schnorr signatures work on 32-byte message hashes
	messageHash := sha256.Sum256(msg)

	// Step 3: Create BIP340 Schnorr signature using the btcec library
	// This handles deterministic nonce derivation and tagged hashing internally
	sig, err := btcschnorr.Sign(priv, messageHash[:])
	if err != nil {
		return [64]byte{}, err
	}

	// Step 4: Serialize the signature to 64 bytes
	// Format: [r (32 bytes)][s (32 bytes)]
	var out [64]byte
	copy(out[:], sig.Serialize())
	return out, nil
}

// VerifyBIP340 verifies a BIP340 Schnorr signature over a message using a public key
//
// Returns true if the signature is valid, false otherwise.
// A valid signature proves that the message was signed by the holder of the private key
// corresponding to the given public key.
//
// The message is hashed to 32 bytes using SHA256 before verification (BIP340 requirement)
//
// Example:
//
//	publicKey := privateKey.PubKey()
//	message := []byte("Hello, Bitcoin!")
//	signature := [64]byte{0x12, 0x34, 0x56, ...}
//	isValid := VerifyBIP340(message, publicKey, signature)
//	// Result: true if signature is valid
func VerifyBIP340(msg []byte, pub *btcec.PublicKey, sigBz [64]byte) bool {
	// Step 1: Validate inputs
	if len(msg) == 0 {
		return false
	}
	if pub == nil {
		return false
	}

	// Step 2: Hash the message to 32 bytes (BIP340 requirement)
	// BIP340 Schnorr signatures work on 32-byte message hashes
	messageHash := sha256.Sum256(msg)

	// Step 3: Parse the 64-byte signature into a signature object
	// This validates the signature format and extracts r and s components
	sig, err := btcschnorr.ParseSignature(sigBz[:])
	if err != nil {
		return false
	}

	// Step 4: Verify the signature against the message hash and public key
	// This performs the Schnorr verification algorithm
	return sig.Verify(messageHash[:], pub)
}

// SignAndVerify demonstrates a complete Schnorr signature workflow
//
// This function shows how to:
// 1. Generate a key pair
// 2. Sign a message
// 3. Verify the signature
// 4. Handle errors appropriately
//
// Example:
//
//	message := []byte("Test message for Schnorr signature")
//	success, err := SignAndVerify(message)
//	// Result: success = true, err = nil if everything works
func SignAndVerify(msg []byte) (bool, error) {
	// Step 1: Generate a new private key
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return false, err
	}

	// Step 2: Get the corresponding public key
	publicKey := privateKey.PubKey()

	// Step 3: Sign the message
	signature, err := SignBIP340(msg, privateKey)
	if err != nil {
		return false, err
	}

	// Step 4: Verify the signature
	isValid := VerifyBIP340(msg, publicKey, signature)
	if !isValid {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}
