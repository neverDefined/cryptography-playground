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

// VerifyBIP340 verifies a BIP340 Schnorr signature over a message using a full public key
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

// XOnlyFromPub extracts the x-only public key from a full Bitcoin public key
//
// Bitcoin public keys come in different formats:
// - Uncompressed: 65 bytes [0x04][x (32 bytes)][y (32 bytes)]
// - Compressed: 33 bytes [0x02 or 0x03][x (32 bytes)]
// - X-Only: 32 bytes [x (32 bytes)] (just the x-coordinate)
//
// X-only public keys are used in Bitcoin Taproot (BIP340) for efficiency.
// The y-coordinate can be recovered from the x-coordinate and signature.
//
// Example:
//
//	publicKey := privateKey.PubKey()
//	xOnly := XOnlyFromPub(publicKey)
//	// Result: [32]byte{0x12, 0x34, 0x56, ...} (x-only part of public key)
func XOnlyFromPub(pub *btcec.PublicKey) [32]byte {
	// Step 1: Get the compressed public key (33 bytes)
	// Format: [0x02 or 0x03][x (32 bytes)]
	compressed := pub.SerializeCompressed()

	// Step 2: Extract the x-coordinate (skip the first byte)
	// The first byte is the prefix (0x02 for even y, 0x03 for odd y)
	var out [32]byte
	copy(out[:], compressed[1:]) // Skip prefix byte, take next 32 bytes
	return out
}

// VerifyWithXOnly verifies a BIP340 Schnorr signature using an x-only public key
//
// This function is useful for Bitcoin Taproot addresses which use x-only public keys.
// It converts the x-only key to a full public key (using even-Y lift) and then verifies.
//
// Example:
//
//	xOnly := XOnlyFromPub(publicKey)
//	message := []byte("Hello, Bitcoin!")
//	signature := [64]byte{0x12, 0x34, 0x56, ...}
//	isValid, err := VerifyWithXOnly(message, signature, xOnly)
//	// Result: true if signature is valid
func VerifyWithXOnly(msg []byte, sigBz [64]byte, xOnly [32]byte) (bool, error) {
	// Step 1: Validate inputs
	if len(msg) == 0 {
		return false, errors.New("message cannot be empty")
	}

	// Step 2: Convert x-only public key to full public key (even-Y lift)
	// BIP340 uses even-Y lift convention for x-only keys
	pub, err := btcschnorr.ParsePubKey(xOnly[:])
	if err != nil {
		return false, err
	}

	// Step 3: Use the standard verification function with the full public key
	return VerifyBIP340(msg, pub, sigBz), nil
}

// ParseXOnly converts a 32-byte x-only key into a full secp256k1 public key (even-Y lift)
//
// This is the inverse operation of XOnlyFromPub. It reconstructs a full public key
// from just the x-coordinate, using the even-Y lift convention from BIP340.
//
// Example:
//
//	xOnly := [32]byte{0x12, 0x34, 0x56, ...}
//	publicKey, err := ParseXOnly(xOnly)
//	// Result: Full public key with even Y coordinate
func ParseXOnly(x32 [32]byte) (*btcec.PublicKey, error) {
	// Parse the x-only key using BIP340 even-Y lift convention
	pub, err := btcschnorr.ParsePubKey(x32[:])
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ParseSignature parses a 64-byte signature into a signature object
//
// This is a helper function to parse the signature from raw bytes.
// It validates the signature format and extracts the r and s components.
//
// Example:
//
//	signatureBytes := [64]byte{0x12, 0x34, 0x56, ...}
//	signature, err := ParseSignature(signatureBytes)
//	// Result: Signature object with r and s components
func ParseSignature(sigBz [64]byte) (*btcschnorr.Signature, error) {
	// Parse the 64-byte signature into a signature object
	sig, err := btcschnorr.ParseSignature(sigBz[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// JoinSig merges the r,s components of a signature into a 64-byte signature
//
// Schnorr signatures consist of two 32-byte components: r and s.
// This function combines them into the standard 64-byte format.
//
// Example:
//
//	r := [32]byte{0x12, 0x34, 0x56, ...} // First 32 bytes
//	s := [32]byte{0x78, 0x9a, 0xbc, ...} // Second 32 bytes
//	signature := JoinSig(r, s)
//	// Result: [64]byte{r (32 bytes) + s (32 bytes)}
func JoinSig(r, s [32]byte) [64]byte {
	var out [64]byte
	copy(out[:32], r[:]) // First 32 bytes: r component
	copy(out[32:], s[:]) // Second 32 bytes: s component
	return out
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
