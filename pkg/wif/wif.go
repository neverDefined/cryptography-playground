package wif

import (
	"errors"

	"github.com/neverDefined/cryptography-playground/pkg/base58"
)

const (
	MAINNET_VERSION = 0x80
	TESTNET_VERSION = 0xEF
)

// Encode converts a private key to WIF (Wallet Import Format) string
//
// WIF format: [version][private_key][compression_flag] → Base58Check encoded
//
// Example:
//
//	privateKey := []byte{0x12, 0x34, 0x56, ...} // 32-byte private key
//	wif, err := Encode(privateKey, true, false)  // compressed, mainnet
//	// Result: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
func Encode(privateKey []byte, compressed bool, testnet bool) (string, error) {
	// Step 1: Validate private key length (must be exactly 32 bytes)
	if len(privateKey) != 32 {
		return "", errors.New("private key must be 32 bytes")
	}

	// Step 2: Choose version byte based on network
	// 0x80 = mainnet, 0xEF = testnet
	var version byte = MAINNET_VERSION
	if testnet {
		version = TESTNET_VERSION
	}

	// Step 3: Build payload: [version][private_key][compression_flag]
	// Start with private key (32 bytes)
	payload := make([]byte, 32)
	copy(payload, privateKey)

	// Add compression flag if needed (0x01 for compressed public keys)
	if compressed {
		payload = append(payload, 0x01)
	}

	// Step 4: Encode to Base58Check format
	return base58.Base58CheckEncode(version, payload), nil
}

// Decode converts a WIF (Wallet Import Format) string to a 32-byte private key and metadata
//
// WIF format: Base58Check decode → [version][private_key][compression_flag]
//
// Example:
//
//	wif := "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
//	privateKey, compressed, version, err := Decode(wif)
//	// Result: privateKey = [32]byte{0x12, 0x34, 0x56, ...}, compressed = true, version = 0x80
func Decode(wif string) ([32]byte, bool, byte, error) {
	// Step 1: Decode Base58Check string to get payload and version
	// This validates the checksum and extracts the raw bytes
	payload, version, err := base58.Base58CheckDecode(wif)
	if err != nil {
		return [32]byte{}, false, 0, err
	}

	// Step 2: Determine compression and validate payload length
	// WIF can be 32 bytes (uncompressed) or 33 bytes (compressed with 0x01 flag)
	var compressed bool
	if len(payload) == 33 {
		// Step 2a: Check if the last byte is the compression flag (0x01)
		flag := payload[len(payload)-1]
		if flag != 0x01 {
			return [32]byte{}, false, 0, errors.New("invalid compression flag: expected 0x01")
		}
		compressed = true
	} else if len(payload) != 32 {
		// Step 2b: Payload must be exactly 32 or 33 bytes
		return [32]byte{}, false, 0, errors.New("invalid payload length: expected 32 or 33 bytes")
	}

	// Step 3: Extract the 32-byte private key
	// For compressed: payload[0:32] (first 32 bytes)
	// For uncompressed: payload[0:32] (all 32 bytes)
	var privateKey [32]byte
	copy(privateKey[:], payload[:32])

	// Step 4: Validate version byte and return it
	// 0x80 = mainnet, 0xEF = testnet
	if version != MAINNET_VERSION && version != TESTNET_VERSION {
		return [32]byte{}, false, 0, errors.New("invalid version byte: expected 0x80 (mainnet) or 0xEF (testnet)")
	}

	return privateKey, compressed, version, nil
}
