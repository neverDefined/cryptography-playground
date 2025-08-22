package base58

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// The alphabet that we are going to use for encoding and decoding Base58 strings.
// The alphabet consists of the following characters:
// 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
const alphabet string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Encode encodes a byte slice into a Base58 string.
func Encode(data []byte) string {
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	result := ""

	// Example: encoding [0x1A, 0x2B] (26, 43 in decimal)
	// Step 1: num = 26*256 + 43 = 6699 (big-endian: 26 is MSB, 43 is LSB)
	// Step 2: 6699 ÷ 58 = 115 remainder 29 → alphabet[29] = 'W'
	// Step 3: 115 ÷ 58 = 1 remainder 57 → alphabet[57] = 'z'
	// Step 4: 1 ÷ 58 = 0 remainder 1 → alphabet[1] = '2'
	// Result: "2zW" (reading remainders in reverse order)
	for num.Cmp(zero) > 0 {
		mod := new(big.Int)
		num.DivMod(num, base, mod)                      // divide num by 58 and store the remainder in mod
		result = string(alphabet[mod.Int64()]) + result // add the character to the result, prepend it to the result
	}

	// Handle leading zeros (add '1' for each 0x00 byte)
	// Example: encoding [0x00, 0x00, 0x1A, 0x2B]
	// The main loop would convert [0x1A, 0x2B] to "2zW"
	// But we need to preserve the two leading zeros
	// So we add "11" (two '1' characters) to the front
	// Final result: "112zW"
	leadingZeroCount := 0
	for _, b := range data {
		if b == 0x00 {
			leadingZeroCount++
		} else {
			break
		}
	}

	// Add '1' characters for each leading zero
	for i := 0; i < leadingZeroCount; i++ {
		result = "1" + result
	}

	return result
}

// Decode decodes a Base58 string into a byte slice.
func Decode(data string) ([]byte, error) {
	// Handle empty string
	if data == "" {
		return []byte{}, nil
	}

	num := big.NewInt(0)
	base := big.NewInt(58)

	// Example: decoding "2zW"
	// Step 1: '2' = alphabet[1] = 1 → num = 0*58 + 1 = 1
	// Step 2: 'z' = alphabet[57] = 57 → num = 1*58 + 57 = 115
	// Step 3: 'W' = alphabet[29] = 29 → num = 115*58 + 29 = 6699
	// Result: 6699 in decimal = [0x1A, 0x2B] in bytes
	for _, char := range data {
		// Find the position of the character in the alphabet
		pos := strings.IndexRune(alphabet, char)
		if pos == -1 {
			return nil, fmt.Errorf("invalid character: %c", char)
		}

		// Multiply current number by 58 and add the new digit
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(pos)))
	}

	// Convert the big int to a byte slice
	decodedBytes := num.Bytes()

	// Handle leading '1' characters (which represent 0x00 bytes)
	// Example: decoding "112zW"
	// We found 2 leading '1' characters, so we need to add 2 leading 0x00 bytes
	// result = [0x1A, 0x2B] becomes [0x00, 0x00, 0x1A, 0x2B]
	leadingZeroCount := 0
	for _, char := range data {
		if char == '1' {
			leadingZeroCount++
		} else {
			break
		}
	}

	// Create the result byte slice with: [leadingZeroCount] + [decodedBytes]
	result := append(make([]byte, leadingZeroCount), decodedBytes...)

	return result, nil
}

// Base58CheckEncode creates a Base58Check encoded string with version byte and checksum.
// This is commonly used in Bitcoin addresses and other cryptocurrency applications.
//
// The Base58Check format is: [version][payload][checksum] → Base58 encoded
//
// Verified examples from tests:
// - version 0x00, payload [] → "1Wh4bh"
// - version 0x00, payload [0x1A, 0x2B] → "1E2riae4C"
// - version 0x00, payload [0x60, 0x23, 0xBD, ...] → "19mLgd5RjgEcyGfnj5ra4gW8FjtvLc2Adr"
// - version 0x6F, payload [0x60, 0x23, 0xBD, ...] → "mpHHygAQYhfskP9QSepwtbiT7jVdFgjEA8"
func Base58CheckEncode(version byte, payload []byte) string {
	// Step 1: Combine version byte with payload
	// Example: version 0x00, payload [0x1A, 0x2B] → data = [0x00, 0x1A, 0x2B]
	// The version byte indicates the type of address (0x00 = Bitcoin mainnet, 0x6F = Bitcoin testnet)
	data := append([]byte{version}, payload...)

	// Step 2: Calculate double SHA256 hash of the data
	// Example: SHA256([0x00, 0x1A, 0x2B]) → SHA256(result) → [0x12, 0x34, 0x56, 0x78, ...]
	// This provides cryptographic integrity checking
	hash256 := sha256.Sum256(data)
	hash256d := sha256.Sum256(hash256[:])

	// Step 3: Extract first 4 bytes as checksum
	// Example: checksum = [0x12, 0x34, 0x56, 0x78]
	// The checksum allows detection of typos or corruption
	checksum := hash256d[:4]

	// Step 4: Combine original data with checksum
	// Example: [0x00, 0x1A, 0x2B, 0x12, 0x34, 0x56, 0x78]
	// Final format: [version][payload][checksum]
	dataToEncode := append(data, checksum...)

	// Step 5: Encode the complete data to Base58
	// Example: [0x00, 0x1A, 0x2B, 0x12, 0x34, 0x56, 0x78] → "1E2riae4C"
	return Encode(dataToEncode)
}

// Base58CheckDecode decodes a Base58Check string and returns the payload, version, and validates the checksum.
// This is the reverse operation of Base58CheckEncode.
//
// The Base58Check format is: [version][payload][checksum] → Base58 encoded
// When decoding: Base58 decode → [version][payload][checksum] → validate checksum → return payload and version
//
// Returns: (payload, version, error)
// - payload: the original data without version and checksum
// - version: the version byte (0x00 = Bitcoin mainnet, 0x6F = Bitcoin testnet)
// - error: nil if successful, error message if validation fails
//
// Verified examples from tests:
// - "1E2riae4C" → (payload: [0x1A, 0x2B], version: 0x00)
// - "1Wh4bh" → (payload: [], version: 0x00)
// - "19mLgd5RjgEcyGfnj5ra4gW8FjtvLc2Adr" → (payload: [0x60, 0x23, ...], version: 0x00)
// - "mpHHygAQYhfskP9QSepwtbiT7jVdFgjEA8" → (payload: [0x60, 0x23, ...], version: 0x6F)
func Base58CheckDecode(data string) ([]byte, byte, error) {
	// Step 1: Decode the Base58 string to get the raw bytes
	// Example: "1E2riae4C" → [0x00, 0x1A, 0x2B, 0x12, 0x34, 0x56, 0x78]
	decoded, err := Decode(data)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid Base58 string: %w", err)
	}

	// Step 2: Validate minimum length (version + payload + checksum)
	// Minimum: 1 byte version + 0 bytes payload + 4 bytes checksum = 5 bytes
	if len(decoded) < 5 {
		return nil, 0, fmt.Errorf("Base58Check string too short: expected at least 5 bytes, got %d", len(decoded))
	}

	// Step 3: Extract version, payload, and checksum
	// Format: [version][payload][checksum]
	version := decoded[0]                  // First byte is version
	payload := decoded[1 : len(decoded)-4] // Middle bytes are payload
	checksum := decoded[len(decoded)-4:]   // Last 4 bytes are checksum

	// Step 4: Recalculate checksum and validate
	// Example: payload [0x1A, 0x2B] → double SHA256 → [0x12, 0x34, 0x56, 0x78]
	// Compare with stored checksum [0x12, 0x34, 0x56, 0x78]
	dataToHash := append([]byte{version}, payload...)
	hash256 := sha256.Sum256(dataToHash)
	hash256d := sha256.Sum256(hash256[:])
	expectedChecksum := hash256d[:4]

	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, 0, fmt.Errorf("checksum validation failed")
	}

	return payload, version, nil
}
