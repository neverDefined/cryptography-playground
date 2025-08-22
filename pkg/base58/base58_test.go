package base58

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{name: "empty", data: []byte{}, expected: ""},
		{name: "single byte 0", data: []byte{0x00}, expected: "1"},
		{name: "single byte 1", data: []byte{0x01}, expected: "2"},
		{name: "single byte 57", data: []byte{0x39}, expected: "z"},
		{name: "single byte 58", data: []byte{0x3A}, expected: "21"},
		{name: "two bytes example", data: []byte{0x1A, 0x2B}, expected: "2zW"},
		{name: "leading zeros", data: []byte{0x00, 0x00, 0x1A, 0x2B}, expected: "112zW"},
		{name: "bitcoin address example", data: []byte{0x00, 0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}, expected: "12LghLnSJct2kpP9M29HeRUP3uS4u"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.data)
			if got != tt.expected {
				t.Errorf("Encode() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: []byte{}},
		{name: "single byte", input: []byte{0x42}},
		{name: "two bytes", input: []byte{0x1A, 0x2B}},
		{name: "with leading zeros", input: []byte{0x00, 0x00, 0x1A, 0x2B}},
		{name: "bitcoin address bytes", input: []byte{0x00, 0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode bytes to Base58 string
			encoded := Encode(tt.input)

			// Decode Base58 string back to bytes
			decoded, err := Decode(encoded)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
				return
			}

			// Verify round trip preserves original data
			if len(decoded) != len(tt.input) {
				t.Errorf("Length mismatch: got %d, expected %d", len(decoded), len(tt.input))
				return
			}

			for i := range tt.input {
				if decoded[i] != tt.input[i] {
					t.Errorf("Byte mismatch at position %d: got %d, expected %d", i, decoded[i], tt.input[i])
				}
			}
		})
	}
}

func TestBase58CheckEncode(t *testing.T) {
	tests := []struct {
		name    string
		version byte
		payload []byte
	}{
		{name: "empty payload", version: 0x00, payload: []byte{}},
		{name: "simple payload", version: 0x00, payload: []byte{0x1A, 0x2B}},
		{name: "bitcoin mainnet", version: 0x00, payload: []byte{0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}},
		{name: "bitcoin testnet", version: 0x6F, payload: []byte{0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base58CheckEncode(tt.version, tt.payload)

			// Basic validation: result should not be empty and should be valid Base58
			if result == "" {
				t.Error("Base58CheckEncode returned empty string")
			}

			// Check that it's valid Base58 (only contains alphabet characters)
			for _, char := range result {
				if !strings.ContainsRune(alphabet, char) {
					t.Errorf("Invalid Base58 character: %c", char)
				}
			}
		})
	}
}

func TestBase58CheckDecode(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedPayload []byte
		expectedVersion byte
		expectError     bool
	}{
		{
			name:            "valid simple payload",
			input:           "1E2riae4C",
			expectedPayload: []byte{0x1A, 0x2B},
			expectedVersion: 0x00,
			expectError:     false,
		},
		{
			name:            "valid empty payload",
			input:           "1Wh4bh",
			expectedPayload: []byte{},
			expectedVersion: 0x00,
			expectError:     false,
		},
		{
			name:            "valid bitcoin mainnet",
			input:           "19mLgd5RjgEcyGfnj5ra4gW8FjtvLc2Adr",
			expectedPayload: []byte{0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26},
			expectedVersion: 0x00,
			expectError:     false,
		},
		{
			name:            "valid bitcoin testnet",
			input:           "mpHHygAQYhfskP9QSepwtbiT7jVdFgjEA8",
			expectedPayload: []byte{0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26},
			expectedVersion: 0x6F,
			expectError:     false,
		},
		{
			name:        "invalid Base58 string",
			input:       "1E2riae4C!@#",
			expectError: true,
		},
		{
			name:        "too short string",
			input:       "1234",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, version, err := Base58CheckDecode(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if version != tt.expectedVersion {
				t.Errorf("Version mismatch: got %d, expected %d", version, tt.expectedVersion)
			}

			if !bytes.Equal(payload, tt.expectedPayload) {
				t.Errorf("Payload mismatch: got %v, expected %v", payload, tt.expectedPayload)
			}
		})
	}
}

func TestBase58CheckEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		version byte
		payload []byte
	}{
		{name: "empty payload", version: 0x00, payload: []byte{}},
		{name: "simple payload", version: 0x00, payload: []byte{0x1A, 0x2B}},
		{name: "bitcoin mainnet", version: 0x00, payload: []byte{0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}},
		{name: "bitcoin testnet", version: 0x6F, payload: []byte{0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the data
			encoded := Base58CheckEncode(tt.version, tt.payload)

			// Decode the encoded data
			decodedPayload, decodedVersion, err := Base58CheckDecode(encoded)
			if err != nil {
				t.Errorf("Decode error: %v", err)
				return
			}

			// Verify round trip
			if decodedVersion != tt.version {
				t.Errorf("Version mismatch: got %d, expected %d", decodedVersion, tt.version)
			}

			if !bytes.Equal(decodedPayload, tt.payload) {
				t.Errorf("Payload mismatch: got %v, expected %v", decodedPayload, tt.payload)
			}
		})
	}
}
