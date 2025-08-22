package hash

import (
	"encoding/hex"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty string",
			input:    []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "bitcoin genesis block",
			input:    []byte("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"),
			expected: "a6d72baa3db900b03e70df880e503e9164013b4d9a470853edc115776323a098",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256(tt.input)
			resultHex := hex.EncodeToString(result[:])

			if resultHex != tt.expected {
				t.Errorf("SHA256() = %s, expected %s", resultHex, tt.expected)
			}
		})
	}
}

func TestSHA256D(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty string",
			input:    []byte{},
			expected: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "042a7d64a581ef2ee983f21058801cc35663b705e6c55f62fa8e0f18ecc70989",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256D(tt.input)
			resultHex := hex.EncodeToString(result[:])

			if resultHex != tt.expected {
				t.Errorf("SHA256D() = %s, expected %s", resultHex, tt.expected)
			}
		})
	}
}

func TestRIPEMD160(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty string",
			input:    []byte{},
			expected: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "527a6a4b9a6da75607546842e0e00105350b1aaf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RIPEMD160(tt.input)
			resultHex := hex.EncodeToString(result[:])

			if resultHex != tt.expected {
				t.Errorf("RIPEMD160() = %s, expected %s", resultHex, tt.expected)
			}
		})
	}
}

func TestHash160(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty string",
			input:    []byte{},
			expected: "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "e3c83f9d9adb8fcbccc4399da8ebe609ba4352e4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Hash160(tt.input)
			resultHex := hex.EncodeToString(result[:])

			if resultHex != tt.expected {
				t.Errorf("Hash160() = %s, expected %s", resultHex, tt.expected)
			}
		})
	}
}

func TestConcat(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected []byte
	}{
		{
			name:     "empty arrays",
			a:        []byte{},
			b:        []byte{},
			expected: []byte{},
		},
		{
			name:     "version and payload",
			a:        []byte{0x00},
			b:        []byte{0x1A, 0x2B},
			expected: []byte{0x00, 0x1A, 0x2B},
		},
		{
			name:     "bitcoin address components",
			a:        []byte{0x00, 0x60, 0x23, 0xBD},
			b:        []byte{0x3F, 0x2B, 0x3B, 0xE1},
			expected: []byte{0x00, 0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Concat(tt.a, tt.b)

			if len(result) != len(tt.expected) {
				t.Errorf("Concat() length = %d, expected %d", len(result), len(tt.expected))
				return
			}

			for i := range tt.expected {
				if result[i] != tt.expected[i] {
					t.Errorf("Concat()[%d] = %d, expected %d", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestHashFunctionsConsistency(t *testing.T) {
	// Test that our hash functions are consistent with standard library
	data := []byte("test data")

	// Test SHA256 consistency
	hash1 := SHA256(data)
	hash2 := SHA256(data)

	if hash1 != hash2 {
		t.Error("SHA256 is not deterministic")
	}

	// Test SHA256D consistency
	doubleHash1 := SHA256D(data)
	doubleHash2 := SHA256D(data)

	if doubleHash1 != doubleHash2 {
		t.Error("SHA256D is not deterministic")
	}

	// Test Hash160 consistency
	hash160_1 := Hash160(data)
	hash160_2 := Hash160(data)

	if hash160_1 != hash160_2 {
		t.Error("Hash160 is not deterministic")
	}
}

func TestHash160BitcoinExample(t *testing.T) {
	// This test demonstrates how Hash160 is used in Bitcoin
	// A typical uncompressed public key (65 bytes starting with 0x04)
	publicKey := []byte{
		0x04, 0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26,
		0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26, 0x60,
		0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26, 0x60, 0x23,
		0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26,
	}

	// Calculate the public key hash (this is what becomes a Bitcoin address)
	pubKeyHash := Hash160(publicKey)

	// Verify the hash is 20 bytes (160 bits)
	if len(pubKeyHash) != 20 {
		t.Errorf("Public key hash should be 20 bytes, got %d", len(pubKeyHash))
	}

	t.Logf("Public key hash: %x", pubKeyHash)
	t.Logf("This 20-byte hash would be Base58Check encoded to create a Bitcoin address")
}
