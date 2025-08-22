package hash

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

// SHA256 calculates the SHA256 hash of the input data.
// SHA256 is a cryptographic hash function that produces a 256-bit (32-byte) hash.
// It's widely used in Bitcoin and other cryptocurrencies for data integrity and security.
//
// Example:
//
//	data := []byte("Hello, World!")
//	hash := SHA256(data)
//	fmt.Printf("SHA256: %x\n", hash)
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// SHA256D calculates the double SHA256 hash of the input data.
// This is SHA256 applied twice: SHA256(SHA256(data)).
// Double SHA256 is used in Bitcoin for transaction IDs, block headers, and checksums.
// It provides additional security against length extension attacks.
//
// Example:
//
//	data := []byte("transaction data")
//	doubleHash := SHA256D(data)
//	fmt.Printf("Double SHA256: %x\n", doubleHash)
func SHA256D(data []byte) [32]byte {
	sha256Hash := sha256.Sum256(data)
	return sha256.Sum256(sha256Hash[:])
}

// RIPEMD160 calculates the RIPEMD160 hash of the input data.
// RIPEMD160 is a 160-bit (20-byte) cryptographic hash function.
// It's used in Bitcoin addresses (P2PKH) to create shorter, more manageable addresses.
// RIPEMD160 is often used in combination with SHA256 (see Hash160).
//
// Example:
//
//	data := []byte("public key")
//	hash := RIPEMD160(data)
//	fmt.Printf("RIPEMD160: %x\n", hash)
func RIPEMD160(data []byte) [20]byte {
	h := ripemd160.New()
	_, _ = h.Write(data)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Hash160 calculates RIPEMD160(SHA256(data)) — commonly used for public key hashes.
// This is the standard way to create Bitcoin addresses from public keys.
// The process: SHA256(public_key) → RIPEMD160(result) → 20-byte hash
// This 20-byte hash is then Base58Check encoded to create a Bitcoin address.
//
// Use cases:
// - Bitcoin P2PKH addresses (Pay to Public Key Hash)
// - Bitcoin P2WPKH addresses (Pay to Witness Public Key Hash)
// - Creating shorter, more secure identifiers from public keys
//
// Example:
//
//	publicKey := []byte("04a1b2c3...") // 65-byte uncompressed public key
//	addressHash := Hash160(publicKey)
//	// addressHash can then be Base58Check encoded to create a Bitcoin address
func Hash160(data []byte) [20]byte {
	sha := SHA256(data)
	return RIPEMD160(sha[:])
}

// Concat concatenates two byte slices: a || b.
// This is a utility function for combining byte arrays in cryptographic operations.
// It's commonly used when building data structures for hashing or signing.
//
// Example:
//
//	version := []byte{0x00}
//	payload := []byte{0x1A, 0x2B}
//	combined := Concat(version, payload)
//	// combined = [0x00, 0x1A, 0x2B]
func Concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}
