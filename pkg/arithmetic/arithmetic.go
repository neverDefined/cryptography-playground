package arithmetic

import (
	"crypto/rand"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

var (
	// CURVE is the secp256k1 curve used for Bitcoin
	CURVE = btcec.S256()
	// N is the order of the secp256k1 curve
	N = CURVE.N
)

// ToBytes32 converts a byte slice to a 32-byte slice, padding with zeros if necessary
//
// This function is useful for converting variable-length byte slices to fixed-length
// 32-byte slices, which is required for many cryptographic operations.
//
// Example:
//
//	ToBytes32([]byte{1, 2, 3}) -> [0x00,0x00 ... 0x01, 0x02, 0x03]
func ToBytes32(b []byte) [32]byte {
	var out [32]byte
	if len(b) > 32 {
		// If input is longer than 32 bytes, take the rightmost 32 bytes
		copy(out[:], b[len(b)-32:])
	} else {
		// Otherwise, copy to the right side and pad with zeros
		copy(out[32-len(b):], b)
	}
	return out
}

// ModN performs modular arithmetic with the curve order N
//
// This ensures that all values are within the valid range for the secp256k1 curve.
// If the result is negative, it adds N to make it positive.
func ModN(x *big.Int) *big.Int {
	x.Mod(x, N)
	if x.Sign() < 0 {
		x.Add(x, N)
	}
	return x
}

// AddModN adds two big integers modulo N
func AddModN(a, b *big.Int) *big.Int {
	out := new(big.Int).Add(a, b)
	return ModN(out)
}

// MulModN multiplies two big integers modulo N
func MulModN(a, b *big.Int) *big.Int {
	out := new(big.Int).Mul(a, b)
	return ModN(out)
}

// NegModN negates a big integer modulo N
func NegModN(a *big.Int) *big.Int {
	out := new(big.Int).Sub(N, a)
	return ModN(out)
}

// RandScalar generates a random scalar (private key) for the secp256k1 curve
//
// This function generates a cryptographically secure random number that is
// suitable for use as a private key or nonce in cryptographic operations.
func RandScalar() (*big.Int, error) {
	for {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(buf[:])
		k.Mod(k, N)
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

// GetCurveOrder returns the order of the secp256k1 curve
func GetCurveOrder() *big.Int {
	return N
}

// GetCurve returns the secp256k1 curve
func GetCurve() *btcec.KoblitzCurve {
	return CURVE
}
