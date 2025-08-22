package base58

import (
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
	for _, b := range data {
		if b == 0x00 {
			result = "1" + result
		} else {
			break
		}
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
