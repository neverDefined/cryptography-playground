package base58

import "math/big"

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
	// Step 1: num = 26*256 + 43 = 6699 (big endian 26 is the most significant byte and 43 is the least significant byte)
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
	// The main loop would convert [0x1A, 0x2B] to "2zN"
	// But we need to preserve the two leading zeros
	// So we add "11" (two '1' characters) to the front
	// Final result: "112zN"
	for _, b := range data {
		if b == 0x00 {
			result = "1" + result
		} else {
			break
		}
	}

	return result
}
