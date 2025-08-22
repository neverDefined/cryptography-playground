# Base58 Cryptography Package

A Go implementation of Base58 encoding and Base58Check encoding/decoding, commonly used in Bitcoin and other cryptocurrency applications.

## Overview

This package provides robust Base58 encoding and decoding with support for:
- **Base58 encoding/decoding** of byte arrays
- **Base58Check encoding/decoding** with version bytes and checksums
- **Leading zero preservation** for cryptographic applications
- **Comprehensive error handling** and validation

## Features

### ✅ Base58 Encoding
- Converts byte arrays to human-readable strings
- Uses the standard Base58 alphabet (no 0, O, I, l characters)
- Preserves leading zeros correctly
- Handles empty inputs gracefully

### ✅ Base58Check Encoding
- Adds version byte and checksum to Base58 encoding
- Provides error detection for typos and corruption
- Supports different address types (mainnet, testnet, etc.)
- Uses double SHA256 for checksum calculation

### ✅ Comprehensive Testing
- Unit tests for all functions
- Round-trip validation (encode → decode → verify)
- Error case testing
- Real-world Bitcoin address examples

## Installation

```bash
go get github.com/neverDefined/cryptography-playground/pkg/base58
```

## Usage

### Basic Base58 Encoding/Decoding

```go
package main

import (
    "fmt"
    "github.com/neverDefined/cryptography-playground/pkg/base58"
)

func main() {
    // Encode bytes to Base58
    data := []byte{0x1A, 0x2B}
    encoded := base58.Encode(data)
    fmt.Printf("Encoded: %s\n", encoded) // Output: "2zW"

    // Decode Base58 back to bytes
    decoded, err := base58.Decode(encoded)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decoded: %v\n", decoded) // Output: [26 43]
}
```

### Base58Check Encoding/Decoding

```go
package main

import (
    "fmt"
    "github.com/neverDefined/cryptography-playground/pkg/base58"
)

func main() {
    // Encode with version byte and checksum
    version := byte(0x00) // Bitcoin mainnet
    payload := []byte{0x1A, 0x2B}
    encoded := base58.Base58CheckEncode(version, payload)
    fmt.Printf("Base58Check encoded: %s\n", encoded) // Output: "1E2riae4C"

    // Decode and validate checksum
    decodedPayload, decodedVersion, err := base58.Base58CheckDecode(encoded)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Version: %d, Payload: %v\n", decodedVersion, decodedPayload)
    // Output: Version: 0, Payload: [26 43]
}
```

### Working with Hex Strings

**Important Note**: When comparing with online Base58 encoders, be aware that they often interpret input as hex strings:

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/neverDefined/cryptography-playground/pkg/base58"
)

func main() {
    // Online encoder input: "000000ab34" (hex string)
    // This represents 5 bytes: [0x00, 0x00, 0x00, 0xab, 0x34]
    hexString := "000000ab34"
    bytes, _ := hex.DecodeString(hexString)
    
    fmt.Printf("Hex string: %s\n", hexString)
    fmt.Printf("As bytes: %v\n", bytes)
    fmt.Printf("Base58 encoded: %s\n", base58.Encode(bytes))
    // Output: "111E2f"
    
    // Direct byte array (6 bytes)
    directBytes := []byte{0x00, 0x00, 0x00, 0x00, 0xab, 0x34}
    fmt.Printf("Direct bytes: %v\n", directBytes)
    fmt.Printf("Base58 encoded: %s\n", base58.Encode(directBytes))
    // Output: "1111E2f" (note the extra '1')
}
```

## API Reference

### Base58 Functions

#### `Encode(data []byte) string`
Encodes a byte slice to Base58 string.

**Parameters:**
- `data`: Byte slice to encode

**Returns:**
- Base58 encoded string

**Example:**
```go
encoded := base58.Encode([]byte{0x1A, 0x2B}) // Returns "2zW"
```

#### `Decode(data string) ([]byte, error)`
Decodes a Base58 string to byte slice.

**Parameters:**
- `data`: Base58 string to decode

**Returns:**
- Decoded byte slice and error (if any)

**Example:**
```go
decoded, err := base58.Decode("2zW") // Returns []byte{0x1A, 0x2B}, nil
```

### Base58Check Functions

#### `Base58CheckEncode(version byte, payload []byte) string`
Encodes payload with version byte and checksum using Base58Check format.

**Parameters:**
- `version`: Version byte (e.g., 0x00 for Bitcoin mainnet, 0x6F for testnet)
- `payload`: Data to encode

**Returns:**
- Base58Check encoded string

**Format:**
```
[version][payload][checksum] → Base58 encoded
```

#### `Base58CheckDecode(data string) ([]byte, byte, error)`
Decodes a Base58Check string and validates the checksum.

**Parameters:**
- `data`: Base58Check string to decode

**Returns:**
- `payload`: Original data without version and checksum
- `version`: Version byte
- `error`: Error if validation fails

## How It Works

### Base58 Encoding Algorithm

1. **Convert bytes to big integer** (big-endian)
2. **Repeatedly divide by 58** and use remainders to index alphabet
3. **Build result string** by prepending characters (reverse order)
4. **Handle leading zeros** by adding '1' characters

**Example:**
```
Input: [0x1A, 0x2B] (26, 43 in decimal)
Step 1: num = 26*256 + 43 = 6699
Step 2: 6699 ÷ 58 = 115 remainder 29 → alphabet[29] = 'W'
Step 3: 115 ÷ 58 = 1 remainder 57 → alphabet[57] = 'z'
Step 4: 1 ÷ 58 = 0 remainder 1 → alphabet[1] = '2'
Result: "2zW"
```

### Base58Check Encoding Algorithm

1. **Combine version + payload**: `[version][payload]`
2. **Calculate double SHA256**: `SHA256(SHA256(data))`
3. **Extract checksum**: First 4 bytes of double SHA256
4. **Combine all parts**: `[version][payload][checksum]`
5. **Base58 encode**: Convert to Base58 string

**Example:**
```
Input: version 0x00, payload [0x1A, 0x2B]
Step 1: data = [0x00, 0x1A, 0x2B]
Step 2: double SHA256 → [0x12, 0x34, 0x56, 0x78, ...]
Step 3: checksum = [0x12, 0x34, 0x56, 0x78]
Step 4: dataToEncode = [0x00, 0x1A, 0x2B, 0x12, 0x34, 0x56, 0x78]
Step 5: Base58 encode → "1E2riae4C"
```

## Alphabet

The package uses the standard Base58 alphabet:
```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

**Note:** Characters `0`, `O`, `I`, and `l` are excluded to prevent confusion.

## Testing

Run the test suite:

```bash
# Run all tests
go test ./pkg/base58

# Run with verbose output
go test ./pkg/base58 -v

# Run specific test
go test ./pkg/base58 -run TestBase58CheckEncode
```

### Test Coverage

The package includes tests for:
- ✅ Basic Base58 encoding/decoding
- ✅ Leading zero handling
- ✅ Base58Check encoding/decoding
- ✅ Checksum validation
- ✅ Error cases (invalid characters, short strings)
- ✅ Round-trip validation (encode → decode → verify)
- ✅ Real-world Bitcoin address examples
- ✅ Hex string compatibility with online encoders

## Use Cases

### Cryptocurrency Applications
- **Bitcoin addresses** (mainnet and testnet)
- **Private key encoding** (WIF format)
- **Transaction IDs** and **block hashes**
- **Multi-signature addresses**

### General Applications
- **URL-safe encoding** for binary data
- **Human-readable identifiers**
- **Error-resistant data transmission**
- **QR code generation**

## Security Considerations

### Checksum Validation
- Base58Check includes a 4-byte checksum using double SHA256
- Protects against **typing errors**, **copy-paste corruption**, and **transmission errors**
- **Not designed** to prevent malicious tampering (checksums can be regenerated)
- **Primary purpose**: Error detection for human and system errors

### Leading Zero Preservation
- Base58 encoding preserves the exact number of leading zeros
- Critical for cryptographic applications where zero count is significant
- Each leading `0x00` byte becomes a `'1'` character in Base58

## Performance

The implementation uses:
- **Big integer arithmetic** for Base58 conversion
- **Standard library SHA256** for checksum calculation
- **Efficient string operations** for alphabet indexing
- **Minimal memory allocations** for typical use case## References

- [Bitcoin Base58Check Encoding](https://en.bitcoin.it/wiki/Base58Check_encoding)
- [RFC 4648 - Base Encoding](https://tools.ietf.org/html/rfc4648)
- [Bitcoin Address Format](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses)
