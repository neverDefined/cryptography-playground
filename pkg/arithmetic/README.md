# Arithmetic Package

This package provides shared arithmetic utilities for cryptographic operations, specifically designed for the secp256k1 elliptic curve used in Bitcoin and other cryptocurrencies.

## Purpose

The arithmetic package centralizes common mathematical operations used across multiple cryptographic packages:

- **Modular arithmetic** operations for the secp256k1 curve order
- **Byte conversion utilities** for fixed-length arrays
- **Random scalar generation** for cryptographic operations
- **Curve constants** and accessor functions

## Mathematical Foundation

### Modular Arithmetic

All arithmetic operations in elliptic curve cryptography are performed modulo the curve order `N`. For secp256k1:

```
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

This is approximately 2²⁵⁶, ensuring that all scalar values fit within the curve's cyclic group.

### Why Modular Arithmetic?

1. **Finite Field Operations**: Elliptic curve operations work in a finite field
2. **Cyclic Group Properties**: The curve points form a cyclic group of order N
3. **Security**: Prevents overflow and ensures mathematical correctness
4. **Standardization**: Follows established cryptographic standards

## Functions

### ToBytes32

Converts variable-length byte slices to fixed 32-byte arrays:

```go
func ToBytes32(b []byte) [32]byte
```

**Use Cases:**
- Converting private keys to fixed format
- Preparing data for cryptographic operations
- Ensuring consistent byte lengths

**Example:**
```go
input := []byte{1, 2, 3}
result := ToBytes32(input)
// result: [0x00, 0x00, ..., 0x01, 0x02, 0x03]
```

### ModN

Performs modular arithmetic with the curve order:

```go
func ModN(x *big.Int) *big.Int
```

**Mathematical Operation:**
```
result = x mod N
if result < 0:
    result = result + N
```

**Properties:**
- Ensures result is in range [0, N-1]
- Handles negative numbers correctly
- Maintains mathematical consistency

### AddModN

Adds two integers modulo N:

```go
func AddModN(a, b *big.Int) *big.Int
```

**Mathematical Operation:**
```
result = (a + b) mod N
```

**Example:**
```go
a := big.NewInt(100)
b := big.NewInt(200)
result := AddModN(a, b) // 300 mod N
```

### MulModN

Multiplies two integers modulo N:

```go
func MulModN(a, b *big.Int) *big.Int
```

**Mathematical Operation:**
```
result = (a * b) mod N
```

**Example:**
```go
a := big.NewInt(100)
b := big.NewInt(200)
result := MulModN(a, b) // 20000 mod N
```

### NegModN

Negates an integer modulo N:

```go
func NegModN(a *big.Int) *big.Int
```

**Mathematical Operation:**
```
result = (-a) mod N = (N - a) mod N
```

**Example:**
```go
a := big.NewInt(100)
result := NegModN(a) // (N - 100) mod N
```

### RandScalar

Generates a cryptographically secure random scalar:

```go
func RandScalar() (*big.Int, error)
```

**Properties:**
- Cryptographically secure random number generation
- Ensures result is in range [1, N-1]
- Suitable for private keys and nonces
- Handles edge cases (zero values)

**Use Cases:**
- Private key generation
- Nonce generation for signatures
- Random scalar for cryptographic protocols

### GetCurveOrder

Returns the order of the secp256k1 curve:

```go
func GetCurveOrder() *big.Int
```

**Value:**
```
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

### GetCurve

Returns the secp256k1 curve:

```go
func GetCurve() *btcec.KoblitzCurve
```

## Mathematical Examples

### Basic Modular Arithmetic

```go
// Addition
a := big.NewInt(1000)
b := big.NewInt(2000)
sum := AddModN(a, b) // (1000 + 2000) mod N

// Multiplication
product := MulModN(a, b) // (1000 * 2000) mod N

// Negation
neg := NegModN(a) // (N - 1000) mod N
```

### Random Scalar Generation

```go
// Generate a random scalar for private key
privateKey, err := RandScalar()
if err != nil {
    // Handle error
}

// Generate a random nonce for signature
nonce, err := RandScalar()
if err != nil {
    // Handle error
}
```

### Byte Conversion

```go
// Convert private key to 32-byte format
privateKeyBytes := privateKey.Bytes()
fixedBytes := ToBytes32(privateKeyBytes)

// Convert message hash to 32-byte format
messageHash := sha256.Sum256([]byte("Hello"))
fixedHash := ToBytes32(messageHash[:])
```

## Security Considerations

### Random Number Generation

- **Cryptographic Quality**: Uses `crypto/rand` for secure random generation
- **Range Validation**: Ensures generated values are in valid range [1, N-1]
- **Zero Handling**: Rejects zero values and regenerates if necessary

### Modular Arithmetic

- **Overflow Prevention**: All operations are performed modulo N
- **Negative Handling**: Properly handles negative numbers
- **Consistency**: Ensures mathematical consistency across operations

### Input Validation

- **Null Checks**: Functions handle nil inputs gracefully
- **Range Validation**: Ensures inputs are within valid ranges
- **Error Handling**: Returns appropriate errors for invalid inputs

## Performance Characteristics

### Computational Complexity

- **ModN**: O(log N) - depends on integer size
- **AddModN**: O(log N) - addition + modular reduction
- **MulModN**: O(log² N) - multiplication + modular reduction
- **NegModN**: O(log N) - subtraction + modular reduction
- **RandScalar**: O(1) average case, O(∞) worst case (unlikely)

### Memory Usage

- **ToBytes32**: 32 bytes output
- **Modular Operations**: O(log N) temporary storage
- **RandScalar**: 32 bytes for random generation

## Integration with Other Packages

### Schnorr Package

The schnorr package uses arithmetic functions for:
- Nonce generation (`RandScalar`)
- Signature component calculations (`ModN`, `AddModN`, `MulModN`)
- Byte format conversion (`ToBytes32`)

### Multisig Package

The multisig package uses arithmetic functions for:
- Partial signature calculations
- Signature combination
- Threshold verification
- Key aggregation

### Hash Package

The hash package may use arithmetic functions for:
- Merkle tree calculations
- Hash-based operations
- Byte format conversions

## Best Practices

### 1. Use Shared Functions

Always use the arithmetic package functions instead of implementing your own:

```go
// Good
result := arithmetic.AddModN(a, b)

// Bad
result := new(big.Int).Add(a, b)
result.Mod(result, N)
```

### 2. Handle Errors

Always check for errors in random generation:

```go
scalar, err := arithmetic.RandScalar()
if err != nil {
    return err
}
```

### 3. Use Consistent Types

Use `*big.Int` for all scalar operations:

```go
// Good
a := big.NewInt(100)
b := big.NewInt(200)
result := arithmetic.AddModN(a, b)

// Bad
a := 100
b := 200
// This won't work with arithmetic functions
```

### 4. Validate Inputs

Validate inputs before passing to arithmetic functions:

```go
if privateKey == nil || privateKey.Sign() <= 0 {
    return errors.New("invalid private key")
}
result := arithmetic.ModN(privateKey)
```

## Testing

The arithmetic package includes comprehensive tests:

```bash
go test ./pkg/arithmetic/...
```

Tests cover:
- Modular arithmetic operations
- Random scalar generation
- Byte conversion utilities
- Edge cases and error conditions
- Performance benchmarks

## Conclusion

The arithmetic package provides essential mathematical utilities for cryptographic operations. By centralizing these functions, we ensure:

- **Consistency**: All packages use the same mathematical operations
- **Security**: Proper implementation of cryptographic arithmetic
- **Maintainability**: Single source of truth for arithmetic operations
- **Performance**: Optimized implementations for common operations

This package serves as the mathematical foundation for all cryptographic operations in the project.
