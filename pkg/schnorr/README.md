# Schnorr Signatures: Theory and Implementation

This package provides an implementation of Schnorr signatures following Bitcoin's BIP340 standard. It demonstrates the fundamental concepts and mathematical principles behind Schnorr signatures, which are more secure and efficient than traditional ECDSA signatures.

## What Are Schnorr Signatures?

Schnorr signatures are a type of digital signature scheme based on the discrete logarithm problem. They were proposed by Claus-Peter Schnorr in 1989 and offer several advantages over ECDSA:

- **Security**: Provably secure under the discrete logarithm assumption
- **Efficiency**: Faster verification and smaller signatures
- **Linearity**: Signatures can be combined and aggregated
- **Deterministic**: Same inputs always produce the same signature
- **Batch Verification**: Multiple signatures can be verified together efficiently

## Mathematical Foundation

### Elliptic Curve Cryptography

Schnorr signatures are built on elliptic curve cryptography, specifically the secp256k1 curve used by Bitcoin:

- **Curve**: secp256k1 (y² = x³ + 7 over finite field)
- **Generator Point**: G (base point of the curve)
- **Order**: N ≈ 2²⁵⁶ (number of points in the cyclic subgroup)
- **Private Key**: d (random integer in [1, N-1])
- **Public Key**: P = d * G (elliptic curve scalar multiplication)

### Schnorr Signature Algorithm

#### Signing Process

For a message `m` and private key `d`:

1. **Generate Nonce**: Choose random `k` in [1, N-1]
2. **Calculate Commitment**: `R = k * G`
3. **Calculate Challenge**: `e = H(R || P || m)`
4. **Calculate Response**: `s = k + e * d`
5. **Output Signature**: `(R, s)`

#### Verification Process

Given signature `(R, s)`, public key `P`, and message `m`:

1. **Calculate Challenge**: `e = H(R || P || m)`
2. **Verify Equation**: `s * G = R + e * P`

### Mathematical Proof

The verification works because:

```
s * G = (k + e * d) * G
      = k * G + e * d * G
      = R + e * P
```

This is the fundamental equation that makes Schnorr signatures secure.

## BIP340 Standard

Bitcoin's BIP340 standard defines a specific implementation of Schnorr signatures:

### Key Features

1. **X-Only Public Keys**: Only the x-coordinate of the public key is used (32 bytes)
2. **Deterministic Nonces**: Nonces are derived deterministically from the private key and message
3. **Tagged Hashing**: Uses domain-separated hashing to prevent cross-protocol attacks
4. **Even-Y Convention**: Public keys are "lifted" to have even Y-coordinate

### Signature Format

- **Size**: 64 bytes
- **Format**: `[r (32 bytes)][s (32 bytes)]`
- **r**: x-coordinate of the commitment point R
- **s**: scalar response

### X-Only Public Keys

Instead of storing both x and y coordinates (65 bytes uncompressed or 33 bytes compressed), BIP340 uses only the x-coordinate:

```
Compressed: [0x02/0x03][x (32 bytes)]  # 33 bytes
X-Only:     [x (32 bytes)]             # 32 bytes
```

The y-coordinate can be recovered during verification using the even-Y lift convention.

## Advantages Over ECDSA

### 1. Security

**ECDSA Issues:**
- Nonce reuse leads to private key compromise
- Biased nonces can leak private key information
- Complex security proofs

**Schnorr Benefits:**
- Deterministic nonces prevent reuse
- Simpler security proofs
- No bias issues

### 2. Efficiency

**ECDSA:**
- Verification: 2 scalar multiplications
- Signature size: 64-65 bytes

**Schnorr:**
- Verification: 2 scalar multiplications (but simpler)
- Signature size: 64 bytes (fixed)
- Batch verification: O(n) instead of O(n²)

### 3. Linearity

**ECDSA:**
- Signatures cannot be combined
- No aggregation possible

**Schnorr:**
- Signatures can be combined: `s₁ + s₂ = (k₁ + k₂) + e * (d₁ + d₂)`
- Enables multisignatures and threshold signatures
- Key aggregation: `P₁ + P₂ = (d₁ + d₂) * G`

## Mathematical Examples

### Basic Schnorr Signature

Let's work through a simple example with small numbers:

```
Private key: d = 5
Message: m = "Hello"
Nonce: k = 3

Step 1: R = k * G = 3 * G
Step 2: e = H(R || P || m) = 2 (simplified)
Step 3: s = k + e * d = 3 + 2 * 5 = 13

Signature: (R, s) = (3*G, 13)

Verification:
s * G = 13 * G
R + e * P = 3 * G + 2 * 5 * G = 3 * G + 10 * G = 13 * G ✅
```

### Signature Aggregation

Schnorr signatures can be combined:

```
Participant 1: d₁ = 5, k₁ = 3, s₁ = 3 + e * 5
Participant 2: d₂ = 7, k₂ = 4, s₂ = 4 + e * 7

Combined signature:
s_agg = s₁ + s₂ = (3 + e * 5) + (4 + e * 7) = 7 + e * 12

Verification:
s_agg * G = (7 + e * 12) * G
R₁ + R₂ + e * (P₁ + P₂) = (3 + 4) * G + e * (5 + 7) * G = 7 * G + e * 12 * G ✅
```

### X-Only Key Recovery

Given x-coordinate and signature, we can recover the full public key:

```
X-coordinate: x = 0x1234...
Signature: (r, s)

1. Calculate R from r (even-Y lift)
2. Calculate e = H(R || P || m)
3. Recover P = (s * G - R) / e
```

## Security Properties

### 1. Unforgeability

Under the discrete logarithm assumption, it's computationally infeasible to forge a Schnorr signature without knowing the private key.

**Proof Sketch:**
- If an adversary can forge signatures, they can solve the discrete logarithm problem
- The discrete logarithm problem is believed to be hard on elliptic curves

### 2. Deterministic

Same inputs always produce the same signature:
- Prevents timing attacks
- Eliminates nonce reuse vulnerabilities
- Enables efficient batch verification

### 3. Random Oracle Model

Security relies on the hash function `H` behaving like a random function:
- Challenge `e` is unpredictable
- No correlation between different signatures
- Prevents various cryptographic attacks

## Implementation Details

### Nonce Generation

BIP340 uses deterministic nonce generation:

```
k = H(privkey || H(message) || x || 0x00)
```

This ensures:
- No nonce reuse
- Deterministic signatures
- Security against various attacks

### Tagged Hashing

Domain separation prevents cross-protocol attacks:

```
H(tag || tag || message)
```

Where `tag` is a protocol-specific identifier.

### Even-Y Lift

When recovering public keys from x-only format:

1. Try y-coordinate = sqrt(x³ + 7)
2. If y is odd, negate it
3. This ensures consistent even-Y convention

## Performance Characteristics

### Computational Complexity

- **Signing**: 1 scalar multiplication + 1 hash
- **Verification**: 2 scalar multiplications + 1 hash
- **Batch Verification**: n+1 scalar multiplications for n signatures

### Memory Usage

- **Private Key**: 32 bytes
- **Public Key**: 32 bytes (x-only) or 33 bytes (compressed)
- **Signature**: 64 bytes (fixed)

### Comparison with ECDSA

| Operation | ECDSA | Schnorr |
|-----------|-------|---------|
| Signing | 1 scalar mult | 1 scalar mult |
| Verification | 2 scalar mults | 2 scalar mults |
| Signature Size | 64-65 bytes | 64 bytes |
| Batch Verification | O(n²) | O(n) |
| Key Size | 33 bytes | 32 bytes |

## Use Cases

### 1. Bitcoin Taproot

Schnorr signatures enable Bitcoin's Taproot upgrade:
- More efficient multisignatures
- Better privacy through key aggregation
- Smaller transaction sizes

### 2. Multisignatures

Multiple parties can create a single signature:
- Threshold signatures
- Key aggregation
- Improved privacy

### 3. Batch Verification

Multiple signatures can be verified together:
- Reduced computational cost
- Better scalability
- Lower transaction fees

### 4. Smart Contracts

Schnorr signatures enable complex cryptographic protocols:
- Atomic swaps
- Payment channels
- Zero-knowledge proofs

## Security Considerations

### 1. Nonce Generation

**Critical**: Nonces must be:
- Random and unpredictable
- Unique for each signature
- Never reused

**BIP340 Solution**: Deterministic nonce generation prevents reuse.

### 2. Key Management

- Private keys must be kept secure
- Use hardware security modules when possible
- Implement proper key derivation

### 3. Implementation Attacks

- Timing attacks
- Side-channel attacks
- Fault injection attacks

**Mitigation**: Constant-time implementations and proper validation.

### 4. Protocol Integration

- Domain separation
- Message formatting
- Signature encoding

## Advanced Topics

### 1. Threshold Signatures

Schnorr enables efficient threshold signatures:
- n participants
- t-of-n threshold
- Single aggregated signature

### 2. Ring Signatures

Schnorr can be extended to ring signatures:
- Signer anonymity
- Linkable ring signatures
- Confidential transactions

### 3. Zero-Knowledge Proofs

Schnorr signatures are building blocks for:
- Bulletproofs
- Range proofs
- Membership proofs

### 4. Post-Quantum Security

While Schnorr is vulnerable to quantum computers, it can be:
- Upgraded to post-quantum schemes
- Used in hybrid systems
- Combined with quantum-resistant primitives

## Mathematical Deep Dive

### Elliptic Curve Operations

1. **Point Addition**: `P + Q = R`
   - Geometric construction
   - Algebraic formulas
   - Special cases (infinity point)

2. **Scalar Multiplication**: `k * G = P`
   - Double-and-add algorithm
   - Window methods
   - Constant-time implementations

3. **Modular Arithmetic**: All operations modulo N
   - Field arithmetic
   - Modular inversion
   - Montgomery multiplication

### Hash Functions

BIP340 uses SHA256 for:
- Challenge calculation
- Nonce generation
- Domain separation

Properties required:
- Collision resistance
- Preimage resistance
- Random oracle behavior

### Security Proofs

1. **Unforgeability**: Reduction to discrete logarithm
2. **Unlinkability**: Statistical indistinguishability
3. **Aggregation**: Linear combination properties

## Conclusion

Schnorr signatures represent a significant improvement over ECDSA, offering better security, efficiency, and functionality. Their linear properties enable advanced cryptographic protocols like multisignatures and threshold signatures.

The BIP340 standard provides a concrete, secure implementation that's being adopted by Bitcoin and other cryptocurrencies. Understanding the mathematical foundations is crucial for implementing and using Schnorr signatures correctly.

## Further Reading

- [BIP340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [Schnorr Signatures for Bitcoin](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [Taproot: Privacy Preserving Alternative to SegWit](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [Schnorr Digital Signature Scheme](https://en.wikipedia.org/wiki/Schnorr_signature)
- [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
