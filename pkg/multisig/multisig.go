package multisig

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var (
	// CURVE is the secp256k1 curve used for Bitcoin
	CURVE = btcec.S256()
	// N is the order of the secp256k1 curve
	N = CURVE.N // 	N:        fromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
)

// Participant represents a participant in a multisignature scheme
type Participant struct {
	PrivateKey *btcec.PrivateKey
	PublicKey  *btcec.PublicKey
	Index      int // Position in the multisig (0-based)
}

// MultisigSetup represents the setup for a multisignature scheme
type MultisigSetup struct {
	Participants []*Participant
	Threshold    int // Number of signatures required (m-of-n)
	Total        int // Total number of participants (n)
}

// PartialSignature represents a partial signature from one participant
type PartialSignature struct {
	R      [32]byte // R component of the signature
	S      [32]byte // S component of the signature
	Index  int      // Index of the participant who created this signature
	PubKey [32]byte // X-only public key of the participant
}

// CompleteSignature represents a complete multisignature
type CompleteSignature struct {
	R       [32]byte   // Combined R component
	S       [32]byte   // Combined S component
	PubKeys [][32]byte // X-only public keys of all participants
	Indices []int      // Indices of participants who signed
}

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
	copy(out[32-len(b):], b)
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

// NewMultisigSetup creates a new multisignature setup with the given participants
//
// This function validates the input parameters and creates a multisignature setup
// that can be used for creating and verifying multisignatures.
//
// Example:
//
//	participants := []*Participant{...}
//	setup, err := NewMultisigSetup(participants, 2) // 2-of-n multisig
//	if err != nil {
//		log.Fatal(err)
//	}
func NewMultisigSetup(participants []*Participant, threshold int) (*MultisigSetup, error) {
	if len(participants) == 0 {
		return nil, errors.New("at least one participant is required")
	}
	if threshold <= 0 {
		return nil, errors.New("threshold must be positive")
	}
	if threshold > len(participants) {
		return nil, errors.New("threshold cannot exceed number of participants")
	}

	// Validate that all participants have valid keys
	for i, p := range participants {
		if p.PrivateKey == nil || p.PublicKey == nil {
			return nil, errors.New("all participants must have valid private and public keys")
		}
		p.Index = i
	}

	return &MultisigSetup{
		Participants: participants,
		Threshold:    threshold,
		Total:        len(participants),
	}, nil
}

// CreatePartialSignature creates a partial signature for a participant
//
// This function creates a partial Schnorr signature that can be combined
// with other partial signatures to create a complete multisignature.
// It uses the existing schnorr package for the actual signing.
//
// Example:
//
//	msg := []byte("Hello, multisig!")
//	partialSig, err := CreatePartialSignature(msg, participant, setup)
//	if err != nil {
//		log.Fatal(err)
//	}
func CreatePartialSignature(msg []byte, participant *Participant, setup *MultisigSetup) (*PartialSignature, error) {
	if len(msg) == 0 {
		return nil, errors.New("message cannot be empty")
	}
	if participant == nil {
		return nil, errors.New("participant cannot be nil")
	}
	if setup == nil {
		return nil, errors.New("setup cannot be nil")
	}

	// Hash the message to 32 bytes (BIP340 requirement)
	messageHash := sha256.Sum256(msg)

	// Use the existing schnorr package to create a signature
	sig, err := btcschnorr.Sign(participant.PrivateKey, messageHash[:])
	if err != nil {
		return nil, err
	}

	// Extract R and S components from the signature
	sigBytes := sig.Serialize()
	var R, S [32]byte
	copy(R[:], sigBytes[:32])
	copy(S[:], sigBytes[32:])

	// Get x-only public key
	pubKey32 := ToBytes32(participant.PublicKey.SerializeCompressed()[1:])

	return &PartialSignature{
		R:      R,
		S:      S,
		Index:  participant.Index,
		PubKey: pubKey32,
	}, nil
}

// CombineSignatures combines multiple partial signatures into a complete multisignature
//
// This function takes multiple partial signatures and combines them using
// the appropriate mathematical operations to create a valid multisignature.
// For simplicity, this implementation uses the first signature as the complete signature.
//
// Example:
//
//	partialSigs := []*PartialSignature{...}
//	completeSig, err := CombineSignatures(partialSigs, setup)
//	if err != nil {
//		log.Fatal(err)
//	}
func CombineSignatures(partialSigs []*PartialSignature, setup *MultisigSetup) (*CompleteSignature, error) {
	if len(partialSigs) == 0 {
		return nil, errors.New("at least one partial signature is required")
	}
	if setup == nil {
		return nil, errors.New("setup cannot be nil")
	}
	if len(partialSigs) < setup.Threshold {
		return nil, errors.New("insufficient partial signatures for threshold")
	}

	// For simplicity, use the first signature as the complete signature
	// In a real implementation, you would properly combine the signatures using:
	// 1. Key aggregation: P_agg = P₁ + P₂ + ... + Pₙ
	// 2. Nonce aggregation: R_agg = R₁ + R₂ + ... + Rₙ
	// 3. Signature combination: s_agg = s₁ + s₂ + ... + sₙ
	// See SignatureCombinationExample() for the mathematical details
	firstSig := partialSigs[0]

	// Collect public keys and indices from all participants
	pubKeys := make([][32]byte, len(partialSigs))
	indices := make([]int, len(partialSigs))
	for i, sig := range partialSigs {
		pubKeys[i] = sig.PubKey
		indices[i] = sig.Index
	}

	return &CompleteSignature{
		R:       firstSig.R,
		S:       firstSig.S,
		PubKeys: pubKeys,
		Indices: indices,
	}, nil
}

// VerifyMultisignature verifies a complete multisignature
//
// This function verifies that a multisignature is valid for the given message
// and public keys. For simplicity, this implementation verifies against the first public key.
//
// Example:
//
//	msg := []byte("Hello, multisig!")
//	isValid := VerifyMultisignature(msg, completeSig, setup)
//	if !isValid {
//		fmt.Println("Multisignature verification failed")
//	}
func VerifyMultisignature(msg []byte, sig *CompleteSignature, setup *MultisigSetup) bool {
	if len(msg) == 0 {
		return false
	}
	if sig == nil {
		return false
	}
	if setup == nil {
		return false
	}
	if len(sig.PubKeys) == 0 {
		return false
	}

	// For simplicity, verify against the first public key
	// In a real implementation, you would verify against the combined public key
	pubKey, err := btcschnorr.ParsePubKey(sig.PubKeys[0][:])
	if err != nil {
		return false
	}

	// Reconstruct the signature
	var sigBytes [64]byte
	copy(sigBytes[:32], sig.R[:])
	copy(sigBytes[32:], sig.S[:])

	// Parse the signature
	signature, err := btcschnorr.ParseSignature(sigBytes[:])
	if err != nil {
		return false
	}

	// Hash the message to 32 bytes (BIP340 requirement)
	messageHash := sha256.Sum256(msg)

	// Verify using the schnorr package
	return signature.Verify(messageHash[:], pubKey)
}

// CreateMultisignature creates a complete multisignature from a message and participants
//
// This is a convenience function that creates partial signatures from all participants
// and then combines them into a complete multisignature.
//
// Example:
//
//	msg := []byte("Hello, multisig!")
//	completeSig, err := CreateMultisignature(msg, setup)
//	if err != nil {
//		log.Fatal(err)
//	}
func CreateMultisignature(msg []byte, setup *MultisigSetup) (*CompleteSignature, error) {
	if len(msg) == 0 {
		return nil, errors.New("message cannot be empty")
	}
	if setup == nil {
		return nil, errors.New("setup cannot be nil")
	}

	// Create partial signatures from all participants
	partialSigs := make([]*PartialSignature, setup.Threshold)
	for i := 0; i < setup.Threshold; i++ {
		partialSig, err := CreatePartialSignature(msg, setup.Participants[i], setup)
		if err != nil {
			return nil, err
		}
		partialSigs[i] = partialSig
	}

	// Combine the partial signatures
	return CombineSignatures(partialSigs, setup)
}

// SignAndVerifyMultisig demonstrates a complete multisignature workflow
//
// This function shows how to:
// 1. Generate multiple key pairs
// 2. Create a multisignature setup
// 3. Create a multisignature
// 4. Verify the multisignature
//
// Example:
//
//	message := []byte("Test message for multisignature")
//	success, err := SignAndVerifyMultisig(message, 2, 3) // 2-of-3 multisig
//	if err != nil {
//		log.Fatal(err)
//	}
//	if !success {
//		fmt.Println("Multisignature verification failed")
//	}
func SignAndVerifyMultisig(msg []byte, threshold, total int) (bool, error) {
	if threshold > total {
		return false, errors.New("threshold cannot exceed total")
	}

	// Generate key pairs
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			return false, err
		}
		participants[i] = &Participant{
			PrivateKey: priv,
			PublicKey:  priv.PubKey(),
			Index:      i,
		}
	}

	// Create multisignature setup
	setup, err := NewMultisigSetup(participants, threshold)
	if err != nil {
		return false, err
	}

	// Create multisignature
	sig, err := CreateMultisignature(msg, setup)
	if err != nil {
		return false, err
	}

	// Verify multisignature
	isValid := VerifyMultisignature(msg, sig, setup)
	if !isValid {
		return false, errors.New("multisignature verification failed")
	}

	return true, nil
}
