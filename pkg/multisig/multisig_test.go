package multisig

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/neverDefined/cryptography-playground/pkg/arithmetic"
)

// TestMultisigSetup tests the creation and validation of multisignature setups
func TestMultisigSetup(t *testing.T) {
	// Generate test participants
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate private key: %v", err)
		}
		participants[i] = &Participant{
			PrivateKey: priv,
			PublicKey:  priv.PubKey(),
			Index:      i,
		}
	}

	// Test valid setup
	setup, err := NewMultisigSetup(participants, 2)
	if err != nil {
		t.Fatalf("Failed to create valid setup: %v", err)
	}
	if setup.Threshold != 2 {
		t.Errorf("Expected threshold 2, got %d", setup.Threshold)
	}
	if setup.Total != 3 {
		t.Errorf("Expected total 3, got %d", setup.Total)
	}

	// Test invalid setups
	_, err = NewMultisigSetup([]*Participant{}, 1)
	if err == nil {
		t.Error("Expected error for empty participants")
	}

	_, err = NewMultisigSetup(participants, 0)
	if err == nil {
		t.Error("Expected error for zero threshold")
	}

	_, err = NewMultisigSetup(participants, 4)
	if err == nil {
		t.Error("Expected error for threshold exceeding participants")
	}
}

// TestPartialSignature tests the creation of partial signatures
func TestPartialSignature(t *testing.T) {
	// Generate test participant
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	participant := &Participant{
		PrivateKey: priv,
		PublicKey:  priv.PubKey(),
		Index:      0,
	}

	// Create setup
	setup, err := NewMultisigSetup([]*Participant{participant}, 1)
	if err != nil {
		t.Fatalf("Failed to create setup: %v", err)
	}

	// Test valid partial signature
	msg := []byte("Test message for partial signature")
	partialSig, err := CreatePartialSignature(msg, participant, setup)
	if err != nil {
		t.Fatalf("Failed to create partial signature: %v", err)
	}

	if partialSig.Index != 0 {
		t.Errorf("Expected index 0, got %d", partialSig.Index)
	}

	// Test error cases
	_, err = CreatePartialSignature([]byte{}, participant, setup)
	if err == nil {
		t.Error("Expected error for empty message")
	}

	_, err = CreatePartialSignature(msg, nil, setup)
	if err == nil {
		t.Error("Expected error for nil participant")
	}

	_, err = CreatePartialSignature(msg, participant, nil)
	if err == nil {
		t.Error("Expected error for nil setup")
	}
}

// TestCombineSignatures tests the combination of partial signatures
func TestCombineSignatures(t *testing.T) {
	// Generate test participants
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate private key: %v", err)
		}
		participants[i] = &Participant{
			PrivateKey: priv,
			PublicKey:  priv.PubKey(),
			Index:      i,
		}
	}

	// Create setup
	setup, err := NewMultisigSetup(participants, 2)
	if err != nil {
		t.Fatalf("Failed to create setup: %v", err)
	}

	// Create partial signatures
	msg := []byte("Test message for signature combination")
	partialSigs := make([]*PartialSignature, 2)
	for i := 0; i < 2; i++ {
		partialSig, err := CreatePartialSignature(msg, participants[i], setup)
		if err != nil {
			t.Fatalf("Failed to create partial signature: %v", err)
		}
		partialSigs[i] = partialSig
	}

	// Test valid combination
	completeSig, err := CombineSignatures(partialSigs, setup)
	if err != nil {
		t.Fatalf("Failed to combine signatures: %v", err)
	}

	if len(completeSig.PubKeys) != 2 {
		t.Errorf("Expected 2 public keys, got %d", len(completeSig.PubKeys))
	}
	if len(completeSig.Indices) != 2 {
		t.Errorf("Expected 2 indices, got %d", len(completeSig.Indices))
	}

	// Test error cases
	_, err = CombineSignatures([]*PartialSignature{}, setup)
	if err == nil {
		t.Error("Expected error for empty partial signatures")
	}

	_, err = CombineSignatures(partialSigs[:1], setup)
	if err == nil {
		t.Error("Expected error for insufficient signatures")
	}

	_, err = CombineSignatures(partialSigs, nil)
	if err == nil {
		t.Error("Expected error for nil setup")
	}
}

// TestCreateMultisignature tests the complete multisignature creation process
func TestCreateMultisignature(t *testing.T) {
	// Generate test participants
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate private key: %v", err)
		}
		participants[i] = &Participant{
			PrivateKey: priv,
			PublicKey:  priv.PubKey(),
			Index:      i,
		}
	}

	// Create setup
	setup, err := NewMultisigSetup(participants, 2)
	if err != nil {
		t.Fatalf("Failed to create setup: %v", err)
	}

	// Test valid multisignature creation
	msg := []byte("Test message for multisignature")
	completeSig, err := CreateMultisignature(msg, setup)
	if err != nil {
		t.Fatalf("Failed to create multisignature: %v", err)
	}

	if len(completeSig.PubKeys) != 2 {
		t.Errorf("Expected 2 public keys, got %d", len(completeSig.PubKeys))
	}

	// Test error cases
	_, err = CreateMultisignature([]byte{}, setup)
	if err == nil {
		t.Error("Expected error for empty message")
	}

	_, err = CreateMultisignature(msg, nil)
	if err == nil {
		t.Error("Expected error for nil setup")
	}
}

// TestSignAndVerifyMultisig tests the complete multisignature workflow
func TestSignAndVerifyMultisig(t *testing.T) {
	// Test 2-of-3 multisignature
	msg := []byte("Test message for complete workflow")
	success, err := SignAndVerifyMultisig(msg, 2, 3)
	if err != nil {
		t.Fatalf("SignAndVerifyMultisig failed: %v", err)
	}
	if !success {
		t.Error("Multisignature verification failed")
	}

	// Test 1-of-2 multisignature
	success, err = SignAndVerifyMultisig(msg, 1, 2)
	if err != nil {
		t.Fatalf("SignAndVerifyMultisig failed: %v", err)
	}
	if !success {
		t.Error("Multisignature verification failed")
	}

	// Test error case
	_, err = SignAndVerifyMultisig(msg, 3, 2)
	if err == nil {
		t.Error("Expected error for threshold exceeding total")
	}
}

// TestUtilityFunctions tests the utility functions
func TestUtilityFunctions(t *testing.T) {
	// Test ToBytes32
	input := []byte{1, 2, 3}
	result := arithmetic.ToBytes32(input)
	if len(result) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(result))
	}
	if result[31] != 3 {
		t.Errorf("Expected last byte to be 3, got %d", result[31])
	}

	// Test ModN
	x := new(big.Int).SetInt64(1000)
	resultInt := arithmetic.ModN(x)
	if resultInt.Cmp(N) >= 0 {
		t.Error("ModN result should be less than N")
	}

	// Test AddModN
	a := new(big.Int).SetInt64(100)
	b := new(big.Int).SetInt64(200)
	sum := arithmetic.AddModN(a, b)
	if sum.Cmp(N) >= 0 {
		t.Error("AddModN result should be less than N")
	}

	// Test MulModN
	product := arithmetic.MulModN(a, b)
	if product.Cmp(N) >= 0 {
		t.Error("MulModN result should be less than N")
	}

	// Test NegModN
	neg := arithmetic.NegModN(a)
	if neg.Cmp(N) >= 0 {
		t.Error("NegModN result should be less than N")
	}

	// Test RandScalar
	scalar, err := arithmetic.RandScalar()
	if err != nil {
		t.Fatalf("RandScalar failed: %v", err)
	}
	if scalar.Cmp(N) >= 0 {
		t.Error("RandScalar result should be less than N")
	}
	if scalar.Sign() <= 0 {
		t.Error("RandScalar result should be positive")
	}
}

// TestMultisigExamples demonstrates the example usage patterns
func TestMultisigExamples(t *testing.T) {
	t.Run("NewMultisigSetup Example", func(t *testing.T) {
		// Generate participants
		participants := make([]*Participant, 3)
		for i := 0; i < 3; i++ {
			priv, _ := btcec.NewPrivateKey()
			participants[i] = &Participant{
				PrivateKey: priv,
				PublicKey:  priv.PubKey(),
				Index:      i,
			}
		}

		// Create setup
		setup, err := NewMultisigSetup(participants, 2) // 2-of-3 multisig
		if err != nil {
			t.Fatalf("NewMultisigSetup failed: %v", err)
		}

		t.Logf("Created %d-of-%d multisignature setup", setup.Threshold, setup.Total)
		t.Logf("✓ NewMultisigSetup example successful")
	})

	t.Run("CreatePartialSignature Example", func(t *testing.T) {
		// Generate participant
		priv, _ := btcec.NewPrivateKey()
		participant := &Participant{
			PrivateKey: priv,
			PublicKey:  priv.PubKey(),
			Index:      0,
		}

		// Create setup
		setup, _ := NewMultisigSetup([]*Participant{participant}, 1)

		// Create partial signature
		msg := []byte("Hello, multisig!")
		partialSig, err := CreatePartialSignature(msg, participant, setup)
		if err != nil {
			t.Fatalf("CreatePartialSignature failed: %v", err)
		}

		t.Logf("Created partial signature from participant %d", partialSig.Index)
		t.Logf("✓ CreatePartialSignature example successful")
	})

	t.Run("CreateMultisignature Example", func(t *testing.T) {
		// Generate participants
		participants := make([]*Participant, 2)
		for i := 0; i < 2; i++ {
			priv, _ := btcec.NewPrivateKey()
			participants[i] = &Participant{
				PrivateKey: priv,
				PublicKey:  priv.PubKey(),
				Index:      i,
			}
		}

		// Create setup
		setup, _ := NewMultisigSetup(participants, 2)

		// Create multisignature
		msg := []byte("Hello, multisig!")
		completeSig, err := CreateMultisignature(msg, setup)
		if err != nil {
			t.Fatalf("CreateMultisignature failed: %v", err)
		}

		t.Logf("Created multisignature with %d participants", len(completeSig.PubKeys))
		t.Logf("✓ CreateMultisignature example successful")
	})

	t.Run("SignAndVerifyMultisig Example", func(t *testing.T) {
		// Test the complete workflow
		message := []byte("Test message")
		success, err := SignAndVerifyMultisig(message, 2, 3)
		if err != nil {
			t.Fatalf("SignAndVerifyMultisig failed: %v", err)
		}
		if !success {
			t.Error("SignAndVerifyMultisig should return true")
		}

		t.Logf("Multisignature workflow successful: %t", success)
		t.Logf("✓ SignAndVerifyMultisig example successful")
	})
}
