package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/neverDefined/cryptography-playground/pkg/multisig"
)

func main() {
	fmt.Println("=== Bitcoin Multisignature Example ===")

	// 1) Generate multiple key pairs for participants
	fmt.Println("1) Generating key pairs for participants...")
	participants := make([]*multisig.Participant, 3)
	for i := range participants {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			log.Fatal(err)
		}
		participants[i] = &multisig.Participant{
			PrivateKey: priv,
			PublicKey:  priv.PubKey(),
			Index:      i,
		}
		fmt.Printf("   Participant %d: %x\n", i, priv.Key.Bytes())
	}

	// 2) Create a 2-of-3 multisignature setup
	fmt.Println("\n2) Creating 2-of-3 multisignature setup...")
	setup, err := multisig.NewMultisigSetup(participants, 2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Setup: %d-of-%d multisignature\n", setup.Threshold, setup.Total)

	// 3) Create partial signatures from participants
	fmt.Println("\n3) Creating partial signatures...")
	msg := []byte("Hello, multisignature!")
	partialSigs := make([]*multisig.PartialSignature, 2)
	for i := range partialSigs {
		partialSig, err := multisig.CreatePartialSignature(msg, participants[i], setup)
		if err != nil {
			log.Fatal(err)
		}
		partialSigs[i] = partialSig
		fmt.Printf("   Partial signature %d: R=%x, S=%x\n", i, partialSig.R, partialSig.S)
	}

	// 4) Combine partial signatures into a complete multisignature
	fmt.Println("\n4) Combining partial signatures...")
	completeSig, err := multisig.CombineSignatures(partialSigs, setup)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Complete signature: R=%x, S=%x\n", completeSig.R, completeSig.S)
	fmt.Printf("   Participants who signed: %v\n", completeSig.Indices)

	// 5) Verify the multisignature
	fmt.Println("\n5) Verifying multisignature...")
	isValid := multisig.VerifyMultisignature(msg, completeSig, setup)
	fmt.Printf("   Verification result: %v\n", isValid)

	// 6) Test with different threshold configurations
	fmt.Println("\n6) Testing different threshold configurations...")

	// Test 1-of-2
	fmt.Println("   Testing 1-of-2 multisignature...")
	success, err := multisig.SignAndVerifyMultisig(msg, 1, 2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   1-of-2 result: %v\n", success)

	// Test 2-of-3
	fmt.Println("   Testing 2-of-3 multisignature...")
	success, err = multisig.SignAndVerifyMultisig(msg, 2, 3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   2-of-3 result: %v\n", success)

	// Test 3-of-3
	fmt.Println("   Testing 3-of-3 multisignature...")
	success, err = multisig.SignAndVerifyMultisig(msg, 3, 3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   3-of-3 result: %v\n", success)

	// 7) Demonstrate utility functions
	fmt.Println("\n7) Demonstrating utility functions...")

	// Test ToBytes32
	input := []byte{1, 2, 3, 4, 5}
	result := multisig.ToBytes32(input)
	fmt.Printf("   ToBytes32([1,2,3,4,5]): %x\n", result)

	// Test modular arithmetic
	a := new(big.Int).SetInt64(100)
	b := new(big.Int).SetInt64(200)
	sum := multisig.AddModN(a, b)
	product := multisig.MulModN(a, b)
	neg := multisig.NegModN(a)
	fmt.Printf("   AddModN(100, 200): %s\n", sum.String())
	fmt.Printf("   MulModN(100, 200): %s\n", product.String())
	fmt.Printf("   NegModN(100): %s\n", neg.String())

	// Test random scalar generation
	scalar, err := multisig.RandScalar()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Random scalar: %x\n", scalar.Bytes())

	// 8) Show signature components
	fmt.Println("\n8) Signature components...")
	fmt.Printf("   Message: %q\n", string(msg))
	msgHash := sha256.Sum256(msg)
	fmt.Printf("   Message hash: %x\n", msgHash)
	fmt.Printf("   R component: %x\n", completeSig.R)
	fmt.Printf("   S component: %x\n", completeSig.S)
	fmt.Printf("   Combined signature: %x\n", append(completeSig.R[:], completeSig.S[:]...))

	// 9) Demonstrate error handling
	fmt.Println("\n9) Demonstrating error handling...")

	// Test invalid setup
	_, err = multisig.NewMultisigSetup([]*multisig.Participant{}, 1)
	if err != nil {
		fmt.Printf("   Expected error for empty participants: %v\n", err)
	}

	// Test invalid threshold
	_, err = multisig.NewMultisigSetup(participants, 0)
	if err != nil {
		fmt.Printf("   Expected error for zero threshold: %v\n", err)
	}

	// Test threshold exceeding participants
	_, err = multisig.NewMultisigSetup(participants, 4)
	if err != nil {
		fmt.Printf("   Expected error for threshold > participants: %v\n", err)
	}

	fmt.Println("\n=== Example completed successfully! ===")
	fmt.Println("\nKey takeaways:")
	fmt.Println("- Multisignatures allow m-of-n participants to sign a message")
	fmt.Println("- Partial signatures can be combined into a complete signature")
	fmt.Println("- The verification process ensures the signature is valid")
	fmt.Println("- Different threshold configurations provide different security levels")
	fmt.Println("- The implementation uses Schnorr signatures for better security")
}
