package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/neverDefined/cryptography-playground/pkg/schnorr"
)

func main() {
	fmt.Println("=== Bitcoin Taproot Schnorr Signature Example ===")

	// 1) Key generation
	fmt.Println("1) Generating Bitcoin key pair...")
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.PubKey()

	fmt.Printf("   Private key: %x\n", priv.Key.Bytes())
	fmt.Printf("   Public key (compressed): %x\n", pub.SerializeCompressed())

	// 2) Extract x-only public key (BIP340 uses 32-byte x)
	fmt.Println("\n2) Extracting x-only public key...")
	xonly := schnorr.XOnlyFromPub(pub)
	fmt.Printf("   X-only public key: %x\n", xonly)
	fmt.Printf("   Size: %d bytes (vs %d bytes for compressed)\n", len(xonly), len(pub.SerializeCompressed()))

	// 3) Sign arbitrary message bytes (BIP340 takes arbitrary-length msg)
	fmt.Println("\n3) Signing message with Schnorr...")
	msg := []byte("Taproot says hello")
	sig, err := schnorr.SignBIP340(msg, priv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Message: %q\n", string(msg))
	fmt.Printf("   Signature (64B): %x\n", sig[:])

	// 4) Verify using full public key
	fmt.Println("\n4) Verifying with full public key...")
	ok := schnorr.VerifyBIP340(msg, pub, sig)
	fmt.Printf("   Verify w/ full pub: %v\n", ok)

	// 5) Verify using x-only public key
	fmt.Println("\n5) Verifying with x-only public key...")
	ok2, err := schnorr.VerifyWithXOnly(msg, sig, xonly)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Verify w/ x-only pub: %v\n", ok2)

	// 6) Negative test (tamper message)
	fmt.Println("\n6) Testing tampered message...")
	ok3, _ := schnorr.VerifyWithXOnly([]byte("Taproot says hELlo"), sig, xonly)
	fmt.Printf("   Verify tampered msg: %v\n", ok3)

	// 7) Demonstrate round-trip conversion
	fmt.Println("\n7) Testing round-trip conversion...")
	reconstructedPub, err := schnorr.ParseXOnly(xonly)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Reconstructed public key: %x\n", reconstructedPub.SerializeCompressed())
	reconstructedXOnly := schnorr.XOnlyFromPub(reconstructedPub)
	fmt.Printf("   X-coordinates match: %v\n", hex.EncodeToString(reconstructedXOnly[:]) == hex.EncodeToString(xonly[:]))

	// 8) Show signature components
	fmt.Println("\n8) Signature components...")
	r := sig[:32] // First 32 bytes: r component
	s := sig[32:] // Second 32 bytes: s component
	fmt.Printf("   R component: %x\n", r)
	fmt.Printf("   S component: %x\n", s)

	// Reconstruct signature
	reconstructedSig := schnorr.JoinSig([32]byte(r), [32]byte(s))
	fmt.Printf("   Reconstructed signature: %x\n", reconstructedSig[:])
	fmt.Printf("   Signatures match: %v\n", reconstructedSig == sig)

	fmt.Println("\n=== Example completed successfully! ===")
	fmt.Println("\nKey takeaways:")
	fmt.Println("- X-only public keys save 1 byte compared to compressed keys")
	fmt.Println("- Schnorr signatures are deterministic and more secure than ECDSA")
	fmt.Println("- Taproot uses x-only keys for efficiency")
	fmt.Println("- BIP340 provides standardized Schnorr signatures for Bitcoin")
}
