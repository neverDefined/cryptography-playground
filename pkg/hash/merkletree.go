package hash

// Bitcoin Merkle trees: hash pairs of leaves together until you get one root hash

// MerkleRoot creates a single root hash from a list of transaction IDs
// Each transaction ID must be exactly 32 bytes
//
// Example:
//
//	tx1 := [32]byte{0xaa, 0xaa, 0xaa, ...} // 32 bytes of 0xaa
//	tx2 := [32]byte{0xbb, 0xbb, 0xbb, ...} // 32 bytes of 0xbb
//	tx3 := [32]byte{0xcc, 0xcc, 0xcc, ...} // 32 bytes of 0xcc
//	tx4 := [32]byte{0xdd, 0xdd, 0xdd, ...} // 32 bytes of 0xdd
//	leaves := [][32]byte{tx1, tx2, tx3, tx4}
//	root := MerkleRoot(leaves)
//	// Result: 0xef, 0xe8, 0xb6, 0x6f, 0x51, 0x9d, 0x51, 0x3b, 0x0f, 0xb5, 0x4d, 0xf9, 0xbf, 0xea, 0x1d, 0xa6, 0xd3, 0x15, 0x25, 0xe0, 0x4b, 0x67, 0xa7, 0xe8, 0x5f, 0xf5, 0xe9, 0x70, 0x90, 0xfb, 0x02, 0xfd
func MerkleRoot(leaves [][32]byte) [32]byte {
	// Step 1: Handle empty list - return zero hash
	if len(leaves) == 0 {
		return [32]byte{}
	}

	// Step 2: Handle single leaf - that leaf is the root
	// Example: if leaves = [0xaa, 0xaa, ...], return [0xaa, 0xaa, ...]
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Step 3: Start with the original leaves
	current := make([][32]byte, len(leaves))
	copy(current, leaves)

	// Step 4: Keep combining pairs until we have only one hash left
	for len(current) > 1 {
		next := make([][32]byte, 0)

		// Step 4a: Process pairs of hashes (go through list 2 at a time)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				// Step 4b: Two hashes found - combine them with SHA256D
				// Example: SHA256D([0xaa, ...] + [0xbb, ...]) = [0x12, 0x34, ...]
				combined := SHA256D(Concat(current[i][:], current[i+1][:]))
				next = append(next, combined)
			} else {
				// Step 4c: One hash left (odd number) - duplicate it
				// Example: SHA256D([0xcc, ...] + [0xcc, ...]) = [0x56, 0x78, ...]
				combined := SHA256D(Concat(current[i][:], current[i][:]))
				next = append(next, combined)
			}
		}

		// Step 4d: Move to next level (current becomes the combined hashes)
		current = next
	}

	// Step 5: Return the final single hash (the root)
	return current[0]
}

// MerkleProofStep is one piece of a proof path
// Example:
//
//	step := MerkleProofStep{
//	  Sibling: [32]byte{0xbb, 0xbb, 0xbb, ...}, // 32-byte sibling hash
//	  LeftIsSibling: false,                      // sibling is on the right
//	}
type MerkleProofStep struct {
	Sibling       [32]byte // The other hash at this level
	LeftIsSibling bool     // True if sibling is on the left, false if on the right
}

// VerifyMerkleProof checks if a transaction is in a block using a proof
// Example:
//
//	leaf := [32]byte{0xaa, 0xaa, 0xaa, ...} // transaction ID to verify
//	steps := []MerkleProofStep{
//	  {Sibling: [32]byte{0xbb, 0xbb, 0xbb, ...}, LeftIsSibling: false}, // sibling on right
//	  {Sibling: [32]byte{0xdd, 0xdd, 0xdd, ...}, LeftIsSibling: true},  // sibling on left
//	}
//	wantRoot := [32]byte{0xef, 0xe8, 0xb6, ...} // expected root
//	isValid, err := VerifyMerkleProof(leaf, steps, wantRoot)
func VerifyMerkleProof(leaf [32]byte, steps []MerkleProofStep, wantRoot [32]byte) (bool, error) {
	// Step 1: Handle single leaf tree - leaf must equal root
	// Example: if leaf = [0xaa, ...] and wantRoot = [0xaa, ...], return true
	if len(steps) == 0 {
		return leaf == wantRoot, nil
	}

	// Step 2: Start with the leaf we want to verify
	current := leaf

	// Step 3: Follow each step in the proof path
	for _, step := range steps {
		if step.LeftIsSibling {
			// Step 3a: Sibling is on the left - combine: sibling + current
			// Example: SHA256D([0xdd, ...] + [0x12, ...]) = [0x34, ...]
			current = SHA256D(Concat(step.Sibling[:], current[:]))
		} else {
			// Step 3b: Sibling is on the right - combine: current + sibling
			// Example: SHA256D([0xaa, ...] + [0xbb, ...]) = [0x12, ...]
			current = SHA256D(Concat(current[:], step.Sibling[:]))
		}
	}

	// Step 4: Check if we reached the expected root
	return current == wantRoot, nil
}

// Reverse32 flips the byte order (useful for converting between formats)
// Example:
//
//	bigEndian := [32]byte{0x12, 0x34, 0x56, 0x78, ...} // as shown in block explorer
//	littleEndian := Reverse32(bigEndian)                // internal Bitcoin format
//	// Result: [0x78, 0x56, 0x34, 0x12, ...] (reversed byte order)
func Reverse32(in [32]byte) (out [32]byte) {
	// Step 1: Go through each byte position
	for i := range in {
		// Step 2: Copy byte from position i to position (31-i) - this flips the order
		// Example: in[0] = 0x12 goes to out[31] = 0x12
		//          in[1] = 0x34 goes to out[30] = 0x34
		out[i] = in[31-i]
	}
	return
}
