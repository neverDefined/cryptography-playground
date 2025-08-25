package arithmetic

import (
	"math/big"
	"testing"
)

// TestToBytes32 tests the ToBytes32 function
func TestToBytes32(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected [32]byte
	}{
		{
			name:     "Empty input",
			input:    []byte{},
			expected: [32]byte{},
		},
		{
			name:  "Short input",
			input: []byte{1, 2, 3},
			expected: func() [32]byte {
				var out [32]byte
				copy(out[29:], []byte{1, 2, 3})
				return out
			}(),
		},
		{
			name:     "Exact 32 bytes",
			input:    make([]byte, 32),
			expected: [32]byte{},
		},
		{
			name: "Longer than 32 bytes",
			input: func() []byte {
				b := make([]byte, 40)
				for i := range b {
					b[i] = byte(i)
				}
				return b
			}(),
			expected: func() [32]byte {
				var out [32]byte
				// For inputs longer than 32 bytes, take the rightmost 32 bytes
				// The input has bytes 0-39, so we want bytes 8-39 (last 32 bytes)
				for i := 0; i < 32; i++ {
					out[i] = byte(i + 8)
				}
				return out
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ToBytes32(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %x, got %x", tc.expected, result)
			}
		})
	}
}

// TestModN tests the ModN function
func TestModN(t *testing.T) {
	N := GetCurveOrder()

	testCases := []struct {
		name     string
		input    *big.Int
		expected *big.Int
	}{
		{
			name:     "Zero",
			input:    big.NewInt(0),
			expected: big.NewInt(0),
		},
		{
			name:     "Positive number less than N",
			input:    big.NewInt(100),
			expected: big.NewInt(100),
		},
		{
			name:     "Positive number equal to N",
			input:    new(big.Int).Set(N),
			expected: big.NewInt(0),
		},
		{
			name:     "Positive number greater than N",
			input:    new(big.Int).Add(N, big.NewInt(100)),
			expected: big.NewInt(100),
		},
		{
			name:     "Negative number",
			input:    big.NewInt(-100),
			expected: new(big.Int).Sub(N, big.NewInt(100)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ModN(tc.input)
			if result.Cmp(tc.expected) != 0 {
				t.Errorf("Expected %s, got %s", tc.expected.String(), result.String())
			}
		})
	}
}

// TestAddModN tests the AddModN function
func TestAddModN(t *testing.T) {
	N := GetCurveOrder()

	testCases := []struct {
		name     string
		a        *big.Int
		b        *big.Int
		expected *big.Int
	}{
		{
			name:     "Simple addition",
			a:        big.NewInt(100),
			b:        big.NewInt(200),
			expected: big.NewInt(300),
		},
		{
			name:     "Addition with overflow",
			a:        new(big.Int).Sub(N, big.NewInt(100)),
			b:        big.NewInt(200),
			expected: big.NewInt(100),
		},
		{
			name:     "Zero addition",
			a:        big.NewInt(100),
			b:        big.NewInt(0),
			expected: big.NewInt(100),
		},
		{
			name:     "Negative addition",
			a:        big.NewInt(100),
			b:        big.NewInt(-50),
			expected: big.NewInt(50),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := AddModN(tc.a, tc.b)
			if result.Cmp(tc.expected) != 0 {
				t.Errorf("Expected %s, got %s", tc.expected.String(), result.String())
			}
		})
	}
}

// TestMulModN tests the MulModN function
func TestMulModN(t *testing.T) {
	N := GetCurveOrder()

	testCases := []struct {
		name     string
		a        *big.Int
		b        *big.Int
		expected *big.Int
	}{
		{
			name:     "Simple multiplication",
			a:        big.NewInt(10),
			b:        big.NewInt(20),
			expected: big.NewInt(200),
		},
		{
			name:     "Multiplication with overflow",
			a:        big.NewInt(2),
			b:        new(big.Int).Div(N, big.NewInt(2)),
			expected: new(big.Int).Mod(new(big.Int).Mul(big.NewInt(2), new(big.Int).Div(N, big.NewInt(2))), N),
		},
		{
			name:     "Zero multiplication",
			a:        big.NewInt(100),
			b:        big.NewInt(0),
			expected: big.NewInt(0),
		},
		{
			name:     "Negative multiplication",
			a:        big.NewInt(10),
			b:        big.NewInt(-5),
			expected: new(big.Int).Sub(N, big.NewInt(50)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := MulModN(tc.a, tc.b)
			if result.Cmp(tc.expected) != 0 {
				t.Errorf("Expected %s, got %s", tc.expected.String(), result.String())
			}
		})
	}
}

// TestNegModN tests the NegModN function
func TestNegModN(t *testing.T) {
	N := GetCurveOrder()

	testCases := []struct {
		name     string
		input    *big.Int
		expected *big.Int
	}{
		{
			name:     "Zero",
			input:    big.NewInt(0),
			expected: big.NewInt(0),
		},
		{
			name:     "Positive number",
			input:    big.NewInt(100),
			expected: new(big.Int).Sub(N, big.NewInt(100)),
		},
		{
			name:     "Negative number",
			input:    big.NewInt(-100),
			expected: big.NewInt(100),
		},
		{
			name:     "Half of N",
			input:    new(big.Int).Div(N, big.NewInt(2)),
			expected: new(big.Int).Mod(new(big.Int).Sub(N, new(big.Int).Div(N, big.NewInt(2))), N),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := NegModN(tc.input)
			if result.Cmp(tc.expected) != 0 {
				t.Errorf("Expected %s, got %s", tc.expected.String(), result.String())
			}
		})
	}
}

// TestRandScalar tests the RandScalar function
func TestRandScalar(t *testing.T) {
	N := GetCurveOrder()

	// Test multiple generations
	for i := 0; i < 100; i++ {
		t.Run("Random generation", func(t *testing.T) {
			result, err := RandScalar()
			if err != nil {
				t.Fatalf("RandScalar failed: %v", err)
			}

			// Check range
			if result.Cmp(big.NewInt(0)) <= 0 {
				t.Errorf("Result should be positive, got %s", result.String())
			}
			if result.Cmp(N) >= 0 {
				t.Errorf("Result should be less than N, got %s", result.String())
			}
		})
	}
}

// TestGetCurveOrder tests the GetCurveOrder function
func TestGetCurveOrder(t *testing.T) {
	result := GetCurveOrder()

	// Check that it's not nil
	if result == nil {
		t.Error("GetCurveOrder returned nil")
	}

	// Check that it's a reasonable size (should be around 2^256)
	expectedMin := new(big.Int).Lsh(big.NewInt(1), 255)
	expectedMax := new(big.Int).Lsh(big.NewInt(1), 256)

	if result.Cmp(expectedMin) <= 0 {
		t.Errorf("Curve order too small: %s", result.String())
	}
	if result.Cmp(expectedMax) >= 0 {
		t.Errorf("Curve order too large: %s", result.String())
	}
}

// TestGetCurve tests the GetCurve function
func TestGetCurve(t *testing.T) {
	result := GetCurve()

	// Check that it's not nil
	if result == nil {
		t.Error("GetCurve returned nil")
	}

	// Check that it's the secp256k1 curve
	if result.Name != "secp256k1" {
		t.Errorf("Expected secp256k1 curve, got %s", result.Name)
	}
}

// TestArithmeticProperties tests mathematical properties
func TestArithmeticProperties(t *testing.T) {
	t.Run("AddModN associativity", func(t *testing.T) {
		a := big.NewInt(100)
		b := big.NewInt(200)
		c := big.NewInt(300)

		// (a + b) + c = a + (b + c)
		left := AddModN(AddModN(a, b), c)
		right := AddModN(a, AddModN(b, c))

		if left.Cmp(right) != 0 {
			t.Errorf("AddModN is not associative: (%s + %s) + %s != %s + (%s + %s)",
				a.String(), b.String(), c.String(), a.String(), b.String(), c.String())
		}
	})

	t.Run("MulModN distributivity", func(t *testing.T) {
		a := big.NewInt(10)
		b := big.NewInt(20)
		c := big.NewInt(30)

		// a * (b + c) = a * b + a * c
		left := MulModN(a, AddModN(b, c))
		right := AddModN(MulModN(a, b), MulModN(a, c))

		if left.Cmp(right) != 0 {
			t.Errorf("MulModN is not distributive: %s * (%s + %s) != %s * %s + %s * %s",
				a.String(), b.String(), c.String(), a.String(), b.String(), a.String(), c.String())
		}
	})

	t.Run("NegModN double negation", func(t *testing.T) {
		a := big.NewInt(100)
		doubleNeg := NegModN(NegModN(a))

		if doubleNeg.Cmp(a) != 0 {
			t.Errorf("Double negation should equal original: -(-%s) != %s", a.String(), a.String())
		}
	})
}

// Benchmark tests for performance
func BenchmarkModN(b *testing.B) {
	x := big.NewInt(123456789)
	for i := 0; i < b.N; i++ {
		ModN(x)
	}
}

func BenchmarkAddModN(b *testing.B) {
	a := big.NewInt(100)
	b_val := big.NewInt(200)
	for i := 0; i < b.N; i++ {
		AddModN(a, b_val)
	}
}

func BenchmarkMulModN(b *testing.B) {
	a := big.NewInt(100)
	b_val := big.NewInt(200)
	for i := 0; i < b.N; i++ {
		MulModN(a, b_val)
	}
}

func BenchmarkRandScalar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RandScalar()
	}
}
