package base58

import "testing"

func TestEncode(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{name: "empty", data: []byte{}, expected: ""},
		{name: "single byte 0", data: []byte{0x00}, expected: "1"},
		{name: "single byte 1", data: []byte{0x01}, expected: "2"},
		{name: "single byte 57", data: []byte{0x39}, expected: "z"},
		{name: "single byte 58", data: []byte{0x3A}, expected: "21"},
		{name: "two bytes example", data: []byte{0x1A, 0x2B}, expected: "2zW"},
		{name: "leading zeros", data: []byte{0x00, 0x00, 0x1A, 0x2B}, expected: "112zW"},
		// {name: "bitcoin address example", data: []byte{0x00, 0x60, 0x23, 0xBD, 0x3F, 0x2B, 0x3B, 0xE1, 0x3C, 0x4F, 0x5A, 0x49, 0xFD, 0x7E, 0x08, 0x10, 0xA8, 0xE4, 0x3D, 0x81, 0x26}, expected: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.data)
			if got != tt.expected {
				t.Errorf("Encode() = %v, expected %v", got, tt.expected)
			}
		})
	}
}
