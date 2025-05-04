package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsTruthy(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
		name     string
	}{
		{input: "1", expected: true, name: "Numeric 1"},
		{input: "true", expected: true, name: "Lower true"},
		{input: "TRUE", expected: true, name: "Upper true"},
		{input: "True", expected: true, name: "Title true"},
		{input: "t", expected: true, name: "Single t"},
		{input: "T", expected: true, name: "Single T"},
		{input: "on", expected: true, name: "Lower on"},
		{input: "ON", expected: true, name: "Upper on"},
		{input: "yes", expected: true, name: "Lower yes"},
		{input: "YES", expected: true, name: "Upper yes"},
		{input: "y", expected: true, name: "Single y"},
		{input: "Y", expected: true, name: "Single Y"},

		{input: "0", expected: false, name: "Numeric 0"},
		{input: "false", expected: false, name: "Lower false"},
		{input: "FALSE", expected: false, name: "Upper false"},
		{input: "no", expected: false, name: "No"},
		{input: "off", expected: false, name: "Off"},
		{input: "n", expected: false, name: "Single n"},
		{input: "", expected: false, name: "Empty string"},
		{input: "something else", expected: false, name: "Long string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsTruthy(test.input)
			require.Equal(t, test.expected, result)
		})
	}
}
