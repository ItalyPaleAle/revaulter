package protocolv2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestCreateBody_ValidateNote(t *testing.T) {
	tests := []struct {
		name  string
		note  string
		valid bool
	}{
		{name: "empty", note: "", valid: true},
		{name: "letters", note: "boot unlock", valid: true},
		{name: "numbers", note: "slot 01", valid: true},
		{name: "punctuation", note: "disk/key_name-01.txt", valid: true},
		{name: "mixed", note: "Vault 7 / key_file-02", valid: true},
		{name: "exclamation mark", note: "boot unlock!", valid: false},
		{name: "tab", note: "boot\tunlock", valid: false},
		{name: "newline", note: "boot\nunlock", valid: false},
		{name: "unicode", note: "cafe-chiave-e" + "\u0301", valid: false},
		{name: "at sign", note: "ops@home", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := RequestCreateBody{
				Note: tt.note,
			}
			require.Equal(t, tt.valid, obj.ValidateNote())
		})
	}
}

func TestNormalizeAndValidateKeyLabel(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLabel string
		wantOK    bool
	}{
		{name: "lowercase letters", input: "diskkey", wantLabel: "diskkey", wantOK: true},
		{name: "letters and digits", input: "key01", wantLabel: "key01", wantOK: true},
		{name: "all allowed punctuation", input: "a_b-c.d+e", wantLabel: "a_b-c.d+e", wantOK: true},
		{name: "uppercase folds to lowercase", input: "DiskKey", wantLabel: "diskkey", wantOK: true},
		{name: "mixed case with punctuation", input: "Key.Label-01", wantLabel: "key.label-01", wantOK: true},
		{name: "max length is accepted", input: strings.Repeat("a", MaxKeyLabelLength), wantLabel: strings.Repeat("a", MaxKeyLabelLength), wantOK: true},
		{name: "single char accepted", input: "k", wantLabel: "k", wantOK: true},

		{name: "empty rejected", input: "", wantLabel: "", wantOK: false},
		{name: "over max length rejected", input: strings.Repeat("a", MaxKeyLabelLength+1), wantLabel: "", wantOK: false},
		{name: "space rejected", input: "bad label", wantLabel: "", wantOK: false},
		{name: "slash rejected", input: "vault/key", wantLabel: "", wantOK: false},
		{name: "asterisk rejected", input: "boom*", wantLabel: "", wantOK: false},
		{name: "newline rejected", input: "ab\nc", wantLabel: "", wantOK: false},
		{name: "tab rejected", input: "ab\tc", wantLabel: "", wantOK: false},
		{name: "backtick rejected", input: "x`y", wantLabel: "", wantOK: false},
		{name: "angle bracket rejected", input: "a<b", wantLabel: "", wantOK: false},
		// The check is on raw bytes, so any multibyte UTF-8 sequence falls outside [A-Za-z0-9_.+-]
		{name: "unicode rejected", input: "café", wantLabel: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLabel, gotOK := NormalizeAndValidateKeyLabel(tt.input)
			require.Equal(t, tt.wantOK, gotOK)
			require.Equal(t, tt.wantLabel, gotLabel)
		})
	}
}

func TestNormalizeAndValidateKeyLabel_CaseInsensitive(t *testing.T) {
	// Two inputs that differ only in case must canonicalize to the same value
	a, okA := NormalizeAndValidateKeyLabel("DiskKey")
	b, okB := NormalizeAndValidateKeyLabel("diskkey")
	require.True(t, okA)
	require.True(t, okB)
	require.Equal(t, a, b)
}
