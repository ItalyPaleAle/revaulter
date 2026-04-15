package protocolv2

import (
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
