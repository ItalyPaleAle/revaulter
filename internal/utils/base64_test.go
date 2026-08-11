package utils

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestDecodeBase64String(t *testing.T) {
	data := []byte("🤷🤷")

	tests := []struct {
		name    string
		arg     string
		wantOut []byte
		wantErr bool
	}{
		{name: "empty", arg: "", wantOut: nil},
		{name: "base64 standard", arg: base64.StdEncoding.EncodeToString(data), wantOut: data},
		{name: "base64 standard nopad", arg: base64.RawStdEncoding.EncodeToString(data), wantOut: data},
		{name: "base64 url", arg: base64.URLEncoding.EncodeToString(data), wantOut: data},
		{name: "base64 url nopad", arg: base64.RawURLEncoding.EncodeToString(data), wantOut: data},
		{name: "invalid base64", arg: "🤷", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOut, err := DecodeBase64String(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("DecodeBase64String() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}
