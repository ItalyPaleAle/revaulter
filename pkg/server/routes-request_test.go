//go:build unit

package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func newTestRequestCreateBody(t *testing.T) protocolv2.RequestCreateBody {
	t.Helper()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	cliJWK, err := protocolv2.ECP256PublicJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)

	mlkemCiphertext := []byte{0xfb, 0xff, 0xff}
	encryptedPayloadNonce := []byte{0x01, 0x02}
	encryptedPayload := []byte{0xfb, 0xef}

	return protocolv2.RequestCreateBody{
		KeyLabel:              "disk-key",
		Algorithm:             "A256GCM",
		Note:                  "ticket 42 / primary",
		RequestEncAlg:         protocolv2.TransportAlg,
		CliEphemeralPublicKey: cliJWK,
		MlkemCiphertext:       base64.StdEncoding.EncodeToString(mlkemCiphertext),
		EncryptedPayloadNonce: base64.StdEncoding.EncodeToString(encryptedPayloadNonce),
		EncryptedPayload:      base64.StdEncoding.EncodeToString(encryptedPayload),
	}
}

func TestValidateV2CreateBodyValidEncryptNormalizesBase64(t *testing.T) {
	body := newTestRequestCreateBody(t)

	err := validateV2CreateBody(protocolv2.OperationEncrypt, &body)
	require.NoError(t, err)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xff}), body.MlkemCiphertext)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02}), body.EncryptedPayloadNonce)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xef}), body.EncryptedPayload)
}

func TestValidateV2CreateBodyValidSign(t *testing.T) {
	body := newTestRequestCreateBody(t)
	body.Algorithm = protocolv2.SigningAlgES256

	err := validateV2CreateBody(protocolv2.OperationSign, &body)
	require.NoError(t, err)
}

func TestValidateV2CreateBodyRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		op         string
		mutateBody func(*protocolv2.RequestCreateBody)
		wantErr    string
	}{
		{
			name:    "invalid operation",
			op:      "rotate",
			wantErr: "Invalid operation",
		},
		{
			name: "missing key label",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.KeyLabel = ""
			},
			wantErr: "missing parameter 'keyLabel'",
		},
		{
			name: "key label too long",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.KeyLabel = strings.Repeat("k", 129)
			},
			wantErr: "parameter 'keyLabel' cannot be longer than 128 characters",
		},
		{
			name: "missing algorithm",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Algorithm = ""
			},
			wantErr: "missing parameter 'algorithm'",
		},
		{
			name: "algorithm too long",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Algorithm = strings.Repeat("a", 65)
			},
			wantErr: "parameter 'algorithm' cannot be longer than 64 characters",
		},
		{
			name: "unsupported signing algorithm",
			op:   protocolv2.OperationSign,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Algorithm = "HS256"
			},
			wantErr: `unsupported signing algorithm "HS256"`,
		},
		{
			name: "note has invalid characters",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Note = "bad\nnote"
			},
			wantErr: "parameter 'note' contains invalid characters",
		},
		{
			name: "note too long",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Note = strings.Repeat("n", 41)
			},
			wantErr: "parameter 'note' cannot be longer than 40 characters",
		},
		{
			name: "unsupported request encryption algorithm",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.RequestEncAlg = "rsa-oaep"
			},
			wantErr: "unsupported requestEncAlg",
		},
		{
			name: "invalid cli ephemeral public key",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.CliEphemeralPublicKey.Kty = "RSA"
			},
			wantErr: `invalid cliEphemeralPublicKey: invalid JWK 'kty': "RSA"`,
		},
		{
			name: "empty mlkem ciphertext",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.MlkemCiphertext = ""
			},
			wantErr: "mlkemCiphertext is empty or invalid",
		},
		{
			name: "malformed mlkem ciphertext",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.MlkemCiphertext = "***"
			},
			wantErr: "mlkemCiphertext is empty or invalid",
		},
		{
			name: "empty encrypted payload nonce",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayloadNonce = ""
			},
			wantErr: "encryptedPayloadNonce is empty or invalid",
		},
		{
			name: "malformed encrypted payload nonce",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayloadNonce = "***"
			},
			wantErr: "encryptedPayloadNonce is empty or invalid",
		},
		{
			name: "empty encrypted payload",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayload = ""
			},
			wantErr: "encryptedPayload is empty or invalid",
		},
		{
			name: "malformed encrypted payload",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayload = "***"
			},
			wantErr: "encryptedPayload is empty or invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := newTestRequestCreateBody(t)
			if tt.mutateBody != nil {
				tt.mutateBody(&body)
			}

			err := validateV2CreateBody(tt.op, &body)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}
