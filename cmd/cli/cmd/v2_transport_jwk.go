package cmd

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type v2TransportKeyPair struct {
	EcdhPrivate  *ecdh.PrivateKey
	EcdhPublic   protocolv2.ECP256PublicJWK
	MlkemPrivate *mlkem.DecapsulationKey768
	MlkemPublic  string // base64url-encoded raw encapsulation key
}

func newV2TransportKeyPair() (*v2TransportKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 transport key: %w", err)
	}
	pub, err := protocolv2.ECP256PublicJWKFromECDH(priv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to convert transport public key to JWK: %w", err)
	}

	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-768 transport key: %w", err)
	}

	return &v2TransportKeyPair{
		EcdhPrivate:  priv,
		EcdhPublic:   pub,
		MlkemPrivate: mlkemDK,
		MlkemPublic:  base64.RawURLEncoding.EncodeToString(mlkemDK.EncapsulationKey().Bytes()),
	}, nil
}
