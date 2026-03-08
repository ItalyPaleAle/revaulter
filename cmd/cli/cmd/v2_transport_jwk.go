package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type v2TransportKeyPair struct {
	Private *ecdh.PrivateKey
	Public  protocolv2.ECP256PublicJWK
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
	return &v2TransportKeyPair{
		Private: priv,
		Public:  pub,
	}, nil
}
