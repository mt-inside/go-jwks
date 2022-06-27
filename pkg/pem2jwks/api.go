package pem2jwks

import "encoding/pem"

func PublicPEM2Printable(block *pem.Block) (Jwk, error) {
	key, err := ParsePublicKey(block)
	if err != nil {
		return nil, err
	}

	return PublicKey2Printable(key)
}

func PrivatePEM2Printable(block *pem.Block) (Jwk, error) {
	key, err := ParsePrivateKey(block)
	if err != nil {
		return nil, err
	}

	return PrivateKey2Printable(key)
}
