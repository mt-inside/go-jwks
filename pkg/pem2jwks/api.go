package pem2jwks

import (
	"fmt"
)

type Jwks struct {
	Keys []Jwk `json:"keys"`
}

func PublicPEM2Printable(bytes []byte) (*Jwks, error) {
	ders, err := ParsePEM(bytes)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := new(Jwks)
	for i, der := range ders {
		key, err := ParsePublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		printable, err := PublicKey2Printable(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		keys.Keys = append(keys.Keys, printable)
	}

	return keys, nil
}

func PrivatePEM2Printable(bytes []byte) (*Jwks, error) {
	ders, err := ParsePEM(bytes)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := new(Jwks)
	for i, der := range ders {
		key, err := ParsePrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		printable, err := PrivateKey2Printable(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		keys.Keys = append(keys.Keys, printable)
	}

	return keys, nil
}
