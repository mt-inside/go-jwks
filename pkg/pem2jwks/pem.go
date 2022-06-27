package pem2jwks

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePublicKey(block *pem.Block) (crypto.PublicKey, error) {

	if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pubKey, nil
	} else if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	} else if privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil { // RSA only; type *rsa.PrivateKey
		return privKey.Public(), nil
	} else if privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil { // OpenSSL 3+ default. RSA, ECDSA, Ed25519; type any, however: https://pkg.go.dev/crypto#PrivateKey
		return privKey.(interface {
			Public() crypto.PublicKey
		}).Public(), nil
	} else if privKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil { // ECDSA only; type *ecdsa.PrivateKey
		return privKey.Public(), nil
	} else {
		return nil, fmt.Errorf("input PEM does not encode a public key, certificate, or private key")
	}
}

func ParsePrivateKey(block *pem.Block) (crypto.PrivateKey /* alias: any */, error) {

	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return nil, fmt.Errorf("need a private key; got a public")
	} else if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		return nil, fmt.Errorf("need a private key; got a cert")
	} else if privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil { // RSA only; type *rsa.PrivateKey
		return privKey, nil
	} else if privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil { // RSA, ECDSA, Ed25519; type any, however: https://pkg.go.dev/crypto#PrivateKey
		return privKey, nil
	} else if privKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil { // ECDSA only; type *ecdsa.PrivateKey
		return privKey, nil
	} else {
		return nil, fmt.Errorf("input PEM does not encode a private key")
	}
}
