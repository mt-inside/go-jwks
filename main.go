package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

type jwk interface {
	MarshalJSON() ([]byte, error)
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type myRsaPublicKey rsa.PublicKey
type myEcdsaPublicKey ecdsa.PublicKey
type myEd25519PublicKey ed25519.PublicKey

func padEven(n string) string {
	if len(n)%2 == 1 {
		return "0" + n
	}
	return n
}

func main() {
	var singleton bool = false

	// TODO: add a --private option to output the private bits of the key too, ref: https://datatracker.ietf.org/doc/html/rfc7517#appendix-A

	// TODO: read keys(s) from stdin

	bytes, err := os.ReadFile(os.Args[1]) // TODO arg parsing (and --singleton)
	if err != nil {
		panic(err)
	}

	// TODO check "rest" != len(0) and loop over all the pem blocks
	block, _ := pem.Decode(bytes)
	if err != nil {
		panic(err)
	}

	var key crypto.PublicKey
	if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key = pubKey
	} else if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		key = cert.PublicKey
	} else if privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil { // RSA only; type *rsa.PrivateKey
		key = privKey.Public()
	} else if privKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil { // RSA, ECDSA, Ed25519; type any, however: https://pkg.go.dev/crypto#PrivateKey
		key = privKey.(interface {
			Public() crypto.PublicKey
		}).Public()
	} else if privKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil { // ECDSA only; type *ecdsa.PrivateKey
		key = privKey.Public()
	} else {
		panic("input PEM does not encode a public key, certificate, or private key")
	}

	// TODO: do generics help??
	var foo jwk
	switch bar := key.(type) {
	case *rsa.PublicKey:
		foo = (*myRsaPublicKey)(bar)
	case *ecdsa.PublicKey:
		foo = (*myEcdsaPublicKey)(bar)
	case ed25519.PublicKey: // Not a pointer *shrug*
		foo = (myEd25519PublicKey)(bar)
		panic("JWK does not support Ed25519")
	default:
		panic(fmt.Sprintf("Unknown key type: %T", key))
	}

	if singleton {
		op(foo)
	} else {
		ks := jwks{
			Keys: []jwk{foo},
		}

		op(ks)
	}
}

func (k *myRsaPublicKey) MarshalJSON() ([]byte, error) {
	bufE := make([]byte, 4)
	binary.LittleEndian.PutUint32(bufE, uint32(k.E))
	bufE = bufE[:3] // TODO: what does the spec say? Are they always 3byte? Do we calcualte nearest power-of-2? Does Write() do this automatically?
	return json.Marshal(&struct {
		KeyType string `json:"kty"`
		N       string `json:"n"`
		E       string `json:"e"`
	}{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(bufE),
	})
}

func (k *myEcdsaPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
		Y       string `json:"y"`
	}{
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
	})
}

func (k myEd25519PublicKey) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func op(d interface{}) {
	op, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(op))
}
