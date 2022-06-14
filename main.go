package main

import (
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
	MarshalJson() ([]byte, error)
}

type jwks struct {
	Keys []*myRsaPublicKey `json:"keys"`
}

type myRsaPublicKey rsa.PublicKey

func padEven(n string) string {
	if len(n)%2 == 1 {
		return "0" + n
	}
	return n
}

func main() {
	var singleton bool = false

	bytes, err := os.ReadFile(os.Args[1]) // TODO arg parsing (and --singleton)
	if err != nil {
		panic(err)
	}

	// TODO check "rest" != len(0) and loop over all the pem blocks
	block, _ := pem.Decode(bytes)
	if err != nil {
		panic(err)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	rsaKey := key.(*rsa.PublicKey) // FIXME

	// TODO: do this is a custom marshaller

	if singleton {
		op(rsaKey)
	} else {
		ks := jwks{
			Keys: []*myRsaPublicKey{(*myRsaPublicKey)(rsaKey)},
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

func op(d interface{}) {
	op, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(op))
}
