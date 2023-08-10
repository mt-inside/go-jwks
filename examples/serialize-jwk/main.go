package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {
	/* Get a PEM (must contain a single block encoding a public or private key) */

	pem := []byte(`
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALjgHGuN+Vt2I6jvtacbJcW9JzdQtUtb
QrqvaehMS/LwELd7TcHq4FJ/VZZm1+it1OQ9Rti8Vw9nwYKJPUfYFGECAwEAAQ==
-----END PUBLIC KEY-----
`)

	/* We can render it straight to JSON (no need to decode to a crypto.Key first) */

	jsonStr, _ := jwks.PEM2JWK(pem)
	fmt.Println(jsonStr)

	/* Or we can get an object that will marshal to JSON */

	printer, _ := jwks.PEM2JWKMarshaler(pem)
	jsonBytes, _ := json.Marshal(printer)
	fmt.Println(string(jsonBytes))

	/* The main advantage of getting hold of that intermediate object is that we can embed it in a larger one */

	type MyType struct {
		Foo int       `json:"foo"`
		Key *jwks.JWK `json:"key"`
	}
	myT := MyType{42, printer}
	fooBytes, _ := json.Marshal(myT)
	fmt.Println(string(fooBytes))

	/* These functions are all available for crypto.[Public,Private]Key, eg */

	key, _ := rsa.GenerateKey(rand.Reader, 512)
	keyStr, _ := jwks.Key2JWK(key.Public())
	fmt.Println(keyStr)

	/* If you need KeyIDs, use the structs directly. */

	printer = &jwks.JWK{KeyID: "deadbeef", Key: key.Public()}
	jsonBytes, _ = json.Marshal(printer)
	fmt.Println(string(jsonBytes))
}
