package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {
	/* Get a PEM containing one or more public and/or private keys */

	// Remember: you need to tell openssl curve `prime256v1` to get the NIST curve Go understands
	pem := []byte(`
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALjgHGuN+Vt2I6jvtacbJcW9JzdQtUtb
QrqvaehMS/LwELd7TcHq4FJ/VZZm1+it1OQ9Rti8Vw9nwYKJPUfYFGECAwEAAQ==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHwVHY6YsRb9xjzdPJYnXZMkIKDs
miIEia6RgiPAFUEjRd4QiUSWWTeSbsweADB4SICCfFWYQkjuACx7xXc7qw==
-----END PUBLIC KEY-----
`)

	/* We can render it straight to JSON (no need to decode to []crypto.Key first) */

	jsonStr, _ := jwks.PEM2JWKS(pem)
	fmt.Println(jsonStr)

	/* If you want to do manipulation, eg how cmd/pem2jwks turns private keys into public, you can take two steps and transform PEM->Key->JSON */

	/* Or we can get an object that will marshal to JSON */

	printer, _ := jwks.PEM2JWKSMarshaler(pem)
	jsonBytes, _ := json.Marshal(printer)
	fmt.Println(string(jsonBytes))

	/* The main advantage of getting hold of that intermediate object is that we can embed it in a larger one */

	type MyType struct {
		Foo    int        `json:"foo"`
		MyJWKS *jwks.JWKS `json:"myjwks"`
	}
	myT := MyType{42, printer}
	fooBytes, _ := json.Marshal(myT)
	fmt.Println(string(fooBytes))

	/* These functions are all available for []crypto.[Public,Private]Key, eg */

	rKey, _ := rsa.GenerateKey(rand.Reader, 512)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := []any{rKey.Public(), ecKey.Public()}
	keyStr, _ := jwks.Keys2JWKS(keys)
	fmt.Println(keyStr)

	/* If you need KeyIDs, use the structs directly. */
	printer = &jwks.JWKS{
		Keys: []*jwks.JWK{
			&jwks.JWK{KeyID: "deadbeef", Key: rKey.Public()},
			&jwks.JWK{KeyID: "deafcafe", Key: ecKey.Public()},
		},
	}
	jsonBytes, _ = json.Marshal(printer)
	fmt.Println(string(jsonBytes))
}
