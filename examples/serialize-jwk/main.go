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
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAuOAca435W3YjqO+1
pxslxb0nN1C1S1tCuq9p6ExL8vAQt3tNwergUn9VlmbX6K3U5D1G2LxXD2fBgok9
R9gUYQIDAQABAkAEZ0omAa6zz/+PcY45Gbtvl07M0X5P+i9/tNfn8ZFJiwXno9r/
0pdVzAtibhdDzmvlYYXKdH6Nxo04/WxkyZrBAiEA6OjwCddiOg8MovfTzZZ0RhDZ
4CjQ4p8QfgTZFhCpzdkCIQDLNBkEqnpbFsdKZzqyG4BKJKmQWKBXsewscUhHpwb9
yQIgaX8hQwPpPS0V5zdkG6o7joUReyRhwVSVTs95WTJBB7kCIQCq6ff9D7L4eLFJ
aIhbFHyUYD/q9FBxUmq2etXzxo4/2QIgFZcj9fsrAXKZ6SerFfAPGWZLILD6ORCx
0FxzmNY9RoA=
-----END PRIVATE KEY-----
`)

	/* We can render it straight to JSON (no need to decode to a crypto.Key first) */

	jsonStr, _ := jwks.PEM2JWKPublic(pem)
	fmt.Println(jsonStr)

	/* Or we can get an object that will marshal to JSON */

	printer, _ := jwks.PEM2JWKMarshalerPublic(pem)
	jsonBytes, _ := json.Marshal(printer)
	fmt.Println(string(jsonBytes))

	/* The main advantage of getting hold of that intermediate object is that we can embed it in a larger one */

	type MyType struct {
		Foo int             `json:"foo"`
		Key *jwks.JWKPublic `json:"key"`
	}
	myT := MyType{42, printer}
	fooBytes, _ := json.Marshal(myT)
	fmt.Println(string(fooBytes))

	/* These functions are all available for crypto.[Public,Private]Key, eg */

	key, _ := rsa.GenerateKey(rand.Reader, 512)
	keyStr, _ := jwks.Key2JWKPublic(key)
	fmt.Println(keyStr)
}
