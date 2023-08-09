package main

import (
	"crypto"
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
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJYavAltDcEwF/3n3zjRThYK1AtJzFvM+7XzagE/aJ68oAoGCCqGSM49
AwEHoUQDQgAEqHwVHY6YsRb9xjzdPJYnXZMkIKDsmiIEia6RgiPAFUEjRd4QiUSW
WTeSbsweADB4SICCfFWYQkjuACx7xXc7qw==
-----END EC PRIVATE KEY-----
`)

	/* We can render it straight to JSON (no need to decode to []crypto.Key first) */

	jsonStr, _ := jwks.PEM2JWKSPublic(pem)
	fmt.Println(jsonStr)

	/* Or we can get an object that will marshal to JSON */

	printer, _ := jwks.PEM2JWKSMarshalerPublic(pem)
	jsonBytes, _ := json.Marshal(printer)
	fmt.Println(string(jsonBytes))

	/* The main advantage of getting hold of that intermediate object is that we can embed it in a larger one */

	type MyType struct {
		Foo    int              `json:"foo"`
		MyJWKS *jwks.JWKSPublic `json:"myjwks"`
	}
	myT := MyType{42, printer}
	fooBytes, _ := json.Marshal(myT)
	fmt.Println(string(fooBytes))

	/* These functions are all available for []crypto.[Public,Private]Key, eg */

	rKey, _ := rsa.GenerateKey(rand.Reader, 512)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := []crypto.PublicKey{rKey, ecKey}
	keyStr, _ := jwks.Keys2JWKSPublic(keys)
	fmt.Println(keyStr)

	/* If you need KeyIDs, use the structs directly.
	* Note that if you use them directly, you must supply Public keys to the public structs / functions; this won't be dealt with for you.
	 */
	printer = &jwks.JWKSPublic{
		Keys: []*jwks.JWKPublic{
			&jwks.JWKPublic{KeyID: "deadbeef", Key: rKey.Public()},
			&jwks.JWKPublic{KeyID: "deafcafe", Key: ecKey.Public()},
		},
	}
	jsonBytes, _ = json.Marshal(printer)
	fmt.Println(string(jsonBytes))
}
