package main

import (
	"encoding/json"
	"fmt"

	"github.com/mt-inside/go-jwks"
)

func main() {
	/* Given a JWK */

	jwk := []byte(`{"kty":"RSA","alg":"RS64","n":"uOAca435W3YjqO-1pxslxb0nN1C1S1tCuq9p6ExL8vAQt3tNwergUn9VlmbX6K3U5D1G2LxXD2fBgok9R9gUYQ","e":"AQAB"}`)

	/* We can parse it to a set of crypto.Keys.
	*  These are indexed by their KeyID, if present, else by a short int */

	key, _ := jwks.JWK2Key(jwk)
	fmt.Println(key)

	/* Or we can get an object that will unmarshal JSON into Keys */

	parser := &jwks.JWK{} // No getter for this as it wouldn't do anything
	_ = json.Unmarshal(jwk, parser)
	fmt.Println(parser.Key)

	/* The main advantage of getting hold of that intermediate object is that we can embed it in a larger one */

	type MyType struct {
		Foo   int      `json:"foo"`
		MyJWK jwks.JWK `json:"myjwk"`
	}
	embeddedJwk := []byte(`{"foo": 69, "myjwk": {"kty":"RSA","alg":"RS64","n":"uOAca435W3YjqO-1pxslxb0nN1C1S1tCuq9p6ExL8vAQt3tNwergUn9VlmbX6K3U5D1G2LxXD2fBgok9R9gUYQ","e":"AQAB"}}`)
	myT := MyType{}
	json.Unmarshal(embeddedJwk, &myT)
	fmt.Println(myT.MyJWK.Key)

	/* We can also render it straight to PEM (no need to decode to a crypto.Key first) */

	pem, _ := jwks.JWK2PEM(jwk)
	fmt.Println(string(pem))
}
