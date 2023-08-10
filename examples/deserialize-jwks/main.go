package main

import (
	"encoding/json"
	"fmt"

	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {
	/* Given a JWKS */

	jwksIn := []byte(`{"keys":[{"kty":"RSA","alg":"RS64","n":"uOAca435W3YjqO-1pxslxb0nN1C1S1tCuq9p6ExL8vAQt3tNwergUn9VlmbX6K3U5D1G2LxXD2fBgok9R9gUYQ","e":"AQAB"},{"kty":"EC","crv":"P-256","x":"qHwVHY6YsRb9xjzdPJYnXZMkIKDsmiIEia6RgiPAFUE","y":"I0XeEIlEllk3km7MHgAweEiAgnxVmEJI7gAse8V3O6s"}]}`)

	/* We can parse it to a set of crypto.Keys.
	*  These are indexed by their KeyID, if present, else by a short int */

	keys, _ := jwks.JWKS2Keys(jwksIn)
	fmt.Println(keys)

	/* Or we can get an object that will unmarshal JSON into Keys */

	parser := &jwks.JWKS{} // No getter for this as it wouldn't do anything
	_ = json.Unmarshal(jwksIn, parser)
	fmt.Println(parser)

	/* The main advantage of getting hold of that intermediate object is that we can embed it in a larger one */

	type MyType struct {
		Foo    int       `json:"foo"`
		MyJWKS jwks.JWKS `json:"myjwks"`
	}
	embeddedJwks := []byte(`{"foo": 42, "myjwks": {"keys":[{"kty":"RSA","alg":"RS64","n":"uOAca435W3YjqO-1pxslxb0nN1C1S1tCuq9p6ExL8vAQt3tNwergUn9VlmbX6K3U5D1G2LxXD2fBgok9R9gUYQ","e":"AQAB"},{"kty":"EC","crv":"P-256","x":"qHwVHY6YsRb9xjzdPJYnXZMkIKDsmiIEia6RgiPAFUE","y":"I0XeEIlEllk3km7MHgAweEiAgnxVmEJI7gAse8V3O6s"}]}}`)
	myT := MyType{}
	_ = json.Unmarshal(embeddedJwks, &myT)
	fmt.Println(myT.MyJWKS)

	/* We can also render it straight to PEM (no need to decode to a crypto.Key first) */

	pem, _ := jwks.JWKS2PEM(jwksIn)
	fmt.Println(string(pem))
}
