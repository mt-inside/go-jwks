package main

import (
	"encoding/json"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt/v5"

	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {
	src := []byte(`{
      "kid": "fd48a75138d9d48f0aa635ef569c4e196f7ae8d6",
      "use": "sig",
      "alg": "RS256",
      "kty": "RSA",
      "e": "AQAB",
      "n": "8KImylelEspnZ0X-ekZb9VPbUFhgB_yEPJuLKOhXOWJLVsU0hJP6B_mQOfVk0CHm66UsAhqV8qrINk-RXgwVaaFLMA827pbOOBhyvHsThcyo7AY5s6M7qbftFKKnkfVHO6c9TsQ9wpIfmhCVL3QgTlqlgFQWcNsY-qemSKpqvVi-We9I3kPvbTf0PKJ_rWA7GQQnU_GA5JRU46uvw4I1ODf0icNBHw7pWc7oTvmSl1G8OWABEyiFakcUG2Xd4qZnmWaKwLHBvifPuIyy2vK-yHH91mVZCuleVu53Vzj77RgUtF2EEuB-zizwC-fzaBmvnfx1kgQLsdK22J0Ivgu4Xw"
    }`)

	// TO TEST: identity transform
	u := jwks.JSONPublicKey{}
	err := json.Unmarshal(src, &u)
	key := u.Key
	spew.Dump(err)
	spew.Dump(key)

	foo, _ := jwks.PublicKey2Marshaler(key)
	fooBytes, _ := foo.MarshalJSON()
	fmt.Println(string(fooBytes))

	// TO TEST
	token := `eyJhbGciOiJSUzI1NiIsImtpZCI6ImZkNDhhNzUxMzhkOWQ0OGYwYWE2MzVlZjU2OWM0ZTE5NmY3YWU4ZDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNTAzNDQxODg4NjMtbGRkbWdiYXNiZG9tOXFwdDFtcjBya2xuNjIyODFzNmQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyNTAzNDQxODg4NjMtbGRkbWdiYXNiZG9tOXFwdDFtcjBya2xuNjIyODFzNmQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDU0MzExMzg2OTcwMTQ1MDYxNzMiLCJhdF9oYXNoIjoiQ0ljRGlFSWc2NGlmV3Q5WW5KYkRwUSIsImlhdCI6MTY5MDc5OTE0MiwiZXhwIjoxNjkwODAyNzQyfQ.vGQLJw5jNkm84H6JXPzIVsMpQ07yrXcrC-e6t-520FUmJDnouv8yCKRei147yvkQIokvOKKoxvrnv1Z0l8XSH6y4NphBS0wa5Stz3M0bublHRi9NwPE4PETk9TjbWJd8l6h-T1ZlSYfIUoYyGPYigKaelgIbVPYBzDMAC4oxiVXNhjzpNtqOIcwrOS98nKBJkMvPkX8lPT_POIB3BX0LeMhbOGVvIAzxQ0lwKHU48Wp6zgLfpyPHB3IdY9z1DRigBsKKzfzwrQvBmVtp9Wb9SpHPl2Sn_JtcCWCgF04hAZH5cKtAjoUyinesBzGTYWx00QKE4cFV0FXXHKWejvECow`

	tok, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(*jwt.Token) (interface{}, error) { return key, nil })
	spew.Dump(tok)
	if err != nil {
		fmt.Println(err)
	}
}
