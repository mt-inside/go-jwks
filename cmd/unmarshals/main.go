package main

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kr/pretty"

	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {
	src := `{
  "keys": [
    {
      "kid": "fd48a75138d9d48f0aa635ef569c4e196f7ae8d6",
      "use": "sig",
      "alg": "RS256",
      "kty": "RSA",
      "e": "AQAB",
      "n": "8KImylelEspnZ0X-ekZb9VPbUFhgB_yEPJuLKOhXOWJLVsU0hJP6B_mQOfVk0CHm66UsAhqV8qrINk-RXgwVaaFLMA827pbOOBhyvHsThcyo7AY5s6M7qbftFKKnkfVHO6c9TsQ9wpIfmhCVL3QgTlqlgFQWcNsY-qemSKpqvVi-We9I3kPvbTf0PKJ_rWA7GQQnU_GA5JRU46uvw4I1ODf0icNBHw7pWc7oTvmSl1G8OWABEyiFakcUG2Xd4qZnmWaKwLHBvifPuIyy2vK-yHH91mVZCuleVu53Vzj77RgUtF2EEuB-zizwC-fzaBmvnfx1kgQLsdK22J0Ivgu4Xw"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "alg": "RS256",
      "kid": "911e39e27928ae9f1e9d1e21646de92d19351b44",
      "e": "AQAB",
      "n": "4kGxcWQdTW43aszLmftsGswmwDDKdfcse-lKeT_zjZTB2KGw9E6LVY6IThJVxzYF6mcyU-Z5_jDAW_yi7D_gXep2rxchZvoFayXynbhxyfjK6RtJ6_k30j-WpsXCSAiNAkupYHUyDIBNocvUcrDJsC3U65l8jl1I3nW98X6d-IlAfEb2In2f0fR6d-_lhIQZjXLupjymJduPjjA8oXCUZ9bfAYPhGYj3ZELUHkAyDpZNrnSi8hFVMSUSnorAt9F7cKMUJDM4-Uopzaqcl_f-HxeKvxN7NjiLSiIYaHdgtTpCEuNvsch6q6JTsllJNr3c__BxrG4UMlJ3_KsPxbcvXw"
    },
    {
      "use": "sig",
      "alg": "RS256",
      "n": "wYvSKSQYKnGNV72_uVc9jbyUeTMsMbUgZPP0uVQX900To7A8a0XA3O17wuImgOG_BwGkpZrIRXF_RRYSK8IOH8N_ViTWh1vyEYSYwr_jfCpDoedJT0O6TZpBhBSmimtmO8ZBCkhZJ4w0AFNIMDPhMokbxwkEapjMA5zio_06dKfb3OBNmrwedZY86W1204-Pfma9Ih15Dm4o8SNFo5Sl0NNO4Ithvj2bbg1Bz1ydE4lMrXdSQL5C2uM9JYRJLnIjaYopBENwgf2Egc9CdVY8tr8jED-WQB6bcUBhDV6lJLZbpBlTHLkF1RlEMnIV2bDo02CryjThnz8l_-6G_7pJww",
      "kid": "a3bdbfdede3babb2651afca2678dde8c0b35df76",
      "e": "AQAB",
      "kty": "RSA"
    }
  ]
}`

	ks, err := jwks.JSON2PublicKeys([]byte(src))
	spew.Dump(err)
	spew.Dump(ks)

	// TO TEST
	token := `eyJhbGciOiJSUzI1NiIsImtpZCI6ImZkNDhhNzUxMzhkOWQ0OGYwYWE2MzVlZjU2OWM0ZTE5NmY3YWU4ZDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNTAzNDQxODg4NjMtbGRkbWdiYXNiZG9tOXFwdDFtcjBya2xuNjIyODFzNmQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyNTAzNDQxODg4NjMtbGRkbWdiYXNiZG9tOXFwdDFtcjBya2xuNjIyODFzNmQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDU0MzExMzg2OTcwMTQ1MDYxNzMiLCJhdF9oYXNoIjoiQ0ljRGlFSWc2NGlmV3Q5WW5KYkRwUSIsImlhdCI6MTY5MDc5OTE0MiwiZXhwIjoxNjkwODAyNzQyfQ.vGQLJw5jNkm84H6JXPzIVsMpQ07yrXcrC-e6t-520FUmJDnouv8yCKRei147yvkQIokvOKKoxvrnv1Z0l8XSH6y4NphBS0wa5Stz3M0bublHRi9NwPE4PETk9TjbWJd8l6h-T1ZlSYfIUoYyGPYigKaelgIbVPYBzDMAC4oxiVXNhjzpNtqOIcwrOS98nKBJkMvPkX8lPT_POIB3BX0LeMhbOGVvIAzxQ0lwKHU48Wp6zgLfpyPHB3IdY9z1DRigBsKKzfzwrQvBmVtp9Wb9SpHPl2Sn_JtcCWCgF04hAZH5cKtAjoUyinesBzGTYWx00QKE4cFV0FXXHKWejvECow`

	tok, err := jwt.ParseWithClaims(
		token,
		&jwt.RegisteredClaims{},
		func(t *jwt.Token) (interface{}, error) { return ks[t.Header["kid"].(string)], nil },
	)
	pretty.Print(tok)
	fmt.Println()
	if err != nil {
		fmt.Println(err)
	}
}
