package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mt-inside/go-jwks"
)

func main() {
	discoURL := "https://accounts.google.com/.well-known/openid-configuration"
	fmt.Println("Fetching OIDC Discovery Document from", discoURL)
	oidcDiscoResp, err := http.Get(discoURL)
	checkErr(err)
	defer oidcDiscoResp.Body.Close()
	fmt.Println("Status", oidcDiscoResp.Status)

	oidcDisco := map[string]interface{}{}
	err = json.NewDecoder(oidcDiscoResp.Body).Decode(&oidcDisco)
	checkErr(err)

	jwksURL := oidcDisco["jwks_uri"].(string)
	fmt.Println("Fetching OIDC JWKS from ", jwksURL)
	oidcJWKSResp, err := http.Get(jwksURL)
	checkErr(err)
	defer oidcJWKSResp.Body.Close()
	fmt.Println("Status", oidcJWKSResp.Status)

	jwksBytes, err := io.ReadAll(oidcJWKSResp.Body)
	checkErr(err)

	pubKeys, err := jwks.JWKS2KeysMap(jwksBytes)
	checkErr(err)

	// Note: Google rotates these keys quite regularly; the key needed for this token is probably gone by now.
	token := `eyJhbGciOiJSUzI1NiIsImtpZCI6ImZkNDhhNzUxMzhkOWQ0OGYwYWE2MzVlZjU2OWM0ZTE5NmY3YWU4ZDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNTAzNDQxODg4NjMtbGRkbWdiYXNiZG9tOXFwdDFtcjBya2xuNjIyODFzNmQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyNTAzNDQxODg4NjMtbGRkbWdiYXNiZG9tOXFwdDFtcjBya2xuNjIyODFzNmQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDU0MzExMzg2OTcwMTQ1MDYxNzMiLCJhdF9oYXNoIjoiQ0ljRGlFSWc2NGlmV3Q5WW5KYkRwUSIsImlhdCI6MTY5MDc5OTE0MiwiZXhwIjoxNjkwODAyNzQyfQ.vGQLJw5jNkm84H6JXPzIVsMpQ07yrXcrC-e6t-520FUmJDnouv8yCKRei147yvkQIokvOKKoxvrnv1Z0l8XSH6y4NphBS0wa5Stz3M0bublHRi9NwPE4PETk9TjbWJd8l6h-T1ZlSYfIUoYyGPYigKaelgIbVPYBzDMAC4oxiVXNhjzpNtqOIcwrOS98nKBJkMvPkX8lPT_POIB3BX0LeMhbOGVvIAzxQ0lwKHU48Wp6zgLfpyPHB3IdY9z1DRigBsKKzfzwrQvBmVtp9Wb9SpHPl2Sn_JtcCWCgF04hAZH5cKtAjoUyinesBzGTYWx00QKE4cFV0FXXHKWejvECow`

	_, err = jwt.ParseWithClaims(
		token,
		&jwt.RegisteredClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return pubKeys[t.Header["kid"].(string)], nil
		},
	)
	fmt.Println("Token status:", err)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
