package jwks

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strconv"
)

// TODO: the combinatorial explosion is horrid (4 above * {pub,priv} * {struct,string})
// - can pub/priv be combined? can we know from the DERs whether they're public or private?
// - can we use generics where we need crypto.[Public,Private]Key?

// On naming:
// * PEN is singular - you don't have multiple PEMs, you have multiple blocks in one PEM

// TODO: why isn't the marshal and unmarshal type the same? Is it KeyId? Should be used tbh.
type Jwks struct {
	Keys []Jwk `json:"keys"`
}

// ===
// PEM -> JSON
// ===

func PEM2JWKSMarshalerPublic(p []byte) (*Jwks, error) {
	ders, err := parsePEM(p)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := []crypto.PublicKey{}

	for i, der := range ders {
		key, err := parsePublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		keys = append(keys, key)
	}

	return Keys2JWKSMarshalerPublic(keys)
}
func PEM2JWKSPublic(p []byte) (string, error) {
	return marshaler2JSON(p, PEM2JWKSMarshalerPublic)
}

func PEM2JWKSMarshalerPrivate(p []byte) (*Jwks, error) {
	ders, err := parsePEM(p)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := []crypto.PrivateKey{}

	for i, der := range ders {
		key, err := parsePrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		keys = append(keys, key)
	}

	return Keys2JWKSMarshalerPrivate(keys)
}
func PEM2JWKSPrivate(p []byte) (string, error) {
	return marshaler2JSON(p, PEM2JWKSMarshalerPrivate)
}

// ===
// crypto.Key -> JSON
// ===

func Keys2JWKSMarshalerPublic(ks []crypto.PublicKey) (*Jwks, error) {
	js := new(Jwks)

	for i, k := range ks {
		printable, err := Key2JWKMarshalerPublic(k)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}
func Keys2JWKSPublic(ks []crypto.PublicKey) (string, error) {
	return marshaler2JSON(ks, Keys2JWKSMarshalerPublic)
}

func Keys2JWKSMarshalerPrivate(ks []crypto.PrivateKey) (*Jwks, error) {
	js := new(Jwks)

	for i, k := range ks {
		printable, err := Key2JWKMarshalerPrivate(k)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}
func Keys2JWKSPrivate(ks []crypto.PrivateKey) (string, error) {
	return marshaler2JSON(ks, Keys2JWKSMarshalerPrivate)
}

// ===
// JSON -> crypto.Key
// ===

type jsonPublicJwks struct {
	Keys []jwkPublic `json:"keys"`
}

func JWKS2KeysPublic(j []byte) (map[string]crypto.PublicKey, error) {
	ks := &jsonPublicJwks{}
	err := json.Unmarshal(j, ks)
	if err != nil {
		return nil, err
	}

	// kid is optional, so generate one as necessary to avoid clashing map keys
	autoKid := 0
	ksm := map[string]crypto.PublicKey{}
	for _, k := range ks.Keys {
		kid := k.KeyId
		if kid == "" {
			kid = strconv.Itoa(autoKid)
			autoKid++
		}
		ksm[kid] = k.Key
	}

	return ksm, nil
}

type jsonPrivateJwks struct {
	Keys []jwkPrivate `json:"keys"`
}

func JWKS2KeysPrivate(j []byte) (map[string]crypto.PrivateKey, error) {
	ks := &jsonPrivateJwks{}
	err := json.Unmarshal(j, ks)
	if err != nil {
		return nil, err
	}

	// kid is optional, so generate one as necessary to avoid clashing map keys
	autoKid := 0
	ksm := map[string]crypto.PrivateKey{}
	for _, k := range ks.Keys {
		kid := k.KeyId
		if kid == "" {
			kid = strconv.Itoa(autoKid)
			autoKid++
		}
		ksm[kid] = k.Key
	}

	return ksm, nil
}

// ===
// JSON -> PEM
// ===

func JWKS2PEMPublic(j []byte) ([]byte, error) {
	keys, err := JWKS2KeysPublic(j)
	if err != nil {
		return nil, err
	}

	ders := [][]byte{}

	for id, key := range keys {
		der, err := renderPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %s: %w", id, err)
		}

		ders = append(ders, der)
	}

	return renderPEM(ders, "PUBLIC KEY")
}

func JWKS2PEMPrivate(j []byte) ([]byte, error) {
	keys, err := JWKS2KeysPrivate(j)
	if err != nil {
		return nil, err
	}

	ders := [][]byte{}

	for id, key := range keys {
		der, err := renderPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %s: %w", id, err)
		}

		ders = append(ders, der)
	}

	// Because we encode all priv keys as pkcs8 (even ecdsa, for which this isn't the openssl default), this string is always correct. If we used openssl's default SEC1 for ecdsa, this would need to be "EC PRIVATE KEY"
	return renderPEM(ders, "PRIVATE KEY")
}
