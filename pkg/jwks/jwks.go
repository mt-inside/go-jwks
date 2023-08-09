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
type JWKSPublic struct {
	Keys []*JWKPublic `json:"keys"`
}
type JWKSPrivate struct {
	Keys []*JWKPrivate `json:"keys"`
}

// ===
// PEM -> JSON
// ===

// PUBLIC

func PEM2JWKSMarshalerPublic(p []byte) (*JWKSPublic, error) {
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

// PRIVATE

func PEM2JWKSMarshalerPrivate(p []byte) (*JWKSPrivate, error) {
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
// crypto.Key -> JSON / Marshaler
// ===

// PUBLIC

/* JWK implements [Un]MarshalJSON, it'd be nice if this type did too
* - for symmetry
* - to allow people to store these structs in json.[Un]Marshaler interface objects
*   - Note that although json.[Un]Marshal() will take one of these fine, as it takes an arg of type `any` and reflects over the members, it doesn't actually fullfil the json.[Un]Marshaler iface
* However, I can't figure out a way to do it without either infinite recursion, or another intermediate "rendering" type
 */

func Keys2JWKSMarshalerPublic(ks []crypto.PublicKey) (*JWKSPublic, error) {
	js := new(JWKSPublic)

	for i, k := range ks {
		printable, err := Key2JWKMarshalerPublic(k)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}

/* This is a convenience method; it deals directly in crypto.Key types, not jwks.JWKS types.
* It does this by skipping KeyIDs - you don't have to provide them in the container (eg a map) or the elements.
* This will result in JWKs with an omitted "kid" field.
* To provide KeyIDs, use the jwks.JWKS types directly.
 */
func Keys2JWKSPublic(ks []crypto.PublicKey) (string, error) {
	return marshaler2JSON(ks, Keys2JWKSMarshalerPublic)
}

// PRIVATE

// Ditto func (k *JWKSPublic) MarshalJSON()

func Keys2JWKSMarshalerPrivate(ks []crypto.PrivateKey) (*JWKSPrivate, error) {
	js := new(JWKSPrivate)

	for i, k := range ks {
		printable, err := Key2JWKMarshalerPrivate(k)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}

// Ditto Keys2JWKSPublic
func Keys2JWKSPrivate(ks []crypto.PrivateKey) (string, error) {
	return marshaler2JSON(ks, Keys2JWKSMarshalerPrivate)
}

// ===
// JSON -> crypto.Key / Unmarshaler
// ===

// PUBLIC

func JWKS2KeysPublic(j []byte) (map[string]crypto.PublicKey, error) {
	ks := &JWKSPublic{}
	err := json.Unmarshal(j, ks)
	if err != nil {
		return nil, err
	}

	// kid is optional, so generate one as necessary to avoid clashing map keys
	autoKid := 0
	ksm := map[string]crypto.PublicKey{}
	for _, k := range ks.Keys {
		kid := k.KeyID
		if kid == "" {
			kid = strconv.Itoa(autoKid)
			autoKid++
		}
		ksm[kid] = k.Key
	}

	return ksm, nil
}

// PRIVATE

func JWKS2KeysPrivate(j []byte) (map[string]crypto.PrivateKey, error) {
	ks := &JWKSPrivate{}
	err := json.Unmarshal(j, ks)
	if err != nil {
		return nil, err
	}

	// kid is optional, so generate one as necessary to avoid clashing map keys
	autoKid := 0
	ksm := map[string]crypto.PrivateKey{}
	for _, k := range ks.Keys {
		kid := k.KeyID
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

// PUBLIC

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

// PRIVATE

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
