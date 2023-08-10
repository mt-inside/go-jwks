package jwks

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// TODO: the combinatorial explosion is horrid (4 ops * {pub,priv} * {struct,string})
// - can pub/priv be combined? can we know from the DERs whether they're public or private?
// - can we use generics where we need crypto.[Public,Private]Key?

// TODO: this is where the iface is tested. User prolly doesn't want an any, cause they can't .Sign() etc. Outermost fns should prolly have allowPub/allowPriv flags, and filter/error

// On naming:
// * PEN is singular - you don't have multiple PEMs, you have multiple blocks in one PEM

type JWKS struct {
	Keys []*JWK `json:"keys"`
}

// ===
// PEM -> JSON / Marshaler
// ===

func PEM2JWKSMarshaler(p []byte) (*JWKS, error) {
	keys, err := PEM2Keys(p)
	if err != nil {
		return nil, err
	}

	return Keys2JWKSMarshaler(keys)
}
func PEM2JWKS(p []byte) (string, error) {
	return marshaler2JSON(p, PEM2JWKSMarshaler)
}

// ===
// JSON -> PEM
// ===

func JWKS2PEM(j []byte) ([]byte, error) {
	keys, err := JWKS2Keys(j)
	if err != nil {
		return nil, err
	}

	vals := make([]any, 0, len(keys))
	for _, val := range keys {
		vals = append(vals, val)
	}
	return Keys2PEM(vals)
}

// ===
// crypto.Key -> JSON / Marshaler
// ===

/* JWK implements [Un]MarshalJSON, it'd be nice if this type did too
* - for symmetry
* - to allow people to store these structs in json.[Un]Marshaler interface objects
*   - Note that although json.[Un]Marshal() will take one of these fine, as it takes an arg of type `any` and reflects over the members, it doesn't actually fullfil the json.[Un]Marshaler iface
* However, I can't figure out a way to do it without either infinite recursion, or another intermediate "rendering" type
 */

func Keys2JWKSMarshaler(ks []any) (*JWKS, error) {
	js := new(JWKS)

	for i, k := range ks {
		printable, err := Key2JWKMarshaler(k)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}

func Keys2JWKS(ks []any) (string, error) {
	return marshaler2JSON(ks, Keys2JWKSMarshaler)
}

// ===
// JSON -> crypto.Key / Unmarshaler
// ===

// Unmarshaler implict

func JWKS2Keys(j []byte) (map[string]any, error) {
	ks := &JWKS{}
	err := json.Unmarshal(j, ks)
	if err != nil {
		return nil, err
	}

	// kid is optional, so generate one as necessary to avoid clashing map keys
	autoKid := 0
	ksm := map[string]any{}
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
// PEM -> crypto.Key
// ===

func PEM2Keys(p []byte) ([]any, error) {
	ders, err := parsePEM(p)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := []any{}

	for i, der := range ders {
		key, err := parseDER(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// ===
// crypto.Key -> PEM
// ===

func Keys2PEM(ks []any) ([]byte, error) {
	ders := []pemBlock{}

	for i, k := range ks {
		der, err := renderDER(k)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		blockTitle := "PUBLIC KEY"
		if KeyIsPrivate(k) {
			// Because we encode all priv keys as pkcs8 (even ecdsa, for which this isn't the openssl default), this string is always correct. If we used openssl's default SEC1 for ecdsa, this would need to be "EC PRIVATE KEY"
			blockTitle = "PRIVATE KEY"
		}

		ders = append(ders, pemBlock{der, blockTitle})
	}

	return renderPEM(ders)
}
