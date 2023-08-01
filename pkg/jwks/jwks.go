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

type Jwks struct {
	Keys []json.Marshaler `json:"keys"`
}

// ===
// PEM -> JSON
// ===

func PublicPEM2Marshaler(bytes []byte) (*Jwks, error) {
	ders, err := ParsePEM(bytes)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := []crypto.PublicKey{}

	for i, der := range ders {
		key, err := ParsePublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		keys = append(keys, key)
	}

	return PublicKeys2Marshaler(keys)
}
func PublicPEM2JSON(bytes []byte) (string, error) {
	return marshaler2JSON(bytes, PublicPEM2Marshaler)
}

func PrivatePEM2Marshaler(bytes []byte) (*Jwks, error) {
	ders, err := ParsePEM(bytes)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}

	keys := []crypto.PrivateKey{}

	for i, der := range ders {
		key, err := ParsePrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("error in PEM block %d: %w", i, err)
		}

		keys = append(keys, key)
	}

	return PrivateKeys2Marshaler(keys)
}
func PrivatePEM2JSON(bytes []byte) (string, error) {
	return marshaler2JSON(bytes, PrivatePEM2Marshaler)
}

// ===
// crypto.Key -> JSON
// ===

func PublicKeys2Marshaler(keys []crypto.PublicKey) (*Jwks, error) {
	js := new(Jwks)

	for i, key := range keys {
		printable, err := PublicKey2Marshaler(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}
func PublicKeys2JSON(keys []crypto.PublicKey) (string, error) {
	return marshaler2JSON(keys, PublicKeys2Marshaler)
}

func PrivateKeys2Marshaler(keys []crypto.PrivateKey) (*Jwks, error) {
	js := new(Jwks)

	for i, key := range keys {
		printable, err := PrivateKey2Marshaler(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %d: %w", i, err)
		}

		js.Keys = append(js.Keys, printable)
	}

	return js, nil
}
func PrivateKeys2JSON(keys []crypto.PrivateKey) (string, error) {
	return marshaler2JSON(keys, PrivateKeys2Marshaler)
}

// ===
// JSON -> crypto.Key
// ===

type JSONPublicJwks struct {
	Keys []JSONPublicKey `json:"keys"`
}

func JSON2PublicKeys(data []byte) (map[string]crypto.PublicKey, error) {
	ks := &JSONPublicJwks{}
	err := json.Unmarshal(data, ks)
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

type JSONPrivateJwks struct {
	Keys []JSONPrivateKey `json:"keys"`
}

func JSON2PrivateKeys(data []byte) (map[string]crypto.PrivateKey, error) {
	ks := &JSONPrivateJwks{}
	err := json.Unmarshal(data, ks)
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

func JSON2PublicPEMs(data []byte) ([]byte, error) {
	keys, err := JSON2PublicKeys(data)
	if err != nil {
		return nil, err
	}

	ders := [][]byte{}

	for id, key := range keys {
		der, err := RenderPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %s: %w", id, err)
		}

		ders = append(ders, der)
	}

	return RenderPEM(ders, "PUBLIC KEY")
}
func JSON2PrivatePEMs(data []byte) ([]byte, error) {
	keys, err := JSON2PrivateKeys(data)
	if err != nil {
		return nil, err
	}

	ders := [][]byte{}

	for id, key := range keys {
		der, err := RenderPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error in key %s: %w", id, err)
		}

		ders = append(ders, der)
	}

	// Because we encode all priv keys as pkcs8 (even ecdsa, for which this isn't the openssl default), this string is always correct. If we used openssl's default SEC1 for ecdsa, this would need to be "EC PRIVATE KEY"
	return RenderPEM(ders, "PRIVATE KEY")
}
