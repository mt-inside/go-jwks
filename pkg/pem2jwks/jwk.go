package pem2jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
)

type Jwk json.Marshaler

type Jwks struct {
	Keys []Jwk `json:"keys"`
}

func PublicKey2Printable(key crypto.PublicKey) (Jwk, error) {

	switch typedKey := key.(type) {
	case *rsa.PublicKey:
		return (*printableRsaPublicKey)(typedKey), nil
	case *ecdsa.PublicKey:
		return (*printableEcdsaPublicKey)(typedKey), nil
	case ed25519.PublicKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	default:
		return nil, fmt.Errorf("unknown key type: %T", key)
	}
}

func PrivateKey2Printable(key crypto.PrivateKey) (Jwk, error) {

	switch typedKey := key.(type) {
	case *rsa.PrivateKey:
		return (*printableRsaPrivateKey)(typedKey), nil
	case *ecdsa.PrivateKey:
		return (*printableEcdsaPrivateKey)(typedKey), nil
	case ed25519.PrivateKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	default:
		return nil, fmt.Errorf("unknown key type: %T", key)
	}
}

type printableRsaPublicKey rsa.PublicKey
type printableEcdsaPublicKey ecdsa.PublicKey

type printableRsaPrivateKey rsa.PrivateKey
type printableEcdsaPrivateKey ecdsa.PrivateKey

func (k *printableRsaPublicKey) MarshalJSON() ([]byte, error) {
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&struct {
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		N         string `json:"n"` // Modulus ie P * Q
		E         string `json:"e"` // Public exponent
	}{
		KeyType:   "RSA",
		Algorithm: "RS" + strconv.Itoa((*rsa.PublicKey)(k).Size()),
		N:         base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(bufE),
	})
}
func (k *printableRsaPrivateKey) MarshalJSON() ([]byte, error) {
	if len(k.Primes) != 2 {
		return nil, fmt.Errorf("don't know how to deal with keys that don't have precisely 2 factors")
	}
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&struct {
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		N         string `json:"n"` // Modulus ie P * Q
		E         string `json:"e"` // Public exponent
		D         string `json:"d"` // Private exponent
		// Pre-computed values to speed stuff up.
		P string `json:"p"`
		Q string `json:"q"`
		// Primes - some other programmes (like npm pem-jwk) output a field called Primes which I guess contains P and Q but I can't work out the format of it. Ths actual spec just shows P and Q though.
		Dp   string `json:"dp"`
		Dq   string `json:"dq"`
		Qinv string `json:"qi"`
	}{
		KeyType:   "RSA",
		Algorithm: "RS" + strconv.Itoa(k.Size()),
		N:         base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(bufE),
		D:         base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
		P:         base64.RawURLEncoding.EncodeToString(k.Primes[0].Bytes()),
		Q:         base64.RawURLEncoding.EncodeToString(k.Primes[1].Bytes()),
		Dp:        base64.RawURLEncoding.EncodeToString(k.Precomputed.Dp.Bytes()),
		Dq:        base64.RawURLEncoding.EncodeToString(k.Precomputed.Dq.Bytes()),
		Qinv:      base64.RawURLEncoding.EncodeToString(k.Precomputed.Qinv.Bytes()),
	})
}
func determineLenE(e int) uint {
	// https://www.ibm.com/docs/en/linux-on-systems?topic=formats-rsa-public-key-token
	if e == 3 || e == 5 || e == 17 {
		return 1
	} else if e == 257 || e == 65537 {
		return 3
	} else {
		return strconv.IntSize / 8
	}
}

func (k *printableEcdsaPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
		Y       string `json:"y"`
	}{
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
	})
}
func (k *printableEcdsaPrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
		Y       string `json:"y"`
		D       string `json:"d"`
	}{
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		D:       base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
	})
}
