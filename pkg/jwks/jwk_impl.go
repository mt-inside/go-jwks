package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ===
// Impl for RSA::Public
// ===

type rsaPublicKeyFields struct {
	KeyID     string `json:"kid,omitempty"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	N         string `json:"n"` // Modulus ie P * Q
	E         string `json:"e"` // Public exponent
}

func renderRsaPublicKey(k *rsa.PublicKey, kid string) ([]byte, error) {
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	// TODO: try big-endian, and trim the string from the other end
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&rsaPublicKeyFields{
		KeyID:     kid,
		KeyType:   "RSA",
		Algorithm: "RS" + strconv.Itoa((*rsa.PublicKey)(k).Size()),
		N:         base64.RawURLEncoding.EncodeToString(k.N.Bytes()), // Bytes returns big-endian
		E:         base64.RawURLEncoding.EncodeToString(bufE),
	})
}

func parseRsaPublicKey(data []byte) (*rsa.PublicKey, error) {
	key := rsaPublicKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != "RSA" {
		return nil, fmt.Errorf("key type must be RSA, not %s", key.KeyType)
	}
	if !strings.HasPrefix(key.Algorithm, "RS") {
		return nil, fmt.Errorf("unknown algorithm %s; must start 'RS'", key.Algorithm)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	eBuf := make([]byte, 8) // will be zero-filled
	//copy(eBuf[8-len(eBytes):], eBytes) - even though these numbers are allegedly big-endian, we have to put this at the start of the memory
	copy(eBuf[:], eBytes)
	e := binary.LittleEndian.Uint64(eBuf[:])

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}

// ===
// Impl for RSA::Private
// ===

type rsaPrivateKeyFields struct {
	KeyID     string `json:"kid,omitempty"`
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
}

func renderRsaPrivateKey(k *rsa.PrivateKey, kid string) ([]byte, error) {
	if len(k.Primes) != 2 {
		return nil, fmt.Errorf("don't know how to deal with keys that don't have precisely 2 factors")
	}
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&rsaPrivateKeyFields{
		KeyID:     kid,
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

func base64toBigInt(data string) *big.Int {
	bytes, _ := base64.RawURLEncoding.DecodeString(data)
	return new(big.Int).SetBytes(bytes)
}

func parseRsaPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	key := rsaPrivateKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != "RSA" {
		return nil, fmt.Errorf("key type must be RSA, not %s", key.KeyType)
	}
	if !strings.HasPrefix(key.Algorithm, "RS") {
		return nil, fmt.Errorf("unknown algorithm %s; must start 'RS'", key.Algorithm)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	eBuf := make([]byte, 8) // will be zero-filled
	//copy(eBuf[8-len(eBytes):], eBytes) - even though these numbers are allegedly big-endian, we have to put this at the start of the memory
	copy(eBuf[:], eBytes)
	e := binary.LittleEndian.Uint64(eBuf[:])

	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: base64toBigInt(key.N),
			E: int(e),
		},
		D: base64toBigInt(key.D),
		Primes: []*big.Int{
			base64toBigInt(key.P),
			base64toBigInt(key.Q),
		},
	}
	k.Precompute()

	return k, nil
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

// ===
// Impl for ECDSA::Public
// ===

type ecdsaPublicKeyFields struct {
	KeyID   string `json:"kid,omitempty"`
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

func renderEcdsaPublicKey(k *ecdsa.PublicKey, kid string) ([]byte, error) {
	return json.Marshal(&ecdsaPublicKeyFields{
		KeyID:   kid,
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
	})
}
func parseEcdsaPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	key := ecdsaPublicKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != "EC" {
		return nil, fmt.Errorf("key type must be EC, not %s", key.KeyType)
	}

	k := &ecdsa.PublicKey{}
	switch key.Curve {
	case "P-224":
		k.Curve = elliptic.P224()
	case "P-256":
		k.Curve = elliptic.P256()
	case "P-384":
		k.Curve = elliptic.P384()
	case "P-521":
		k.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unknown Curve %s", key.Curve)
	}

	k.X = base64toBigInt(key.X)
	k.Y = base64toBigInt(key.Y)

	return k, nil
}

// ===
// Impl for ECDSA::Private
// ===

type ecdsaPrivateKeyFields struct {
	KeyID   string `json:"kid,omitempty"`
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
	D       string `json:"d"`
}

func renderEcdsaPrivateKey(k *ecdsa.PrivateKey, kid string) ([]byte, error) {
	return json.Marshal(&ecdsaPrivateKeyFields{
		KeyID:   kid,
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		D:       base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
	})
}

func parseEcdsaPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	key := ecdsaPrivateKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}

	if key.KeyType != "EC" {
		return nil, fmt.Errorf("key type must be EC, not %s", key.KeyType)
	}

	k := &ecdsa.PrivateKey{}
	switch key.Curve {
	case "P-224":
		k.Curve = elliptic.P224()
	case "P-256":
		k.Curve = elliptic.P256()
	case "P-384":
		k.Curve = elliptic.P384()
	case "P-521":
		k.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unknown Curve %s", key.Curve)
	}

	k.X = base64toBigInt(key.X)
	k.Y = base64toBigInt(key.Y)
	k.D = base64toBigInt(key.D)

	return k, nil
}
