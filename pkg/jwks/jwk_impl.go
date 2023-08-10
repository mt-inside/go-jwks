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

// The parse funcs need to be combined, because of the caller - this is the only place we know its privateness
// render funcs make more sense uncombined

// ===
// Impl for RSA
// ===

type rsaPublicKeyFields struct {
	KeyID     string `json:"kid,omitempty"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	N         string `json:"n"` // Modulus ie P * Q
	E         string `json:"e"` // Public exponent
}

type rsaPrivateKeyFields struct {
	rsaPublicKeyFields
	D string `json:"d"` // Private exponent
	// Pre-computed values to speed stuff up.
	P string `json:"p"`
	Q string `json:"q"`
	// Primes - some other programmes (like npm pem-jwk) output a field called Primes which I guess contains P and Q but I can't work out the format of it. Ths actual spec just shows P and Q though.
	Dp   string `json:"dp"`
	Dq   string `json:"dq"`
	Qinv string `json:"qi"`
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

func renderRsaPrivateKey(k *rsa.PrivateKey, kid string) ([]byte, error) {
	if len(k.Primes) != 2 {
		return nil, fmt.Errorf("don't know how to deal with keys that don't have precisely 2 factors")
	}
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&rsaPrivateKeyFields{
		rsaPublicKeyFields: rsaPublicKeyFields{
			KeyID:     kid,
			KeyType:   "RSA",
			Algorithm: "RS" + strconv.Itoa(k.Size()),
			N:         base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:         base64.RawURLEncoding.EncodeToString(bufE),
		},
		D:    base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
		P:    base64.RawURLEncoding.EncodeToString(k.Primes[0].Bytes()),
		Q:    base64.RawURLEncoding.EncodeToString(k.Primes[1].Bytes()),
		Dp:   base64.RawURLEncoding.EncodeToString(k.Precomputed.Dp.Bytes()),
		Dq:   base64.RawURLEncoding.EncodeToString(k.Precomputed.Dq.Bytes()),
		Qinv: base64.RawURLEncoding.EncodeToString(k.Precomputed.Qinv.Bytes()),
	})
}

// TODO: would be nice to more closely specify the return type, but not possible since they're structs?
func parseRsaKey(data []byte) (any, error) {
	pubFields := rsaPublicKeyFields{}
	err := json.Unmarshal(data, &pubFields)
	if err != nil {
		return nil, err
	}

	if pubFields.KeyType != "RSA" {
		return nil, fmt.Errorf("key type must be RSA, not %s", pubFields.KeyType)
	}
	if !strings.HasPrefix(pubFields.Algorithm, "RS") {
		return nil, fmt.Errorf("unknown algorithm %s; must start 'RS'", pubFields.Algorithm)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(pubFields.E)
	if err != nil {
		return nil, err
	}
	eBuf := make([]byte, 8) // will be zero-filled
	//copy(eBuf[8-len(eBytes):], eBytes) - even though these numbers are allegedly big-endian, we have to put this at the start of the memory
	copy(eBuf[:], eBytes)
	e := binary.LittleEndian.Uint64(eBuf[:])

	pubKey := rsa.PublicKey{
		N: base64toBigInt(pubFields.N),
		E: int(e),
	}

	privCheck := &struct {
		D string `json:"d,omitempty"` // Private exponent
	}{}
	err = json.Unmarshal(data, &privCheck)
	if err != nil {
		return nil, err
	}
	if privCheck.D == "" {
		return &pubKey, nil
	} else {
		privFields := rsaPrivateKeyFields{}
		err := json.Unmarshal(data, &privFields)
		if err != nil {
			return nil, err
		}

		privKey := &rsa.PrivateKey{
			PublicKey: pubKey,
			D:         base64toBigInt(privFields.D),
			Primes: []*big.Int{
				base64toBigInt(privFields.P),
				base64toBigInt(privFields.Q),
			},
		}
		privKey.Precompute()

		return privKey, nil
	}
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

type ecdsaPrivateKeyFields struct {
	ecdsaPublicKeyFields
	D string `json:"d"`
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

func renderEcdsaPrivateKey(k *ecdsa.PrivateKey, kid string) ([]byte, error) {
	return json.Marshal(&ecdsaPrivateKeyFields{
		ecdsaPublicKeyFields{
			KeyID:   kid,
			KeyType: "EC",
			Curve:   k.Curve.Params().Name,
			X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
			Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		},
		base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
	})
}

func parseEcdsaKey(data []byte) (any, error) {
	pubFields := ecdsaPublicKeyFields{}
	err := json.Unmarshal(data, &pubFields)
	if err != nil {
		return nil, err
	}

	if pubFields.KeyType != "EC" {
		return nil, fmt.Errorf("key type must be EC, not %s", pubFields.KeyType)
	}

	pubKey := ecdsa.PublicKey{}
	switch pubFields.Curve {
	case "P-224":
		pubKey.Curve = elliptic.P224()
	case "P-256":
		pubKey.Curve = elliptic.P256()
	case "P-384":
		pubKey.Curve = elliptic.P384()
	case "P-521":
		pubKey.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unknown Curve %s", pubFields.Curve)
	}

	pubKey.X = base64toBigInt(pubFields.X)
	pubKey.Y = base64toBigInt(pubFields.Y)

	privCheck := &struct {
		D string `json:"d,omitempty"` // Private exponent
	}{}
	err = json.Unmarshal(data, &privCheck)
	if err != nil {
		return nil, err
	}

	if privCheck.D == "" {
		return &pubKey, nil
	} else {
		privFields := ecdsaPrivateKeyFields{}
		err := json.Unmarshal(data, &privFields)
		if err != nil {
			return nil, err
		}

		privKey := &ecdsa.PrivateKey{
			PublicKey: pubKey,
			D:         base64toBigInt(privFields.D),
		}

		return privKey, nil
	}
}

func base64toBigInt(data string) *big.Int {
	bytes, _ := base64.RawURLEncoding.DecodeString(data)
	return new(big.Int).SetBytes(bytes)
}
