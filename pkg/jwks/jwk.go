/* TODO
* - doc.go (explain the ortho of the funcs, eg to/from json vs to/from an [un]marshaler
* - README.md
* - examples
*   - http get google jwks, parse, pick key by key id and verify JWT
*   - get marshaller and put it in larger object which is then serialised
*   - ditto unmarshaller - unmarhsal some JSON object that has a jwk embedded in it
 */
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

/* Go's Serialization APIs:
* Anything that implementes MarshalJSON fullfils json.Marshaler
* Ditto UnmashalJSON with json.Unmarshaler
* Note that pkg encoding/json just provides the [Un]MarshalJSON ifaces; types (that can represent themselves as JSON) have to implement it.
* json.Marshal() then walks objects and calls the members' MarshalJSON(), or errors if they don't have that iface
* root encoding/ pkg encoding also has ifaces [Un]Marshall[Binary,Text] for things that can represent themselves that way
* [Un]Marshal deal with strings/[]byte
* [En,De]coder deal with streams (io.[Reader,Writer])
* - There aren't Decode/Encode ifaces
* These two often share code.
 */

/* On type wrangling in Go:
* Go doesn't allow "extension methods", ie we can't add methods to other package's types, so we can't add MarshalJSON to rsa.PublicKey
* Hence, we alias those types and impl the marshal funcs on our aliases
* Often you'll hold a variable typed as the crypto.[Public,Private]Key interface, and want to marshal that.
* That iface doesn't include MarshalJSON, so again we wanna add it.
* However we can't even alias the interface and do it that way, because you can't have iface receivers.
* Hence, functions like these at the top that go from the stdlib iface to one of our concrete impls.
 */

// TODO Use generics to collapse all this public/private split?

// ===
// crypto.Key -> JSON
// ===

func Key2MarshalerPublic(k crypto.PublicKey) (json.Marshaler, error) {
	switch typedKey := k.(type) {
	case *rsa.PublicKey:
		return (*printableRsaPublicKey)(typedKey), nil
	case *ecdsa.PublicKey:
		return (*printableEcdsaPublicKey)(typedKey), nil
	case ed25519.PublicKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	default:
		return nil, fmt.Errorf("unknown key type: %T", k)
	}
}
func Key2JWKPublic(k crypto.PublicKey) (string, error) {
	return marshaler2JSON(k, Key2MarshalerPublic)
}

func Key2MarshalerPrivate(k crypto.PrivateKey) (json.Marshaler, error) {
	switch typedKey := k.(type) {
	case *rsa.PrivateKey:
		return (*printableRsaPrivateKey)(typedKey), nil
	case *ecdsa.PrivateKey:
		return (*printableEcdsaPrivateKey)(typedKey), nil
	case ed25519.PrivateKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	default:
		return nil, fmt.Errorf("unknown key type: %T", k)
	}
}
func Key2JWKPrivate(k crypto.PrivateKey) (string, error) {
	return marshaler2JSON(k, Key2MarshalerPrivate)
}

// ===
// JSON -> crypto.Key
// ===

// TODO: make all the examples of embedding these in other structs etc, cause this might need to be public?
type jwkPublic struct {
	KeyId string
	Key   crypto.PublicKey
}

func (p *jwkPublic) UnmarshalJSON(data []byte) error {
	protoKey := struct {
		KeyId   string `json:"kid,omitempty"`
		KeyType string `json:"kty"`
	}{}
	err := json.Unmarshal(data, &protoKey)
	if err != nil {
		return err
	}
	p.KeyId = protoKey.KeyId

	switch protoKey.KeyType {
	case "RSA":
		k := new(printableRsaPublicKey)
		err := k.UnmarshalJSON(data)
		if err != nil {
			return err
		}
		p.Key = (*rsa.PublicKey)(k)
		return nil
	case "EC":
		k := new(printableEcdsaPublicKey)
		err := k.UnmarshalJSON(data)
		if err != nil {
			return err
		}
		p.Key = (*ecdsa.PublicKey)(k)
		return nil
	default:
		return fmt.Errorf("unknown key type %s", protoKey.KeyType)
	}
}

func JWK2KeyPublic(j []byte) (crypto.PublicKey, error) {
	u := &jwkPublic{}
	err := u.UnmarshalJSON(j)
	return u.Key, err
}

type jwkPrivate struct {
	KeyId string
	Key   crypto.PrivateKey
}

func (p *jwkPrivate) UnmarshalJSON(data []byte) error {
	protoKey := struct {
		KeyId   string `json:"kid,omitempty"`
		KeyType string `json:"kty"`
	}{}
	err := json.Unmarshal(data, &protoKey)
	if err != nil {
		return err
	}
	p.KeyId = protoKey.KeyId

	switch protoKey.KeyType {
	case "RSA":
		k := new(printableRsaPrivateKey)
		err := k.UnmarshalJSON(data)
		if err != nil {
			return err
		}
		p.Key = (*rsa.PrivateKey)(k)
		return nil
	case "EC":
		k := new(printableEcdsaPrivateKey)
		err := k.UnmarshalJSON(data)
		if err != nil {
			return err
		}
		p.Key = (*ecdsa.PrivateKey)(k)
		return nil
	default:
		return fmt.Errorf("unknown key type %s", protoKey.KeyType)
	}
}

func JWK2KeyPrivate(j []byte) (crypto.PrivateKey, error) {
	u := &jwkPrivate{}
	err := u.UnmarshalJSON(j)
	return u.Key, err
}

// ===
// Impl for RSA::Public
// ===

type printableRsaPublicKey rsa.PublicKey

type rsaPublicKeyFields struct {
	KeyId     string `json:"kid,omitempty"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	N         string `json:"n"` // Modulus ie P * Q
	E         string `json:"e"` // Public exponent
}

func (k *printableRsaPublicKey) MarshalJSON() ([]byte, error) {
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	// TODO: try big-endian, and trim the string from the other end
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&rsaPublicKeyFields{
		KeyType:   "RSA",
		Algorithm: "RS" + strconv.Itoa((*rsa.PublicKey)(k).Size()),
		N:         base64.RawURLEncoding.EncodeToString(k.N.Bytes()), // Bytes returns big-endian
		E:         base64.RawURLEncoding.EncodeToString(bufE),
	})
}

func (k *printableRsaPublicKey) UnmarshalJSON(data []byte) error {
	key := rsaPublicKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return err
	}

	if key.KeyType != "RSA" {
		return fmt.Errorf("key type must be RSA, not %s", key.KeyType)
	}
	if !strings.HasPrefix(key.Algorithm, "RS") {
		return fmt.Errorf("unknown algorithm %s; must start 'RS'", key.Algorithm)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}
	n := new(big.Int).SetBytes(nBytes)

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}
	eBuf := make([]byte, 8) // will be zero-filled
	//copy(eBuf[8-len(eBytes):], eBytes) - even though these numbers are allegedly big-endian, we have to put this at the start of the memory
	copy(eBuf[:], eBytes)
	e := binary.LittleEndian.Uint64(eBuf[:])

	*k = printableRsaPublicKey{
		N: n,
		E: int(e),
	}

	return nil
}

// ===
// Impl for RSA::Private
// ===

type printableRsaPrivateKey rsa.PrivateKey

type rsaPrivateKeyFields struct {
	KeyId     string `json:"kid,omitempty"`
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

func (k *printableRsaPrivateKey) MarshalJSON() ([]byte, error) {
	if len(k.Primes) != 2 {
		return nil, fmt.Errorf("don't know how to deal with keys that don't have precisely 2 factors")
	}
	bufE := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufE, uint64(k.E)) // Seems to need to be little-endian to make the URL-encoded version ome out right
	bufE = bufE[:determineLenE(k.E)]
	return json.Marshal(&rsaPrivateKeyFields{
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

func (k *printableRsaPrivateKey) UnmarshalJSON(data []byte) error {
	key := rsaPrivateKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return err
	}

	if key.KeyType != "RSA" {
		return fmt.Errorf("key type must be RSA, not %s", key.KeyType)
	}
	if !strings.HasPrefix(key.Algorithm, "RS") {
		return fmt.Errorf("unknown algorithm %s; must start 'RS'", key.Algorithm)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}
	eBuf := make([]byte, 8) // will be zero-filled
	//copy(eBuf[8-len(eBytes):], eBytes) - even though these numbers are allegedly big-endian, we have to put this at the start of the memory
	copy(eBuf[:], eBytes)
	e := binary.LittleEndian.Uint64(eBuf[:])

	*k = printableRsaPrivateKey{
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
	(*rsa.PrivateKey)(k).Precompute()

	return nil
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

type printableEcdsaPublicKey ecdsa.PublicKey

type ecdsaPublicKeyFields struct {
	KeyId   string `json:"kid,omitempty"`
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

func (k *printableEcdsaPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ecdsaPublicKeyFields{
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
	})
}
func (k *printableEcdsaPublicKey) UnmarshalJSON(data []byte) error {
	key := ecdsaPublicKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return err
	}

	if key.KeyType != "EC" {
		return fmt.Errorf("key type must be EC, not %s", key.KeyType)
	}

	*k = printableEcdsaPublicKey{}
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
		return fmt.Errorf("unknown Curve %s", key.Curve)
	}

	k.X = base64toBigInt(key.X)
	k.Y = base64toBigInt(key.Y)

	return nil
}

// ===
// Impl for ECDSA::Private
// ===

type printableEcdsaPrivateKey ecdsa.PrivateKey

type ecdsaPrivateKeyFields struct {
	KeyId   string `json:"kid,omitempty"`
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
	D       string `json:"d"`
}

func (k *printableEcdsaPrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ecdsaPrivateKeyFields{
		KeyType: "EC",
		Curve:   k.Curve.Params().Name,
		X:       base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		D:       base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
	})
}

func (k *printableEcdsaPrivateKey) UnmarshalJSON(data []byte) error {
	key := ecdsaPrivateKeyFields{}
	err := json.Unmarshal(data, &key)
	if err != nil {
		return err
	}

	if key.KeyType != "EC" {
		return fmt.Errorf("key type must be EC, not %s", key.KeyType)
	}

	*k = printableEcdsaPrivateKey{}
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
		return fmt.Errorf("unknown Curve %s", key.Curve)
	}

	k.X = base64toBigInt(key.X)
	k.Y = base64toBigInt(key.Y)
	k.D = base64toBigInt(key.D)

	return nil
}
