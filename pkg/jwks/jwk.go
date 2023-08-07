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
	"crypto/rsa"
	"encoding/json"
	"fmt"
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

type Jwk json.Marshaler

// ===
// PEM -> JSON
// ===

func PEM2JWKMarshalerPublic(p []byte) (Jwk, error) {
	ders, err := parsePEM(p)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}
	if len(ders) != 1 {
		return nil, fmt.Errorf("PEM must contain precisely one block")
	}

	key, err := parsePublicKey(ders[0])
	if err != nil {
		return nil, fmt.Errorf("error in PEM block: %w", err)
	}

	return Key2JWKMarshalerPublic(key)
}
func PEM2JWKPublic(p []byte) (string, error) {
	return marshaler2JSON(p, PEM2JWKMarshalerPublic)
}

func PEM2JWKMarshalerPrivate(p []byte) (Jwk, error) {
	ders, err := parsePEM(p)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}
	if len(ders) != 1 {
		return nil, fmt.Errorf("PEM must contain precisely one block")
	}

	key, err := parsePrivateKey(ders[0])
	if err != nil {
		return nil, fmt.Errorf("error in PEM block: %w", err)
	}

	return Key2JWKMarshalerPrivate(key)
}
func PEM2JWKPrivate(p []byte) (string, error) {
	return marshaler2JSON(p, PEM2JWKMarshalerPrivate)
}

// ===
// crypto.Key -> JSON
// ===

func Key2JWKMarshalerPublic(k crypto.PublicKey) (json.Marshaler, error) {
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
	return marshaler2JSON(k, Key2JWKMarshalerPublic)
}

func Key2JWKMarshalerPrivate(k crypto.PrivateKey) (json.Marshaler, error) {
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
	return marshaler2JSON(k, Key2JWKMarshalerPrivate)
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
// JSON -> PEM
// ===

func JWK2PEMPublic(j []byte) ([]byte, error) {
	key, err := JWK2KeyPublic(j)
	if err != nil {
		return nil, err
	}

	der, err := renderPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("error in key: %w", err)
	}

	return renderPEM([][]byte{der}, "PUBLIC KEY")
}

func JWK2PEMPrivate(j []byte) ([]byte, error) {
	key, err := JWK2KeyPrivate(j)
	if err != nil {
		return nil, err
	}

	der, err := renderPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error in key: %w", err)
	}

	// Because we encode all priv keys as pkcs8 (even ecdsa, for which this isn't the openssl default), this string is always correct. If we used openssl's default SEC1 for ecdsa, this would need to be "EC PRIVATE KEY"
	return renderPEM([][]byte{der}, "PRIVATE KEY")
}
