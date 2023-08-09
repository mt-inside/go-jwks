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

// TODO Use generics and/or any to collapse all this public/private split?
// - when collapsed, private2public flag that makes it read the public bit or error

type JWKPublic struct {
	KeyID string
	Key   crypto.PublicKey
}

type JWKPrivate struct {
	KeyID string
	Key   crypto.PrivateKey
}

// ===
// PEM -> JSON/Marshaler
// ===

func PEM2JWKMarshalerPublic(p []byte) (*JWKPublic, error) {
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

func PEM2JWKMarshalerPrivate(p []byte) (*JWKPrivate, error) {
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
// crypto.Key -> JSON/Marshaler
// ===

// TODO: keyId (involves breaking the interface off the impl types, indeed sacking them off
// - this still needs to be iface, so impl method over there that takes keyID?
func (k *JWKPublic) MarshalJSON() ([]byte, error) {
	switch typedKey := k.Key.(type) {
	case *rsa.PublicKey:
		return (*printableRsaPublicKey)(typedKey).MarshalJSON()
	case *ecdsa.PublicKey:
		return (*printableEcdsaPublicKey)(typedKey).MarshalJSON()
	default:
		panic(fmt.Errorf("invalid key type %T", k.Key))
	}
}

// This does a bit more than the JWKS-version because
// - needs to check for JWK-unsupported key types.
// - does the public-part extraction. When we have generics we can do it at render time? No! If we want one type, that won't encode whether we should do it, so we need to do so here at ctor time.
//   - TODO factor out to inisial call
//
// TODO: extra key types (wait for go 1.21; this API is being sorted apaz)
func Key2JWKMarshalerPublic(k crypto.PublicKey) (*JWKPublic, error) {
	switch typedKey := k.(type) {
	case *rsa.PublicKey:
		return &JWKPublic{Key: k}, nil
	case *ecdsa.PublicKey:
		return &JWKPublic{Key: k}, nil
	case ed25519.PublicKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	case *rsa.PrivateKey:
		return &JWKPublic{Key: typedKey.Public().(*rsa.PublicKey)}, nil
	case *ecdsa.PrivateKey:
		return &JWKPublic{Key: typedKey.Public().(*ecdsa.PublicKey)}, nil
	case ed25519.PrivateKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	default:
		return nil, fmt.Errorf("unknown key type: %T", k)
	}
}
func Key2JWKPublic(k crypto.PublicKey) (string, error) {
	return marshaler2JSON(k, Key2JWKMarshalerPublic)
}

// TODO: keyId (involves breaking the interface off the impl types, indeed sacking them off
func (k *JWKPrivate) MarshalJSON() ([]byte, error) {
	switch typedKey := k.Key.(type) {
	case *rsa.PrivateKey:
		return (*printableRsaPrivateKey)(typedKey).MarshalJSON()
	case *ecdsa.PrivateKey:
		return (*printableEcdsaPrivateKey)(typedKey).MarshalJSON()
	default:
		panic(fmt.Errorf("invalid key type %T", k.Key))
	}
}

func Key2JWKMarshalerPrivate(k crypto.PrivateKey) (*JWKPrivate, error) {
	switch k.(type) {
	case *rsa.PrivateKey:
		return &JWKPrivate{Key: k}, nil
	case *ecdsa.PrivateKey:
		return &JWKPrivate{Key: k}, nil
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
// JSON -> crypto.Key/Unmarshaler
// ===

func (p *JWKPublic) UnmarshalJSON(data []byte) error {
	protoKey := struct {
		KeyID   string `json:"kid,omitempty"`
		KeyType string `json:"kty"`
	}{}
	err := json.Unmarshal(data, &protoKey)
	if err != nil {
		return err
	}
	p.KeyID = protoKey.KeyID

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

// Could have a `JWK2KeyUnmarshalerPublic() *JWKPublic` for symmetry, but it wouldn't do anything, and dw people to think they have to use it

func JWK2KeyPublic(j []byte) (crypto.PublicKey, error) {
	u := &JWKPublic{}
	err := u.UnmarshalJSON(j)
	return u.Key, err
}

func (p *JWKPrivate) UnmarshalJSON(data []byte) error {
	protoKey := struct {
		KeyID   string `json:"kid,omitempty"`
		KeyType string `json:"kty"`
	}{}
	err := json.Unmarshal(data, &protoKey)
	if err != nil {
		return err
	}
	p.KeyID = protoKey.KeyID

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

// Ditto as JWK2KeyUnmarshalerPublic

func JWK2KeyPrivate(j []byte) (crypto.PrivateKey, error) {
	u := &JWKPrivate{}
	err := u.UnmarshalJSON(j)
	return u.Key, err
}

// ===
// JSON -> PEM
// * Note: no unmarshaler here, which would be strictly orthoganal, but why would I want a promise of a PEM? I'm almost certainly dealing with public keys in the JWKs, so I'm almost certainly verifying
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
