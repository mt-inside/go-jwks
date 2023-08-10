package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
)

type JWK struct {
	KeyID string
	Key   any
}

// ===
// PEM -> JSON / Marshaler
// ===

func PEM2JWKMarshaler(p []byte) (*JWK, error) {
	ders, err := parsePEM(p)
	if err != nil {
		return nil, fmt.Errorf("can't decode input as PEM: %w", err)
	}
	if len(ders) != 1 {
		return nil, fmt.Errorf("PEM must contain precisely one block")
	}

	key, err := parseDER(ders[0])
	if err != nil {
		return nil, fmt.Errorf("error in PEM block: %w", err)
	}

	return Key2JWKMarshaler(key)
}
func PEM2JWK(p []byte) (string, error) {
	return marshaler2JSON(p, PEM2JWKMarshaler)
}

// ===
// JSON -> PEM
// ===

func JWK2PEM(j []byte) ([]byte, error) {
	key, err := JWK2Key(j)
	if err != nil {
		return nil, err
	}

	der, err := renderDER(key)
	if err != nil {
		return nil, fmt.Errorf("error in key: %w", err)
	}

	blockTitle := "PUBLIC KEY"
	if KeyIsPrivate(key) {
		// Because we encode all priv keys as pkcs8 (even ecdsa, for which this isn't the openssl default), this string is always correct. If we used openssl's default SEC1 for ecdsa, this would need to be "EC PRIVATE KEY"
		blockTitle = "PRIVATE KEY"
	}
	return renderPEM([]pemBlock{{der, blockTitle}})
}

// ===
// crypto.Key -> JSON / Marshaler
// ===

func (k *JWK) MarshalJSON() ([]byte, error) {
	switch typedKey := k.Key.(type) {
	case *rsa.PublicKey:
		return renderRsaPublicKey(typedKey, k.KeyID)
	case *ecdsa.PublicKey:
		return renderEcdsaPublicKey(typedKey, k.KeyID)
	case *rsa.PrivateKey:
		return renderRsaPrivateKey(typedKey, k.KeyID)
	case *ecdsa.PrivateKey:
		return renderEcdsaPrivateKey(typedKey, k.KeyID)
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
func Key2JWKMarshaler(k any) (*JWK, error) {
	switch k.(type) {
	case *rsa.PublicKey:
		return &JWK{Key: k}, nil
	case *ecdsa.PublicKey:
		return &JWK{Key: k}, nil
	case ed25519.PublicKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	case *rsa.PrivateKey:
		return &JWK{Key: k}, nil
	case *ecdsa.PrivateKey:
		return &JWK{Key: k}, nil
	case ed25519.PrivateKey: // Not a pointer *shrug*
		return nil, fmt.Errorf("JWK does not support Ed25519")
	default:
		return nil, fmt.Errorf("unknown key type: %T", k)
	}
}
func Key2JWK(k any) (string, error) {
	return marshaler2JSON(k, Key2JWKMarshaler)
}

// ===
// JSON -> crypto.Key / Unmarshaler
// ===

func (p *JWK) UnmarshalJSON(data []byte) error {
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
		k, err := parseRsaKey(data)
		if err != nil {
			return err
		}
		p.Key = k
		return nil
	case "EC":
		k, err := parseEcdsaKey(data)
		if err != nil {
			return err
		}
		p.Key = k
		return nil
	default:
		return fmt.Errorf("unknown key type %s", protoKey.KeyType)
	}
}

func JWK2Key(j []byte) (any, error) {
	u := &JWK{}
	err := u.UnmarshalJSON(j)
	return u.Key, err
}
