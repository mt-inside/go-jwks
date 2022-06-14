package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"
)

type jwk interface {
	MarshalJSON() ([]byte, error)
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type printableRsaPublicKey rsa.PublicKey
type printableEcdsaPublicKey ecdsa.PublicKey
type printableEd25519PublicKey ed25519.PublicKey

func padEven(n string) string {
	if len(n)%2 == 1 {
		return "0" + n
	}
	return n
}

func main() {
	var opts struct {
		Singleton bool `short:"1" long:"singleton" description:"Output only a single JWK rather than an array of them (a JWKS)"`
		// TODO: https://datatracker.ietf.org/doc/html/rfc7517#appendix-A
		Private bool `short:"p" long:"private" description:"Include private key parameters in output. If not specified then supplying a private key will extract just the public fields from it"`
	}
	flags.Parse(&opts)

	// TODO: read keys(s) from stdin
	bytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	var blocks []*pem.Block
	for len(bytes) != 0 {
		block, rest := pem.Decode(bytes)
		if block == nil {
			panic("Input doesn't decode as PEM")
		}
		blocks = append(blocks, block)
		bytes = rest
	}

	if opts.Singleton {
		if len(blocks) != 1 {
			panic("--singleton requires input PEM containing precisely one key")
		}
		op(process(blocks[0]))
		os.Exit(0)
	}

	var keys jwks
	for _, block := range blocks {
		keys.Keys = append(keys.Keys, process(block))
	}
	op(keys)
}

func process(block *pem.Block) jwk {

	var key crypto.PublicKey
	if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key = pubKey
	} else if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		key = cert.PublicKey
	} else if privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil { // RSA only; type *rsa.PrivateKey
		key = privKey.Public()
	} else if privKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil { // RSA, ECDSA, Ed25519; type any, however: https://pkg.go.dev/crypto#PrivateKey
		key = privKey.(interface {
			Public() crypto.PublicKey
		}).Public()
	} else if privKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil { // ECDSA only; type *ecdsa.PrivateKey
		key = privKey.Public()
	} else {
		panic("input PEM does not encode a public key, certificate, or private key")
	}

	// TODO: do generics help??
	var printableKey jwk
	switch typedKey := key.(type) {
	case *rsa.PublicKey:
		printableKey = (*printableRsaPublicKey)(typedKey)
	case *ecdsa.PublicKey:
		printableKey = (*printableEcdsaPublicKey)(typedKey)
	case ed25519.PublicKey: // Not a pointer *shrug*
		printableKey = (printableEd25519PublicKey)(typedKey)
		panic("JWK does not support Ed25519")
	default:
		panic(fmt.Sprintf("Unknown key type: %T", key))
	}

	return printableKey
}

func (k *printableRsaPublicKey) MarshalJSON() ([]byte, error) {
	bufE := make([]byte, 4)
	binary.LittleEndian.PutUint32(bufE, uint32(k.E))
	bufE = bufE[:3] // TODO: what does the spec say? Are they always 3byte? Do we calcualte nearest power-of-2? Does Write() do this automatically?
	return json.Marshal(&struct {
		KeyType string `json:"kty"`
		N       string `json:"n"`
		E       string `json:"e"`
	}{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(bufE),
	})
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

func (k printableEd25519PublicKey) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func op(d interface{}) {
	op, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(op))
}
