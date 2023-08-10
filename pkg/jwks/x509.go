package jwks

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// https://pkg.go.dev/crypto#PublicKey
type actualPublic interface {
	Equal(x crypto.PublicKey) bool
}

// https://pkg.go.dev/crypto#PrivateKey
type actualPrivate interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

func KeyIsPrivate(key any) bool {
	if _, ok := key.(actualPublic); ok {
		return false
	} else if _, ok := key.(actualPrivate); ok {
		return true
	} else {
		panic(fmt.Errorf("%T is neither crypto.[Public,Private]Key", key))
	}
}

func KeyPublicPart(key any) crypto.PublicKey {
	if KeyIsPrivate(key) {
		return key.(actualPrivate).Public()
	} else {
		return key
	}
}

// ParsePublicKey extracts the public key from the given cryptographic object.
// That object is expected to be the DER encoding of:
// * an x509 encoding (ie ASN.1 serialization) of a public key
// * a PKCS#1 (ie ASN.1 encoding) containing a public key, RSA-only
// * an x509 encoding (ie ASN.1 serialization) of a certificate
// * a PKCS#1 (ie ASN.1 encoding) containing a private key, RSA-only
// * a PKCS#8 (ie ASN.1 encoding) containing a private key
// * a SEC 1 (ie ASN.1 encoding) containing an EC private key
func parseDER(der []byte) (any, error) {

	if pubKey, err := x509.ParsePKIXPublicKey(der); err == nil { // returns type "any" (will be *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey). All stdlib PubKey types do conform to an unnamed iface: https://pkg.go.dev/crypto#PublicKey
		return pubKey, nil
	} else if pubKey, err := x509.ParsePKCS1PublicKey(der); err == nil { // RSA only; type *rsa.PublicKey
		return pubKey, nil
	} else if cert, err := x509.ParseCertificate(der); err == nil { // returns type "any"
		return cert.PublicKey, nil
	} else if privKey, err := x509.ParsePKCS1PrivateKey(der); err == nil { // RSA only; type *rsa.PrivateKey
		return privKey, nil
	} else if privKey, err := x509.ParsePKCS8PrivateKey(der); err == nil { // OpenSSL 3+ default. Returns type any (will be *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey). All stdlib PrivKey types do conform to an unnamed iface: https://pkg.go.dev/crypto#PrivateKey
		return privKey, nil
	} else if privKey, err := x509.ParseECPrivateKey(der); err == nil { // ECDSA only; type *ecdsa.PrivateKey
		return privKey, nil
	} else {
		return nil, fmt.Errorf("DER block does not encode a recognised cryptographic object")
	}
}

func renderDER(key any) ([]byte, error) {
	if !KeyIsPrivate(key) {
		// We chose to represent all public keys as PKIX ASN.1 DER. This is openssl 3.1.2's default for all of them anyway.
		return x509.MarshalPKIXPublicKey(key)
	} else {
		// We chose to represent all private keys as PKCS#8 ASN.1 DER. This is openssl 3.1.2's default for all of them except ecdsa (where it uses SEC1) but wanna keep it consistent
		return x509.MarshalPKCS8PrivateKey(key)
	}
}
