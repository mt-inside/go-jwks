# go-jwks

[![build](https://github.com/mt-inside/go-jwks/actions/workflows/test.yaml/badge.svg)](https://github.com/mt-inside/go-jwks/actions/workflows/test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mt-inside/go-jwks.svg)](https://pkg.go.dev/github.com/mt-inside/go-jwks)

go-jwks is a comprehensive library for de/serialising JWK[S] to PEMs, and Go's crypto.[Public,Private]Key types.

## pem2jwks

pem2jwks converts public keys in PEM format (typically used to _sign_ JWTs) to the JWKS format usually required by software that _validates_ them.

### Obtaining

Run from container image:
```bash
cat key.pem | docker run -i --rm ghcr.io/mt-inside/pem2jwks:latest
```

Download single, statically-linked binary
```bash
wget -O pem2jwks https://github.com/mt-inside/pem2jwks/releases/download/v0.0.10/pem2jwks-$(uname -s)-$(uname -m)
chmod u+x pem2jwks
cat key.pem | ./pem2jwks
```

Install from source
```bash
go install github.com/mt-inside/go-jwks/cmd/pem2jwks@latest
cat key.pem | ${GOPATH}/bin/pem2jwks
```

### Running

```
Usage:
  pem2jwks [OPTIONS]

Application Options:
  -1, --singleton  Output only a single JWK rather than an array of them (a JWKS)
  -p, --private    Include private key parameters in output. If not specified then supplying a private key will
                   extract just the public fields from it
```

### Alternatives
* [pem-to-jwk](https://github.com/callstats-io/pem-to-jwk) - JavaScript, last commit in 2016, uses string manipulation. Only works on EC keys? Only takes private keys as input? Only emits individual JWKs.
* [pem-jwk](https://github.com/dannycoates/pem-jwk) - JavaScript, last commit in 2018, uses string manipulation. Only works on RSA keys? Only takes public keys? Only emits individual JWKs.

### Istio JWT Auth Example
Generate a keypair, which will be used to sign JWTs and verify them
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Use the private key, in PEM form, to sign the JWT
```bash
go install github.com/golang-jwt/jwt/v5/cmd/jwt@latest
echo '{"sub": "one", "iss": "example.local", "iat": 1234567890, "exp": 2345678901}' | jwt -key private.pem -alg RS256 -sign - > one.jwt
```

Configure Istio to do authN of requests.
JWTs will have their signature checked against the public part of the key, which needs to be in JWKS format.
```bash
cat public.pem | pem2jwks | jq . > keystore.jwks

kubectl apply -f - << EOF
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-example
spec:
  selector:
    matchLabels:
      app: http-log
  jwtRules:
    - issuer: "example.local"
      outputPayloadToHeader: "x-end-user"
      forwardOriginalToken: true
      jwks: |
$(cat keystore.jwks | sed 's/^/        /')
EOF
```

Configure some request authZ rules
* Only logged-in users can access paths by default (ie anyone with a JWT with valid signature and matching our issuer)
* Allow anyone to access `/public`, logged-in or not
* Allow only the user `one` to access `/admin`
```bash
kubectl apply -f - << EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-all-public
spec:
  selector:
    matchLabels:
      app: http-log
  action: ALLOW
  rules:
    - to:
        - operation:
            paths: ["/public"]
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-authd-all
spec:
  selector:
    matchLabels:
      app: http-log
  action: ALLOW
  rules:
    - from:
        - source:
            requestPrincipals: ["*"]
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-one-admin
spec:
  selector:
    matchLabels:
      app: http-log
  action: DENY
  rules:
    - from:
        - source:
            notRequestPrincipals: ["example.local/one"]
      to:
        - operation:
            paths: ["/admin"]
EOF
```

Requests should pass the signed JWT in the `:authorization` header.
```bash
curlie http://$URL/admin
token="$(cat one.jwt | tr -d '\n')"
curlie http://$URL/admin "Authorization: Bearer $token"
```
