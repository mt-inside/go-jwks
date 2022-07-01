# pem2jwks 📜➡️🏦

pem2jwks converts public keys in PEM format (typically used to _sign_ JWTs) to the JWKS format usually required by software that _validates_ them.

## Running

Run from container image:
```bash
cat key.pem | docker run -i --rm ghcr.io/mt-inside/pem2jwks:v0.0.7
```

Download single, statically-linked binary
```bash
curl --output pem2jwks https://github.com/mt-inside/pem2jwks/releases/download/v0.0.7/pem2jwks-$(uname -s)-$(uname -m)
```

Install from source
```bash
go install github.com/mt-inside/pem2jwks@latest
```

## Options

```
Usage:
  pem2jwks [OPTIONS]

Application Options:
  -1, --singleton  Output only a single JWK rather than an array of them (a JWKS)
  -p, --private    Include private key parameters in output. If not specified then supplying a private key will
                   extract just the public fields from it
```

## Alternatives
* [pem-to-jwk](https://github.com/callstats-io/pem-to-jwk) - JavaScript, last commit in 2016, uses string manipulation. Only works on EC keys? Only takes private keys as input? Only emits individual JWKs.
* [pem-jwk](https://github.com/dannycoates/pem-jwk) - JavaScript, last commit in 2018, uses string manipulation. Only works on RSA keys? Only takes public keys? Only emits individual JWKs.
