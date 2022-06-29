# pem2jwks

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
