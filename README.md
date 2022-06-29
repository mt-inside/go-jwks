# pem2jwks

Run from container image:
```bash
cat key.pwm | docker run -i --rm ghcr.io/mt-inside/pem2jwks:latest
```

Download single, statically-linked binary
```bash
curl --output pem2jwks https://github.com/mt-inside/pem2jwks/releases/download/v0.0.6/pem2jwks-$(uname -s)-$(uname -m)
```

Install from source
```bash
go install github.com/mt-inside/pem2jwks@latest
```
