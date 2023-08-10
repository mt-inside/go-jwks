#!/usr/bin/env bash

openssl genrsa -out rsa.pem 4096
openssl rsa -in rsa.pem -pubout -out rsa.pub.pem

# Has to be this curve rather than the more common secp256k1 or Go will spit it out
# * See list with openssl ecparam -list_curves
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -in ecdsa.pem -nocrypt | sponge ecdsa.pem
openssl ec -in ecdsa.pem -pubout -out ecdsa.pub.pem

openssl genpkey -algorithm ed25519 -out ed25519.pem
openssl pkey -in ed25519.pem -pubout -out ed25519.pub.pem

openssl genpkey -algorithm x25519 -out x25519.pem
openssl pkey -in x25519.pem -pubout -out x25519.pub.pem

openssl genpkey -algorithm ed448 -out ed448.pem
openssl pkey -in ed448.pem -pubout -out ed448.pub.pem

openssl genpkey -algorithm x448 -out x448.pem
openssl pkey -in x448.pem -pubout -out x448.pub.pem
