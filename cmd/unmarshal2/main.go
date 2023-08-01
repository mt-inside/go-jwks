package main

import (
	"github.com/davecgh/go-spew/spew"

	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {
	src := `{
  "kid": "fd48a75138d9d48f0aa635ef569c4e196f7ae8d6",
  "use": "sig",
  "alg": "RS256",
  "kty": "RSA",
  "e": "AQAB",
  "n": "8KImylelEspnZ0X-ekZb9VPbUFhgB_yEPJuLKOhXOWJLVsU0hJP6B_mQOfVk0CHm66UsAhqV8qrINk-RXgwVaaFLMA827pbOOBhyvHsThcyo7AY5s6M7qbftFKKnkfVHO6c9TsQ9wpIfmhCVL3QgTlqlgFQWcNsY-qemSKpqvVi-We9I3kPvbTf0PKJ_rWA7GQQnU_GA5JRU46uvw4I1ODf0icNBHw7pWc7oTvmSl1G8OWABEyiFakcUG2Xd4qZnmWaKwLHBvifPuIyy2vK-yHH91mVZCuleVu53Vzj77RgUtF2EEuB-zizwC-fzaBmvnfx1kgQLsdK22J0Ivgu4Xw"
}`

	k, err := jwks.JSON2PublicKey([]byte(src))
	spew.Dump(k)
	spew.Dump(err)
}
