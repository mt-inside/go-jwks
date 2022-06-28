package pem2jwks

import (
	"encoding/pem"
	"fmt"
)

// ParsePEM extracts the set of byte blocks from a PEM "ascii-armoured" file.
// These are expected to be DER encodings of cryptographic objects
func ParsePEM(bytes []byte) ([][]byte, error) {

	var blocks [][]byte
	for len(bytes) != 0 {
		block, rest := pem.Decode(bytes)
		if block == nil {
			return nil, fmt.Errorf("input doesn't decode as PEM")
		}
		blocks = append(blocks, block.Bytes)
		bytes = rest
	}
	return blocks, nil
}
