package jwks

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

// ParsePEM extracts the set of byte blocks from a PEM "ascii-armoured" file.
// These are expected to be DER encodings of cryptographic objects
func parsePEM(in []byte) ([][]byte, error) {
	var blocks [][]byte

	for len(in) != 0 {
		block, rest := pem.Decode(in)
		if block == nil {
			return nil, fmt.Errorf("input doesn't decode as PEM")
		}
		blocks = append(blocks, block.Bytes)
		in = rest
	}
	return blocks, nil
}

func renderPEM(ders [][]byte, title string) ([]byte, error) {
	var out [][]byte

	for _, der := range ders {
		block := &pem.Block{
			Type:  title,
			Bytes: der,
		}

		out = append(out, pem.EncodeToMemory(block))
	}

	return bytes.Join(out, nil), nil
}
