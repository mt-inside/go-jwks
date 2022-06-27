package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/mt-inside/pem2jwks/pkg/pem2jwks"
)

func main() {
	var opts struct {
		Singleton bool `short:"1" long:"singleton" description:"Output only a single JWK rather than an array of them (a JWKS)"`
		Private   bool `short:"p" long:"private" description:"Include private key parameters in output. If not specified then supplying a private key will extract just the public fields from it"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

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

	pem2Printable := pem2jwks.PublicPEM2Printable
	if opts.Private {
		pem2Printable = pem2jwks.PrivatePEM2Printable
	}

	var keys pem2jwks.Jwks
	for i, block := range blocks {
		key, err := pem2Printable(block)
		if err != nil {
			fmt.Printf("Error in PEM block %d, skipping: %v\n", i, err)
			continue
		}
		keys.Keys = append(keys.Keys, key)
	}

	if opts.Singleton {
		if len(keys.Keys) != 1 {
			panic("--singleton requires input PEM containing precisely one key")
		}
		render(keys.Keys[0])
		os.Exit(0)
	}

	render(keys)
}

func render(d interface{}) {
	op, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(op))
}
