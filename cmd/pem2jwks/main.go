/*
* pem2jwks
* This is the root command, so it's an easy `go install .../mt-inside/pem2jwks`
 */
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/mt-inside/go-jwks"
	"github.com/mt-inside/go-jwks/internal/build"
)

func main() {

	var opts struct {
		Singleton bool `short:"1" long:"singleton" description:"Output only a single JWK rather than an array of them (a JWKS)"`
		Private   bool `short:"p" long:"private" description:"Include private key parameters in output. If not specified then supplying a private key will extract just the public fields from it"`
		Version   bool `short:"v" long:"version" description:"Print version information and exit"`
	}
	flagParser := flags.NewParser(&opts, flags.Default)
	rest, err := flagParser.Parse()
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(2)
		}
		os.Exit(1)
	}
	if len(rest) != 0 {
		flagParser.WriteHelp(os.Stdout)
		os.Exit(2)
	}
	if opts.Version {
		fmt.Println(build.Name, build.Version)
		os.Exit(0)
	}

	bytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	keys, err := jwks.PEM2Keys(bytes)
	if err != nil {
		panic(err)
	}

	if !opts.Private {
		pubKeys := make([]any, 0, len(keys))
		for _, key := range keys {
			pubKey := jwks.KeyPublicPart(key)
			pubKeys = append(pubKeys, pubKey)
		}
		keys = pubKeys
	}

	if opts.Singleton {
		if len(keys) != 1 {
			panic("--singleton requires input PEM containing precisely one key")
		}
		str, err := jwks.Key2JWK(keys[0])
		if err != nil {
			panic(err)
		}
		fmt.Println(str)
		os.Exit(0)
	}

	str, err := jwks.Keys2JWKS(keys)
	if err != nil {
		panic(err)
	}
	fmt.Println(str)
}
