/*
* pem2jwks
* This is the root command, so it's an easy `go install .../mt-inside/pem2jwks`
 */
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/mt-inside/pem2jwks/internal/build"
	"github.com/mt-inside/pem2jwks/pkg/jwks"
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

	pem2Printable := jwks.PublicPEM2Marshaler
	if opts.Private {
		pem2Printable = jwks.PrivatePEM2Marshaler
	}

	bytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	keys, err := pem2Printable(bytes)
	if err != nil {
		panic(err)
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
