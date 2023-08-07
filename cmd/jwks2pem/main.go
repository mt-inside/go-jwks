package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/mt-inside/pem2jwks/internal/build"
	"github.com/mt-inside/pem2jwks/pkg/jwks"
)

func main() {

	var opts struct {
		Version bool `short:"v" long:"version" description:"Print version information and exit"`
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

	pem, err := jwks.PEM2JWKSPublic(bytes)
	if err != nil {
		panic(err)
	}

	fmt.Print(string(pem)) // pem already has a trailing newline
}
