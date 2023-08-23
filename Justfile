set dotenv-load

default:
	@just --list --unsorted --color=always

DH_USER := "mtinside"
GH_USER := "mt-inside"
DH_REPO := "docker.io/" + DH_USER + "/pem2jwks"
GH_REPO := "ghcr.io/" + GH_USER + "/pem2jwks"
TAG := `git describe --tags --always --abbrev`
TAGD := `git describe --tags --always --abbrev --dirty --broken`
CGR_ARCHS := "aarch64,amd64" # "x86,armv7"
LD_COMMON := "-ldflags \"-X 'github.com/mt-inside/go-jwks/internal/build.Version=" + TAGD + "'\""
LD_STATIC := "-ldflags \"-X 'github.com/mt-inside/go-jwks/internal/build.Version=" + TAGD + "' -w -linkmode external -extldflags '-static'\""
MELANGE := "melange"
APKO    := "apko"

tools-install:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/exp/cmd/...@latest
	go install github.com/kisielk/godepgraph@latest
	go install golang.org/x/tools/cmd/stringer@latest

generate:
	go generate ./...

lint: generate
	gofmt -s -w .
	goimports -local github.com/mt-inside/go-jwks -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./...

test: lint
	go test ./... -race -covermode=atomic -coverprofile=coverage.out

render-mod-graph:
	go mod graph | modgraphviz | dot -Tpng -o mod_graph.png

render-pkg-graph:
	godepgraph -s -onlyprefixes github.com/mt-inside ./cmd/pem2jwks | dot -Tpng -o pkg_graph.png

build-dev: test
	# Don't use CGO here, like in the container, so this binary is pretty representative.
	GCO_ENABLED=0 go build {{LD_COMMON}} ./cmd/pem2jwks

# Don't lint/test, because it doesn't work in various CI envs
build-ci *ARGS:
	# We don't use CGO as we've no need for it
	CGO_ENABLED=0 go build {{LD_COMMON}} -v {{ARGS}} ./cmd/pem2jwks

install: test
	CGO_ENABLED=0 go install {{LD_COMMON}} ./cmd/pem2jwks

package: test
	# if there's >1 package in this directory, apko seems to pick the _oldest_ without fail
	rm -rf ./packages/
	{{MELANGE}} bump melange.yaml {{TAGD}}
	{{MELANGE}} keygen
	{{MELANGE}} build --arch {{CGR_ARCHS}} --signing-key melange.rsa melange.yaml

image-local:
	{{APKO}} build --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{GH_REPO}}:{{TAG}} pem2jwks.tar
	docker load < pem2jwks.tar
image-publish:
	{{APKO}} login docker.io -u {{DH_USER}} --password "${DH_TOKEN}"
	{{APKO}} login ghcr.io   -u {{GH_USER}} --password "${GH_TOKEN}"
	{{APKO}} publish --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{GH_REPO}}:{{TAG}} {{DH_REPO}}:{{TAG}}
cosign-sign:
	# Experimental includes pushing the signature to a Rekor transparency log, default: rekor.sigstore.dev
	COSIGN_EXPERIMENTAL=1 cosign sign {{DH_REPO}}:{{TAG}}
	COSIGN_EXPERIMENTAL=1 cosign sign {{GH_REPO}}:{{TAG}}

image-ls:
	hub-tool tag ls --platforms {{GH_REPO}}
image-inspect:
	docker buildx imagetools inspect {{GH_REPO}}:{{TAG}}
sbom-show:
	docker sbom {{GH_REPO}}:{{TAG}}
snyk:
	snyk test .
	snyk container test {{GH_REPO}}:{{TAG}}
cosign-verify:
	COSIGN_EXPERIMENTAL=1 cosign verify {{GH_REPO}}:{{TAG}} | jq .

clean:
	rm -f coverage.out
	rm -f mod_graph.png pkg_graph.png
	rm -f sbom-*
	rm -rf packages/
	rm -f pem2jwks.tar
	rm -f pem2jwks
	rm -f melange.rsa*

run *ARGS: test
	go run {{LD_COMMON}} ./cmd/pem2jwks {{ARGS}}
