set dotenv-load

default:
	@just --list

DH_USER := "mtinside"
REPO := "docker.io/" + DH_USER + "/pem2jwks"
TAG := `git describe --tags --always --abbrev`
TAGD := `git describe --tags --always --abbrev --dirty --broken`
CGR_ARCHS := "aarch64,amd64" # "x86,armv7"
LD_COMMON := "-ldflags \"-X 'github.com/mt-inside/go-jwks/internal/build.Version=" + TAGD + "'\""
MELANGE := "melange"
APKO    := "apko"

tools-install:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/exp/cmd/...@latest
	go install github.com/kisielk/godepgraph@latest

lint:
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
	godepgraph -s -onlyprefixes github.com/mt-inside ./cmd/http-log | dot -Tpng -o pkg_graph.png

build: test
	go build {{LD_COMMON}} ./cmd/pem2jwks

install: test
	go install {{LD_COMMON}} ./cmd/pem2jwks

package: test
	{{MELANGE}} bump melange.yaml {{TAGD}}
	{{MELANGE}} keygen
	{{MELANGE}} build --arch {{CGR_ARCHS}} --signing-key melange.rsa melange.yaml

image-local:
	{{APKO}} build --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}} pem2jwks.tar
	docker load < pem2jwks.tar
image-publish:
	{{APKO}} login docker.io -u {{DH_USER}} --password "${DH_TOKEN}"
	{{APKO}} publish --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}}
cosign-sign:
	# Experimental includes pushing the signature to a Rekor transparency log, default: rekor.sigstore.dev
	COSIGN_EXPERIMENTAL=1 cosign sign {{REPO}}:{{TAG}}

image-ls:
	hub-tool tag ls --platforms {{REPO}}
image-inspect:
	docker buildx imagetools inspect {{REPO}}:{{TAG}}

image-ls:
	hub-tool tag ls --platforms {{REPO}}
image-inspect:
	docker buildx imagetools inspect {{REPO}}:{{TAG}}
sbom-show:
	docker sbom {{REPO}}:{{TAG}}
snyk:
	snyk test .
	snyk container test {{REPO}}:{{TAG}}
cosign-verify:
	COSIGN_EXPERIMENTAL=1 cosign verify {{REPO}}:{{TAG}} | jq .

clean:
	rm -f sbom-*
	rm -f pem2jwks.tar
	rm -f pem2jwks
	rm -f coverage.out
	rm -f melange.rsa*
	rm -rf packages/

run *ARGS: test
	go run {{LD_COMMON}} ./cmd/pem2jwks {{ARGS}}
