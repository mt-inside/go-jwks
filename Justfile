set dotenv-load

default:
	@just --list

DH_USER := "mtinside"
REPO := "docker.io/" + DH_USER + "/pem2jwks"
TAG := `git describe --tags --always --abbrev`
TAGD := `git describe --tags --always --abbrev --dirty --broken`
CGR_ARCHS := "aarch64,amd64" # "x86,armv7"
MELANGE := "melange"
APKO    := "apko"

tools-install:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# TODO: factor out into build scripts, share with dockerfile and github action
lint:
	goimports -local github.com/mt-inside/pem2jwks -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./...

test: lint
	go test ./... -race -covermode=atomic -coverprofile=coverage.out

run *ARGS: test
	go run ./cmd/pem2jwks {{ARGS}}

build: test
	go build -ldflags="-X 'github.com/mt-inside/pem2jwks/internal/build.Version="{{TAGD}}"'" ./cmd/pem2jwks

install: test
	go install -ldflags="-X 'github.com/mt-inside/pem2jwks/internal/build.Version="{{TAGD}}"'" ./cmd/pem2jwks

package:
	{{MELANGE}} keygen
	{{MELANGE}} build --arch {{CGR_ARCHS}} --signing-key melange.rsa melange.yaml

image-local:
	{{APKO}} build --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}} pem2jwks.tar
	docker load < pem2jwks.tar
image-publish:
	{{APKO}} login docker.io -u {{DH_USER}} --password "${DH_TOKEN}"
	{{APKO}} publish --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}}

image-ls:
	hub-tool tag ls --platforms {{REPO}}
image-inspect:
	docker buildx imagetools inspect {{REPO}}:{{TAG}}

clean:
	rm -f sbom-*
	rm -f pem2jwks.tar
	rm -f pem2jwks
	rm -f coverage.out
	rm -f melange.rsa*
	rm -rf packages/
