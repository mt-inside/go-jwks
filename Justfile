default:
	@just --list

containerRepo := "docker.io/mtinside/pem2jwks"
cleanVersion  := `git describe --tags --always --abbrev=0`
verboseVersion  := `git describe --tags --always --abbrev --dirty --broken`
platforms     := "linux/amd64,linux/arm64,linux/arm/v7"

tools-install:
	bingo get

tools-update-pins:
	bingo get staticcheck@latest
	bingo get golangci-lint@latest

# TODO: factor out into build scripts, share with dockerfile and github action
lint: tools-install
	#!/usr/bin/env bash
	source .bingo/variables.env
	go fmt ./...
	go vet ./...
	${STATICCHECK} -tags native ./...
	${GOLANGCI_LINT} run --build-tags native ./...
	go test ./...

run *ARGS: lint
	go run . {{ARGS}}

install:
	go install .

image-build-local:
	docker buildx build --build-arg VERSION={{verboseVersion}} -t {{containerRepo}}:{{cleanVersion}} -t {{containerRepo}}:latest --load .
image-publish:
	docker buildx build --platform={{platforms}} --build-arg VERSION={{verboseVersion}} -t {{containerRepo}}:{{cleanVersion}} -t {{containerRepo}}:latest --push .
image-ls:
	hub-tool tag ls --platforms {{containerRepo}}
image-inspect:
	docker buildx imagetools inspect {{containerRepo}}:{{cleanVersion}}
