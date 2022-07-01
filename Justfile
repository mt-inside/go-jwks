default:
	@just --list

containerRepo := "docker.io/mtinside/pem2jwks"
containerTag  := `git describe --tag --abbrev`
buildTag      := `git describe --tag --abbrev --dirty`
platforms := "linux/amd64,linux/arm64,linux/arm/v7"

install-tools:
	bingo get

update-tool-pins:
	bingo get staticcheck@latest
	bingo get golangci-lint@latest

# TODO: factor out into build scripts, share with dockerfile and github action
lint: install-tools
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

image-build:
	# TODO: think i can use docker build and docker push, just need to have done buildx create --use first
	docker buildx build -t {{containerRepo}}:{{containerTag}} -t {{containerRepo}}:latest --load .
image-push:
	docker buildx build --platform={{platforms}} -t {{containerRepo}}:{{containerTag}} -t {{containerRepo}}:latest --push .
image-ls:
	hub-tool tag ls --platforms {{containerRepo}}
image-inspect:
	docker buildx imagetools inspect {{containerRepo}}:{{containerTag}}
