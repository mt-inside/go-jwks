containerImage := "docker.io/mtinside/pem2jwks"
containerTag := "0.0.3" # TODO get from git tag
platforms := "linux/amd64,linux/arm64,linux/arm/v7"

default:
	@just --list

# TODO: factor out into build scripts, share with dockerfile and github action
lint:
	go fmt ./...
	go vet ./...
	staticcheck -tags native ./...
	golangci-lint run --build-tags native ./...
	go test ./...

run *ARGS: lint
	go run . {{ARGS}}

install:
	go install .

image-build:
	# TODO: think i can use docker build and docker push, just need to have done buildx create --use first
	docker buildx build -t {{containerImage}}:{{containerTag}} -t {{containerImage}}:latest --load .
image-push:
	docker buildx build --platform={{platforms}} -t {{containerImage}}:{{containerTag}} -t {{containerImage}}:latest --push .
image-ls:
	hub-tool tag ls --platforms {{containerImage}}
image-inspect:
	docker buildx imagetools inspect {{containerImage}}:{{containerTag}}
