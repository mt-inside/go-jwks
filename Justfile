default:
	@just --list

containerRepo := "docker.io/mtinside/pem2jwks"
containerTag  := `git describe --tag --abbrev`
buildTag      := `git describe --tag --abbrev --dirty`
platforms := "linux/amd64,linux/arm64,linux/arm/v7"

install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

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
	docker buildx build -t {{containerRepo}}:{{containerTag}} -t {{containerRepo}}:latest --load .
image-push:
	docker buildx build --platform={{platforms}} -t {{containerRepo}}:{{containerTag}} -t {{containerRepo}}:latest --push .
image-ls:
	hub-tool tag ls --platforms {{containerRepo}}
image-inspect:
	docker buildx imagetools inspect {{containerRepo}}:{{containerTag}}
