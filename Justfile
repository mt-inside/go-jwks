default:
	@just --list

containerRepo := "docker.io/mtinside/pem2jwks"
cleanVersion  := `git describe --tags --always --abbrev=0`
verboseVersion  := `git describe --tags --always --abbrev --dirty --broken`
platforms     := "linux/amd64,linux/arm64,linux/arm/v7"

tools-install:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

# TODO: factor out into build scripts, share with dockerfile and github action
lint:
	goimports -local github.com/mt-inside/pem2jwks -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./...
	go test ./... -race -covermode=atomic -coverprofile=coverage.out

run *ARGS: lint
	go run . {{ARGS}}

build: lint
	go build -ldflags="-X 'github.com/mt-inside/pem2jwks/internal/build.Version="{{verboseVersion}}"'" .

install: lint
	go install -ldflags="-X 'github.com/mt-inside/pem2jwks/internal/build.Version="${VERSION}"'" .

image-build-local:
	docker buildx build --build-arg VERSION={{verboseVersion}} -t {{containerRepo}}:{{cleanVersion}} -t {{containerRepo}}:latest --load .
image-publish:
	docker buildx build --platform={{platforms}} --build-arg VERSION={{verboseVersion}} -t {{containerRepo}}:{{cleanVersion}} -t {{containerRepo}}:latest --push .
image-ls:
	hub-tool tag ls --platforms {{containerRepo}}
image-inspect:
	docker buildx imagetools inspect {{containerRepo}}:{{cleanVersion}}
