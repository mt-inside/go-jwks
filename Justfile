containerImage := "docker.io/mtinside/pem2jwks"
containerTag := "0.0.2" # TODO get from git tag
platforms := "linux/amd64,linux/arm64,linux/arm/v7"

default:
	@just --list

run *ARGS:
	go run . {{ARGS}}

install:
	go install .

image-build:
	# TODO: think i can use docker build and docker push, just need to have done buildx create --use first
	docker buildx build --platform={{platforms}} -t {{containerImage}}:{{containerTag}} -t {{containerImage}}:latest --load .
image-push:
	docker buildx build --platform={{platforms}} -t {{containerImage}}:{{containerTag}} -t {{containerImage}}:latest --push .
image-ls:
	hub-tool tag ls --platforms mtinside/pem2jwks
image-inspect:
	docker buildx imagetools inspect {{containerImage}}:{{containerTag}}
