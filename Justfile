containerImage := "docker.io/mtinside/pem2jwks"
containerTag := "0.0.1" # TODO get from git tag

default:
	@just --list

run *ARGS:
	go run . {{ARGS}}

install:
	go install .

image-build:
	docker build -t {{containerImage}}:{{containerTag}} -t {{containerImage}}:latest .
image-push: image-build
	docker push {{containerImage}}
image-ls:
	hub-tool tag ls --platforms mtinside/pem2jwks
