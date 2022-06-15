default:
	@just --list

run *ARGS:
	go run . {{ARGS}}
