.PHONY: pwn build

all: pwn

pwn: build
	docker run --rm -it \
		-v "$(PWD):/chall" \
		--cap-add=SYS_PTRACE \
		--security-opt seccomp=unconfined \
		ppp-debug \
		tmux

build:
	docker build -t sekai-base .
	docker build -f Dockerfile.pwn -t ppp-debug .

