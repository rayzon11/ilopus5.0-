## Simple Makefile for the Rust workspace
## Usage (from this directory):
##   make           # build release
##   make debug     # build debug
##   make run       # run release binary with a sample prompt
##   make test      # run tests
##   make clean     # clean target dir

.PHONY: all build debug run test clean

all: build

build:
	cargo build --release

debug:
	cargo build

run: build
	./target/release/claw --model opus prompt "hello from make"

test:
	cargo test

clean:
	cargo clean

