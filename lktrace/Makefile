all: build

build:
	@cargo build --release

run: build
	@cargo run --release

install:
	@cargo install lktrace --path=.

clean:
	@cargo clean

.PHONY: all build run install clean
