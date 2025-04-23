.PHONY: all clean

all: parse-quote

parse-quote:
	@cargo build --release
	@cp target/release/parse-quote ./parse-quote

clean:
	cargo clean
	rm -f parse-quote
