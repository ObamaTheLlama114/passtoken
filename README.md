# Passtoken

Passtoken is a lightweight authentication system that allows you to:

1. Separate your authentication database from the rest of your data
2. Be sure it wont crash on you (because its written in rust)
3. Run it [standalone](#standalone) or [embed](#embedding) it into any [Rust](#rust), [C](#cc), [Python](#python) (WIP) or [Javascript/Typescript](#tsjs) (WIP) project, or anywhere you can run [Web Assembly](#wasm) (WIP)

## Using Passtoken

Passtoken can be run [standalone](#standalone) or [embeded](#embedding) into other projects.

## Standalone

### Prerequisites

- cargo and rustc
- postgres database
- redis database

### Steps

- Create a `.env` file in the `core` directory, and in that file set `DATABASE_URL` to the url of your postgres database.
- Run `cargo build --release -p server` to build a release binary.
- The final binary will be located at `target/release/passtoken._` The file extension will be different depending on what operating system you build for.
- When running the binary, make sure to create a `.env` file with `REDIS_URL` as the url to your redis database, and `POSTGRES_URL` as the url to your postgres database.

## Embedding

### Rust

For embeding into rust, it is as simple as including the library in your projects `Cargo.toml`

### C/C++

To build the C/C++ bindings, compile the `c_bindings` project with `cargo build --release -p c_bindings`

The bindings will be in the `include` directory, and the library file will be in `target/release/libc_bindings._` depending on what operating system you build for and what type of library you build. By default the c_bindings compile to a static library. To change it to a dynamic library, in `c_bindings/Cargo.toml` change `["staticlib"]` to `["cdylib"]`

### Python

WIP

### TS/JS

WIP

### WASM

WIP
