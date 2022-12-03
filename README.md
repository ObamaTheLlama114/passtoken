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

- Rename `core/.env.example` to `.env` and set `DATABASE_URL` to the url to your postgres database.
- Run `cargo build --release -p server` to build a release binary.
- The final binary will be located at `target/release/passtoken._` The file extension will be different depending on what operating system you build for.
- When running the binary, make sure to copy `.env.example` as `.env` and edit the file to set `REDIS_URL` as the url to your redis database, and `POSTGRES_URL` as the url to your postgres database, and optionally set `TOKEN_EXPIRE_TIME` as how long in seconds you want tokens to last after being used.

## Embedding

### Rust

For embeding into rust, it is as simple as including the library in your projects `Cargo.toml`

### C/C++

To build the C/C++ bindings, compile the `c_bindings` project with `cargo build --release -p c_bindings`

The headers will be in the `include` directory, and the library file will be in `target/release/libc_bindings._` The file extension will be different depending on what operating system you build for.

### Python

WIP

### TS/JS

WIP

### WASM

WIP
