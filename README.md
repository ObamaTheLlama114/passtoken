# Passtoken

Passtoken is a lightweight authentication system that allows you to:

1. Separate your authentication database from the rest of your data
2. Be sure it wont crash on you (because its written in rust)
3. Run it [standalone](#standalone) or [embed](#embedding) it into any [Rust](#rust), [C](#cc) (WIP), [Python](#python) (WIP) or [Javascript/Typescript](#tsjs) (WIP) project, or anywhere you can run [Web Assembly](#wasm) (WIP)

## Using Passtoken

Passtoken can be run [standalone](#standalone) or [embeded](#embedding) into other projects.

## Standalone

### Prerequisites

- cargo and rustc
- a postgres database

### Steps

- Make sure you have both cargo and rustc installed.
- Run `cargo build --release` to build a release binary.
- The final binary will be located at `target/release/passtoken._` The file extension will be different depending on what operating system you build for.
- When running the binary, make sure to create a `.env` file with `POSTGRES_URL` as the url to your postgres database.

## Embedding

### Rust

For embeding into rust, it is as simple as including the library in you `Cargo.toml`

### C/C++

WIP

### Python

WIP

### TS/JS

WIP

### WASM

WIP
