# OAuth2

<a href="https://crates.io/crates/oauth2"><img src="https://img.shields.io/crates/v/oauth2.svg"></a>
<a href="https://travis-ci.org/ramosbugs/oauth2-rs"><img src="https://travis-ci.org/ramosbugs/oauth2-rs.svg?branch=master"></a>

A simple implementation of the OAuth2 flow in Rust.

Documentation is available on [docs.rs](https://docs.rs/crate/oauth2) or check the [examples](https://github.com/ramosbugs/oauth2-rs/tree/master/examples).

Before upgrading make sure to check out the [changelog](https://github.com/ramosbugs/oauth2-rs/releases).

## Development

Build:

```
cargo build
```

using futures 0.3:
```
cargo build --no-default-features --features "futures-03"
```

Run tests:

```
cargo test
```

using futures 0.3:
```
cargo test --no-default-features --features "futures-03"
```

Release:

```
cargo package && cargo publish
```
