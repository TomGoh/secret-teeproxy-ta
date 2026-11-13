# rust-libutee

## Introduction

`rust-libutee` is a Rust wrapper for **libutee**, providing Rust bindings and utilities to interact with the TEE user-mode TEE runtime.

Third-party dependencies (`mbedtls-smx`, `libc`, …) are declared in this crate's `Cargo.toml` only, not in the xtee-rust-sdk root workspace.

### Feature: `xtee-panic-notify`

For **x-kernel** TAs hosted by [`xtee-utee`](../xtee-utee), enable this feature so `TEE_Panic` calls `xtee_ta_panic_notify` and the CA receives `TEE_ERROR_TARGET_DEAD` on the in-flight invoke connection.

Without this feature, `_utee_panic` only spins in a loop (no undefined symbols when building standalone `src/bin/*` tools).

- **xtee-utee** enables it via a path dependency in `crates/xtee-utee/Cargo.toml`.
- **examples / ta-runtime TA** use the root workspace alias `rust_libutee.workspace = true`.

## Prerequisites

Before building the project, ensure that the required cross-compilers are available in your `PATH`.

Example:

```bash
export PATH=/home/data/tools/aarch64-linux-musl-cross/bin:$PATH
export PATH=/home/data/tools/x86_64-linux-musl-cross/bin:$PATH
```

## Build

Standalone (library + `src/bin/*`, default features, no `xtee-panic-notify`):

```bash
cd crates/rust-libutee
cargo build
cargo build --bin storage_test
cargo build --target x86_64-unknown-linux-musl --release
```

From **xtee-rust-sdk** root (TA / examples; `xtee-panic-notify` via workspace or `xtee-utee`):

```bash
cargo build --workspace --lib
```

## Test

`cargo test` runs the host unit and integration tests of this crate. The
inter-TA syscall entries (`TEE_OpenTASession` / `TEE_InvokeTACommand`) call
through `src/syscalls/seam.rs`: production builds forward to the raw
macro-generated syscall entries with unchanged signatures and argument
words, while test builds capture the five syscall argument words into a
thread-local and emulate the kernel-side write-backs, so syscall argument
passing (e.g. the `utee_params` address for Invoke) can be asserted on the
host without trapping.
