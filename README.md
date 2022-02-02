# Tomb Drive

## Introduction

Tomb Drive is a simple cryptographic toolkit that allows you to encrypt and
decrypt single files, as well as to mount an encrypted / decrypted
representation of a directory as a virtual filesystem using FUSE.

It is written entirely in Rust and started as a little personal playground
project of mine to get familiar with the language. As such, it might not be
very Rusty ... I would not know.

The project currently uses AES-CTR (256bit key) cipher with PBKDF2 key
derivation, although I'm planning to change the latter to Argon2 before the
first major version release. Maybe.

## Status

The project is still in its early stages of development. The following
functionality kind of works:
  - single file encryption and decryption
  - mounting and browsing of the filesystem

The following is still very buggy:
  - reading on-the-fly encrypted/decrypted files from the filesystem

The following functionality is not expected to be implemented for the first
major version release:
  - writing into the filesystem

## Platforms

The project is developed and tested on Arch Linux. I currently do not have
resources to test beyond that.

## Requirements

To compile the project, you will need a Rust compiler that supports the
language edition 2021. As of writing of this document, I'm using `rustc 1.57.0`,
but some older or newer version should work too.

You will also need [libfuse](https://github.com/libfuse/libfuse/) installed
on your computer. Most Linux distributions have it in their repositories.

## Compilation and Usage

To compile the project, use `cargo` (that should come with your Rust
installation):

    cd tombdrive
    cargo build --release

To run Tomb Drive, copy the executable to your desired location, or run it
directly from the compiler's target directory:

    target/release/tombdrive --help

## Versioning and Backward Compatibility

The current version can be found in the _Cargo.toml_ file or by running:

    tombdrive --version

The version is made of three numbers, `MAJOR.MINOR.PATCH`. Up until the first
major version, anything is possible. Encryption might change so that your files
will no longer be decipherable with a newer version. The CLI flags may
disappear. Or the project may become something completely different. You've
been warned!

Once we reach `1.0.0`, breaking changes will only happen between major version
changes. Minor version will add or improve current features without breaking
backward compatibility. Patch versions are reserved for bug fixes.

## Security

Best effort. That about sums it up. Nobody qualified to do so has reviewed
this project from the security point of view.
