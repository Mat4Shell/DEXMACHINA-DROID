# DEX MACHINA // DROID

DEX MACHINA // DROID is the Android module of DEX MACHINA, a family of application security analyzers. It takes an Android package (APK, XAPK, APKS or AAB) and is meant to produce a security analysis that a penetration tester or a security analyst can act on, starting with static analysis and later extending to dynamic analysis.

Every file DROID opens is treated as potentially hostile. The parsers for the archive structure, Android binary XML, resource tables, DEX files and the APK signing block are being written for this project in Rust, with no unsafe code, bounded reads and explicit resource limits, so that a crafted application cannot act on the machine of the person analyzing it.

## Project status

DROID is in early development. The repository contains the Cargo workspace and its continuous integration, with one crate per area of the analysis: archive reading, binary XML and resources, DEX, signatures, the manifest model, reporting, and the `droid` command-line tool. The `droid` binary only answers `--version` and `--help` for now. Nothing here is ready for real use, and interfaces will change without notice until a first release is published.

The first parser is the ZIP container reader of `droid-archive`. It reads the central directory the way Android's own ZIP library does, so that the analysis covers the application Android would actually install, and it reports every construction that Android rejects, or that Android reads differently from a general-purpose ZIP tool, as a typed anomaly with a stable code. These differences are a common anti-analysis technique: a fake encryption flag, an unknown compression method that Android reads as stored, local headers that disagree with the central directory, duplicate names, data prepended or appended to the archive, or entries hidden from one reader or the other. Entries are only ever read in memory, never extracted to disk, under configurable limits on the number of entries, the length of names, the uncompressed size of each entry and of the whole archive, and the compression ratio.

## Building and testing

DROID is built with stable Rust. The exact toolchain is pinned in `rust-toolchain.toml`, so with [rustup](https://rustup.rs) installed, the right compiler and components are selected automatically when you run Cargo from the repository. Build the whole workspace with `cargo build --workspace --locked`, and run the test suite with `cargo test --workspace --locked`. The command-line tool can then be started with `cargo run --bin droid -- --help`.

The continuous integration also checks formatting with `cargo fmt --all --check`, runs Clippy with `cargo clippy --workspace --all-targets --locked -- -D warnings`, and checks dependency licenses, security advisories, duplicate versions and sources with [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) through `cargo deny check`. Running these commands locally before opening a pull request avoids a round trip with the CI. Contribution guidelines are in `CONTRIBUTING.md`.

The parsers are also fuzzed with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), which needs a nightly toolchain. Each fuzzing harness is a separate Cargo workspace that is never part of the product. For the ZIP reader, run `cargo +nightly fuzz run zip_archive -- -dict=zip.dict` from `crates/droid-archive/fuzz`.

## License

DEX MACHINA // DROID is dual-licensed. It is available under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), and a commercial license is offered by the copyright holder for uses that cannot meet the obligations of the AGPL. See [LICENSING.md](LICENSING.md) for the details, including the attribution that copies and derivative works must preserve, and `LICENSE` for the full text of the AGPL.

Copyright (C) 2026 Mathias EMON (Mat4Shell).
