#!/bin/bash
set -e

cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --all-targets
cargo test --workspace --all-features --doc
