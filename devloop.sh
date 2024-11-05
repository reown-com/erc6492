#!/bin/bash
set -e

forge build --contracts=contracts

mkdir -p bytecode/Erc6492.sol
jq -r .bytecode.object out/Erc6492.sol/ValidateSigOffchain.json | xxd -r -p > bytecode/Erc6492.sol/ValidateSigOffchain.bytecode

mkdir -p bytecode/Erc1271Mock.sol
jq -r .bytecode.object out/Erc1271Mock.sol/Erc1271Mock.json | xxd -r -p > bytecode/Erc1271Mock.sol/Erc1271Mock.bytecode

cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --all-targets
cargo test --workspace --all-features --doc
