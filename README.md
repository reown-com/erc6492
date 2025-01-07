# Universal Rust Etheruem signature verification with ERC-6492

This crate verifies any Ethereum signature including:

- EOAs
- Smart contract wallets with [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271)
- Predeploy contract wallets with [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492)

This crate is implemented using a single `eth_call` RPC request, and is described in the [off-chain validation section](https://eips.ethereum.org/EIPS/eip-6492#off-chain-validation) of the ERC-6492 spec.

## Install

```bash
cargo add erc6492 --git https://github.com/reown-com/erc6492
```

or

```toml
erc6492 = { git = "https://github.com/reown-com/erc6492.git" }
```

We recommend pinning to a commit ref to avoid unexpected breaking changes while in v0.

We will publish to crates.io soon.

## Usage

This crate uses [Alloy](https://github.com/alloy-rs) and requires an RPC provider in order to verify all signature types.

```rust
let address = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
let message = eip191_hash_message("Hello, world!");
let signature = bytes!("aaaa");
let provider = ReqwestProvider::<Ethereum>::new_http("https://rpc.example.com".parse().unwrap());

let verification = verify_signature(signature, address, message, provider).await.unwrap();
if verification.is_valid() {
    // signature valid
}
```

See doctest on `verify_signature()` and test cases in `src/lib.rs` for more examples.
