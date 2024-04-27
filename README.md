# Universal Etheruem signature verification with ERC-6492

This crate verifies any Ethereum signature including:

- EOAs
- Smart contract wallets with [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271)
- Predeploy contract wallets with [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492)

## Usage

This crate uses [Alloy](https://github.com/alloy-rs) and requires an RPC provider in order to verify all signature types.

```rust
use alloy_primitives::{address, bytes, eip191_hash_message};
use alloy_provider::{network::Ethereum, ReqwestProvider};

let address = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
let message = "xxx";
let signature = bytes!("aaaa");
let provider = ReqwestProvider::<Ethereum>::new_http("https://rpc.example.com");

let verification = verify_signature(signature, address, message, provider).await.unwrap();
if verification.is_valid() {
    // signature valid
}
```

See test cases in `src/lib.rs` for more examples.
