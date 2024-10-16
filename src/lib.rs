use alloy::{
    primitives::{Address, Bytes, B256},
    providers::Provider,
    rpc::types::{TransactionInput, TransactionRequest},
    sol,
    sol_types::SolConstructor,
    transports::{Transport, TransportErrorKind},
};

const SUCCESS_RESULT: u8 = 0x01;
sol! {
  contract ValidateSigOffchain {
    constructor (address _signer, bytes32 _hash, bytes memory _signature);
  }
}
const VALIDATE_SIG_OFFCHAIN_BYTECODE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/../../../../.foundry/forge/out/Erc6492.sol/ValidateSigOffchain.bytecode"
));

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Valid,
    Invalid,
}

impl Verification {
    pub fn is_valid(self) -> bool {
        matches!(self, Verification::Valid)
    }
}

pub type RpcError = alloy::transports::RpcError<TransportErrorKind>;

/// Verify a signature using ERC-6492.
///
/// This will return `Ok(Verification::Valid)` if the signature passes verification.
/// If the signature is invalid, it will return `Ok(Verification::Invalid)`.
///
/// If an error occurs while making the RPC call, it will return `Err(RpcError)`.
/// ```rust
/// # use alloy::primitives::eip191_hash_message;
/// # use alloy::providers::{network::Ethereum, ReqwestProvider};
/// # use alloy::signers::{local::LocalSigner, SignerSync};
/// # use erc6492::verify_signature;
/// #
/// # #[tokio::main]
/// # async fn main() {
/// # let account = LocalSigner::random();
/// # let message = "Hello, world!";
/// # let message_hash = eip191_hash_message(message);
/// # let signature = account.sign_message_sync(message.as_bytes()).unwrap().as_bytes().into();
/// # let address = account.address();
/// #
/// # let provider = ReqwestProvider::<Ethereum>::new_http("https://rpc.sepolia.org".parse().unwrap());
/// let verification = verify_signature(signature, address, message_hash, &provider).await.unwrap();
/// assert!(verification.is_valid());
/// # }
/// ```
pub async fn verify_signature<P, T>(
    signature: Bytes,
    address: Address,
    message_hash: B256,
    provider: &P,
) -> Result<Verification, RpcError>
where
    P: Provider<T>,
    T: Transport + Clone,
{
    let call = ValidateSigOffchain::constructorCall {
        _signer: address,
        _hash: message_hash,
        _signature: signature,
    };
    let bytes = VALIDATE_SIG_OFFCHAIN_BYTECODE
        .iter()
        .cloned()
        .chain(call.abi_encode())
        .collect::<Vec<u8>>();
    let transaction_request =
        TransactionRequest::default().input(TransactionInput::new(bytes.into()));

    let result = provider.call(&transaction_request).await;

    match result {
        Err(e) => {
            if let Some(error_response) = e.as_error_resp() {
                if error_response.message.starts_with("execution reverted") {
                    Ok(Verification::Invalid)
                } else {
                    Err(e)
                }
            } else {
                Err(e)
            }
        }
        Ok(result) => {
            if let Some(result) = result.first() {
                if result == &SUCCESS_RESULT {
                    Ok(Verification::Valid)
                } else {
                    Ok(Verification::Invalid)
                }
            } else {
                Ok(Verification::Invalid)
            }
        }
    }
}

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
mod test {
    use {
        super::*,
        alloy::{
            network::Ethereum,
            primitives::{address, b256, bytes, eip191_hash_message, Uint},
            providers::ReqwestProvider,
            signers::{k256::ecdsa::SigningKey, local::LocalSigner, SignerSync},
            sol_types::{SolCall, SolValue},
        },
        test_helpers::{deploy_contract, spawn_anvil, CREATE2_CONTRACT, ERC1271_MOCK_CONTRACT},
    };

    // Manual test. Paste address, signature, message, and project ID to verify
    // function
    #[tokio::test]
    #[ignore]
    async fn manual() {
        let address = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = bytes!("aaaa");

        let provider = ReqwestProvider::<Ethereum>::new_http(
            "https://rpc.walletconnect.com/v1?chainId=eip155:1&projectId=xxx"
                .parse()
                .unwrap(),
        );
        assert!(
            verify_signature(signature, address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn eoa_pass() {
        let (_anvil, _rpc_url, provider, _signer) = spawn_anvil();

        let signer = LocalSigner::random();
        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes();
        let address = signer.address();
        assert!(
            verify_signature(signature.into(), address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn eoa_wrong_signature() {
        let (_anvil, _rpc_url, provider, _signer) = spawn_anvil();

        let signer = LocalSigner::random();
        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let mut signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes();
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);
        let address = signer.address();
        assert!(
            !verify_signature(signature.into(), address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn eoa_wrong_address() {
        let (_anvil, _rpc_url, provider, _signer) = spawn_anvil();

        let signer = LocalSigner::random();
        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes();
        let mut address = signer.address();
        *address.0.first_mut().unwrap() = address.0.first().unwrap().wrapping_add(1);
        assert!(
            !verify_signature(signature.into(), address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn eoa_wrong_message() {
        let (_anvil, _rpc_url, provider, _signer) = spawn_anvil();

        let signer = LocalSigner::random();
        let message = "xxx";
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();
        let address = signer.address();
        let message2 = "yyy";
        let message2_hash = eip191_hash_message(message2);
        assert!(
            !verify_signature(signature, address, message2_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_pass() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &signer,
            ERC1271_MOCK_CONTRACT,
            Some(&signer.address().to_string()),
        )
        .await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();

        assert!(
            verify_signature(signature, contract_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_signature() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &signer,
            ERC1271_MOCK_CONTRACT,
            Some(&signer.address().to_string()),
        )
        .await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let mut signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes();
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);

        assert!(
            !verify_signature(signature.into(), contract_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_signer() {
        let (anvil, rpc_url, provider, signer) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &signer,
            ERC1271_MOCK_CONTRACT,
            Some(&signer.address().to_string()),
        )
        .await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = LocalSigner::from_signing_key(
            SigningKey::from_bytes(&anvil.keys().get(1).unwrap().to_bytes()).unwrap(),
        )
        .sign_message_sync(message.as_bytes())
        .unwrap()
        .as_bytes()
        .into();

        assert!(
            !verify_signature(signature, contract_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_contract_address() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let mut contract_address = deploy_contract(
            &rpc_url,
            &signer,
            ERC1271_MOCK_CONTRACT,
            Some(&signer.address().to_string()),
        )
        .await;

        *contract_address.0.first_mut().unwrap() =
            contract_address.0.first().unwrap().wrapping_add(1);

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();

        assert!(
            !verify_signature(signature, contract_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc1271_wrong_message() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let contract_address = deploy_contract(
            &rpc_url,
            &signer,
            ERC1271_MOCK_CONTRACT,
            Some(&signer.address().to_string()),
        )
        .await;

        let message = "xxx";
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();

        let message2 = "yyy";
        let message2_hash = eip191_hash_message(message2);
        assert!(
            !verify_signature(signature, contract_address, message2_hash, &provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    const ERC1271_MOCK_BYTECODE: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/../../../../.foundry/forge/out/Erc1271Mock.sol/Erc1271Mock.bytecode"
    ));
    const ERC6492_MAGIC_BYTES: [u16; 16] = [
        0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492, 0x6492,
        0x6492, 0x6492, 0x6492, 0x6492, 0x6492,
    ];
    sol! {
        contract Erc1271Mock {
            address owner_eoa;

            constructor(address owner_eoa) {
                owner_eoa = owner_eoa;
            }
        }
    }

    sol! {
        contract Create2 {
            function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) external payable returns (address addr);
        }
    }

    fn predeploy_signature(
        owner_eoa: Address,
        create2_factory_address: Address,
        signature: Vec<u8>,
    ) -> (Address, Vec<u8>) {
        let salt = b256!("7c5ea36004851c764c44143b1dcb59679b11c9a68e5f41497f6cf3d480715331");
        let contract_bytecode = ERC1271_MOCK_BYTECODE;
        let contract_constructor = Erc1271Mock::constructorCall { owner_eoa };

        let bytecode = contract_bytecode
            .iter()
            .cloned()
            .chain(contract_constructor.abi_encode())
            .collect::<Vec<u8>>();
        let predeploy_address = create2_factory_address.create2_from_code(salt, bytecode.clone());
        let signature = (
            create2_factory_address,
            Create2::deployCall {
                amount: Uint::ZERO,
                salt,
                bytecode: bytecode.into(),
            }
            .abi_encode(),
            signature,
        )
            .abi_encode_sequence()
            .into_iter()
            .chain(
                ERC6492_MAGIC_BYTES
                    .iter()
                    .flat_map(|&x| x.to_be_bytes().into_iter()),
            )
            .collect::<Vec<u8>>();
        (predeploy_address, signature)
    }

    #[tokio::test]
    async fn erc6492_pass() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &signer, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();
        let (predeploy_address, signature) =
            predeploy_signature(signer.address(), create2_factory_address, signature);

        assert!(
            verify_signature(signature.into(), predeploy_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_signature() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &signer, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let mut signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes();
        *signature.first_mut().unwrap() = signature.first().unwrap().wrapping_add(1);
        let (predeploy_address, signature) =
            predeploy_signature(signer.address(), create2_factory_address, signature.into());

        assert!(
            !verify_signature(signature.into(), predeploy_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_signer() {
        let (anvil, rpc_url, provider, signer) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &signer, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = LocalSigner::from_signing_key(
            SigningKey::from_bytes(&anvil.keys().get(1).unwrap().to_bytes()).unwrap(),
        )
        .sign_message_sync(message.as_bytes())
        .unwrap()
        .as_bytes()
        .into();
        let (predeploy_address, signature) =
            predeploy_signature(signer.address(), create2_factory_address, signature);

        assert!(
            !verify_signature(signature.into(), predeploy_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_contract_address() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &signer, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let message_hash = eip191_hash_message(message);
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();
        let (mut predeploy_address, signature) =
            predeploy_signature(signer.address(), create2_factory_address, signature);

        *predeploy_address.0.first_mut().unwrap() =
            predeploy_address.0.first().unwrap().wrapping_add(1);

        assert!(
            !verify_signature(signature.into(), predeploy_address, message_hash, &provider)
                .await
                .unwrap()
                .is_valid(),
        );
    }

    #[tokio::test]
    async fn erc6492_wrong_message() {
        let (_anvil, rpc_url, provider, signer) = spawn_anvil();
        let create2_factory_address =
            deploy_contract(&rpc_url, &signer, CREATE2_CONTRACT, None).await;

        let message = "xxx";
        let signature = signer
            .sign_message_sync(message.as_bytes())
            .unwrap()
            .as_bytes()
            .into();
        let (predeploy_address, signature) =
            predeploy_signature(signer.address(), create2_factory_address, signature);

        let message2 = "yyy";
        let message2_hash = eip191_hash_message(message2);
        assert!(!verify_signature(
            signature.into(),
            predeploy_address,
            message2_hash,
            &provider
        )
        .await
        .unwrap()
        .is_valid());
    }
}
