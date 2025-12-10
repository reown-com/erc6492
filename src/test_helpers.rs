use {
    alloy::{
        hex,
        node_bindings::{Anvil, AnvilInstance},
        primitives::Address,
        providers::{Provider, ProviderBuilder},
        signers::{k256::ecdsa::SigningKey, local::LocalSigner},
    },
    regex::Regex,
    std::process::Stdio,
    tokio::process::Command,
};

pub fn spawn_anvil() -> (
    AnvilInstance,
    String,
    impl Provider,
    LocalSigner<SigningKey>,
) {
    let anvil = Anvil::new().spawn();
    let rpc_url = anvil.endpoint();
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let private_key = anvil.keys().first().unwrap().clone();
    (
        anvil,
        rpc_url,
        provider,
        LocalSigner::from_signing_key(private_key.into()),
    )
}

pub const ERC1271_MOCK_CONTRACT: &str = "Erc1271Mock";
pub const CREATE2_CONTRACT: &str = "Create2";

pub async fn deploy_contract(
    rpc_url: &str,
    signer: &LocalSigner<SigningKey>,
    contract_name: &str,
    constructor_arg: Option<&str>,
) -> Address {
    let key_encoded = hex::encode(signer.to_bytes());
    let mut args = vec![
        "create",
        "--broadcast",
        "--contracts=contracts",
        contract_name,
        "--rpc-url",
        rpc_url,
        "--private-key",
        &key_encoded,
    ];
    if let Some(arg) = constructor_arg {
        args.push("--constructor-args");
        args.push(arg);
    }
    let output = Command::new("forge")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .await
        .unwrap();
    println!("forge status: {:?}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    println!("forge stdout: {stdout:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    println!("forge stderr: {stderr:?}");
    assert!(output.status.success());
    let (_, [contract_address]) = Regex::new("Deployed to: (0x[0-9a-fA-F]+)")
        .unwrap()
        .captures(&stdout)
        .unwrap()
        .extract();
    contract_address.parse().unwrap()
}
