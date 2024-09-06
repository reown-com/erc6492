use {
    alloy::{
        hex,
        network::Ethereum,
        primitives::{eip191_hash_message, Address},
        providers::ReqwestProvider,
    },
    alloy_node_bindings::{Anvil, AnvilInstance},
    k256::ecdsa::SigningKey,
    regex::Regex,
    std::process::Stdio,
    tokio::process::Command,
};

fn format_foundry_dir(path: &str) -> String {
    format!(
        "{}/../../../../.foundry/{}",
        std::env::var("OUT_DIR").unwrap(),
        path
    )
}

pub fn spawn_anvil() -> (AnvilInstance, String, ReqwestProvider, SigningKey) {
    let anvil = Anvil::at(format_foundry_dir("bin/anvil")).spawn();
    let rpc_url = anvil.endpoint();
    let provider = ReqwestProvider::<Ethereum>::new_http(anvil.endpoint_url());
    let private_key = anvil.keys().first().unwrap().clone();
    (
        anvil,
        rpc_url,
        provider,
        SigningKey::from_bytes(&private_key.to_bytes()).unwrap(),
    )
}

pub const ERC1271_MOCK_CONTRACT: &str = "Erc1271Mock";
pub const CREATE2_CONTRACT: &str = "Create2";

pub async fn deploy_contract(
    rpc_url: &str,
    private_key: &SigningKey,
    contract_name: &str,
    constructor_arg: Option<&str>,
) -> Address {
    let key_encoded = hex::encode(private_key.to_bytes());
    let cache_folder = format_foundry_dir("forge/cache");
    let out_folder = format_foundry_dir("forge/out");
    let mut args = vec![
        "create",
        "--contracts=contracts",
        contract_name,
        "--rpc-url",
        rpc_url,
        "--private-key",
        &key_encoded,
        "--cache-path",
        &cache_folder,
        "--out",
        &out_folder,
    ];
    if let Some(arg) = constructor_arg {
        args.push("--constructor-args");
        args.push(arg);
    }
    let output = Command::new(format_foundry_dir("bin/forge"))
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

pub fn sign_message(message: &str, private_key: &SigningKey) -> Vec<u8> {
    let hash = eip191_hash_message(message.as_bytes());
    let (signature, recovery): (k256::ecdsa::Signature, _) = private_key
        .sign_prehash_recoverable(hash.as_slice())
        .unwrap();
    let signature = signature.to_bytes();
    // need for +27 is mentioned in ERC-1271 reference implementation
    [&signature[..], &[recovery.to_byte() + 27]].concat()
}
