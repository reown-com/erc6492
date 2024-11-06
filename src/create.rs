use alloy::{
    primitives::{b256, Address, Bytes, B256},
    sol_types::SolValue,
};

pub const ERC6492_MAGIC_BYTES: B256 =
    b256!("6492649264926492649264926492649264926492649264926492649264926492");

pub fn create_erc6492_signature(factory: Address, factory_data: Bytes, signature: Bytes) -> Bytes {
    (
        (factory, factory_data, signature).abi_encode_params(),
        ERC6492_MAGIC_BYTES,
    )
        .abi_encode_packed()
        .into()
}
