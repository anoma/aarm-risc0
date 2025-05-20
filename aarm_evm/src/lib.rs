pub mod call;
pub mod conversion;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, Bytes, U256};
    use alloy::sol_types::SolType;
    use conversion::ProtocolAdapter::Resource;
    use rand::random;

    #[test]
    fn test_encode_resource() {
        let res = Resource {
            logicRef: B256::from_slice(&[0x11; 32]),
            labelRef: B256::from_slice(&[0x22; 32]),
            quantity: U256::from(12),
            valueRef: B256::from(U256::from(1)),
            ephemeral: true,
            nonce: U256::from_be_bytes(random::<[u8; 32]>()),
            nullifierKeyCommitment: B256::from(U256::from(0)),
            randSeed: U256::from(0),
        };

        let encoded: Vec<u8> = <Resource as SolType>::abi_encode(&res);
        println!("{}", Bytes::from(encoded));
    }
}
