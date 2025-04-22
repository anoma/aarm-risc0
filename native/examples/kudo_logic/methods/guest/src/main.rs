use aarm_core::{
    action_tree::ACTION_TREE_DEPTH,
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::Ciphertext,
    logic_instance::LogicInstance,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use k256::Scalar;
use risc0_zkvm::{
    guest::env,
    sha::{Digest, Impl, Sha256},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct KudoResourceWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
    pub existence_path: MerklePath<ACTION_TREE_DEPTH>,
    pub denomination_logic: Digest,
    pub issuer: Option<AuthorizationVerifyingKey>,
    pub owner: (AuthorizationVerifyingKey, Digest), // (pk, logic_ref)
    pub receiver_signature: AuthorizationSignature,
    pub encryption_sk: Scalar,
    pub encryption_nonce: [u8; 12],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DenominationResource {
    pub resource: Resource,
    pub existence_path: MerklePath<ACTION_TREE_DEPTH>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ReceiveResource {
    pub resource: Resource,
    pub existence_path: MerklePath<ACTION_TREE_DEPTH>,
}

fn main() {
    // read the input
    let (kudo_resource_witness, denomination_resource, receive_resource): (
        KudoResourceWitness,
        DenominationResource,
        ReceiveResource,
    ) = env::read();

    // Check self resource existence
    let self_cm = kudo_resource_witness.resource.commitment();
    let tag = if kudo_resource_witness.is_consumed {
        kudo_resource_witness
            .resource
            .nullifier_from_commitment(&kudo_resource_witness.nf_key, &self_cm)
            .unwrap()
    } else {
        self_cm
    };
    let root = kudo_resource_witness.existence_path.root(tag);

    // Check denomination_resource existence
    let dr_cm = denomination_resource.resource.commitment();
    let dr_root = denomination_resource.existence_path.root(dr_cm);
    assert_eq!(root, dr_root);

    // Decode label
    if let Some(issuer) = kudo_resource_witness.issuer {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(denomination_resource.resource.logic_ref.as_bytes());
        bytes.extend_from_slice(&issuer.to_bytes());
        assert_eq!(
            kudo_resource_witness.resource.label_ref,
            *Impl::hash_bytes(&bytes)
        );
    } else {
        assert_eq!(
            kudo_resource_witness.resource.label_ref,
            denomination_resource.resource.logic_ref
        );
    }

    // Constrain denomination logic
    assert_eq!(
        kudo_resource_witness.denomination_logic,
        denomination_resource.resource.logic_ref
    );

    // Constrain the receive logic and generate the cipher if creating
    let cipher = if !kudo_resource_witness.is_consumed {
        // Check receive_resource existence
        let rr_cm = receive_resource.resource.commitment();
        let rr_root = receive_resource.existence_path.root(rr_cm);
        assert_eq!(root, rr_root);

        // Decode value
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&kudo_resource_witness.owner.0.to_bytes());
        bytes.extend_from_slice(kudo_resource_witness.owner.1.as_bytes());
        assert_eq!(
            kudo_resource_witness.resource.value_ref,
            *Impl::hash_bytes(&bytes)
        );

        // Constrain receive logic
        assert_eq!(
            kudo_resource_witness.owner.1,
            receive_resource.resource.logic_ref
        );

        // Verify signature
        assert!(kudo_resource_witness
            .owner
            .0
            .verify(root.as_bytes(), &kudo_resource_witness.receiver_signature,)
            .is_ok());

        // Generate the ciphertext
        let plain_text = kudo_resource_witness.resource.to_bytes();
        Ciphertext::encrypt(
            &plain_text,
            kudo_resource_witness.owner.0.as_affine(),
            &kudo_resource_witness.encryption_sk,
            kudo_resource_witness.encryption_nonce,
        )
    } else {
        // If consumed, the ciphertext is empty
        Ciphertext::default()
    };

    let instance = LogicInstance {
        tag,
        is_consumed: kudo_resource_witness.is_consumed,
        root,
        cipher,
        app_data: Vec::new(),
    };

    // write public output to the journal
    env::commit(&instance);
}
