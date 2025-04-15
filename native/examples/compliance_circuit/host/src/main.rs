use aarm_core::{
    compliance::{ComplianceInstance, ComplianceWitness},
    constants::TREE_DEPTH,
    utils::GenericEnv,
};
use bincode;
use methods::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use serde_bytes::ByteBuf;
use std::time::Instant;

pub fn main() {
    let prove_start_timer = Instant::now();

    let compliance_witness: ComplianceWitness<TREE_DEPTH> =
        ComplianceWitness::<TREE_DEPTH>::default();
    let generic_env = GenericEnv {
        data: ByteBuf::from(bincode::serialize(&compliance_witness).unwrap()),
    };

    let env = ExecutorEnv::builder()
        .write(&generic_env)
        .unwrap()
        .build()
        .unwrap();

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            COMPLIANCE_GUEST_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt;

    println!("Receipt: {:?}", receipt);

    let seal = encode_seal(&receipt).unwrap();
    println!("Seal: {:?}", seal);

    println!("imageId: {:?}", COMPLIANCE_GUEST_ID);
    println!("imageId: {:?}", Digest::from(COMPLIANCE_GUEST_ID));

    println!("journal: {:?}", receipt.journal.bytes);

    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);

    let extract_journal_start_timer = Instant::now();
    // Extract journal of receipt
    let _compliance_instance: ComplianceInstance = receipt.journal.decode().unwrap();

    let extract_journal_duration = extract_journal_start_timer.elapsed();
    println!(
        "Extract Journal duration time: {:?}",
        extract_journal_duration
    );

    let verify_start_timer = Instant::now();

    receipt.verify(COMPLIANCE_GUEST_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);
}
