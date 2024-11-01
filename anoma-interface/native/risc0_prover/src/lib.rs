use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
    Receipt,
    sha::{Impl, Sha256, Digest}
};
use rand::Rng;
use aarm_core::{Compliance, Resource, Nsk};
use rustler::{NifResult, Error};
use std::time::Instant;
use serde::{Serialize, Deserialize};
use serde_bytes::ByteBuf;

#[derive(Serialize, Deserialize)]
struct GenericEnv {
    data: ByteBuf,  // Stores unstructured data as bytes
}

#[rustler::nif]
fn prove(
    env_bytes: Vec<u8>,
    elf: Vec<u8>
) -> NifResult<Vec<u8>> {
    
    // let compliance: Compliance<32> = bincode::deserialize(&env_bytes).unwrap();

    let env = ExecutorEnv::builder()
        .write(&env_bytes)
        .expect("Failed to write to ExecutorEnv")
        .build()
        .expect("Failed to build ExecutorEnv");

    let prover = default_prover();
    let prove_start_timer = Instant::now();
    println!("Proving");
    let receipt = prover
        .prove(env, &elf)
        .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to prove: {:?}", e))))?
        .receipt;
    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);
    let receipt_bytes = bincode::serialize(&receipt).unwrap();
    Ok(receipt_bytes)
}


#[rustler::nif]
fn verify(
    receipt_bytes: Vec<u8>,
    guest_id_vec: Vec<u32>
) -> NifResult<bool> {
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).unwrap();
    println!("Vector length: {:?}", guest_id_vec.len());
    let guest_id: [u32; 8] = match guest_id_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(Error::RaiseTerm(Box::new("compliance_guest_id must have exactly 8 u32 values"))),
    };
    println!("Verify");
    let verify_start_timer = Instant::now();
    receipt
    .verify(guest_id)
    .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to verify: {:?}", e))))?;
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration); 
    Ok(true)
}

#[rustler::nif]
fn generate_resource(
    label: Vec<u8>,
    nonce: Vec<u8>,
    quantity: Vec<u8>,
    value: Vec<u8>,
    eph: bool,
    nsk: Vec<u8>,
    image_id: Vec<u8>,
    rseed: Vec<u8>
) -> NifResult<Vec<u8>> {
    let nk: Nsk =  bincode::deserialize(&nsk).unwrap();
    let resource = Resource {
        image_id: *Impl::hash_bytes(&image_id),
        label: bincode::deserialize(&label).unwrap(),
        quantity: bincode::deserialize(&quantity).unwrap(),
        value: bincode::deserialize(&value).unwrap(),
        eph, 
        nonce: *Impl::hash_bytes(&nonce),
        npk: nk.public_key(),
        rseed: bincode::deserialize(&rseed).unwrap(),
    };

    let resource_bytes = bincode::serialize(&resource).map_err(|e| Error::RaiseTerm(Box::new(format!("Serialization error: {:?}", e))))?;
    Ok(resource_bytes)
}

#[rustler::nif]
fn generate_compliance_circuit(
    input_resource: Vec<u8>,
    output_resource: Vec<u8>,
    rcv: Vec<u8>,
    merkle_path: Vec<u8>,
    nsk: Vec<u8>,
) -> NifResult<Vec<u8>> {
    let compliance = Compliance {
        input_resource: bincode::deserialize(&input_resource).unwrap(),
        output_resource: bincode::deserialize(&output_resource).unwrap(),
        merkle_path: bincode::deserialize::<[(Digest, bool); 32]>(&merkle_path).unwrap(),
        rcv: bincode::deserialize(&rcv).unwrap(),
        nsk: bincode::deserialize(&nsk).unwrap(),
    };

    let compliance_bytes = bincode::serialize(&compliance).map_err(|e| Error::RaiseTerm(Box::new(format!("Serialization error: {:?}", e))))?;
    Ok(compliance_bytes)
}

#[rustler::nif]
fn random_32() -> NifResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let random_elem: [u8; 32] = rng.gen();
    Ok(random_elem.to_vec())
}

#[rustler::nif]
fn generate_merkle_path_32() -> NifResult<Vec<u8>> {
    let mut merkle_path: [(Digest, bool); 32] =
    [(Digest::new([0; 8]), false); 32];

    for i in 0..32 {
        merkle_path[i] = (Digest::new([i as u32 + 1; 8]), i % 2 != 0);
    }
    Ok(bincode::serialize(&merkle_path).unwrap())
}

#[rustler::nif]
fn generate_nsk() -> NifResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let random_elem: [u8; 32] = rng.gen();
    let digest = *Impl::hash_bytes(&random_elem);
    Ok(bincode::serialize(&digest).unwrap())
}

rustler::init!(
    "Elixir.Risc0.Risc0Prover",
    [
        prove,
        verify,
        generate_merkle_path_32,
        generate_resource,
        random_32,
        generate_compliance_circuit,
        generate_nsk
    ]
);
