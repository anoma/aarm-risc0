// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use aarm_core::{logic_instance::LogicInstance, resource_logic::TrivialLogicWitness};
use risc0_zkvm::{default_prover, ExecutorEnv};
use trivial_logic::{TRIVIAL_GUEST_ELF, TRIVIAL_GUEST_ID};

fn main() {
    let input = TrivialLogicWitness::default();
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove(env, TRIVIAL_GUEST_ELF).unwrap();

    // extract the receipt.
    let receipt = prove_info.receipt;

    let _output: LogicInstance = receipt.journal.decode().unwrap();

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    receipt.verify(TRIVIAL_GUEST_ID).unwrap();

    println!("TRIVIAL_GUEST_ID: {:?}", TRIVIAL_GUEST_ID);
}

#[ignore]
#[test]
fn print_trivial_elf_id() {
    // Write the elf binary to a file
    std::fs::write("../../aarm/elfs/padding_logic_elf.bin", TRIVIAL_GUEST_ELF)
        .expect("Failed to write trivial guest ELF binary");

    // Print the ID
    println!("Trivial Guest ID: {:?}", TRIVIAL_GUEST_ID);
}
