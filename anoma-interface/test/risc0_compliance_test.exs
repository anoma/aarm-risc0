defmodule Risc0ComplianceTest do
  use ExUnit.Case

  doctest Risc0.Risc0Prover
  # doctest Risc0.Risc0VM


  test "compliance_circuit" do
    @compliance_guest_elf File.read!("../../compliance-circuit/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/compliance_guest")
    @compliance_guest_id [315782455, 1772597895, 583415932, 1109590875, 2105184756, 3389341533, 295239703, 2779425424]

    label = Risc0.random_32()
    nonce_1 = Risc0.random_32()
    nonce_2 = Risc0.random_32()
    quantity = Risc0.random_32()
    value = Risc0.random_32()
    eph = 0
    nsk = Risc0.generate_nsk()
    merkle_path = Risc0.generate_merkle_path_32()

    input_resource = Risc0.generate_resource(
      label,
      nonce_1,
      quantity,
      value,
      eph,
      nsk,
      image_id,
      rseed_1
    )

    output_resource = Risc0.generate_resource(
      label,
      nonce_2,
      quantity,
      value,
      eph,
      nsk,
      image_id,
      rseed_2
    )

    compliance_circuit = Risc0.generate_compliance_circuit(
      input_resource,
      output_resource,
      rcv,
      merkle_path,
      nsk
    )

    # Prove and verify
    receipt = Risc0.prove(compliance_circuit, compliance_guest_elf)
    assert true = Risc0.verify(receipt, compliance_guest_id)
  end
end