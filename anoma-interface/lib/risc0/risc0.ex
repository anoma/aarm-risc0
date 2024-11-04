defmodule Risc0.Risc0Prover do
  use Rustler, otp_app: :risc0, crate: :risc0_prover

  @moduledoc """
  Provides NIF functions for Risc0 proof generation, verification, and related cryptographic operations.
  This module contains the low-level Rust NIF bindings for zero-knowledge proofs and encryption.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  @doc """
  Generates a zero-knowledge proof for the given environment and ELF binary.

  ## Parameters
    - env_bytes: The environment data as a list of bytes
    - elf: The ELF binary as a list of bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The proof receipt as bytes or an error
  """
  @spec prove(list(byte()), list(byte())) ::
          nif_result({list(byte())})
  def prove(_env_bytes, _elf), do: error()

  @doc """
  Verifies a zero-knowledge proof receipt against an ELF binary.

  ## Parameters
    - receipt_bytes: The proof receipt as a list of bytes
    - elf: The ELF binary as a list of bytes

  ## Returns
    - {:ok, boolean()} | {:error, term()}: True if verification succeeds, false otherwise
  """
  @spec verify(list(byte()), list(byte())) :: nif_result(boolean())
  def verify(_receipt_bytes, _elf), do: error()

  @doc """
  Generates a resource with the given parameters.

  ## Parameters
    - label: Resource label as bytes
    - nonce: Nonce value as bytes
    - quantity: Resource quantity as bytes
    - value: Resource value as bytes
    - eph: Boolean flag indicating if resource is ephemeral
    - nsk: Nullifier spending key as bytes
    - image_id: Image identifier as bytes
    - rseed: Random seed as bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated resource as bytes or an error
  """
  @spec generate_resource(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    boolean(),
    list(byte()),
    list(byte()),
    list(byte())) :: nif_result(list(byte()))
  def generate_resource(
    _label,
    _nonce,
    _quantity,
    _value,
    _eph,
    _nsk,
    _image_id,
    _rseed
  ), do: error()

  @doc """
  Generates a compliance circuit for resource transfer verification.

  ## Parameters
    - input_resource: Input resource data as bytes
    - output_resource: Output resource data as bytes
    - rcv: Resource commitment value as bytes
    - merkle_path: Merkle path proof as bytes
    - nsk: Nullifier spending key as bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated circuit as bytes or an error
  """
  @spec generate_compliance_circuit(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte())) :: nif_result(list(byte()))
  def generate_compliance_circuit(
    _input_resource,
    _output_resource,
    _rcv,
    _merkle_path,
    _nsk
  ), do: error()

  @doc """
  Generates 32 random bytes.

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: 32 random bytes or an error
  """
  @spec random_32() :: nif_result(list(byte()))
  def random_32(), do: error()

  @doc """
  Generates a 32-level Merkle path.

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated Merkle path as bytes or an error
  """
  @spec generate_merkle_path_32() ::  nif_result(list(byte()))
  def generate_merkle_path_32(), do: error()

  @doc """
  Generates a nullifier spending key.

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated NSK as bytes or an error
  """
  @spec generate_nsk() :: nif_result(list(byte()))
  def generate_nsk(), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Encrypts a message using AES-256-GCM with the given keys and nonce.

  ## Parameters
    - message: The message to encrypt as bytes
    - pk_bytes: Public key bytes
    - sk_bytes: Secret key bytes
    - nonce_bytes: Nonce bytes for encryption

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The encrypted message as bytes or an error
  """
  @spec encrypt(list(byte()), list(byte()), list(byte()), list(byte())) :: nif_result(list(byte()))
  def encrypt(_message, _pk_bytes, _sk_bytes, _nonce_bytes), do: error()

  @doc """
  Decrypts a message using AES-256-GCM with the given keys and nonce.

  ## Parameters
    - cipher: The encrypted message as bytes
    - pk_bytes: Public key bytes
    - sk_bytes: Secret key bytes
    - nonce_bytes: Nonce bytes used for encryption

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The decrypted message as bytes or an error
  """
  @spec decrypt(list(byte()), list(byte()), list(byte()), list(byte())) :: nif_result(list(byte()))
  def decrypt(_cipher, _pk_bytes, _sk_bytes, _nonce_bytes), do: error()

  @doc """
  Generates a public/private keypair for encryption.

  ## Returns
    - {:ok, {list(byte()), list(byte())}} | {:error, term()}: A tuple containing the secret key and public key bytes
  """
  @spec generate_keypair() :: nif_result({list(byte()), list(byte())})
  def generate_keypair(), do: error()
end
