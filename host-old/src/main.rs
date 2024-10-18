// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use aarm_core::ConsumptionInput;
use aarm_core::ConsumptionOutput;
use aarm_core::CreationInput;
use aarm_core::CreationOutput;
use aarm_core::Hashable;
use aarm_core::MerklePath;
use aarm_core::Nsk;
use aarm_core::Resource;
use aarm_core::COMMITMENT_TREE_DEPTH;
use methods::{
    ALWAYS_TRUE_ELF, ALWAYS_TRUE_ID, CONSUME_RESOURCE_ELF, CONSUME_RESOURCE_ID,
    CREATE_RESOURCE_ELF, CREATE_RESOURCE_ID,
};
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::compute_image_id;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::Receipt;
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use starknet_crypto::FieldElement;
use std::collections::BTreeSet;

/// An immutable commitment tree with a fixed depth
#[derive(Clone, Debug, Default)]
pub struct CommitmentTree<const COMMITMENT_TREE_DEPTH: usize, Node>(Vec<Node>, usize);

impl<const COMMITMENT_TREE_DEPTH: usize, Node: Hashable>
    CommitmentTree<COMMITMENT_TREE_DEPTH, Node>
{
    /// Construct a commitment tree with the given leaf nodes
    pub fn new(leafs: &[Node]) -> Self {
        // This capacity is sufficient to hold a Merkle tree (where an empty node
        // is added onto some rows to ensure that they are of even size) with the
        // given number of leaves. This follows from the identity ceil(ceil(x/m)/n)=ceil(x/(mn))
        let mut tree = Vec::with_capacity(leafs.len() * 2 + COMMITMENT_TREE_DEPTH - 1);
        tree.extend_from_slice(leafs);
        // Infer the rest of the tree
        Self::complete(tree, 0, leafs.len(), 0, leafs.len())
    }
    /// Merge the n-1 full Merkle trees with the last possibly unfilled one. All
    /// full trees must have the same size which must be a power of 2 and the
    /// tree must be smaller than this size.
    pub fn merge(subtrees: &[CommitmentTree<COMMITMENT_TREE_DEPTH, Node>]) -> Self {
        if subtrees.is_empty() {
            return Self(Vec::new(), 0);
        } else if subtrees.len() == 1 {
            return subtrees[0].clone();
        }
        let size = subtrees[0].size();
        assert!(size.is_power_of_two());
        for subtree in subtrees.iter().rev().skip(1) {
            assert_eq!(subtree.size(), size);
        }
        // Combine the 1 or more supplied subtrees
        let mut height = 0;
        let mut prev_first_start = 0;
        let mut prev_first_width = subtrees[0].size();
        let mut prev_last_start = 0;
        let mut prev_last_width = subtrees.last().unwrap().size();
        let mut prev_start = 0;
        let mut prev_width = (subtrees.len() - 1) * prev_first_width + prev_last_width;
        let leafs = prev_width;
        let mut tree = Vec::with_capacity(leafs * 2 + COMMITMENT_TREE_DEPTH - 1);
        loop {
            // Need to make sure that right child is present for parent
            if prev_last_width % 2 == 1 && prev_first_width > 1 {
                prev_last_width += 1;
                prev_width += 1;
            }
            // Combine all the rows at the current level
            for subtree in &subtrees[0..(subtrees.len() - 1)] {
                tree.extend_from_slice(
                    &subtree.0[prev_first_start..(prev_first_start + prev_first_width)],
                );
            }
            tree.extend_from_slice(
                &subtrees.last().unwrap().0[prev_last_start..(prev_last_start + prev_last_width)],
            );
            // Quit when we are the top of the full trees
            if prev_first_width == 1 {
                break;
            }
            // Update our positions on the full and unfull trees
            prev_first_start += prev_first_width;
            prev_first_width /= 2;
            prev_last_start += prev_last_width;
            prev_last_width /= 2;
            prev_start += prev_width;
            prev_width /= 2;
            height += 1;
        }
        // Now that we have taken as many levels as possible from the
        // supplied subtrees, infer the rest
        Self::complete(tree, prev_start, prev_width, height, leafs)
    }
    /// Complete the construction of given Merkle tree given the highest row data
    fn complete(
        mut tree: Vec<Node>,
        mut prev_start: usize,
        mut prev_width: usize,
        heightp: usize,
        leafs: usize,
    ) -> Self {
        // Compute the empty root for the given depth
        let mut empty_root = Node::blank();
        for height in 0..heightp {
            empty_root = Node::combine(height, &empty_root, &empty_root);
        }
        // Add higher and higher rows of the Merkle tree
        for height in heightp..COMMITMENT_TREE_DEPTH {
            if prev_width % 2 == 1 {
                // Add a dummy for the right-most parent's right child
                prev_width += 1;
                tree.push(empty_root)
            }
            for j in 0..(prev_width / 2) {
                // Add the nodes of the next row dependent upon previous row
                let comb = Node::combine(
                    height,
                    &tree[prev_start + 2 * j],
                    &tree[prev_start + 2 * j + 1],
                );
                tree.push(comb);
            }
            // Next row will be adjacent to current row in vector
            prev_start += prev_width;
            prev_width /= 2;
            empty_root = Node::combine(height, &empty_root, &empty_root);
        }
        Self(tree, leafs)
    }
    /// Get the root node of the commitment tree
    pub fn root(&self) -> Node {
        self.0.last().cloned().unwrap_or_else(|| {
            (0..COMMITMENT_TREE_DEPTH).fold(Node::blank(), |x, i| Node::combine(i, &x, &x))
        })
    }
    /// Construct a merkle path to the given position in commitment tree
    pub fn path(&self, mut pos: usize) -> MerklePath<COMMITMENT_TREE_DEPTH, Node>
    where
        Node: Serialize + for<'de2> Deserialize<'de2>,
    {
        let mut path = MerklePath {
            auth_path: [(Node::blank(), false); COMMITMENT_TREE_DEPTH],
            position: pos as u64,
        };
        let mut start = 0;
        let mut width = self.1;
        let mut empty_root = Node::blank();

        for height in 0..COMMITMENT_TREE_DEPTH {
            if width % 2 == 1 {
                width += 1;
            }
            if pos % 2 == 0 {
                // The current node is a left child
                let node = if pos + 1 < width {
                    // Node is within current row
                    self.0[start + pos + 1]
                } else {
                    // Node is to the right of current row
                    empty_root
                };
                path.auth_path[height] = (node, false);
            } else {
                // The current node is a right child
                let node = if pos - 1 < width {
                    self.0[start + pos - 1]
                } else {
                    empty_root
                };
                path.auth_path[height] = (node, true);
            }
            // Move to the parent of the current node
            start += width;
            width /= 2;
            pos /= 2;
            empty_root = Node::combine(height, &empty_root, &empty_root);
        }
        path
    }
    /// Returns the number of leaf nodes in the tree.
    pub fn size(&self) -> usize {
        self.1
    }
}

struct ProofRecord {
    // the proof of the desired statement
    receipt: Receipt,
    // contains the data required to verify a proof with a given witness
    image_id: Digest,
}

#[derive(Debug)]
enum TransactionError {
    // Invalid nullifier secret key given for a resource
    IncorrectNullifierSecretKey(Nsk),
    // Failed to create proof for the resource logic
    ResourceLogicFailure(anyhow::Error),
    // Failed to create a resource compliance proof
    ResourceComplianceFailure(anyhow::Error),
}

#[derive(Default)]
struct Transaction {
    // a set of proof records
    proofs: Vec<ProofRecord>,
    // represents the total delta change induced by the transaction
    delta: FieldElement,
}

impl Transaction {
    // Add an input to the transaction computing its nullifier and proof in the process
    fn add_input(
        &mut self,
        path: MerklePath<COMMITMENT_TREE_DEPTH, Digest>,
        resource: Resource,
        resource_elf: &[u8],
        nsk: Nsk,
        extra: &impl Serialize,
    ) -> Result<(), TransactionError> {
        // Ensure that the nullifier secret keey is correct
        if resource.nullifier(nsk.clone()).is_none() {
            return Err(TransactionError::IncorrectNullifierSecretKey(nsk));
        };
        // Ensure that the elf we run corresponds to the resource image
        assert_eq!(resource.image_id, compute_image_id(resource_elf).unwrap());
        self.delta += resource.delta();
        // Obtain the default prover.
        let prover = default_prover();
        // Provide the extra data to the resource
        let resource_env = ExecutorEnv::builder()
            .write(extra)
            .unwrap()
            .build()
            .unwrap();
        // Produce a receipt by proving the specified ELF binary.
        let resource_receipt = prover
            .prove(resource_env, resource_elf)
            .map_err(TransactionError::ResourceLogicFailure)?;
        // Finally make the consumption compliance proof
        let input = ConsumptionInput {
            nsk,
            resource,
            path,
        };
        // Use the resource receipt and resource to make compliance environment
        let compliance_env = ExecutorEnv::builder()
            .add_assumption(resource_receipt)
            .write(&input)
            .unwrap()
            .build()
            .unwrap();
        // Produce a receipt confirming compliance
        let resource_receipt = prover
            .prove(compliance_env, CONSUME_RESOURCE_ELF)
            .map_err(TransactionError::ResourceComplianceFailure)?;
        // Make record proving input compliance
        let proof_record = ProofRecord {
            receipt: resource_receipt,
            image_id: CONSUME_RESOURCE_ID.into(),
        };
        self.proofs.push(proof_record);
        Ok(())
    }

    // Add an output to the transaction computing its proof in the process
    fn add_output(
        &mut self,
        resource: Resource,
        resource_elf: &[u8],
        extra: &impl Serialize,
    ) -> Result<(), TransactionError> {
        // Ensure that the elf we run corresponds to the resource image
        assert_eq!(resource.image_id, compute_image_id(resource_elf).unwrap());
        self.delta -= resource.delta();
        // Obtain the default prover.
        let prover = default_prover();
        // Provide the extra data to the resource
        let resource_env = ExecutorEnv::builder()
            .write(extra)
            .unwrap()
            .build()
            .unwrap();
        // Produce a receipt by proving the specified ELF binary.
        let resource_receipt = prover.prove(resource_env, resource_elf).unwrap();
        // Finally make the consumption compliance proof
        let input = CreationInput { resource };
        // Use the resource receipt and resource to make compliance environment
        let compliance_env = ExecutorEnv::builder()
            .add_assumption(resource_receipt)
            .write(&input)
            .unwrap()
            .build()
            .unwrap();
        // Produce a receipt confirming compliance
        let resource_receipt = prover.prove(compliance_env, CREATE_RESOURCE_ELF).unwrap();
        // Make record proving input compliance
        let proof_record = ProofRecord {
            receipt: resource_receipt,
            image_id: CREATE_RESOURCE_ID.into(),
        };
        self.proofs.push(proof_record);
        Ok(())
    }
}

// The errors that can occur when processing a transaction
#[derive(Debug)]
enum ResourceMachineError {
    // The proof provided in the transaction is invalid
    InvalidProof(VerificationError),
    // The proof refers to an unknown root
    UnknownRoot(Digest),
    // The nullifier has already been revealed
    RevealedNullifier(Digest),
    // This commitment has already been made
    DuplicateCommitment(Digest),
}

// A representation of the state of a resource machine
#[derive(Default)]
struct ResourceMachine {
    // Contains all the previous roots
    roots: BTreeSet<Digest>,
    // Contains all previously revealed nullifiers
    nullifiers: BTreeSet<Digest>,
    // Contains an ordered list of commitments
    commitments: Vec<Digest>,
    // Current commitment tree
    tree: CommitmentTree<COMMITMENT_TREE_DEPTH, Digest>,
}

impl ResourceMachine {
    // Apply the given transaction to the resource machine
    fn apply(&mut self, tx: Transaction) -> Result<(), ResourceMachineError> {
        for proof in &tx.proofs {
            // The proof must pass the verification, this calls the resource predicate
            proof
                .receipt
                .verify(proof.image_id)
                .map_err(ResourceMachineError::InvalidProof)?;
            match proof.image_id.into() {
                CONSUME_RESOURCE_ID => {
                    let output: ConsumptionOutput = proof.receipt.journal.decode().unwrap();
                    // Ensure that we recognize the root
                    if !self.roots.contains(&output.root) {
                        return Result::Err(ResourceMachineError::UnknownRoot(output.root));
                    }
                    // Ensure that the nullifier has not yet been revealed
                    if self.nullifiers.contains(&output.nullifier) {
                        return Result::Err(ResourceMachineError::RevealedNullifier(
                            output.nullifier,
                        ));
                    }
                }
                CREATE_RESOURCE_ID => {
                    let output: CreationOutput = proof.receipt.journal.decode().unwrap();
                    // Ensure that the commitment has not already been made
                    if self.commitments.contains(&output.commitment) {
                        return Result::Err(ResourceMachineError::DuplicateCommitment(
                            output.commitment,
                        ));
                    }
                }
                _ => {}
            }
        }
        // At this point all the checks have passed. So let's start modifying our state
        for proof in &tx.proofs {
            match proof.image_id.into() {
                CONSUME_RESOURCE_ID => {
                    let output: ConsumptionOutput = proof.receipt.journal.decode().unwrap();
                    // Reveal the nullifier
                    self.nullifiers.insert(output.nullifier);
                }
                CREATE_RESOURCE_ID => {
                    let output: CreationOutput = proof.receipt.journal.decode().unwrap();
                    // Commit the commitment
                    self.commitments.push(output.commitment);
                }
                _ => {}
            }
        }
        // Finally, let's make a new commitment tree
        self.tree = CommitmentTree::<COMMITMENT_TREE_DEPTH, _>::new(&self.commitments);
        // And then record its root
        self.roots.insert(self.tree.root());
        Ok(())
    }
}

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Make a commitment tree
    let dummy_tree = CommitmentTree::<{ COMMITMENT_TREE_DEPTH }, _>::new(&[Digest::default()]);
    // Make the nullifier secret key
    let nsk = Nsk::default();
    // Make the resource with above secret key
    let resource = Resource {
        npk: nsk.public_key(),
        image_id: ALWAYS_TRUE_ID.into(),
        ..Resource::default()
    };
    // Make a new resource machine
    let mut rm = ResourceMachine::default();

    // Make a bad transaction and try to apply it
    let mut tx = Transaction::default();
    // Add a non-existent input to the transaction
    tx.add_input(
        dummy_tree.path(0),
        resource.clone(),
        ALWAYS_TRUE_ELF,
        nsk.clone(),
        &(),
    )
    .unwrap();
    // Add an output to the transaction
    tx.add_output(resource.clone(), ALWAYS_TRUE_ELF, &())
        .unwrap();
    // Try applying the transaction
    rm.apply(tx).expect_err("transaction should not apply");

    // Make a good creation transaction and try to apply it
    let mut tx = Transaction::default();
    // Add an output to the transaction
    tx.add_output(resource.clone(), ALWAYS_TRUE_ELF, &())
        .unwrap();
    // Try applying the transaction
    rm.apply(tx).expect("unable to apply transaction");

    // Make a good consumption transaction and try to apply it
    let mut tx = Transaction::default();
    // Add a non-existent input to the transaction
    tx.add_input(
        rm.tree.path(0),
        resource.clone(),
        ALWAYS_TRUE_ELF,
        nsk.clone(),
        &(),
    )
    .unwrap();
    // Try applying the transaction
    rm.apply(tx).expect_err("unable to apply transaction");
}