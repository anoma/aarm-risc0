use crate::action::ForwarderCalldata;
use crate::{
    action::Action,
    transaction::{Delta, Transaction},
};
use aarm_core::resource::Resource;
use aarm_core::{
    compliance::ComplianceInstance,
    logic_instance::{ExpirableBlob, LogicInstance},
};
use risc0_ethereum_contracts::encode_seal;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterTransaction {
    pub actions: Vec<AdapterAction>,
    // delta_proof is a signature struct corresponding to a tuple of (r,s,v) in
    // EVM adapter where r(32 bytes) and s(bytes) are the signature values and
    // v(1 byte)is the recovery id.
    pub delta_proof: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterAction {
    pub compliance_units: Vec<AdapterComplianceUnit>,
    pub logic_proofs: Vec<AdapterLogicProof>,
    pub resource_forwarder_calldata_pairs: Vec<(Resource, ForwarderCalldata)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterComplianceUnit {
    // The proof corresponds to the seal in risc0
    pub proof: Vec<u8>,
    // The instance corresponds to the journal in risc0
    pub instance: ComplianceInstance,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AdapterLogicInstance {
    pub tag: [u8; 32],
    pub is_consumed: bool,
    pub root: [u8; 32],
    pub cipher: Vec<u8>,
    pub app_data: Vec<AdapterExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AdapterExpirableBlob {
    pub blob: Vec<u8>,
    pub deletion_criterion: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterLogicProof {
    // The verifying key corresponds to the imageID in risc0
    pub verifying_key: [u8; 32],
    // The proof corresponds to the seal in risc0
    pub proof: Vec<u8>,
    // The instance corresponds to the journal in risc0
    pub instance: AdapterLogicInstance,
}

fn insert_zeros(vec: Vec<u8>) -> Vec<u8> {
    vec.into_iter()
        .flat_map(|byte| {
            // Create an iterator that contains the original byte followed by three 0s
            std::iter::once(byte).chain(std::iter::repeat(0).take(3))
        })
        .collect() // Collect into a new Vec<u8>
}

impl From<Transaction> for AdapterTransaction {
    fn from(tx: Transaction) -> Self {
        let actions = tx.actions.into_iter().map(AdapterAction::from).collect();
        let delta_proof = match &tx.delta_proof {
            Delta::Witness(_) => panic!("Unbalanced Transactions cannot be converted"),
            Delta::Proof(proof) => proof.to_bytes().to_vec(),
        };

        AdapterTransaction {
            actions,
            delta_proof,
        }
    }
}

impl From<Action> for AdapterAction {
    fn from(action: Action) -> Self {
        let compliance_units = action
            .compliance_units
            .iter()
            .map(|receipt| AdapterComplianceUnit {
                proof: encode_seal(receipt).unwrap(),
                instance: receipt.journal.decode().unwrap(),
            })
            .collect();

        let logic_proofs = action
            .logic_proofs
            .iter()
            .map(|proof| {
                let instance: LogicInstance = proof.receipt.journal.decode().unwrap();
                AdapterLogicProof {
                    verifying_key: proof.verifying_key.into(),
                    proof: encode_seal(&proof.receipt).unwrap(),
                    instance: instance.into(),
                }
            })
            .collect();

        AdapterAction {
            compliance_units,
            logic_proofs,
            resource_forwarder_calldata_pairs: action.resource_forwarder_calldata_pairs,
        }
    }
}

impl From<ExpirableBlob> for AdapterExpirableBlob {
    fn from(blob: ExpirableBlob) -> Self {
        AdapterExpirableBlob {
            blob: insert_zeros(blob.blob),
            deletion_criterion: blob.deletion_criterion,
        }
    }
}

impl From<LogicInstance> for AdapterLogicInstance {
    fn from(instance: LogicInstance) -> Self {
        let cipher = insert_zeros(instance.cipher);
        let app_data = instance
            .app_data
            .into_iter()
            .map(AdapterExpirableBlob::from)
            .collect();
        AdapterLogicInstance {
            tag: instance.tag.into(),
            is_consumed: instance.is_consumed,
            root: instance.root.into(),
            cipher,
            app_data,
        }
    }
}

// pub fn get_compliance_id() -> Digest {
//     Digest::from(crate::constants::COMPLIANCE_GUEST_ID)
// }

#[cfg(test)]
mod tests {
    use crate::{evm_adapter::AdapterTransaction, transaction::generate_test_transaction};
    use std::env;

    #[test]
    fn print_tx() {
        env::var("BONSAI_API_KEY").expect("Couldn't read BONSAI_API_KEY");
        env::var("BONSAI_API_URL").expect("Couldn't read BONSAI_API_URL");

        let raw_tx = generate_test_transaction(1);
        println!(
            "EVM Tx:\n{:#?}",
            AdapterTransaction::from(raw_tx).actions[0].logic_proofs[0].instance
        );
    }

    // #[test]
    // fn print_compliance_id() {
    //     println!("compliance_id: {:?}", get_compliance_id());
    // }
}
