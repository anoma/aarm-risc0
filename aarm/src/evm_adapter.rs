use aarm_core::{
    compliance::ComplianceInstance,
    logic_instance::{ExpirableBlob, LogicInstance},
};
use risc0_zkvm::sha::Digest;
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
    pub tag: Digest,
    pub is_consumed: bool,
    pub root: Digest,
    pub cipher: Vec<String>,
    pub app_data: Vec<AdapterExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AdapterExpirableBlob {
    pub blob: Vec<String>,
    pub deletion_criterion: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterLogicProof {
    // The verifying key corresponds to the imageID in risc0
    pub verifying_key: Digest,
    // The proof corresponds to the seal in risc0
    pub proof: Vec<u8>,
    // The instance corresponds to the journal in risc0
    pub instance: AdapterLogicInstance,
}

impl From<ExpirableBlob> for AdapterExpirableBlob {
    fn from(blob: ExpirableBlob) -> Self {
        AdapterExpirableBlob {
            blob: blob
                .blob
                .iter()
                .map(|b| format!("{:02x}000000", b))
                .collect(),
            deletion_criterion: format!("{:02x}000000", blob.deletion_criterion),
        }
    }
}

impl From<LogicInstance> for AdapterLogicInstance {
    fn from(instance: LogicInstance) -> Self {
        let cipher = instance
            .cipher
            .iter()
            .map(|b| format!("{:02x}0000000", b))
            .collect();
        let app_data = instance
            .app_data
            .into_iter()
            .map(|blob| AdapterExpirableBlob::from(blob))
            .collect();
        AdapterLogicInstance {
            tag: instance.tag,
            is_consumed: instance.is_consumed,
            root: instance.root,
            cipher,
            app_data,
        }
    }
}
