use crate::{
    action_tree::ACTION_TREE_DEPTH, logic_instance::ExpirableBlob, logic_instance::LogicInstance,
    merkle_path::MerklePath, nullifier_key::NullifierKey, resource::Resource,
};
use serde::{Deserialize, Serialize};

/// This is a trait for logic constraints implementation.
pub trait LogicCircuit: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    // In general, it's implemented as `Self::default()`
    fn default_witness() -> Self {
        Self::default()
    }

    // Logic constraints implementation
    fn constrain(&self) -> LogicInstance;
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TrivialLogicWitness {
    pub resource: Resource,
    pub receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
}

impl LogicCircuit for TrivialLogicWitness {
    fn constrain(&self) -> LogicInstance {
        // Load the self resource, the receive resource is always a
        // created resource
        let self_cm = self.resource.commitment();
        let tag = if self.is_consumed {
            self.resource
                .nullifier_from_commitment(&self.nf_key, &self_cm)
                .unwrap()
        } else {
            self_cm
        };
        let root = self.receive_existence_path.root(tag);

        // Check basic properties of the receive resource
        assert_eq!(self.resource.quantity, 0);
        assert!(self.resource.is_ephemeral);

        LogicInstance {
            tag,
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root,
            cipher: vec![1, 2, 3, 4], // TODO; move it to a special test
            app_data: vec![
                ExpirableBlob {
                    blob: vec![1, 2, 3, 4],
                    deletion_criterion: 0,
                },
                ExpirableBlob {
                    blob: vec![5, 6, 7, 8],
                    deletion_criterion: 1,
                },
            ],
        }
    }
}

impl TrivialLogicWitness {
    pub fn new(
        resource: Resource,
        receive_existence_path: MerklePath<ACTION_TREE_DEPTH>,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        Self {
            resource,
            receive_existence_path,
            is_consumed,
            nf_key,
        }
    }
}
