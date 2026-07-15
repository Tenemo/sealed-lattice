use super::*;

mod common;
mod shares;
mod succinct_proofs;

pub(super) use common::{PublicKeyCommonBinding, public_key_refusal};
pub(super) use shares::verify_public_key_shares;
pub(in crate::bgv::setup) use shares::{
    derive_public_key_share_root, derive_public_key_share_set_root,
};
#[cfg(test)]
pub(in crate::bgv::setup) use succinct_proofs::public_key_share_succinct_proof_verification_binding_hash;
pub(super) use succinct_proofs::{
    PublicKeyShareSuccinctProofVerification, verify_public_key_share_succinct_proofs,
};
