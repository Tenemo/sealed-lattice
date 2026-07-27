// Local modifications: the resumable verifier export and default-off hiding
// implementation are documented in `../UPSTREAM.md`.
#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

pub mod fiat_shamir;
pub mod parameters;
pub mod pcs;
#[cfg(feature = "zk")]
pub(crate) mod utils;

pub use fiat_shamir::domain_separator::DomainSeparator;
pub use parameters::{
    DEFAULT_MAX_POW, FoldingFactor, FoldingFactorError, ProtocolParameters, RoundConfig,
    SecurityAssumption, WhirConfig, WhirConfigError,
};
pub use pcs::WhirProverData;
pub use pcs::proof::{PcsProof, QueryOpening, WhirProof, WhirRoundProof};
pub use pcs::prover::WhirProver;
pub use pcs::verifier::errors::VerifierError;
pub use pcs::verifier::{WhirVerificationState, WhirVerifier};
#[cfg(feature = "zk")]
pub use pcs::zk::{
    BaseCaseZkError, BaseCaseZkProof, BlindedMask, CodeSwitchError, HidingWhirPcs,
    HidingWhirProverData, MaskCodeShape, MaskGroupShape, MaskOpeningPair, ZkConfigError,
    ZkParameters, ZkRoundProof, ZkVerifierError, ZkWhirConfig, ZkWhirProof,
};
