//! Prover-side oracle state carried between phases.
//!
//! Local modification: extension-field source state supports the outer
//! committed-relation handoff, and initial base-oracle encoding can be handed
//! to an outer commitment owner before an MMCS is selected. See
//! `../../../../UPSTREAM.md`.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_commit::Mmcs;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::dense::DenseMatrix;
use p3_matrix::extension::FlatMatrixView;
use p3_multilinear_util::poly::Poly;

/// Exact base-field initial-oracle material before an MMCS commitment.
///
/// An outer protocol can commit the encoded rows with its own authenticated
/// vector commitment while retaining the same message and hiding randomness
/// for the subsequent WHIR reduction.
pub struct HidingWhirEncodedBaseOracle<F, EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    /// Committed multilinear evaluations.
    pub message: Poly<F>,
    /// Limb-major ZK encoding randomness of the initial oracle.
    pub randomness: Vec<F>,
    /// Exact interleaved Reed-Solomon rows consumed by the commitment owner.
    pub encoded: DenseMatrix<F>,
    /// Marker tying the data to its extension field.
    pub(crate) _marker: PhantomData<EF>,
}

/// Prover-side handoff between the commit and open phases.
pub struct HidingWhirProverData<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Committed multilinear evaluations.
    pub message: Poly<F>,
    /// Limb-major ZK encoding randomness of the initial oracle.
    pub randomness: Vec<F>,
    /// Merkle prover data behind the initial commitment.
    pub merkle: MT::ProverData<DenseMatrix<F>>,
    /// Marker tying the data to its extension field.
    pub(crate) _marker: PhantomData<EF>,
}

/// Prover-side handoff for an extension-field source oracle.
///
/// This is the source form required by an outer extension-field reduction,
/// such as the R1CS-to-constrained-code construction. The commitment is made
/// through the same base-field MMCS using its extension-field adapter.
pub struct HidingWhirExtensionProverData<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Committed multilinear evaluations.
    pub message: Poly<EF>,
    /// Limb-major ZK encoding randomness of the initial oracle.
    pub randomness: Vec<EF>,
    /// Merkle prover data behind the initial extension-field commitment.
    pub merkle: <MT as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, DenseMatrix<EF>>>,
}

/// Merkle prover data of the active committed oracle.
pub(super) enum ZkRoundData<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Base-field initial oracle.
    Base(MT::ProverData<DenseMatrix<F>>),
    /// Extension-field folded oracle.
    Ext(<MT as Mmcs<F>>::ProverData<FlatMatrixView<F, EF, DenseMatrix<EF>>>),
}
