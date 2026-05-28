#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GeneratedLinearProofProfileConstants {
    pub(crate) decompression_shift: usize,
    pub(crate) decompression_gamma: i128,
    pub(crate) decompression_modulus: i128,
    pub(crate) decompression_log2_modulus: usize,
    pub(crate) decompression_low_part_bound_squared: u128,
    pub(crate) challenge_centered_bound: i64,
    pub(crate) challenge_coefficient_bit_length: usize,
    pub(crate) euclidean_response_bound_squared: u128,
    pub(crate) infinity_response_bound: u128,
    pub(crate) short_response_message_length: u128,
    pub(crate) short_response_bound_scale_numerator: u128,
    pub(crate) short_response_bound_scale_denominator: u128,
    pub(crate) exact_norm_bound_squared: u64,
}

// Rust short-response cap used by the generated profiles below. It is not a
// literal LaZer header field. It was verified against each generated
// `*_stdev1sq` value and log2 standard deviation pair: demo uses log2 stdev
// `16`, receiver-key uses `17`, and encoded-score field uses `18`.
const GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_NUMERATOR: u128 = 962;
const GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_DENOMINATOR: u128 = 400;

// Source file: `temp/lazer/python/demo/demo_params.h`.
// Generator input: `temp/lazer/python/demo/demo_params.py`.
// Generator: upstream LaZer `scripts/lin-codegen.sage`.
// Verified header fields: `D` in `_param_dcomp`, `_param_gamma`,
// `_param_m`, log2(`_param_m`) rounded up, `_param_Bsq`, `_param`
// challenge entries, `_param_Bz3sqr`, `_param_Bz4`, `_param` short
// message length, `_param_stdev1sq` plus its log2 standard deviation, and
// `_param_l2Bsq0`.
pub(crate) const DEMO_GENERATED_PROFILE: GeneratedLinearProofProfileConstants =
    GeneratedLinearProofProfileConstants {
        // Header field: `D` in `_param_dcomp`.
        decompression_shift: 10,
        // Header field: `_param_gamma`.
        decompression_gamma: 514_206,
        // Header field: `_param_m`.
        decompression_modulus: 70_066_854_566,
        // Header field: bit length needed to encode `_param_m`.
        decompression_log2_modulus: 37,
        // Header field: `_param_Bsq`.
        decompression_low_part_bound_squared: 100_800_248_132_613,
        // Header field: challenge bound encoded by `_param`.
        challenge_centered_bound: 8,
        // Header field: challenge coefficient bit length encoded by `_param`.
        challenge_coefficient_bit_length: 5,
        // Header field: `_param_Bz3sqr`.
        euclidean_response_bound_squared: 6_938_266_263,
        // Header field: `_param_Bz4`.
        infinity_response_bound: 1_625_292,
        // Header field: short message length encoded by `_param`.
        short_response_message_length: 33,
        // Rust cap derived from `_param_stdev1sq` and log2 stdev `16`.
        short_response_bound_scale_numerator:
            GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_NUMERATOR,
        // Rust cap denominator for the `_param_stdev1sq` ratio.
        short_response_bound_scale_denominator:
            GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_DENOMINATOR,
        // Header field: `_param_l2Bsq0`.
        exact_norm_bound_squared: 2_048,
    };

// Source file: `temp/lazer/python/demo/demo_params.h`.
// Generator input: `temp/lazer/python/demo/demo_params.py`.
// Verified fields: generator `deg`, generator `mod`, generator `dim`,
// generated `_param_ring` degree, and generated `lin_params_t param`.
#[cfg(test)]
pub(crate) const DEMO_GENERATED_PARAMETER_CONTRACT: GeneratedLinearProofParameterContractConstants =
    GeneratedLinearProofParameterContractConstants {
        // Generator input field: `deg`.
        source_ring_degree: 256,
        // Header field: `_param_ring` proof-system polynomial degree.
        proof_system_ring_degree: 64,
        // Generator input field: `mod`, emitted as `param_p`.
        source_coefficient_modulus: 4_294_962_689,
        // Generator input field: `dim[0]`.
        statement_rows: 4,
        // Generator input field: `dim[1]`.
        statement_columns: 8,
    };

// Source file: `temp/lazer/python/demo/receiver_key_params.h`.
// Generator input: `tools/lazer-oracle/receiver-key-linear-params.py`.
// Generator: upstream LaZer `scripts/lin-codegen.sage`.
// Verified header fields: `D`, `_receiver_key_param_gamma`,
// `_receiver_key_param_m`, log2(`_receiver_key_param_m`) rounded up,
// `_receiver_key_param_Bsq`, `_receiver_key_param` challenge entries,
// `_receiver_key_param_Bz3sqr`, `_receiver_key_param_Bz4`,
// `_receiver_key_param` short message length, `_receiver_key_param_stdev1sq`
// plus its log2 standard deviation, and `_receiver_key_param_l2Bsq0`.
pub(crate) const RECEIVER_KEY_GENERATED_PROFILE: GeneratedLinearProofProfileConstants =
    GeneratedLinearProofProfileConstants {
        // Header field: `D` in `_receiver_key_param_dcomp`.
        decompression_shift: 10,
        // Header field: `_receiver_key_param_gamma`.
        decompression_gamma: 441_444,
        // Header field: `_receiver_key_param_m`.
        decompression_modulus: 622_679,
        // Header field: bit length needed to encode `_receiver_key_param_m`.
        decompression_log2_modulus: 20,
        // Header field: `_receiver_key_param_Bsq`.
        decompression_low_part_bound_squared: 115_113_594_542_128,
        // Header field: challenge bound encoded by `_receiver_key_param`.
        challenge_centered_bound: 8,
        // Header field: challenge coefficient bit length encoded by `_receiver_key_param`.
        challenge_coefficient_bit_length: 5,
        // Header field: `_receiver_key_param_Bz3sqr`.
        euclidean_response_bound_squared: 27_753_065_054,
        // Header field: `_receiver_key_param_Bz4`.
        infinity_response_bound: 3_250_585,
        // Header field: short message length encoded by `_receiver_key_param`.
        short_response_message_length: 33,
        // Rust cap derived from `_receiver_key_param_stdev1sq` and log2 stdev `17`.
        short_response_bound_scale_numerator:
            GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_NUMERATOR,
        // Rust cap denominator for the `_receiver_key_param_stdev1sq` ratio.
        short_response_bound_scale_denominator:
            GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_DENOMINATOR,
        // Header field: `_receiver_key_param_l2Bsq0`.
        exact_norm_bound_squared: 8_192,
    };

// Source file: `temp/lazer/python/demo/receiver_key_params.h`.
// Generator input: `tools/lazer-oracle/receiver-key-linear-params.py`.
// Verified fields: generator `deg`, generator `mod`, generator `dim`,
// generated `_receiver_key_param_ring` degree, and generated
// `lin_params_t receiver_key_param`.
#[cfg(test)]
pub(crate) const RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT:
    GeneratedLinearProofParameterContractConstants =
    GeneratedLinearProofParameterContractConstants {
        // Generator input field: `deg`.
        source_ring_degree: 256,
        // Header field: `_receiver_key_param_ring` proof-system polynomial degree.
        proof_system_ring_degree: 64,
        // Generator input field: `mod`, emitted as `receiver_key_param_p`.
        source_coefficient_modulus: 12_289,
        // Generator input field: `dim[0]`.
        statement_rows: 4,
        // Generator input field: `dim[1]`.
        statement_columns: 8,
    };

// Source file: `temp/lazer/python/demo/ballot_field_params.h`.
// Generator input: `tools/lazer-oracle/ballot-field-linear-params.py`.
// Generator: upstream LaZer `scripts/lin-codegen.sage`.
// Verified header fields: `D`, `_ballot_field_param_gamma`,
// `_ballot_field_param_m`, log2(`_ballot_field_param_m`) rounded up,
// `_ballot_field_param_Bsq`, `_ballot_field_param` challenge entries,
// `_ballot_field_param_Bz3sqr`, `_ballot_field_param_Bz4`,
// `_ballot_field_param` short message length, `_ballot_field_param_stdev1sq`
// plus its log2 standard deviation, and `_ballot_field_param_l2Bsq0`.
pub(crate) const ENCODED_SCORE_FIELD_GENERATED_PROFILE: GeneratedLinearProofProfileConstants =
    GeneratedLinearProofProfileConstants {
        // Header field: `D` in `_ballot_field_param_dcomp`.
        decompression_shift: 12,
        // Header field: `_ballot_field_param_gamma`.
        decompression_gamma: 3_712_122,
        // Header field: `_ballot_field_param_m`.
        decompression_modulus: 18_956_474,
        // Header field: bit length needed to encode `_ballot_field_param_m`.
        decompression_log2_modulus: 25,
        // Header field: `_ballot_field_param_Bsq`.
        decompression_low_part_bound_squared: 5_369_976_544_106_605,
        // Header field: challenge bound encoded by `_ballot_field_param`.
        challenge_centered_bound: 8,
        // Header field: challenge coefficient bit length encoded by `_ballot_field_param`.
        challenge_coefficient_bit_length: 5,
        // Header field: `_ballot_field_param_Bz3sqr`.
        euclidean_response_bound_squared: 444_049_040_871,
        // Header field: `_ballot_field_param_Bz4`.
        infinity_response_bound: 104_018_739,
        // Header field: short message length encoded by `_ballot_field_param`.
        short_response_message_length: 177,
        // Rust cap derived from `_ballot_field_param_stdev1sq` and log2 stdev `18`.
        short_response_bound_scale_numerator:
            GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_NUMERATOR,
        // Rust cap denominator for the `_ballot_field_param_stdev1sq` ratio.
        short_response_bound_scale_denominator:
            GENERATED_PROFILE_SHORT_RESPONSE_BOUND_SCALE_DENOMINATOR,
        // Header field: `_ballot_field_param_l2Bsq0`.
        exact_norm_bound_squared: 65_536,
    };

// Source file: `temp/lazer/python/demo/ballot_field_params.h`.
// Generator input: `tools/lazer-oracle/ballot-field-linear-params.py`.
// Verified fields: generator `deg`, generator `mod`, generator `dim`,
// generated `_ballot_field_param_ring` degree, and generated
// `lin_params_t ballot_field_param`.
#[cfg(test)]
pub(crate) const ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT:
    GeneratedLinearProofParameterContractConstants =
    GeneratedLinearProofParameterContractConstants {
        // Generator input field: `deg`.
        source_ring_degree: 64,
        // Header field: `_ballot_field_param_ring` proof-system polynomial degree.
        proof_system_ring_degree: 64,
        // Generator input field: `mod`, emitted as `ballot_field_param_p`.
        source_coefficient_modulus: 65_537,
        // Generator input field: `dim[0]`.
        statement_rows: 70,
        // Generator input field: `dim[1]`.
        statement_columns: 176,
    };

// Source file: `temp/lazer/python/demo/ballot_field_params.h`.
// Header field: `_ballot_field_param_l2Bsq0`.
// This bound is reused by generated field-compatible component statements.
pub(crate) const GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED: u64 =
    ENCODED_SCORE_FIELD_GENERATED_PROFILE.exact_norm_bound_squared;

// Source file: `tools/ballot-privacy-vectors/generate-encoded-relation-vectors.mts`.
// Field: `componentProjectionSummaries` entry for
// `share-commitment-component`. This is not a LaZer-generated `l2Bsq`
// header value; it is the registered relation-vector compatibility bound for
// structured share-commitment component statements.
pub(crate) const GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED: u64 = 1_048_576;

// M6 aggregate derivation uses the share-commitment source ring and an
// aggregate witness covering S, rho, Y, and quotient for up to 50 counted
// ballots and 20 options. This is an implementation-side compatibility bound
// for the current Rust/WASM proof experiment, not standalone final theorem
// evidence.
pub(crate) const AGGREGATE_DERIVATION_COMPONENT_EXACT_NORM_BOUND_SQUARED: u64 =
    3_000_000_000_000_000;

// Compatibility cap for generated component-proof experiments that reuse the
// encoded-score decompression tuple over wider generated component statements.
// This value is not present in the generated LaZer headers as `Bz3sqr`; it is
// an explicit Rust-side cap and must not be described as generated or as
// standalone final soundness evidence.
pub(crate) const GENERATED_COMPONENT_EUCLIDEAN_RESPONSE_BOUND_SQUARED: u128 = 1_u128 << 96;

// Compatibility cap for generated component-proof experiments that reuse the
// encoded-score decompression tuple over wider generated component statements.
// This value is not present in the generated LaZer headers as `Bz4`; it is an
// explicit Rust-side cap and must not be described as generated or as
// standalone final soundness evidence.
pub(crate) const GENERATED_COMPONENT_INFINITY_RESPONSE_BOUND: u128 = 1_u128 << 48;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GeneratedLinearProofParameterContractConstants {
    pub(crate) source_ring_degree: usize,
    pub(crate) proof_system_ring_degree: usize,
    pub(crate) source_coefficient_modulus: u64,
    pub(crate) statement_rows: usize,
    pub(crate) statement_columns: usize,
}
