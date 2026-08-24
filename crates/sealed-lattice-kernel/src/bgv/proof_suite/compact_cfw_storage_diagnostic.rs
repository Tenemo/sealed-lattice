//! Measurement-only schedule for the selected compact CFW storage lifecycle.
//!
//! The browser diagnostic consumes this compiler-derived description instead
//! of maintaining a second handwritten geometry. It is not a proof, verifier,
//! suite-activation, capability, or qualification surface.

use serde::Serialize;

use super::PROOF_CHALLENGE_EXTENSION_DEGREE;
use super::compact_cfw::{COMPACT_CFW_MATRIX_COUNT, CompactCfwGeometry};
use super::compact_cfw_external::CompactCfwExternalStorageCatalog;
use super::relation_plan::selected_compact_public_key_relation_catalog;

const COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT: u64 = 16_384;
const BASE_FIELD_ELEMENT_BYTE_LENGTH: u64 = 8;
const ROUND_BOUNDARY_CHECKPOINT_COUNT_PER_ROUND: u64 = 2;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompactCfwStorageDiagnosticRound {
    round_ordinal: u32,
    output_element_count: u64,
    output_object_byte_length: u64,
    append_chunk_count_per_matrix: u64,
    preceding_read_chunk_count_per_matrix: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompactCfwStorageDiagnosticSchedule {
    schema_version: u16,
    witness_element_count: u64,
    r1cs_row_count: u64,
    matrix_count: u64,
    round_count: u32,
    step_count: u32,
    stream_chunk_element_count: u64,
    stream_chunk_byte_length: u64,
    extension_element_byte_length: u64,
    object_lifecycle_count: u64,
    maximum_active_object_count: u64,
    create_transaction_count: u64,
    append_transaction_count: u64,
    seal_transaction_count: u64,
    read_transaction_count: u64,
    delete_transaction_count: u64,
    total_transaction_count: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    peak_stored_byte_length: u64,
    secret_seal_invocation_count: u64,
    secret_sealed_plaintext_byte_length: u64,
    deterministic_safe_boundary_count: u64,
    rounds: Vec<CompactCfwStorageDiagnosticRound>,
}

fn derive_selected_schedule() -> Result<CompactCfwStorageDiagnosticSchedule, String> {
    let relation = selected_compact_public_key_relation_catalog()
        .map_err(|error| format!("selected compact public-key relation failed: {error:?}"))?;
    let witness_element_count = relation.padded_witness_element_count();
    let witness_length = usize::try_from(witness_element_count)
        .map_err(|_| "selected compact witness length exceeds usize".to_owned())?;
    let geometry = CompactCfwGeometry::derive(witness_length)
        .map_err(|error| format!("selected compact CFW geometry failed: {error:?}"))?;
    let catalog = CompactCfwExternalStorageCatalog::derive(geometry)
        .map_err(|error| format!("selected compact CFW storage plan failed: {error:?}"))?;
    let r1cs_row_count = u64::try_from(geometry.r1cs_row_count())
        .map_err(|_| "selected compact CFW row count exceeds u64".to_owned())?;
    let round_count = u32::try_from(geometry.sumcheck_round_count())
        .map_err(|_| "selected compact CFW round count exceeds u32".to_owned())?;
    let matrix_count = u64::try_from(COMPACT_CFW_MATRIX_COUNT)
        .map_err(|_| "selected compact CFW matrix count exceeds u64".to_owned())?;
    let extension_element_byte_length = u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .map_err(|_| "challenge-extension degree exceeds u64".to_owned())?
        .checked_mul(BASE_FIELD_ELEMENT_BYTE_LENGTH)
        .ok_or_else(|| "challenge-extension byte length overflowed".to_owned())?;
    let stream_chunk_byte_length = COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT
        .checked_mul(extension_element_byte_length)
        .ok_or_else(|| "compact CFW stream-chunk byte length overflowed".to_owned())?;

    let mut rounds = Vec::new();
    rounds
        .try_reserve_exact(geometry.sumcheck_round_count())
        .map_err(|_| "compact CFW diagnostic round allocation failed".to_owned())?;
    let mut output_element_count = r1cs_row_count / 2;
    let mut preceding_output_element_count = 0_u64;
    let mut stored_round_chunk_group_count = 0_u64;
    for round_ordinal in 0..round_count {
        let append_chunk_count_per_matrix =
            output_element_count.div_ceil(COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT);
        let preceding_read_chunk_count_per_matrix = if round_ordinal == 0 {
            0
        } else {
            let count =
                preceding_output_element_count.div_ceil(COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT);
            stored_round_chunk_group_count = stored_round_chunk_group_count
                .checked_add(count)
                .ok_or_else(|| "compact CFW stored-round chunk count overflowed".to_owned())?;
            count
        };
        rounds.push(CompactCfwStorageDiagnosticRound {
            round_ordinal,
            output_element_count,
            output_object_byte_length: output_element_count
                .checked_mul(extension_element_byte_length)
                .ok_or_else(|| "compact CFW round byte length overflowed".to_owned())?,
            append_chunk_count_per_matrix,
            preceding_read_chunk_count_per_matrix,
        });
        preceding_output_element_count = output_element_count;
        output_element_count /= 2;
    }
    if output_element_count != 0
        || rounds
            .last()
            .is_none_or(|round| round.output_element_count != 1)
    {
        return Err("selected compact CFW round schedule is incomplete".to_owned());
    }

    let initial_structured_chunk_count =
        r1cs_row_count.div_ceil(COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT);
    let deterministic_safe_boundary_count = initial_structured_chunk_count
        .checked_add(catalog.append_transaction_count())
        .and_then(|count| count.checked_add(stored_round_chunk_group_count))
        .and_then(|count| {
            count.checked_add(u64::from(round_count) * ROUND_BOUNDARY_CHECKPOINT_COUNT_PER_ROUND)
        })
        .ok_or_else(|| "compact CFW safe-boundary count overflowed".to_owned())?;

    Ok(CompactCfwStorageDiagnosticSchedule {
        schema_version: 1,
        witness_element_count,
        r1cs_row_count,
        matrix_count,
        round_count,
        step_count: catalog.step_count(),
        stream_chunk_element_count: COMPACT_CFW_STREAM_CHUNK_ELEMENT_COUNT,
        stream_chunk_byte_length,
        extension_element_byte_length,
        object_lifecycle_count: catalog.object_lifecycle_count(),
        maximum_active_object_count: catalog.maximum_active_object_count(),
        create_transaction_count: catalog.object_lifecycle_count(),
        append_transaction_count: catalog.append_transaction_count(),
        seal_transaction_count: catalog.object_lifecycle_count(),
        read_transaction_count: catalog.read_transaction_count(),
        delete_transaction_count: catalog.delete_transaction_count(),
        total_transaction_count: catalog.total_transaction_count(),
        total_written_byte_length: catalog.total_written_byte_length(),
        total_read_byte_length: catalog.total_read_byte_length(),
        peak_stored_byte_length: catalog.peak_stored_byte_length(),
        secret_seal_invocation_count: catalog.secret_seal_invocation_count(),
        secret_sealed_plaintext_byte_length: catalog.secret_sealed_plaintext_byte_length(),
        deterministic_safe_boundary_count,
        rounds,
    })
}

#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) fn selected_compact_cfw_storage_diagnostic_schedule() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&derive_selected_schedule()?)
        .map_err(|error| format!("compact CFW storage diagnostic encoding failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_schedule_is_derived_from_the_production_relation_and_storage_owner() {
        let schedule = derive_selected_schedule().expect("selected diagnostic schedule");

        assert_eq!(schedule.witness_element_count, 4_194_304);
        assert_eq!(schedule.r1cs_row_count, 8_388_608);
        assert_eq!(schedule.matrix_count, 3);
        assert_eq!(schedule.round_count, 23);
        assert_eq!(schedule.step_count, 70);
        assert_eq!(schedule.stream_chunk_element_count, 16_384);
        assert_eq!(schedule.stream_chunk_byte_length, 655_360);
        assert_eq!(schedule.object_lifecycle_count, 69);
        assert_eq!(schedule.maximum_active_object_count, 4);
        assert_eq!(schedule.create_transaction_count, 69);
        assert_eq!(schedule.append_transaction_count, 1_575);
        assert_eq!(schedule.seal_transaction_count, 69);
        assert_eq!(schedule.read_transaction_count, 3_144);
        assert_eq!(schedule.delete_transaction_count, 69);
        assert_eq!(schedule.total_transaction_count, 4_926);
        assert_eq!(schedule.total_written_byte_length, 1_006_632_840);
        assert_eq!(schedule.total_read_byte_length, 2_013_265_440);
        assert_eq!(schedule.peak_stored_byte_length, 587_202_560);
        assert_eq!(schedule.secret_seal_invocation_count, 1_713);
        assert_eq!(schedule.secret_sealed_plaintext_byte_length, 1_006_633_461);
        assert_eq!(schedule.deterministic_safe_boundary_count, 2_657);
        assert_eq!(schedule.rounds.len(), 23);
        assert_eq!(schedule.rounds[0].output_element_count, 4_194_304);
        assert_eq!(schedule.rounds[0].append_chunk_count_per_matrix, 256);
        assert_eq!(schedule.rounds[0].preceding_read_chunk_count_per_matrix, 0);
        assert_eq!(schedule.rounds[22].output_element_count, 1);
        assert_eq!(schedule.rounds[22].output_object_byte_length, 40);
        assert_eq!(schedule.rounds[22].preceding_read_chunk_count_per_matrix, 1);
    }
}
