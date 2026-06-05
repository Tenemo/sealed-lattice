use super::*;

pub(in crate::bgv::setup) fn evaluation_key_stream_seed(
    setup_seed_hash: &str,
    key_kind: &str,
    level: usize,
    rotation: Option<usize>,
) -> String {
    let level_text = level.to_string();
    let rotation_text = rotation
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string());

    hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-seed-v1",
        &[
            setup_seed_hash.as_bytes(),
            key_kind.as_bytes(),
            level_text.as_bytes(),
            rotation_text.as_bytes(),
        ],
    )
}

pub(super) fn evaluation_key_stream_hash(
    stream_label: &str,
    stream_record: &Value,
) -> CanonicalResult<String> {
    let canonical_stream_record = canonical_json(stream_record)?;

    Ok(hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-hash-v1",
        &[stream_label.as_bytes(), canonical_stream_record.as_bytes()],
    ))
}
