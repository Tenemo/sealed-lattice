use super::*;

pub(crate) fn ciphertext_object_root(ciphertext: &Ciphertext) -> CanonicalResult<String> {
    let canonical_bytes = ciphertext_canonical_bytes(ciphertext)?;

    Ok(ciphertext_root(&canonical_bytes))
}

#[cfg(test)]
pub(crate) fn ciphertext_canonical_bytes_hex(ciphertext: &Ciphertext) -> CanonicalResult<String> {
    Ok(canonical_bytes_hex(&ciphertext_canonical_bytes(
        ciphertext,
    )?))
}

fn ciphertext_canonical_bytes(ciphertext: &Ciphertext) -> CanonicalResult<Vec<u8>> {
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            RnsPolynomial::coefficient_domain(
                BgvBasisKind::Data,
                ciphertext.level,
                component.clone(),
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    serialize_bgv_object(BgvObjectKind::Ciphertext, &components)
}
