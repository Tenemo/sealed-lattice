use super::*;

pub(crate) fn ciphertext_canonical_bytes(ciphertext: &Ciphertext) -> CanonicalResult<Vec<u8>> {
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
