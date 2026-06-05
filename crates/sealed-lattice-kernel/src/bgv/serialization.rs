use crate::{
    bgv::{
        profile::POLYNOMIAL_DEGREE,
        rns::{PolynomialDomain, RnsPolynomial},
    },
    encoding::{
        CanonicalError, CanonicalErrorCode, CanonicalReader, CanonicalResult, append_string,
        append_varuint,
    },
    hashing::{hash512_hex, namespace_root},
    transcript_core::{decode_hex, encode_hex},
};

const CANONICAL_MAGIC: &str = "sealed-lattice-bgv-rns-canonical-object-v1";
const CANONICAL_OBJECT_VERSION: u64 = 1;
// Max polynomial components in a BGV object: a degree-2 ciphertext has 3.
const MAXIMUM_COMPONENT_COUNT: usize = 3;
// Max RNS limbs: 17 data primes + 1 special prime (the extended basis).
const MAXIMUM_MODULUS_COUNT: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BgvObjectKind {
    Plaintext,
    Ciphertext,
}

impl BgvObjectKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Ciphertext => "ciphertext",
        }
    }

    fn from_str(value: &str) -> CanonicalResult<Self> {
        match value {
            "plaintext" => Ok(Self::Plaintext),
            "ciphertext" => Ok(Self::Ciphertext),
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidEnum,
                "BGV canonical object kind is not supported",
            )),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CanonicalBgvObject {
    pub(crate) object_kind: BgvObjectKind,
    pub(crate) components: Vec<RnsPolynomial>,
}

pub(crate) fn serialize_bgv_object(
    object_kind: BgvObjectKind,
    components: &[RnsPolynomial],
) -> CanonicalResult<Vec<u8>> {
    validate_component_count(object_kind, components.len())?;
    for component in components {
        component.validate()?;
    }
    let mut output = Vec::new();
    append_string(&mut output, CANONICAL_MAGIC);
    append_varuint(&mut output, CANONICAL_OBJECT_VERSION);
    append_string(&mut output, object_kind.as_str());
    append_varuint(&mut output, components.len() as u64);
    for component in components {
        append_polynomial(&mut output, component);
    }

    Ok(output)
}

pub(crate) fn parse_bgv_object(bytes: &[u8]) -> CanonicalResult<CanonicalBgvObject> {
    let mut reader = CanonicalReader::new(bytes);
    let magic = reader.read_string()?;
    if magic != CANONICAL_MAGIC {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedMagic,
            "BGV canonical object does not use sealed-lattice canonical bytes",
        ));
    }
    let object_version = reader.read_varuint()?;
    if object_version != CANONICAL_OBJECT_VERSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "BGV canonical object version is not supported",
        ));
    }
    let object_kind = BgvObjectKind::from_str(&reader.read_string()?)?;
    let component_count = read_bounded_count(&mut reader, MAXIMUM_COMPONENT_COUNT, "component")?;
    validate_component_count(object_kind, component_count)?;
    let mut components = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        components.push(read_polynomial(&mut reader)?);
    }
    if !reader.is_finished() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::TrailingBytes,
            "BGV canonical object has trailing bytes",
        ));
    }
    let object = CanonicalBgvObject {
        object_kind,
        components,
    };
    for component in &object.components {
        component.validate()?;
    }
    // Canonicalize-by-round-trip: re-serialize the parsed object and require the
    // bytes to match exactly, rejecting any non-canonical input encoding.
    if serialize_bgv_object(object.object_kind, &object.components)? != bytes {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV object is not canonical because it does not reserialize byte-identically",
        ));
    }

    Ok(object)
}

pub(crate) fn canonical_bytes_hex(bytes: &[u8]) -> String {
    encode_hex(bytes)
}

pub(crate) fn parse_bgv_object_hex(
    canonical_bytes_hex: &str,
) -> CanonicalResult<CanonicalBgvObject> {
    let bytes = decode_hex(canonical_bytes_hex)?;

    parse_bgv_object(&bytes)
}

pub(crate) fn plaintext_root(canonical_bytes: &[u8]) -> String {
    namespace_root("sealed-lattice-root/plaintext-root-v1", canonical_bytes)
}

pub(crate) fn ciphertext_root(canonical_bytes: &[u8]) -> String {
    namespace_root("sealed-lattice-root/ciphertext-root-v1", canonical_bytes)
}

pub(crate) fn canonical_bytes_hash(canonical_bytes: &[u8]) -> String {
    hash512_hex(
        "sealed-lattice-bgv-rns/canonical-bytes-v1",
        &[canonical_bytes],
    )
}

fn append_polynomial(output: &mut Vec<u8>, polynomial: &RnsPolynomial) {
    append_string(output, &polynomial.profile_hash);
    append_string(output, &polynomial.basis_id);
    append_varuint(output, polynomial.level as u64);
    append_varuint(output, polynomial.coefficient_count as u64);
    append_string(output, polynomial.domain.as_str());
    append_string(output, &polynomial.encrypted_ballot_aggregate_layout_hash);
    append_varuint(output, polynomial.moduli.len() as u64);
    for modulus in &polynomial.moduli {
        append_varuint(output, *modulus);
    }
    append_varuint(output, polynomial.residues_by_modulus.len() as u64);
    for residues in &polynomial.residues_by_modulus {
        append_varuint(output, residues.len() as u64);
        for residue in residues {
            append_varuint(output, *residue);
        }
    }
}

fn read_polynomial(reader: &mut CanonicalReader<'_>) -> CanonicalResult<RnsPolynomial> {
    let profile_hash = reader.read_string()?;
    let basis_id = reader.read_string()?;
    let level = usize::try_from(reader.read_varuint()?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "level does not fit usize",
        )
    })?;
    let coefficient_count = usize::try_from(reader.read_varuint()?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "coefficient count does not fit usize",
        )
    })?;
    if coefficient_count != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV-RNS object coefficient count must match the selected polynomial degree",
        ));
    }
    let domain = PolynomialDomain::from_str(&reader.read_string()?).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            "BGV polynomial domain is not supported",
        )
    })?;
    let encrypted_ballot_aggregate_layout_hash = reader.read_string()?;
    let modulus_count = read_bounded_count(reader, MAXIMUM_MODULUS_COUNT, "modulus")?;
    let mut moduli = Vec::with_capacity(modulus_count);
    for _ in 0..modulus_count {
        moduli.push(reader.read_varuint()?);
    }
    let limb_count = read_bounded_count(reader, MAXIMUM_MODULUS_COUNT, "residue limb")?;
    if limb_count != modulus_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV canonical object residue limb count does not match modulus count",
        ));
    }
    let mut residues_by_modulus = Vec::with_capacity(limb_count);
    for _ in 0..limb_count {
        let residue_count = usize::try_from(reader.read_varuint()?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "residue count does not fit usize",
            )
        })?;
        if residue_count != coefficient_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV canonical object residue count does not match coefficient count",
            ));
        }
        let mut residues = Vec::with_capacity(residue_count);
        for _ in 0..residue_count {
            residues.push(reader.read_varuint()?);
        }
        residues_by_modulus.push(residues);
    }

    Ok(RnsPolynomial {
        profile_hash,
        basis_id,
        level,
        coefficient_count,
        domain,
        encrypted_ballot_aggregate_layout_hash,
        moduli,
        residues_by_modulus,
    })
}

fn read_bounded_count(
    reader: &mut CanonicalReader<'_>,
    maximum_count: usize,
    item_name: &str,
) -> CanonicalResult<usize> {
    let count = usize::try_from(reader.read_varuint()?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{item_name} count does not fit usize"),
        )
    })?;
    if count == 0 || count > maximum_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{item_name} count is outside the selected BGV-RNS bounds"),
        ));
    }

    Ok(count)
}

fn validate_component_count(
    object_kind: BgvObjectKind,
    component_count: usize,
) -> CanonicalResult<()> {
    match object_kind {
        BgvObjectKind::Plaintext if component_count == 1 => Ok(()),
        BgvObjectKind::Ciphertext if (2..=3).contains(&component_count) => Ok(()),
        BgvObjectKind::Plaintext => Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV plaintext canonical object must contain exactly one polynomial component",
        )),
        BgvObjectKind::Ciphertext => Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV ciphertext canonical object must contain two or three polynomial components",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BgvObjectKind, CANONICAL_MAGIC, canonical_bytes_hash, ciphertext_root, parse_bgv_object,
        plaintext_root, serialize_bgv_object,
    };
    use crate::{
        bgv::{
            encoding::encode_batch_plaintext_slots,
            profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        },
        encoding::{CanonicalErrorCode, append_string, append_varuint},
    };

    #[test]
    fn plaintext_serialization_is_canonical_and_rooted() {
        let encoded = encode_batch_plaintext_slots(&[1, 2, 65_536], 0).expect("encode");
        let canonical_bytes = serialize_bgv_object(BgvObjectKind::Plaintext, &[encoded.polynomial])
            .expect("serialize");
        let parsed = parse_bgv_object(&canonical_bytes).expect("parse");

        assert_eq!(parsed.object_kind, BgvObjectKind::Plaintext);
        assert_eq!(parsed.components[0].moduli, vec![DATA_PRIMES[0]]);
        assert_eq!(canonical_bytes_hash(&canonical_bytes).len(), 128);
        assert_eq!(plaintext_root(&canonical_bytes).len(), 128);
        assert_eq!(
            serialize_bgv_object(parsed.object_kind, &parsed.components).expect("reserialize"),
            canonical_bytes
        );
    }

    #[test]
    fn ciphertext_serialization_binds_component_count_layout_and_root() {
        let left = encode_batch_plaintext_slots(&[1, 2, 3], 0).expect("left");
        let right = encode_batch_plaintext_slots(&[4, 5, 6], 0).expect("right");
        let canonical_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[left.polynomial.clone(), right.polynomial.clone()],
        )
        .expect("serialize ciphertext convention fixture");
        let parsed = parse_bgv_object(&canonical_bytes).expect("parse");

        assert_eq!(parsed.object_kind, BgvObjectKind::Ciphertext);
        assert_eq!(parsed.components.len(), 2);
        assert_eq!(
            parsed.components[0].encrypted_ballot_aggregate_layout_hash,
            parsed.components[1].encrypted_ballot_aggregate_layout_hash
        );
        assert_eq!(ciphertext_root(&canonical_bytes).len(), 128);
        assert!(serialize_bgv_object(BgvObjectKind::Ciphertext, &[left.polynomial]).is_err());
    }

    #[test]
    fn parser_rejects_noncanonical_domain_and_trailing_bytes() {
        let encoded = encode_batch_plaintext_slots(&[9], 0).expect("encode");
        let mut polynomial = encoded.polynomial;
        polynomial.domain = crate::bgv::rns::PolynomialDomain::Ntt;
        assert!(serialize_bgv_object(BgvObjectKind::Plaintext, &[polynomial]).is_err());

        let encoded = encode_batch_plaintext_slots(&vec![0; POLYNOMIAL_DEGREE], 0).expect("encode");
        let mut canonical_bytes =
            serialize_bgv_object(BgvObjectKind::Plaintext, &[encoded.polynomial])
                .expect("serialize");
        canonical_bytes.push(0);
        assert!(parse_bgv_object(&canonical_bytes).is_err());
    }

    #[test]
    fn parser_rejects_wrong_coefficient_count_before_residue_allocation() {
        let mut canonical_bytes = Vec::new();
        append_string(&mut canonical_bytes, CANONICAL_MAGIC);
        append_varuint(&mut canonical_bytes, 1);
        append_string(&mut canonical_bytes, BgvObjectKind::Plaintext.as_str());
        append_varuint(&mut canonical_bytes, 1);
        append_string(&mut canonical_bytes, "untrusted-profile-hash");
        append_string(&mut canonical_bytes, "untrusted-basis");
        append_varuint(&mut canonical_bytes, 0);
        append_varuint(&mut canonical_bytes, (POLYNOMIAL_DEGREE as u64) + 1);

        let error =
            parse_bgv_object(&canonical_bytes).expect_err("wrong count must fail immediately");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        assert!(
            error.message.contains("selected polynomial degree"),
            "unexpected error: {error:?}"
        );
    }
}
