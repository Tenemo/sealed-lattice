#[cfg(test)]
use crate::bgv::parameters::BgvBasisKind;
#[cfg(test)]
use crate::encoding::CanonicalReader;
#[cfg(test)]
use crate::transcript_core::encode_hex;
use crate::{
    bgv::rns::RnsPolynomial,
    encoding::{
        CanonicalError, CanonicalErrorCode, CanonicalResult, append_string, append_varuint,
    },
    hashing::namespace_root,
};

const CANONICAL_MAGIC: &str = "sealed-lattice-bgv-rns-canonical-object";
const CANONICAL_OBJECT_VERSION: u64 = 2;
// Max polynomial components in a BGV object: a degree-2 ciphertext has 3.
#[cfg(test)]
const MAXIMUM_COMPONENT_COUNT: usize = 3;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BgvObjectKind {
    #[cfg(test)]
    Plaintext,
    Ciphertext,
}

impl BgvObjectKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            #[cfg(test)]
            Self::Plaintext => "plaintext",
            Self::Ciphertext => "ciphertext",
        }
    }

    #[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV object is not canonical because it does not reserialize byte-identically",
        ));
    }

    Ok(object)
}

#[cfg(test)]
pub(crate) fn canonical_bytes_hex(bytes: &[u8]) -> String {
    encode_hex(bytes)
}

#[cfg(test)]
pub(crate) fn plaintext_root(canonical_bytes: &[u8]) -> String {
    namespace_root("sealed-lattice-root/plaintext-root", canonical_bytes)
}

pub(crate) fn ciphertext_root(canonical_bytes: &[u8]) -> String {
    namespace_root("sealed-lattice-root/ciphertext-root", canonical_bytes)
}

fn append_polynomial(output: &mut Vec<u8>, polynomial: &RnsPolynomial) {
    append_string(output, polynomial.basis_kind.basis_id());
    append_varuint(output, polynomial.level as u64);
    for residues in &polynomial.residues_by_modulus {
        for residue in residues {
            append_varuint(output, *residue);
        }
    }
}

#[cfg(test)]
fn read_polynomial(reader: &mut CanonicalReader<'_>) -> CanonicalResult<RnsPolynomial> {
    let basis_id = reader.read_string()?;
    let basis_kind = BgvBasisKind::from_basis_id(&basis_id).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            "BGV-RNS basis identifier is not selected",
        )
    })?;
    let level = usize::try_from(reader.read_varuint()?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "level does not fit usize",
        )
    })?;
    let moduli = basis_kind.moduli_for_level(level).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV-RNS object level is outside the selected basis",
        )
    })?;
    let mut residues_by_modulus = Vec::with_capacity(moduli.len());
    for _ in &moduli {
        let mut residues = Vec::with_capacity(crate::bgv::parameters::POLYNOMIAL_DEGREE);
        for _ in 0..crate::bgv::parameters::POLYNOMIAL_DEGREE {
            residues.push(reader.read_varuint()?);
        }
        residues_by_modulus.push(residues);
    }

    Ok(RnsPolynomial {
        basis_kind,
        level,
        residues_by_modulus,
    })
}

#[cfg(test)]
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
        #[cfg(test)]
        BgvObjectKind::Plaintext if component_count == 1 => Ok(()),
        BgvObjectKind::Ciphertext if (2..=3).contains(&component_count) => Ok(()),
        #[cfg(test)]
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
        BgvObjectKind, CANONICAL_MAGIC, CANONICAL_OBJECT_VERSION, parse_bgv_object,
        serialize_bgv_object,
    };
    use crate::{
        bgv::{encoding::encode_batch_plaintext_slots, parameters::POLYNOMIAL_DEGREE},
        encoding::{CanonicalErrorCode, append_string, append_varuint},
    };

    #[test]
    fn plaintext_serialization_is_canonical_and_rooted() {
        let encoded = encode_batch_plaintext_slots(&[1, 2, 65_536], 0).expect("encode");
        let canonical_bytes = serialize_bgv_object(BgvObjectKind::Plaintext, &[encoded.polynomial])
            .expect("serialize");
        let parsed = parse_bgv_object(&canonical_bytes).expect("parse");

        assert_eq!(parsed.object_kind, BgvObjectKind::Plaintext);
        assert_eq!(
            parsed.components[0].basis_kind,
            crate::bgv::parameters::BgvBasisKind::Data
        );
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
            parsed.components[0].basis_kind,
            parsed.components[1].basis_kind
        );
        assert!(serialize_bgv_object(BgvObjectKind::Ciphertext, &[left.polynomial]).is_err());
    }

    #[test]
    fn parser_rejects_trailing_bytes() {
        let encoded = encode_batch_plaintext_slots(&vec![0; POLYNOMIAL_DEGREE], 0).expect("encode");
        let mut canonical_bytes =
            serialize_bgv_object(BgvObjectKind::Plaintext, &[encoded.polynomial])
                .expect("serialize");
        canonical_bytes.push(0);
        assert!(parse_bgv_object(&canonical_bytes).is_err());
    }

    #[test]
    fn parser_rejects_unknown_basis_before_residue_allocation() {
        let mut canonical_bytes = Vec::new();
        append_string(&mut canonical_bytes, CANONICAL_MAGIC);
        append_varuint(&mut canonical_bytes, CANONICAL_OBJECT_VERSION);
        append_string(&mut canonical_bytes, BgvObjectKind::Plaintext.as_str());
        append_varuint(&mut canonical_bytes, 1);
        append_string(&mut canonical_bytes, "untrusted-basis");
        append_varuint(&mut canonical_bytes, 0);

        let error =
            parse_bgv_object(&canonical_bytes).expect_err("unknown basis must fail immediately");

        assert_eq!(error.code, CanonicalErrorCode::InvalidEnum);
        assert!(
            error.message.contains("basis identifier"),
            "unexpected error: {error:?}"
        );
    }
}
