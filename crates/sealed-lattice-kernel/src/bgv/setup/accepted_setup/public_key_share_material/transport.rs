use std::{
    collections::{BTreeMap, btree_map::Entry},
    mem,
    sync::{Arc, Mutex, OnceLock},
};

use super::*;
use crate::foundation::{CanonicalStreamDomain, VerifiedCanonicalStreamSummary};

#[derive(Clone)]
pub(in crate::bgv::setup) struct CanonicalPublicKeyShareMaterialLimb {
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) rns_prime: u64,
    pub(in crate::bgv::setup) coefficients: Vec<u64>,
}

#[derive(Clone)]
pub(in crate::bgv::setup) struct CanonicalPublicKeyShareMaterialRecord {
    pub(in crate::bgv::setup) trustee_roster_position: u64,
    pub(in crate::bgv::setup) limbs: Vec<CanonicalPublicKeyShareMaterialLimb>,
}

pub(in crate::bgv::setup) struct VerifiedCanonicalPublicKeyShareMaterial {
    pub(in crate::bgv::setup) participant_count: u64,
    pub(in crate::bgv::setup) rns_limb_count: usize,
    pub(in crate::bgv::setup) ring_degree: usize,
    pub(in crate::bgv::setup) records: Vec<CanonicalPublicKeyShareMaterialRecord>,
}

pub(in crate::bgv::setup) type VerifiedCanonicalPublicKeyShareMaterialHandle =
    Arc<VerifiedCanonicalPublicKeyShareMaterial>;

static VERIFIED_CANONICAL_PUBLIC_KEY_SHARE_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedCanonicalPublicKeyShareMaterialStoreEntry>>,
> = OnceLock::new();

struct VerifiedCanonicalPublicKeyShareMaterialStoreEntry {
    material: VerifiedCanonicalPublicKeyShareMaterialHandle,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
}

fn verified_canonical_public_key_share_materials()
-> &'static Mutex<BTreeMap<String, VerifiedCanonicalPublicKeyShareMaterialStoreEntry>> {
    VERIFIED_CANONICAL_PUBLIC_KEY_SHARE_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(in crate::bgv::setup) fn verified_canonical_public_key_share_material(
    material_root: &str,
) -> CanonicalResult<Option<VerifiedCanonicalPublicKeyShareMaterialHandle>> {
    let materials = verified_canonical_public_key_share_materials()
        .lock()
        .map_err(|_| public_key_share_material_store_error())?;
    Ok(materials
        .get(material_root)
        .map(|entry| Arc::clone(&entry.material)))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn authenticated_public_key_share_material_stream_summary(
    material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    authenticated_public_key_share_material_stream_summary_in_session(None, material_root)
}

pub(in crate::bgv::setup) fn authenticated_public_key_share_material_stream_summary_in_session(
    accepted_setup_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
    material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    if let Some(accepted_setup_session) = accepted_setup_session
        && !crate::bgv::setup::accepted_setup_session_owns_material_root(
            accepted_setup_session.session_handle,
            &accepted_setup_session.capability,
            crate::bgv::setup::AcceptedSetupMaterialStore::PublicKeyShare,
            material_root,
        )?
    {
        return Ok(None);
    }
    let materials = verified_canonical_public_key_share_materials()
        .lock()
        .map_err(|_| public_key_share_material_store_error())?;
    Ok(materials
        .get(material_root)
        .map(|entry| Arc::clone(&entry.stream_summary)))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn evict_verified_canonical_public_key_share_materials(
    material_roots: &[String],
) {
    let _ = drain_verified_canonical_public_key_share_materials(material_roots);
}

pub(in crate::bgv::setup) fn drain_verified_canonical_public_key_share_materials(
    material_roots: &[String],
) -> CanonicalResult<()> {
    let mut materials = verified_canonical_public_key_share_materials()
        .lock()
        .map_err(|_| public_key_share_material_store_error())?;
    for material_root in material_roots {
        materials.remove(material_root);
    }
    Ok(())
}

pub(in crate::bgv::setup) struct CanonicalPublicKeyShareMaterialStream {
    material_root: String,
    decoder: CanonicalPublicKeyShareMaterialDecoder,
    total_byte_length: u64,
}

pub(in crate::bgv::setup) fn begin_verified_canonical_public_key_share_material_stream(
    material_root: String,
    total_byte_length: u64,
) -> CanonicalResult<CanonicalPublicKeyShareMaterialStream> {
    if total_byte_length == 0
        || total_byte_length > maximum_public_key_share_material_byte_length()?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material stream length is outside the accepted setup profile",
        ));
    }
    if verified_canonical_public_key_share_materials()
        .lock()
        .map_err(|_| public_key_share_material_store_error())?
        .contains_key(&material_root)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical public-key share material root was already consumed",
        ));
    }

    Ok(CanonicalPublicKeyShareMaterialStream {
        material_root,
        decoder: CanonicalPublicKeyShareMaterialDecoder::new(),
        total_byte_length,
    })
}

pub(in crate::bgv::setup) fn absorb_verified_canonical_public_key_share_material_chunk(
    stream: &mut CanonicalPublicKeyShareMaterialStream,
    chunk: &[u8],
) -> CanonicalResult<()> {
    stream.decoder.absorb(chunk)
}

pub(in crate::bgv::setup) fn finish_verified_canonical_public_key_share_material_stream(
    stream: CanonicalPublicKeyShareMaterialStream,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
) -> CanonicalResult<()> {
    if stream_summary.stream_domain() != CanonicalStreamDomain::PublicKeyShareMaterial
        || stream_summary.total_byte_length() != stream.total_byte_length
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share material does not match its authenticated stream summary",
        ));
    }
    let material = Arc::new(stream.decoder.finish()?);
    let mut materials = verified_canonical_public_key_share_materials()
        .lock()
        .map_err(|_| public_key_share_material_store_error())?;
    match materials.entry(stream.material_root) {
        Entry::Vacant(entry) => {
            entry.insert(VerifiedCanonicalPublicKeyShareMaterialStoreEntry {
                material,
                stream_summary,
            });
            Ok(())
        }
        Entry::Occupied(_) => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical public-key share material root was already consumed",
        )),
    }
}

pub(in crate::bgv::setup) fn cancel_verified_canonical_public_key_share_material_stream(
    _stream: CanonicalPublicKeyShareMaterialStream,
) {
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicKeyShareMaterialDecodePhase {
    Magic,
    Version,
    ParticipantCount,
    RnsLimbCount,
    RingDegree,
    TrusteeRosterPosition,
    RnsLimbIndex,
    RnsPrime,
    Coefficient,
    Complete,
}

struct CanonicalPublicKeyShareMaterialDecoder {
    phase: PublicKeyShareMaterialDecodePhase,
    pending_bytes: Vec<u8>,
    participant_count: u64,
    ring_degree: usize,
    records: Vec<CanonicalPublicKeyShareMaterialRecord>,
    current_limbs: Vec<CanonicalPublicKeyShareMaterialLimb>,
    current_coefficients: Vec<u64>,
    current_rns_prime: u64,
    expected_roster_position: usize,
    expected_rns_limb_index: usize,
    expected_coefficient_index: usize,
}

impl CanonicalPublicKeyShareMaterialDecoder {
    fn new() -> Self {
        Self {
            phase: PublicKeyShareMaterialDecodePhase::Magic,
            pending_bytes: Vec::new(),
            participant_count: 0,
            ring_degree: 0,
            records: Vec::new(),
            current_limbs: Vec::new(),
            current_coefficients: Vec::new(),
            current_rns_prime: 0,
            expected_roster_position: 0,
            expected_rns_limb_index: 0,
            expected_coefficient_index: 0,
        }
    }

    fn absorb(&mut self, chunk: &[u8]) -> CanonicalResult<()> {
        if self.phase == PublicKeyShareMaterialDecodePhase::Complete && !chunk.is_empty() {
            return Err(public_key_share_material_decode_error(
                "public-key share material has trailing bytes",
            ));
        }
        self.pending_bytes.extend_from_slice(chunk);
        let mut consumed_byte_length = 0_usize;
        loop {
            let available_bytes = &self.pending_bytes[consumed_byte_length..];
            let consumed = match self.phase {
                PublicKeyShareMaterialDecodePhase::Magic => {
                    if available_bytes.len() < PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len() {
                        break;
                    }
                    if &available_bytes[..PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len()]
                        != PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC
                    {
                        return Err(public_key_share_material_decode_error(
                            "public-key share material binary magic does not match",
                        ));
                    }
                    self.phase = PublicKeyShareMaterialDecodePhase::Version;
                    PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len()
                }
                PublicKeyShareMaterialDecodePhase::Version => {
                    let Some((version, byte_length)) =
                        decode_varuint(available_bytes, "binary version")?
                    else {
                        break;
                    };
                    if version != PUBLIC_KEY_SHARE_MATERIAL_BINARY_VERSION {
                        return Err(public_key_share_material_decode_error(
                            "public-key share material binary version is unsupported",
                        ));
                    }
                    self.phase = PublicKeyShareMaterialDecodePhase::ParticipantCount;
                    byte_length
                }
                PublicKeyShareMaterialDecodePhase::ParticipantCount => {
                    let Some((participant_count, byte_length)) =
                        decode_varuint(available_bytes, "participantCount")?
                    else {
                        break;
                    };
                    if !super::super::participant_count_is_supported(participant_count) {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material participant count is outside the accepted setup profile",
                        ));
                    }
                    self.participant_count = participant_count;
                    self.records =
                        Vec::with_capacity(usize::try_from(participant_count).map_err(|_| {
                            CanonicalError::new(
                                CanonicalErrorCode::MalformedLength,
                                "public-key share material participant count does not fit usize",
                            )
                        })?);
                    self.phase = PublicKeyShareMaterialDecodePhase::RnsLimbCount;
                    byte_length
                }
                PublicKeyShareMaterialDecodePhase::RnsLimbCount => {
                    let Some((rns_limb_count, byte_length)) =
                        decode_varuint(available_bytes, "rnsLimbCount")?
                    else {
                        break;
                    };
                    if rns_limb_count != DATA_PRIMES.len() as u64 {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "public-key share material RNS limb count does not match Q_share",
                        ));
                    }
                    self.phase = PublicKeyShareMaterialDecodePhase::RingDegree;
                    byte_length
                }
                PublicKeyShareMaterialDecodePhase::RingDegree => {
                    let Some((ring_degree, byte_length)) =
                        decode_varuint(available_bytes, "ringDegree")?
                    else {
                        break;
                    };
                    self.ring_degree = usize::try_from(ring_degree).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material ring degree does not fit usize",
                        )
                    })?;
                    if self.ring_degree == 0 || self.ring_degree > POLYNOMIAL_DEGREE {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material ring degree is outside the accepted setup profile",
                        ));
                    }
                    self.current_limbs = Vec::with_capacity(DATA_PRIMES.len());
                    self.phase = PublicKeyShareMaterialDecodePhase::TrusteeRosterPosition;
                    byte_length
                }
                PublicKeyShareMaterialDecodePhase::TrusteeRosterPosition => {
                    let Some((roster_position, byte_length)) =
                        decode_varuint(available_bytes, "trusteeRosterPosition")?
                    else {
                        break;
                    };
                    if roster_position != self.expected_roster_position as u64 {
                        return Err(public_key_share_material_decode_error(
                            "public-key share material trustee order is not canonical",
                        ));
                    }
                    self.expected_rns_limb_index = 0;
                    self.phase = PublicKeyShareMaterialDecodePhase::RnsLimbIndex;
                    byte_length
                }
                PublicKeyShareMaterialDecodePhase::RnsLimbIndex => {
                    let Some((rns_limb_index, byte_length)) =
                        decode_varuint(available_bytes, "rnsLimbIndex")?
                    else {
                        break;
                    };
                    if rns_limb_index != self.expected_rns_limb_index as u64 {
                        return Err(public_key_share_material_decode_error(
                            "public-key share material RNS limb order is not canonical",
                        ));
                    }
                    self.phase = PublicKeyShareMaterialDecodePhase::RnsPrime;
                    byte_length
                }
                PublicKeyShareMaterialDecodePhase::RnsPrime => {
                    let Some(rns_prime) = decode_unsigned64(available_bytes) else {
                        break;
                    };
                    if DATA_PRIMES.get(self.expected_rns_limb_index).copied() != Some(rns_prime) {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "public-key share material RNS prime does not match Q_share",
                        ));
                    }
                    self.current_rns_prime = rns_prime;
                    self.current_coefficients = Vec::with_capacity(self.ring_degree);
                    self.expected_coefficient_index = 0;
                    self.phase = PublicKeyShareMaterialDecodePhase::Coefficient;
                    8
                }
                PublicKeyShareMaterialDecodePhase::Coefficient => {
                    let Some(coefficient) = decode_unsigned64(available_bytes) else {
                        break;
                    };
                    if coefficient >= self.current_rns_prime {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "public-key share material coefficient is not a canonical residue",
                        ));
                    }
                    self.current_coefficients.push(coefficient);
                    self.expected_coefficient_index += 1;
                    if self.expected_coefficient_index == self.ring_degree {
                        self.finish_limb()?;
                    }
                    8
                }
                PublicKeyShareMaterialDecodePhase::Complete => {
                    if available_bytes.is_empty() {
                        break;
                    }
                    return Err(public_key_share_material_decode_error(
                        "public-key share material has trailing bytes",
                    ));
                }
            };
            consumed_byte_length = consumed_byte_length.checked_add(consumed).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material stream offset overflowed usize",
                )
            })?;
        }
        if consumed_byte_length != 0 {
            self.pending_bytes.drain(..consumed_byte_length);
        }

        Ok(())
    }

    fn finish_limb(&mut self) -> CanonicalResult<()> {
        self.current_limbs
            .push(CanonicalPublicKeyShareMaterialLimb {
                rns_limb_index: self.expected_rns_limb_index,
                rns_prime: self.current_rns_prime,
                coefficients: mem::take(&mut self.current_coefficients),
            });
        self.expected_rns_limb_index += 1;
        if self.expected_rns_limb_index < DATA_PRIMES.len() {
            self.phase = PublicKeyShareMaterialDecodePhase::RnsLimbIndex;
            return Ok(());
        }

        self.records.push(CanonicalPublicKeyShareMaterialRecord {
            trustee_roster_position: self.expected_roster_position as u64,
            limbs: mem::take(&mut self.current_limbs),
        });
        self.expected_roster_position += 1;
        if self.expected_roster_position
            == usize::try_from(self.participant_count).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material participant count does not fit usize",
                )
            })?
        {
            self.phase = PublicKeyShareMaterialDecodePhase::Complete;
        } else {
            self.current_limbs = Vec::with_capacity(DATA_PRIMES.len());
            self.phase = PublicKeyShareMaterialDecodePhase::TrusteeRosterPosition;
        }

        Ok(())
    }

    fn finish(self) -> CanonicalResult<VerifiedCanonicalPublicKeyShareMaterial> {
        if self.phase != PublicKeyShareMaterialDecodePhase::Complete
            || !self.pending_bytes.is_empty()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material stream ended before its canonical object was complete",
            ));
        }

        Ok(VerifiedCanonicalPublicKeyShareMaterial {
            participant_count: self.participant_count,
            rns_limb_count: DATA_PRIMES.len(),
            ring_degree: self.ring_degree,
            records: self.records,
        })
    }
}

fn decode_varuint(bytes: &[u8], field_name: &str) -> CanonicalResult<Option<(u64, usize)>> {
    let mut shift = 0_u32;
    let mut value = 0_u64;
    for byte_index in 0..10 {
        let Some(byte) = bytes.get(byte_index).copied() else {
            return Ok(None);
        };
        let payload = u64::from(byte & 0x7f);
        if byte_index == 9 && payload > 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} binary varuint exceeds u64"),
            ));
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            let mut canonical = Vec::new();
            crate::encoding::append_varuint(&mut canonical, value);
            let consumed_byte_length = byte_index + 1;
            if canonical.as_slice() != &bytes[..consumed_byte_length] {
                return Err(public_key_share_material_decode_error(format!(
                    "{field_name} binary varuint is not minimally encoded"
                )));
            }
            return Ok(Some((value, consumed_byte_length)));
        }
        shift += 7;
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::MalformedLength,
        format!("{field_name} binary varuint is too long"),
    ))
}

fn decode_unsigned64(bytes: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn maximum_public_key_share_material_byte_length() -> CanonicalResult<u64> {
    let coefficient_bytes_per_limb = u64::try_from(POLYNOMIAL_DEGREE)
        .ok()
        .and_then(|degree| degree.checked_mul(8))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material coefficient length overflowed u64",
            )
        })?;
    let bytes_per_limb = coefficient_bytes_per_limb.checked_add(18).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material limb length overflowed u64",
        )
    })?;
    super::super::MAXIMUM_SUPPORTED_PARTICIPANT_COUNT
        .checked_mul(DATA_PRIMES.len() as u64)
        .and_then(|value| value.checked_mul(bytes_per_limb))
        .and_then(|value| value.checked_add(128))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material maximum length overflowed u64",
            )
        })
}

fn public_key_share_material_decode_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

fn public_key_share_material_store_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::ComponentMismatch,
        "canonical public-key share material store is unavailable",
    )
}
