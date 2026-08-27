use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::foundation::Hash512;

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH,
        CollectiveCoinSourceCoordinate320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
        PseudorandomZeroSharingPairSeedContributionCoordinate320,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH, create_collective_coin_source_320,
        create_pseudorandom_zero_sharing_pair_seed_contribution_320,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogInclusionProof320,
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogTree320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::PseudorandomZeroSharingSeedDeliveryLayout320,
    pseudorandom_zero_sharing_subset_seed_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
        create_pseudorandom_zero_sharing_subset_seed_contribution_320,
    },
};

const REQUEST_MAGIC: &[u8; 4] = b"SLSK";
const RESPONSE_MAGIC: &[u8; 4] = b"SLSR";
const CODEC_VERSION: u16 = 1;
const PRODUCE_CATALOG_OPERATION: u8 = 1;
const VALIDATE_CATALOG_OPERATION: u8 = 2;
const PRODUCE_DELIVERY_OPERATION: u8 = 3;
const VALIDATE_DELIVERY_OPERATION: u8 = 4;
const FAILURE_STATUS: u8 = 0;
const CATALOG_STATUS: u8 = 1;
const DELIVERY_STATUS: u8 = 2;
const VALIDATION_STATUS: u8 = 3;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8 * 1024 * 1024;
const MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH: usize = 4096;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 1024 * 1024;
const MAXIMUM_PARTICIPANT_COUNT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogSourceKernelError320 {
    MalformedRequest(&'static str),
    ResourceLimit(&'static str),
    ContextMismatch(&'static str),
    GeometryMismatch(&'static str),
    SourceGeneration(&'static str),
    CatalogMismatch(&'static str),
    DeliveryMismatch(&'static str),
}

impl PseudorandomZeroSharingSeedCatalogSourceKernelError320 {
    const fn response_code(&self) -> u16 {
        match self {
            Self::MalformedRequest(_) => 1,
            Self::ResourceLimit(_) => 2,
            Self::ContextMismatch(_) => 3,
            Self::GeometryMismatch(_) => 4,
            Self::SourceGeneration(_) => 5,
            Self::CatalogMismatch(_) => 6,
            Self::DeliveryMismatch(_) => 7,
        }
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedCatalogSourceKernelError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, field) = match self {
            Self::MalformedRequest(field) => ("malformed request", field),
            Self::ResourceLimit(field) => ("resource limit", field),
            Self::ContextMismatch(field) => ("context mismatch", field),
            Self::GeometryMismatch(field) => ("geometry mismatch", field),
            Self::SourceGeneration(field) => ("source generation", field),
            Self::CatalogMismatch(field) => ("catalog mismatch", field),
            Self::DeliveryMismatch(field) => ("delivery mismatch", field),
        };
        write!(formatter, "seed-catalog source kernel {kind}: {field}")
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedCatalogSourceKernelError320 {}

#[derive(Clone, Copy)]
enum SourceKernelOperation320 {
    ProduceCatalog,
    ValidateCatalog,
    ProduceDelivery,
    ValidateDelivery,
}

impl SourceKernelOperation320 {
    fn from_byte(
        value: u8,
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        match value {
            PRODUCE_CATALOG_OPERATION => Ok(Self::ProduceCatalog),
            VALIDATE_CATALOG_OPERATION => Ok(Self::ValidateCatalog),
            PRODUCE_DELIVERY_OPERATION => Ok(Self::ProduceDelivery),
            VALIDATE_DELIVERY_OPERATION => Ok(Self::ValidateDelivery),
            _ => Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(
                    "operation",
                ),
            ),
        }
    }

    const fn includes_catalog(self) -> bool {
        !matches!(self, Self::ProduceCatalog)
    }

    const fn includes_recipient(self) -> bool {
        matches!(self, Self::ProduceDelivery | Self::ValidateDelivery)
    }
}

#[derive(Clone, Copy)]
struct SourceLeafBytes320<'a> {
    contribution: &'a [u8],
    commitment_salt: &'a [u8],
}

struct ProducedCatalogEntry320 {
    opening_bytes: Zeroizing<Vec<u8>>,
    inclusion_proof_bytes: Vec<u8>,
}

struct ProducedCatalog320 {
    catalog_identity: Hash512,
    root_body_bytes: Vec<u8>,
    entries: Vec<ProducedCatalogEntry320>,
}

struct BoundedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedCursor<'a> {
    fn new(
        bytes: &'a [u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(
                    "input byte length",
                ),
            );
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn read_exact(
        &mut self,
        byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or(PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(field))?;
        if end > self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field),
            );
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_unsigned8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_unsigned16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        Ok(u16::from_le_bytes(
            self.read_exact(size_of::<u16>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field)
                })?,
        ))
    }

    fn read_unsigned32(
        &mut self,
        field: &'static str,
    ) -> Result<usize, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        let value = u32::from_le_bytes(
            self.read_exact(size_of::<u32>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field)
                })?,
        );
        usize::try_from(value).map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(field)
        })
    }

    fn read_hash512(
        &mut self,
        field: &'static str,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        Ok(Hash512::from_bytes(
            self.read_exact(Hash512::BYTE_LENGTH, field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field)
                })?,
        ))
    }

    fn read_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        let byte_length = self.read_unsigned32(field)?;
        if byte_length == 0 || byte_length > maximum_byte_length {
            return Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(field),
            );
        }
        self.read_exact(byte_length, field)
    }

    fn require_magic(
        &mut self,
        expected: &[u8; 4],
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        if self.read_exact(expected.len(), field)? != expected {
            return Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }

    fn require_version(
        &mut self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        if self.read_unsigned16(field)? != CODEC_VERSION {
            return Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }

    fn require_complete(
        &self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
        if self.offset != self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }
}

fn require_context(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    if condition {
        Ok(())
    } else {
        Err(PseudorandomZeroSharingSeedCatalogSourceKernelError320::ContextMismatch(field))
    }
}

fn require_geometry(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    if condition {
        Ok(())
    } else {
        Err(PseudorandomZeroSharingSeedCatalogSourceKernelError320::GeometryMismatch(field))
    }
}

fn require_catalog_bytes(
    actual: &[u8],
    expected: &[u8],
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    if actual.len() == expected.len() && bool::from(actual.ct_eq(expected)) {
        Ok(())
    } else {
        Err(PseudorandomZeroSharingSeedCatalogSourceKernelError320::CatalogMismatch(field))
    }
}

fn opening_byte_length(coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320) -> usize {
    match coordinate {
        PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(_) => {
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::Pair { .. } => {
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
            COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH
        }
    }
}

fn source_material_array<const BYTE_LENGTH: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<Zeroizing<[u8; BYTE_LENGTH]>, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    Ok(Zeroizing::new(bytes.try_into().map_err(|_| {
        PseudorandomZeroSharingSeedCatalogSourceKernelError320::GeometryMismatch(field)
    })?))
}

fn produce_catalog(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    coordinates: &[PseudorandomZeroSharingSeedCatalogCoordinate320],
    source_inventory: &[SourceLeafBytes320<'_>],
) -> Result<ProducedCatalog320, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    if coordinates.len() != source_inventory.len() {
        return Err(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::GeometryMismatch(
                "source inventory count",
            ),
        );
    }
    let mut commitment_digests = Vec::with_capacity(coordinates.len());
    let mut opening_bytes = Vec::with_capacity(coordinates.len());
    for (coordinate, source_leaf) in coordinates.iter().copied().zip(source_inventory) {
        let contribution = source_material_array::<
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        >(source_leaf.contribution, "source contribution")?;
        let commitment_salt = source_material_array::<
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        >(source_leaf.commitment_salt, "commitment salt")?;
        let (commitment_digest, opening) = match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => {
                let subset_coordinate = layout.subset_seed_coordinate(subset).map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                        "subset coordinate",
                    )
                })?;
                let (commitment, opening) =
                    create_pseudorandom_zero_sharing_subset_seed_contribution_320(
                        subset_coordinate,
                        *contribution,
                        *commitment_salt,
                    )
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                            "subset opening",
                        )
                    })?;
                (
                    commitment.digest(),
                    opening.canonical_bytes().map_err(|_| {
                        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                            "subset opening encoding",
                        )
                    })?,
                )
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
                lower_roster_position,
                upper_roster_position,
            } => {
                let counterpart_position = if layout.contributor_position() == lower_roster_position
                {
                    upper_roster_position
                } else {
                    lower_roster_position
                };
                let pair_coordinate =
                    PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
                        layout,
                        counterpart_position,
                    )
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                            "pair coordinate",
                        )
                    })?;
                let (commitment, opening) =
                    create_pseudorandom_zero_sharing_pair_seed_contribution_320(
                        pair_coordinate,
                        *contribution,
                        *commitment_salt,
                    )
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                            "pair opening",
                        )
                    })?;
                (
                    commitment.digest(),
                    opening.canonical_bytes().map_err(|_| {
                        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                            "pair opening encoding",
                        )
                    })?,
                )
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
                let coin_coordinate = CollectiveCoinSourceCoordinate320::from_catalog_layout(
                    layout,
                )
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                        "collective-coin coordinate",
                    )
                })?;
                let (commitment, opening) = create_collective_coin_source_320(
                    coin_coordinate,
                    *contribution,
                    *commitment_salt,
                )
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                        "collective-coin opening",
                    )
                })?;
                (
                    commitment.digest(),
                    opening.canonical_bytes().map_err(|_| {
                        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                            "collective-coin opening encoding",
                        )
                    })?,
                )
            }
        };
        commitment_digests.push(commitment_digest);
        opening_bytes.push(opening);
    }
    let tree = PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests)
        .map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration("catalog tree")
        })?;
    let root_body_bytes = tree.root_body().canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
            "root-body encoding",
        )
    })?;
    let mut entries = Vec::with_capacity(coordinates.len());
    for (leaf_ordinal, opening_bytes) in opening_bytes.into_iter().enumerate() {
        let leaf_ordinal = u64::try_from(leaf_ordinal).map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit("leaf ordinal")
        })?;
        let inclusion_proof_bytes = tree
            .inclusion_proof(leaf_ordinal)
            .and_then(|proof| proof.canonical_bytes())
            .map_err(|_| {
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                    "inclusion-proof encoding",
                )
            })?;
        entries.push(ProducedCatalogEntry320 {
            opening_bytes,
            inclusion_proof_bytes,
        });
    }
    Ok(ProducedCatalog320 {
        catalog_identity: layout.identity(),
        root_body_bytes,
        entries,
    })
}

fn read_and_verify_catalog(
    cursor: &mut BoundedCursor<'_>,
    produced: &ProducedCatalog320,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    let catalog_identity = cursor.read_hash512("catalog identity")?;
    require_catalog_bytes(
        catalog_identity.as_bytes(),
        produced.catalog_identity.as_bytes(),
        "catalog identity",
    )?;
    require_catalog_bytes(
        cursor.read_exact(produced.root_body_bytes.len(), "root body")?,
        &produced.root_body_bytes,
        "root-body bytes",
    )?;
    for entry in &produced.entries {
        require_catalog_bytes(
            cursor.read_exact(entry.opening_bytes.len(), "catalog opening")?,
            &entry.opening_bytes,
            "opening bytes",
        )?;
        require_catalog_bytes(
            cursor.read_exact(entry.inclusion_proof_bytes.len(), "catalog inclusion proof")?,
            &entry.inclusion_proof_bytes,
            "inclusion-proof bytes",
        )?;
    }
    Ok(())
}

fn produce_delivery_source(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    recipient_position: u16,
    produced: &ProducedCatalog320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    let delivery_layout =
        PseudorandomZeroSharingSeedDeliveryLayout320::derive(layout, recipient_position).map_err(
            |_| {
                PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch(
                    "recipient coordinate",
                )
            },
        )?;
    let mut payload = Zeroizing::new(Vec::with_capacity(delivery_layout.payload_byte_length()));
    for subset in delivery_layout.subsets() {
        append_delivery_entry(
            &mut payload,
            layout,
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(*subset),
            produced,
        )?;
    }
    append_delivery_entry(
        &mut payload,
        layout,
        layout.pair_coordinate(recipient_position).map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch(
                "pair coordinate",
            )
        })?,
        produced,
    )?;
    if payload.len() != delivery_layout.payload_byte_length() {
        return Err(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch(
                "payload byte length",
            ),
        );
    }
    Ok(payload)
}

fn append_delivery_entry(
    payload: &mut Vec<u8>,
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    produced: &ProducedCatalog320,
) -> Result<(), PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    let leaf_ordinal = usize::try_from(layout.leaf_ordinal(coordinate).map_err(|_| {
        PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch("leaf coordinate")
    })?)
    .map_err(|_| {
        PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit("leaf ordinal")
    })?;
    let entry = produced.entries.get(leaf_ordinal).ok_or(
        PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch("catalog entry"),
    )?;
    payload.extend_from_slice(&entry.opening_bytes);
    payload.extend_from_slice(&entry.inclusion_proof_bytes);
    Ok(())
}

fn catalog_response(
    produced: &ProducedCatalog320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    let payload_byte_length = Hash512::BYTE_LENGTH
        .checked_add(produced.root_body_bytes.len())
        .and_then(|length| {
            produced.entries.iter().try_fold(length, |total, entry| {
                total
                    .checked_add(entry.opening_bytes.len())
                    .and_then(|value| value.checked_add(entry.inclusion_proof_bytes.len()))
            })
        })
        .ok_or(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(
                "catalog response byte length",
            ),
        )?;
    let response_byte_length = RESPONSE_MAGIC
        .len()
        .checked_add(size_of::<u16>())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(payload_byte_length))
        .ok_or(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(
                "catalog response byte length",
            ),
        )?;
    if response_byte_length > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(
                "catalog response byte length",
            ),
        );
    }
    let mut response = Zeroizing::new(Vec::with_capacity(response_byte_length));
    append_response_header(&mut response, CATALOG_STATUS);
    response.extend_from_slice(produced.catalog_identity.as_bytes());
    response.extend_from_slice(&produced.root_body_bytes);
    for entry in &produced.entries {
        response.extend_from_slice(&entry.opening_bytes);
        response.extend_from_slice(&entry.inclusion_proof_bytes);
    }
    Ok(response)
}

fn delivery_response(
    recipient_position: u16,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    let response_byte_length = RESPONSE_MAGIC
        .len()
        .checked_add(size_of::<u16>())
        .and_then(|value| value.checked_add(1 + size_of::<u16>()))
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(
                "delivery response byte length",
            ),
        )?;
    if response_byte_length > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ResourceLimit(
                "delivery response byte length",
            ),
        );
    }
    let mut response = Zeroizing::new(Vec::with_capacity(response_byte_length));
    append_response_header(&mut response, DELIVERY_STATUS);
    response.extend_from_slice(&recipient_position.to_le_bytes());
    response.extend_from_slice(payload);
    Ok(response)
}

fn validation_response() -> Zeroizing<Vec<u8>> {
    let mut response = Zeroizing::new(Vec::with_capacity(RESPONSE_MAGIC.len() + 3));
    append_response_header(&mut response, VALIDATION_STATUS);
    response
}

fn failure_response(
    error: &PseudorandomZeroSharingSeedCatalogSourceKernelError320,
) -> Zeroizing<Vec<u8>> {
    let mut response = Zeroizing::new(Vec::with_capacity(RESPONSE_MAGIC.len() + 5));
    append_response_header(&mut response, FAILURE_STATUS);
    response.extend_from_slice(&error.response_code().to_le_bytes());
    response
}

fn append_response_header(response: &mut Vec<u8>, status: u8) {
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    response.push(status);
}

fn execute(
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedCatalogSourceKernelError320> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(REQUEST_MAGIC, "request magic")?;
    cursor.require_version("request version")?;
    let operation = SourceKernelOperation320::from_byte(cursor.read_unsigned8("operation")?)?;
    let preparation_context_bytes = cursor.read_bounded_bytes(
        MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH,
        "preparation context",
    )?;
    let preparation_context =
        TallyPreparationContext::from_canonical_bytes(preparation_context_bytes).map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::ContextMismatch(
                "preparation context",
            )
        })?;
    let parameter_identity = cursor.read_hash512("parameter identity")?;
    let roster_identity = cursor.read_hash512("roster identity")?;
    let action_context_identity = cursor.read_hash512("action-context identity")?;
    let preparation_context_identity = cursor.read_hash512("preparation-context identity")?;
    let catalog_compiler_identity = cursor.read_hash512("catalog-compiler identity")?;
    let _state_predecessor_identity = cursor.read_hash512("state-predecessor identity")?;
    let preparation_attempt_ordinal = cursor.read_unsigned16("preparation-attempt ordinal")?;
    let participant_count = cursor.read_unsigned16("participant count")?;
    let participant_position = cursor.read_unsigned16("participant position")?;
    require_context(
        preparation_context.identity() == preparation_context_identity,
        "preparation-context identity",
    )?;
    require_context(
        preparation_context.roster_hash() == roster_identity,
        "roster identity",
    )?;
    require_context(
        preparation_context.action_context_hash() == action_context_identity,
        "action-context identity",
    )?;
    require_context(
        preparation_attempt_ordinal == PREPARATION_ATTEMPT_ORDINAL,
        "preparation-attempt ordinal",
    )?;
    require_context(
        participant_count == preparation_context.participant_count()
            && usize::from(participant_count) <= MAXIMUM_PARTICIPANT_COUNT
            && participant_position < participant_count,
        "participant coordinates",
    )?;
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        preparation_context,
        participant_position,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedCatalogSourceKernelError320::ContextMismatch("catalog layout")
    })?;
    require_context(
        layout.compiler_identity() == catalog_compiler_identity,
        "catalog-compiler identity",
    )?;
    let coordinates = layout
        .coordinates()
        .map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                "catalog coordinates",
            )
        })?
        .collect::<Vec<_>>();
    require_geometry(
        cursor.read_unsigned32("leaf count")? == coordinates.len(),
        "leaf count",
    )?;
    require_geometry(
        cursor.read_unsigned32("source-contribution byte length")?
            == PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH
            && PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH
                == PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH
            && PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH
                == COLLECTIVE_COIN_SOURCE_BYTE_LENGTH,
        "source-contribution byte length",
    )?;
    require_geometry(
        cursor.read_unsigned32("commitment-salt byte length")?
            == PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH
            && PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH
                == SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH,
        "commitment-salt byte length",
    )?;
    let supplied_root_body_byte_length = cursor.read_unsigned32("root-body byte length")?;
    require_geometry(
        supplied_root_body_byte_length > 0
            && supplied_root_body_byte_length <= MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        "root-body byte length",
    )?;
    let expected_inclusion_proof_byte_length =
        PseudorandomZeroSharingSeedCatalogInclusionProof320::canonical_byte_length_for_layout(
            layout,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                "inclusion-proof geometry",
            )
        })?;
    require_geometry(
        cursor.read_unsigned32("inclusion-proof byte length")?
            == expected_inclusion_proof_byte_length,
        "inclusion-proof byte length",
    )?;
    let recipient_positions = (0..participant_count)
        .filter(|position| *position != participant_position)
        .collect::<Vec<_>>();
    require_geometry(
        usize::from(cursor.read_unsigned16("delivery count")?) == recipient_positions.len(),
        "delivery count",
    )?;
    for coordinate in &coordinates {
        require_geometry(
            cursor.read_unsigned32("opening byte length")? == opening_byte_length(*coordinate),
            "opening byte-length table",
        )?;
    }
    let mut expected_delivery_byte_lengths = Vec::with_capacity(recipient_positions.len());
    for recipient_position in &recipient_positions {
        let byte_length =
            PseudorandomZeroSharingSeedDeliveryLayout320::derive(layout, *recipient_position)
                .map_err(|_| {
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::SourceGeneration(
                        "delivery-source geometry",
                    )
                })?
                .payload_byte_length();
        require_geometry(
            cursor.read_unsigned32("delivery-source byte length")? == byte_length,
            "delivery-source byte-length table",
        )?;
        expected_delivery_byte_lengths.push(byte_length);
    }
    let mut source_inventory = Vec::with_capacity(coordinates.len());
    for _ in &coordinates {
        source_inventory.push(SourceLeafBytes320 {
            contribution: cursor.read_exact(
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
                "source contribution",
            )?,
            commitment_salt: cursor.read_exact(
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
                "commitment salt",
            )?,
        });
    }
    let produced = produce_catalog(layout, &coordinates, &source_inventory)?;
    require_geometry(
        produced.root_body_bytes.len() == supplied_root_body_byte_length,
        "root-body byte length",
    )?;
    if operation.includes_catalog() {
        read_and_verify_catalog(&mut cursor, &produced)?;
    }
    if !operation.includes_recipient() {
        cursor.require_complete("request trailing bytes")?;
        return match operation {
            SourceKernelOperation320::ProduceCatalog => catalog_response(&produced),
            SourceKernelOperation320::ValidateCatalog => Ok(validation_response()),
            SourceKernelOperation320::ProduceDelivery
            | SourceKernelOperation320::ValidateDelivery => unreachable!(),
        };
    }
    let recipient_position = cursor.read_unsigned16("recipient position")?;
    let delivery_index = recipient_positions
        .iter()
        .position(|position| *position == recipient_position)
        .ok_or(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch(
                "recipient position",
            ),
        )?;
    let expected_delivery_byte_length = expected_delivery_byte_lengths[delivery_index];
    let delivery_payload = produce_delivery_source(layout, recipient_position, &produced)?;
    if delivery_payload.len() != expected_delivery_byte_length {
        return Err(
            PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch(
                "derived delivery byte length",
            ),
        );
    }
    match operation {
        SourceKernelOperation320::ProduceDelivery => {
            cursor.require_complete("request trailing bytes")?;
            delivery_response(recipient_position, &delivery_payload)
        }
        SourceKernelOperation320::ValidateDelivery => {
            let supplied_payload =
                cursor.read_exact(expected_delivery_byte_length, "delivery-source payload")?;
            cursor.require_complete("request trailing bytes")?;
            if !bool::from(supplied_payload.ct_eq(&delivery_payload)) {
                return Err(
                    PseudorandomZeroSharingSeedCatalogSourceKernelError320::DeliveryMismatch(
                        "delivery-source payload",
                    ),
                );
            }
            Ok(validation_response())
        }
        SourceKernelOperation320::ProduceCatalog | SourceKernelOperation320::ValidateCatalog => {
            unreachable!()
        }
    }
}

pub(crate) fn run_pseudorandom_zero_sharing_seed_catalog_source_kernel_320(
    bytes: &[u8],
) -> Zeroizing<Vec<u8>> {
    execute(bytes).unwrap_or_else(|error| failure_response(&error))
}
