use std::collections::BTreeSet;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    FoundationSchemaError, SchemaResult, read_ascii, read_display_text, read_fixed_bytes,
    read_hash, read_hash_list, read_item, read_list_header, read_nested_tuple_list_with_budget,
    read_nested_tuple_with_budget, read_u16, read_u32, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, ParticipantIdentity, RefusalReason, StabilizedDisplayText, StreamDescriptor, hash512,
};

pub const RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x1801;
pub const RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x1802;
pub const RANDOM_CURSOR_SCHEMA_IDENTIFIER: u16 = 0x1804;
pub const CHECKPOINT_MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x1805;
pub const CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1806;
pub const CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1807;
pub const RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1808;
pub const MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1809;

const RUNTIME_SCHEMA_VERSION: u16 = 1;
const MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH: usize = 65_536;
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MINIMUM_SUPPORTED_FREE_STORAGE_BYTE_LENGTH: u64 = 2_147_483_648;
const RUNTIME_BUDGET_PROFILE_ONE: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum RuntimeAssetRole {
    ApplicationModule = 1,
    WorkerModule = 2,
    WasmModule = 3,
    LocalAsset = 4,
}

impl RuntimeAssetRole {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::ApplicationModule),
            2 => Some(Self::WorkerModule),
            3 => Some(Self::WasmModule),
            4 => Some(Self::LocalAsset),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAssetReference {
    pub asset_role: RuntimeAssetRole,
    pub canonical_path: String,
    pub byte_length: u64,
    pub asset_hash: Hash512,
}

impl RuntimeAssetReference {
    pub fn new(
        asset_role: RuntimeAssetRole,
        canonical_path: String,
        byte_length: u64,
        asset_hash: Hash512,
    ) -> SchemaResult<Self> {
        validate_root_relative_path(&canonical_path)?;
        if byte_length == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime assets must be nonempty",
            ));
        }
        if matches!(
            asset_role,
            RuntimeAssetRole::ApplicationModule | RuntimeAssetRole::WorkerModule
        ) && byte_length
            > u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length).map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "runtime copied-buffer limit does not fit u64",
                )
            })?
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "application and worker assets exceed the copied-buffer limit",
            ));
        }
        Ok(Self {
            asset_role,
            canonical_path,
            byte_length,
            asset_hash,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.asset_role,
            self.canonical_path.clone(),
            self.byte_length,
            self.asset_hash,
        )?;
        Ok(CanonicalTuple::new(
            RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.asset_role.canonical_code()),
                CanonicalItem::ascii(&self.canonical_path)?,
                CanonicalItem::unsigned64(self.byte_length),
                CanonicalItem::hash512(self.asset_hash.into_bytes()),
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER, 4)?;
        let asset_role = RuntimeAssetRole::from_canonical_code(read_u16(&tuple.items[0])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "runtime asset role is not assigned",
                )
            })?;
        Self::new(
            asset_role,
            read_ascii(&tuple.items[1])?.to_string(),
            read_u64(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointRandomUseProfile {
    pub family: u16,
    pub purpose: u16,
}

impl CheckpointRandomUseProfile {
    pub fn new(family: u16, purpose: u16) -> SchemaResult<Self> {
        if family == 0 || purpose == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "checkpoint random-use family and purpose must be assigned",
            ));
        }
        Ok(Self { family, purpose })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.family, self.purpose)?;
        Ok(CanonicalTuple::new(
            CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.family),
                CanonicalItem::unsigned16(self.purpose),
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER, 2)?;
        Self::new(read_u16(&tuple.items[0])?, read_u16(&tuple.items[1])?)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointBoundaryProfile {
    pub safe_boundary_ordinal: u32,
    pub state_schema_identifier: u16,
    pub ordered_random_uses: Vec<CheckpointRandomUseProfile>,
}

impl CheckpointBoundaryProfile {
    pub fn new(
        safe_boundary_ordinal: u32,
        state_schema_identifier: u16,
        ordered_random_uses: Vec<CheckpointRandomUseProfile>,
    ) -> SchemaResult<Self> {
        if state_schema_identifier == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "checkpoint state schema must be assigned",
            ));
        }
        for random_use in &ordered_random_uses {
            CheckpointRandomUseProfile::new(random_use.family, random_use.purpose)?;
        }
        validate_strictly_increasing(
            &ordered_random_uses,
            |random_use| (random_use.family, random_use.purpose),
            "checkpoint random-use profiles must be strictly ordered and duplicate-free",
        )?;
        Ok(Self {
            safe_boundary_ordinal,
            state_schema_identifier,
            ordered_random_uses,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.safe_boundary_ordinal,
            self.state_schema_identifier,
            self.ordered_random_uses.clone(),
        )?;
        Ok(CanonicalTuple::new(
            CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.safe_boundary_ordinal),
                CanonicalItem::unsigned16(self.state_schema_identifier),
                nested_tuple_list(
                    self.ordered_random_uses
                        .iter()
                        .map(CheckpointRandomUseProfile::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
            ],
        ))
    }

    fn from_tuple_with_budget(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER, 3)?;
        let ordered_random_uses =
            read_nested_tuple_list_with_budget(&tuple.items[2], limits, budget)?
                .iter()
                .map(CheckpointRandomUseProfile::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(
            read_u32(&tuple.items[0])?,
            read_u16(&tuple.items[1])?,
            ordered_random_uses,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple_with_budget(&tuple, limits, &mut budget)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOperationProfile {
    pub operation_kind: u16,
    pub safe_boundaries: Vec<CheckpointBoundaryProfile>,
}

impl RuntimeOperationProfile {
    pub fn new(
        operation_kind: u16,
        safe_boundaries: Vec<CheckpointBoundaryProfile>,
    ) -> SchemaResult<Self> {
        if operation_kind == 0 || safe_boundaries.is_empty() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime operation profiles require an assigned operation and boundaries",
            ));
        }
        for (expected_ordinal, boundary) in safe_boundaries.iter().enumerate() {
            CheckpointBoundaryProfile::new(
                boundary.safe_boundary_ordinal,
                boundary.state_schema_identifier,
                boundary.ordered_random_uses.clone(),
            )?;
            if boundary.safe_boundary_ordinal
                != u32::try_from(expected_ordinal).map_err(|_| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "checkpoint boundary ordinal does not fit u32",
                    )
                })?
            {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "checkpoint boundary ordinals must begin at zero and be contiguous",
                ));
            }
        }
        Ok(Self {
            operation_kind,
            safe_boundaries,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.operation_kind, self.safe_boundaries.clone())?;
        Ok(CanonicalTuple::new(
            RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.operation_kind),
                nested_tuple_list(
                    self.safe_boundaries
                        .iter()
                        .map(CheckpointBoundaryProfile::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
            ],
        ))
    }

    fn from_tuple_with_budget(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER, 2)?;
        let boundaries = read_nested_tuple_list_with_budget(&tuple.items[1], limits, budget)?
            .iter()
            .map(|boundary| {
                CheckpointBoundaryProfile::from_tuple_with_budget(boundary, limits, budget)
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(read_u16(&tuple.items[0])?, boundaries)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple_with_budget(&tuple, limits, &mut budget)
    }
}

/// An exact device and browser profile used to bind runtime evidence.
///
/// The profile is evidence metadata only. Protocol verification must not use it
/// as an acceptance input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileRuntimeProfile {
    pub phone_model: StabilizedDisplayText,
    pub hardware_revision: StabilizedDisplayText,
    pub installed_ram_bytes: u64,
    pub minimum_free_storage_bytes: u64,
    pub operating_system_build: StabilizedDisplayText,
    pub browser_engine: StabilizedDisplayText,
    pub browser_version: StabilizedDisplayText,
    pub bootstrap_hash: Hash512,
    pub runtime_build_manifest_hash: Hash512,
    pub runtime_budget_profile: u16,
}

impl MobileRuntimeProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        phone_model: StabilizedDisplayText,
        hardware_revision: StabilizedDisplayText,
        installed_ram_bytes: u64,
        minimum_free_storage_bytes: u64,
        operating_system_build: StabilizedDisplayText,
        browser_engine: StabilizedDisplayText,
        browser_version: StabilizedDisplayText,
        bootstrap_hash: Hash512,
        runtime_build_manifest_hash: Hash512,
        runtime_budget_profile: u16,
    ) -> SchemaResult<Self> {
        for value in [
            &phone_model,
            &hardware_revision,
            &operating_system_build,
            &browser_engine,
            &browser_version,
        ] {
            if value.as_str().is_empty() {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "mobile runtime profile text must be nonempty",
                ));
            }
        }
        if minimum_free_storage_bytes < MINIMUM_SUPPORTED_FREE_STORAGE_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mobile runtime profile free storage is below the supported minimum",
            ));
        }
        if runtime_budget_profile != RUNTIME_BUDGET_PROFILE_ONE {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "mobile runtime budget profile is unsupported",
            ));
        }
        Ok(Self {
            phone_model,
            hardware_revision,
            installed_ram_bytes,
            minimum_free_storage_bytes,
            operating_system_build,
            browser_engine,
            browser_version,
            bootstrap_hash,
            runtime_build_manifest_hash,
            runtime_budget_profile,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.phone_model.clone(),
            self.hardware_revision.clone(),
            self.installed_ram_bytes,
            self.minimum_free_storage_bytes,
            self.operating_system_build.clone(),
            self.browser_engine.clone(),
            self.browser_version.clone(),
            self.bootstrap_hash,
            self.runtime_build_manifest_hash,
            self.runtime_budget_profile,
        )?;
        Ok(CanonicalTuple::new(
            MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::display_text(&self.phone_model)?,
                CanonicalItem::display_text(&self.hardware_revision)?,
                CanonicalItem::unsigned64(self.installed_ram_bytes),
                CanonicalItem::unsigned64(self.minimum_free_storage_bytes),
                CanonicalItem::display_text(&self.operating_system_build)?,
                CanonicalItem::display_text(&self.browser_engine)?,
                CanonicalItem::display_text(&self.browser_version)?,
                CanonicalItem::hash512(self.bootstrap_hash.into_bytes()),
                CanonicalItem::hash512(self.runtime_build_manifest_hash.into_bytes()),
                CanonicalItem::unsigned16(self.runtime_budget_profile),
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER, 10)?;
        Self::new(
            read_display_text(&tuple.items[0])?,
            read_display_text(&tuple.items[1])?,
            read_u64(&tuple.items[2])?,
            read_u64(&tuple.items[3])?,
            read_display_text(&tuple.items[4])?,
            read_display_text(&tuple.items[5])?,
            read_display_text(&tuple.items[6])?,
            read_hash(&tuple.items[7])?,
            read_hash(&tuple.items[8])?,
            read_u16(&tuple.items[9])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }

    pub fn runtime_profile_identifier(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/evidence/mobile-runtime-profile/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBuildManifest {
    pub protocol_version: u16,
    pub release_identifier: String,
    pub suite_id: Hash512,
    pub suite_record_path: String,
    pub ordered_suite_artifact_paths: Vec<String>,
    pub ordered_assets: Vec<RuntimeAssetReference>,
    pub operation_profiles: Vec<RuntimeOperationProfile>,
}

impl RuntimeBuildManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: u16,
        release_identifier: String,
        suite_id: Hash512,
        suite_record_path: String,
        ordered_suite_artifact_paths: Vec<String>,
        ordered_assets: Vec<RuntimeAssetReference>,
        operation_profiles: Vec<RuntimeOperationProfile>,
    ) -> SchemaResult<Self> {
        if protocol_version != FOUNDATION_PROFILE.protocol_version {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "runtime manifest protocol version is unsupported",
            ));
        }
        validate_release_identifier(&release_identifier)?;
        validate_root_relative_path(&suite_record_path)?;
        if ordered_suite_artifact_paths.len() != 6 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime manifest must contain six ordered suite artifact paths",
            ));
        }
        for path in &ordered_suite_artifact_paths {
            validate_root_relative_path(path)?;
        }
        validate_assets(&ordered_assets)?;
        for operation_profile in &operation_profiles {
            RuntimeOperationProfile::new(
                operation_profile.operation_kind,
                operation_profile.safe_boundaries.clone(),
            )?;
        }
        validate_strictly_increasing(
            &operation_profiles,
            |profile| profile.operation_kind,
            "runtime operation profiles must be strictly ordered and duplicate-free",
        )?;

        let mut all_paths = BTreeSet::new();
        for path in std::iter::once(&suite_record_path)
            .chain(ordered_suite_artifact_paths.iter())
            .chain(ordered_assets.iter().map(|asset| &asset.canonical_path))
        {
            if !all_paths.insert(path.as_str()) {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "runtime manifest paths must be pairwise distinct",
                ));
            }
        }

        Ok(Self {
            protocol_version,
            release_identifier,
            suite_id,
            suite_record_path,
            ordered_suite_artifact_paths,
            ordered_assets,
            operation_profiles,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.protocol_version,
            self.release_identifier.clone(),
            self.suite_id,
            self.suite_record_path.clone(),
            self.ordered_suite_artifact_paths.clone(),
            self.ordered_assets.clone(),
            self.operation_profiles.clone(),
        )?;
        Ok(CanonicalTuple::new(
            RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.protocol_version),
                CanonicalItem::ascii(&self.release_identifier)?,
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::ascii(&self.suite_record_path)?,
                ascii_list(&self.ordered_suite_artifact_paths)?,
                nested_tuple_list(
                    self.ordered_assets
                        .iter()
                        .map(RuntimeAssetReference::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                nested_tuple_list(
                    self.operation_profiles
                        .iter()
                        .map(RuntimeOperationProfile::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let bytes = self.canonical_tuple()?.encode()?;
        if bytes.len() > MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime build manifest exceeds its fixed byte limit",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        if bytes.len() > MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime build manifest exceeds its fixed byte limit",
            ));
        }
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER, 7)?;
        let ordered_assets =
            read_nested_tuple_list_with_budget(&tuple.items[5], limits, &mut budget)?
                .iter()
                .map(RuntimeAssetReference::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?;
        let operation_profiles =
            read_nested_tuple_list_with_budget(&tuple.items[6], limits, &mut budget)?
                .iter()
                .map(|profile| {
                    RuntimeOperationProfile::from_tuple_with_budget(profile, limits, &mut budget)
                })
                .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_ascii(&tuple.items[1])?.to_string(),
            read_hash(&tuple.items[2])?,
            read_ascii(&tuple.items[3])?.to_string(),
            read_ascii_list(&tuple.items[4])?,
            ordered_assets,
            operation_profiles,
        )
    }

    pub fn manifest_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/runtime/build-manifest/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    pub fn boundary_profile(
        &self,
        operation_kind: u16,
        safe_boundary_ordinal: u32,
    ) -> Option<&CheckpointBoundaryProfile> {
        self.operation_profiles
            .binary_search_by_key(&operation_kind, |profile| profile.operation_kind)
            .ok()
            .and_then(|profile_index| {
                self.operation_profiles[profile_index]
                    .safe_boundaries
                    .get(usize::try_from(safe_boundary_ordinal).ok()?)
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RandomCursor {
    pub family: u16,
    pub purpose: u16,
    pub derivation_context_hash: Hash512,
    pub next_counter: u64,
}

impl RandomCursor {
    pub fn new(
        family: u16,
        purpose: u16,
        derivation_context_hash: Hash512,
        next_counter: u64,
    ) -> SchemaResult<Self> {
        CheckpointRandomUseProfile::new(family, purpose)?;
        Ok(Self {
            family,
            purpose,
            derivation_context_hash,
            next_counter,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.family,
            self.purpose,
            self.derivation_context_hash,
            self.next_counter,
        )?;
        Ok(CanonicalTuple::new(
            RANDOM_CURSOR_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.family),
                CanonicalItem::unsigned16(self.purpose),
                CanonicalItem::hash512(self.derivation_context_hash.into_bytes()),
                CanonicalItem::unsigned64(self.next_counter),
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, RANDOM_CURSOR_SCHEMA_IDENTIFIER, 4)?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_u16(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_u64(&tuple.items[3])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointManifest {
    pub runtime_build_manifest_hash: Hash512,
    pub suite_id: Hash512,
    pub ceremony_context_hash: Hash512,
    pub action_context_hash: Hash512,
    pub participant_id: ParticipantIdentity,
    pub attempt_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    pub operation_kind: u16,
    pub safe_boundary_ordinal: u32,
    pub ordered_source_digests: Vec<Hash512>,
    pub ordered_random_cursors: Vec<RandomCursor>,
    pub state_stream_descriptor: StreamDescriptor,
}

impl CheckpointManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_build_manifest_hash: Hash512,
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        participant_id: ParticipantIdentity,
        attempt_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        operation_kind: u16,
        safe_boundary_ordinal: u32,
        ordered_source_digests: Vec<Hash512>,
        ordered_random_cursors: Vec<RandomCursor>,
        state_stream_descriptor: StreamDescriptor,
    ) -> SchemaResult<Self> {
        if operation_kind == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "checkpoint operation kind must be assigned",
            ));
        }
        state_stream_descriptor.validate()?;
        for cursor in &ordered_random_cursors {
            RandomCursor::new(
                cursor.family,
                cursor.purpose,
                cursor.derivation_context_hash,
                cursor.next_counter,
            )?;
        }
        validate_strictly_increasing(
            &ordered_random_cursors,
            |cursor| {
                (
                    cursor.family,
                    cursor.purpose,
                    *cursor.derivation_context_hash.as_bytes(),
                )
            },
            "random cursors must be strictly ordered and duplicate-free",
        )?;
        Ok(Self {
            runtime_build_manifest_hash,
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            participant_id,
            attempt_identifier,
            operation_kind,
            safe_boundary_ordinal,
            ordered_source_digests,
            ordered_random_cursors,
            state_stream_descriptor,
        })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.runtime_build_manifest_hash,
            self.suite_id,
            self.ceremony_context_hash,
            self.action_context_hash,
            self.participant_id,
            self.attempt_identifier,
            self.operation_kind,
            self.safe_boundary_ordinal,
            self.ordered_source_digests.clone(),
            self.ordered_random_cursors.clone(),
            self.state_stream_descriptor.clone(),
        )?;
        Ok(CanonicalTuple::new(
            CHECKPOINT_MANIFEST_SCHEMA_IDENTIFIER,
            RUNTIME_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.runtime_build_manifest_hash.into_bytes()),
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.participant_id.into_bytes()),
                CanonicalItem::fixed_bytes(self.attempt_identifier)?,
                CanonicalItem::unsigned16(self.operation_kind),
                CanonicalItem::unsigned32(self.safe_boundary_ordinal),
                hash_list(&self.ordered_source_digests)?,
                nested_tuple_list(
                    self.ordered_random_cursors
                        .iter()
                        .map(RandomCursor::canonical_tuple)
                        .collect::<SchemaResult<Vec<_>>>()?,
                )?,
                CanonicalItem::nested_tuple(&self.state_stream_descriptor.canonical_tuple()?)?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(super) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, CHECKPOINT_MANIFEST_SCHEMA_IDENTIFIER, 11)?;
        let cursor_tuples = read_nested_tuple_list_with_budget(&tuple.items[9], limits, budget)?;
        let ordered_random_cursors = cursor_tuples
            .iter()
            .map(RandomCursor::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        let state_descriptor_tuple =
            read_nested_tuple_with_budget(&tuple.items[10], limits, budget)?;
        Self::new(
            read_hash(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            ParticipantIdentity::from_bytes(read_fixed_semantic_bytes(
                &tuple.items[4],
                CanonicalItemType::ParticipantIdentity,
            )?),
            read_fixed_bytes(&tuple.items[5])?,
            read_u16(&tuple.items[6])?,
            read_u32(&tuple.items[7])?,
            read_hash_list(&tuple.items[8])?,
            ordered_random_cursors,
            StreamDescriptor::from_tuple(&state_descriptor_tuple)?,
        )
    }

    pub fn checkpoint_identifier(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/runtime/checkpoint/v1",
            &[
                CanonicalItem::hash512(self.runtime_build_manifest_hash.into_bytes()),
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.participant_id.into_bytes()),
                CanonicalItem::fixed_bytes(self.attempt_identifier)?,
                CanonicalItem::unsigned16(self.operation_kind),
                CanonicalItem::unsigned32(self.safe_boundary_ordinal),
                hash_list(&self.ordered_source_digests)?,
            ],
        )?)
    }

    pub fn checkpoint_chunk_identifier(
        &self,
        chunk_index: u32,
        chunk_digest: Hash512,
    ) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/runtime/checkpoint-chunk/v1",
            &[
                CanonicalItem::hash512(self.checkpoint_identifier()?.into_bytes()),
                CanonicalItem::unsigned32(chunk_index),
                CanonicalItem::hash512(chunk_digest.into_bytes()),
            ],
        )?)
    }

    /// Checks only manifest-owned profile bindings. Source roles, state bytes,
    /// and the exact live derivation contexts remain verifier-owned inputs.
    pub fn validate_runtime_profile(
        &self,
        runtime_build_manifest: &RuntimeBuildManifest,
    ) -> SchemaResult<u16> {
        if runtime_build_manifest.manifest_hash()? != self.runtime_build_manifest_hash
            || runtime_build_manifest.suite_id != self.suite_id
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "checkpoint build or suite binding is wrong",
            ));
        }
        let boundary = runtime_build_manifest
            .boundary_profile(self.operation_kind, self.safe_boundary_ordinal)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::WrongContext,
                    "checkpoint operation boundary is not declared by the runtime manifest",
                )
            })?;
        let observed_random_uses = self
            .ordered_random_cursors
            .iter()
            .map(|cursor| CheckpointRandomUseProfile {
                family: cursor.family,
                purpose: cursor.purpose,
            })
            .collect::<BTreeSet<_>>();
        let expected_random_uses = boundary
            .ordered_random_uses
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if observed_random_uses != expected_random_uses {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "checkpoint random cursors do not match the declared boundary profile",
            ));
        }
        Ok(boundary.state_schema_identifier)
    }
}

fn validate_assets(assets: &[RuntimeAssetReference]) -> SchemaResult<()> {
    let mut previous_key = None;
    let mut required_role_counts = [0_u8; 3];
    for asset in assets {
        RuntimeAssetReference::new(
            asset.asset_role,
            asset.canonical_path.clone(),
            asset.byte_length,
            asset.asset_hash,
        )?;
        let key = (
            asset.asset_role.canonical_code(),
            asset.canonical_path.as_str(),
        );
        if previous_key.is_some_and(|previous| previous >= key) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime assets must be strictly ordered by role and path",
            ));
        }
        previous_key = Some(key);
        if let 1..=3 = asset.asset_role.canonical_code() {
            let role_index = usize::from(asset.asset_role.canonical_code() - 1);
            required_role_counts[role_index] = required_role_counts[role_index]
                .checked_add(1)
                .ok_or_else(|| {
                    schema_error(
                        RefusalReason::OutsideSupportedProfile,
                        "runtime asset count overflowed",
                    )
                })?;
        }
    }
    if required_role_counts != [1, 1, 1] {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "runtime assets require exactly one application, worker, and WASM module",
        ));
    }
    Ok(())
}

fn validate_release_identifier(value: &str) -> SchemaResult<()> {
    if value.is_empty()
        || value.len() > FOUNDATION_PROFILE.maximum_identifier_byte_length
        || !value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e))
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "runtime release identifier must be short nonempty printable ASCII",
        ));
    }
    Ok(())
}

fn validate_root_relative_path(path: &str) -> SchemaResult<()> {
    let bytes = path.as_bytes();
    if !path.is_ascii()
        || bytes.len() < 2
        || bytes.first() != Some(&b'/')
        || bytes.get(1) == Some(&b'/')
        || bytes
            .iter()
            .any(|byte| matches!(byte, b'\\' | b'%' | b'?' | b'#') || !matches!(byte, 0x21..=0x7e))
        || path[1..]
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "runtime path is not canonical root-relative ASCII",
        ));
    }
    Ok(())
}

fn validate_strictly_increasing<Value, Key: Ord>(
    values: &[Value],
    key: impl Fn(&Value) -> Key,
    message: &'static str,
) -> SchemaResult<()> {
    for adjacent in values.windows(2) {
        if key(&adjacent[0]) >= key(&adjacent[1]) {
            return Err(schema_error(RefusalReason::WrongTypeOrLength, message));
        }
    }
    Ok(())
}

fn nested_tuple_list(tuples: Vec<CanonicalTuple>) -> SchemaResult<CanonicalItem> {
    let items = tuples
        .iter()
        .map(CanonicalItem::nested_tuple)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::NestedTuple,
        &items,
    )?)
}

fn ascii_list(values: &[String]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .map(|value| CanonicalItem::ascii(value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Ascii,
        &items,
    )?)
}

fn hash_list(values: &[Hash512]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .map(|value| CanonicalItem::hash512(value.into_bytes()))
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Hash512,
        &items,
    )?)
}

fn read_ascii_list(item: &CanonicalItem) -> SchemaResult<Vec<String>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Ascii)?;
    let mut values = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let length_end = offset.checked_add(4).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "ASCII list offset overflowed",
            )
        })?;
        let length_bytes: [u8; 4] = bytes
            .get(offset..length_end)
            .ok_or_else(|| {
                schema_error(RefusalReason::MalformedEncoding, "ASCII list is truncated")
            })?
            .try_into()
            .map_err(|_| schema_error(RefusalReason::MalformedEncoding, "ASCII list length"))?;
        let byte_length = usize::try_from(u32::from_le_bytes(length_bytes)).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "ASCII list element length does not fit usize",
            )
        })?;
        let value_end = length_end.checked_add(byte_length).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "ASCII list element length overflowed",
            )
        })?;
        let value = std::str::from_utf8(bytes.get(length_end..value_end).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "ASCII list element is truncated",
            )
        })?)
        .map_err(|_| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "ASCII list element is invalid",
            )
        })?;
        if !value.is_ascii() {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "ASCII list element is invalid",
            ));
        }
        values.push(value.to_string());
        offset = value_end;
    }
    if offset != bytes.len() {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "ASCII list contains trailing bytes",
        ));
    }
    Ok(values)
}

fn read_fixed_semantic_bytes<const LENGTH: usize>(
    item: &CanonicalItem,
    item_type: CanonicalItemType,
) -> SchemaResult<[u8; LENGTH]> {
    read_item(item, item_type)?.try_into().map_err(|_| {
        schema_error(
            RefusalReason::WrongTypeOrLength,
            "fixed semantic byte length",
        )
    })
}

const fn schema_error(
    refusal_reason: RefusalReason,
    message: &'static str,
) -> FoundationSchemaError {
    FoundationSchemaError {
        refusal_reason,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; 64])
    }

    fn asset(role: RuntimeAssetRole, path: &str, byte: u8) -> RuntimeAssetReference {
        RuntimeAssetReference::new(role, path.to_string(), 1024, hash(byte)).expect("asset")
    }

    fn manifest() -> RuntimeBuildManifest {
        RuntimeBuildManifest::new(
            1,
            "release-1".to_string(),
            hash(1),
            "/suite.bin".to_string(),
            (1..=6)
                .map(|index| format!("/artifact-{index}.bin"))
                .collect(),
            vec![
                asset(RuntimeAssetRole::ApplicationModule, "/application.js", 2),
                asset(RuntimeAssetRole::WorkerModule, "/worker.js", 3),
                asset(RuntimeAssetRole::WasmModule, "/kernel.wasm", 4),
                asset(RuntimeAssetRole::LocalAsset, "/style.css", 5),
            ],
            vec![
                RuntimeOperationProfile::new(
                    0x1205,
                    vec![
                        CheckpointBoundaryProfile::new(
                            0,
                            0x1901,
                            vec![
                                CheckpointRandomUseProfile::new(0x0116, 1).expect("random use"),
                                CheckpointRandomUseProfile::new(0x0116, 2).expect("random use"),
                            ],
                        )
                        .expect("boundary"),
                    ],
                )
                .expect("operation profile"),
                RuntimeOperationProfile::new(
                    0x1500,
                    vec![
                        CheckpointBoundaryProfile::new(0, 0x1902, Vec::new())
                            .expect("boundary zero"),
                        CheckpointBoundaryProfile::new(1, 0x1903, Vec::new())
                            .expect("boundary one"),
                    ],
                )
                .expect("operation profile"),
            ],
        )
        .expect("runtime manifest")
    }

    fn checkpoint(runtime_manifest: &RuntimeBuildManifest) -> CheckpointManifest {
        CheckpointManifest::new(
            runtime_manifest.manifest_hash().expect("manifest hash"),
            runtime_manifest.suite_id,
            hash(6),
            hash(7),
            ParticipantIdentity::from_bytes([8; 64]),
            [9; 32],
            0x1205,
            0,
            vec![hash(10), hash(11)],
            vec![
                RandomCursor::new(0x0116, 1, hash(12), 13).expect("cursor"),
                RandomCursor::new(0x0116, 2, hash(14), 15).expect("cursor"),
            ],
            StreamDescriptor::new(17, vec![hash(16)], hash(17)).expect("descriptor"),
        )
        .expect("checkpoint")
    }

    fn display(value: &str) -> StabilizedDisplayText {
        StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).expect("display text")
    }

    fn mobile_runtime_profile() -> MobileRuntimeProfile {
        MobileRuntimeProfile::new(
            display("Phone x\u{0300}\u{0315}"),
            display("Revision 2"),
            8_589_934_592,
            MINIMUM_SUPPORTED_FREE_STORAGE_BYTE_LENGTH,
            display("Operating system 17.5"),
            display("Browser engine 126"),
            display("Browser 126.0.1"),
            hash(31),
            hash(32),
            RUNTIME_BUDGET_PROFILE_ONE,
        )
        .expect("mobile runtime profile")
    }

    #[test]
    fn mobile_runtime_profile_round_trips_and_identifier_binds_every_field() {
        assert_eq!(
            crate::foundation::FoundationSchemaIdentifier::MobileRuntimeProfile as u16,
            MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER
        );
        let profile = mobile_runtime_profile();
        let encoded = profile.encode().expect("profile encodes");
        assert_eq!(
            MobileRuntimeProfile::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("profile decodes"),
            profile
        );

        let identifier = profile
            .runtime_profile_identifier()
            .expect("identifier derives");
        let mut variants = Vec::new();
        let mut changed = profile.clone();
        changed.phone_model = display("Different phone");
        variants.push(changed);
        let mut changed = profile.clone();
        changed.hardware_revision = display("Revision 3");
        variants.push(changed);
        let mut changed = profile.clone();
        changed.installed_ram_bytes += 1;
        variants.push(changed);
        let mut changed = profile.clone();
        changed.minimum_free_storage_bytes += 1;
        variants.push(changed);
        let mut changed = profile.clone();
        changed.operating_system_build = display("Operating system 17.6");
        variants.push(changed);
        let mut changed = profile.clone();
        changed.browser_engine = display("Different browser engine");
        variants.push(changed);
        let mut changed = profile.clone();
        changed.browser_version = display("Browser 127.0.0");
        variants.push(changed);
        let mut changed = profile.clone();
        changed.bootstrap_hash = hash(33);
        variants.push(changed);
        let mut changed = profile;
        changed.runtime_build_manifest_hash = hash(34);
        variants.push(changed);

        for changed in variants {
            assert_ne!(
                changed
                    .runtime_profile_identifier()
                    .expect("changed identifier derives"),
                identifier
            );
        }
    }

    #[test]
    fn mobile_runtime_profile_rejects_invalid_fields_and_noncanonical_bytes() {
        let baseline = mobile_runtime_profile();
        let mut empty_text = baseline.clone();
        empty_text.browser_version = display("");
        assert_eq!(
            empty_text
                .encode()
                .expect_err("empty text refuses")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut low_storage = baseline.clone();
        low_storage.minimum_free_storage_bytes = MINIMUM_SUPPORTED_FREE_STORAGE_BYTE_LENGTH - 1;
        assert_eq!(
            low_storage
                .encode()
                .expect_err("low storage refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let mut unsupported_budget = baseline.clone();
        unsupported_budget.runtime_budget_profile = RUNTIME_BUDGET_PROFILE_ONE + 1;
        assert_eq!(
            unsupported_budget
                .encode()
                .expect_err("unsupported budget refuses")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        let encoded = baseline.encode().expect("baseline encodes");
        for truncated_length in [0, 1, 7, encoded.len() - 1] {
            assert!(
                MobileRuntimeProfile::decode(
                    &encoded[..truncated_length],
                    &CanonicalDecodeLimits::default()
                )
                .is_err()
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(
            MobileRuntimeProfile::decode(&trailing, &CanonicalDecodeLimits::default()).is_err()
        );

        let canonical_text = "x\u{0300}\u{0315}".as_bytes();
        let noncanonical_text = "x\u{0315}\u{0300}".as_bytes();
        assert_eq!(canonical_text.len(), noncanonical_text.len());
        assert!(
            StabilizedDisplayText::from_canonical_utf8(noncanonical_text).is_err(),
            "test mutation must be noncanonical"
        );
        let text_offset = encoded
            .windows(canonical_text.len())
            .position(|window| window == canonical_text)
            .expect("canonical text is present");
        let mut noncanonical = encoded;
        noncanonical[text_offset..text_offset + canonical_text.len()]
            .copy_from_slice(noncanonical_text);
        assert!(
            MobileRuntimeProfile::decode(&noncanonical, &CanonicalDecodeLimits::default()).is_err()
        );
    }

    #[test]
    fn runtime_manifest_and_checkpoint_round_trip_canonically() {
        let runtime_manifest = manifest();
        let runtime_bytes = runtime_manifest.encode().expect("manifest encodes");
        assert_eq!(
            RuntimeBuildManifest::decode(&runtime_bytes, &CanonicalDecodeLimits::default())
                .expect("manifest decodes"),
            runtime_manifest
        );

        let checkpoint = checkpoint(&runtime_manifest);
        let checkpoint_bytes = checkpoint.encode().expect("checkpoint encodes");
        let decoded =
            CheckpointManifest::decode(&checkpoint_bytes, &CanonicalDecodeLimits::default())
                .expect("checkpoint decodes");
        assert_eq!(decoded, checkpoint);
        assert_eq!(
            decoded
                .validate_runtime_profile(&runtime_manifest)
                .expect("runtime profile matches"),
            0x1901
        );
        assert_eq!(
            decoded.checkpoint_identifier().expect("identifier"),
            checkpoint.checkpoint_identifier().expect("identifier")
        );
        assert_eq!(
            decoded
                .checkpoint_chunk_identifier(3, hash(18))
                .expect("chunk identifier"),
            checkpoint
                .checkpoint_chunk_identifier(3, hash(18))
                .expect("chunk identifier")
        );
        assert_ne!(
            decoded
                .checkpoint_chunk_identifier(3, hash(18))
                .expect("chunk identifier"),
            decoded
                .checkpoint_chunk_identifier(4, hash(18))
                .expect("chunk identifier")
        );
        assert_ne!(
            decoded
                .checkpoint_chunk_identifier(3, hash(18))
                .expect("chunk identifier"),
            decoded
                .checkpoint_chunk_identifier(3, hash(19))
                .expect("chunk identifier")
        );
    }

    #[test]
    fn paths_assets_profiles_and_cursors_reject_ambiguous_ordering() {
        for path in [
            "suite.bin",
            "//suite.bin",
            "/",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/a%2fb",
            "/a?b",
            "/a#b",
            "/a\\b",
            "/a b",
        ] {
            assert!(validate_root_relative_path(path).is_err(), "{path}");
        }

        let mut duplicate_asset_role = manifest();
        duplicate_asset_role.ordered_assets.insert(
            1,
            asset(RuntimeAssetRole::ApplicationModule, "/application-2.js", 22),
        );
        assert!(duplicate_asset_role.encode().is_err());

        let mut disordered_assets = manifest();
        disordered_assets.ordered_assets.swap(0, 1);
        assert!(disordered_assets.encode().is_err());

        let mut colliding_path = manifest();
        colliding_path.ordered_suite_artifact_paths[0] = "/worker.js".to_string();
        assert!(colliding_path.encode().is_err());

        assert!(
            RuntimeOperationProfile::new(
                0x1500,
                vec![
                    CheckpointBoundaryProfile::new(1, 0x1901, Vec::new())
                        .expect("individual boundary")
                ],
            )
            .is_err()
        );

        let runtime_manifest = manifest();
        let mut disordered_checkpoint = checkpoint(&runtime_manifest);
        disordered_checkpoint.ordered_random_cursors.swap(0, 1);
        assert!(disordered_checkpoint.encode().is_err());
        let mut duplicate_checkpoint = checkpoint(&runtime_manifest);
        duplicate_checkpoint.ordered_random_cursors[1] =
            duplicate_checkpoint.ordered_random_cursors[0];
        assert!(duplicate_checkpoint.encode().is_err());
    }

    #[test]
    fn constructors_recursively_refuse_invalid_nested_runtime_values() {
        let invalid_random_use = CheckpointRandomUseProfile {
            family: 0,
            purpose: 1,
        };
        assert!(CheckpointBoundaryProfile::new(0, 0x1901, vec![invalid_random_use]).is_err());

        let invalid_boundary = CheckpointBoundaryProfile {
            safe_boundary_ordinal: 0,
            state_schema_identifier: 0,
            ordered_random_uses: Vec::new(),
        };
        assert!(RuntimeOperationProfile::new(0x1205, vec![invalid_boundary]).is_err());

        let invalid_operation_profile = RuntimeOperationProfile {
            operation_kind: 0,
            safe_boundaries: vec![
                CheckpointBoundaryProfile::new(0, 0x1901, Vec::new())
                    .expect("valid nested boundary"),
            ],
        };
        let mut runtime_manifest = manifest();
        runtime_manifest.operation_profiles = vec![invalid_operation_profile];
        assert!(
            RuntimeBuildManifest::new(
                runtime_manifest.protocol_version,
                runtime_manifest.release_identifier,
                runtime_manifest.suite_id,
                runtime_manifest.suite_record_path,
                runtime_manifest.ordered_suite_artifact_paths,
                runtime_manifest.ordered_assets,
                runtime_manifest.operation_profiles,
            )
            .is_err()
        );

        let runtime_manifest = manifest();
        let baseline_checkpoint = checkpoint(&runtime_manifest);
        let invalid_cursor = RandomCursor {
            family: 0,
            purpose: 1,
            derivation_context_hash: hash(12),
            next_counter: 13,
        };
        assert!(
            CheckpointManifest::new(
                baseline_checkpoint.runtime_build_manifest_hash,
                baseline_checkpoint.suite_id,
                baseline_checkpoint.ceremony_context_hash,
                baseline_checkpoint.action_context_hash,
                baseline_checkpoint.participant_id,
                baseline_checkpoint.attempt_identifier,
                baseline_checkpoint.operation_kind,
                baseline_checkpoint.safe_boundary_ordinal,
                baseline_checkpoint.ordered_source_digests,
                vec![invalid_cursor],
                baseline_checkpoint.state_stream_descriptor,
            )
            .is_err()
        );
    }

    #[test]
    fn checkpoint_profile_binding_rejects_wrong_build_suite_boundary_and_random_set() {
        let runtime_manifest = manifest();

        let mut wrong_build = checkpoint(&runtime_manifest);
        wrong_build.runtime_build_manifest_hash = hash(99);
        assert_eq!(
            wrong_build
                .validate_runtime_profile(&runtime_manifest)
                .expect_err("wrong build refuses")
                .refusal_reason,
            RefusalReason::WrongContext
        );

        let mut wrong_boundary = checkpoint(&runtime_manifest);
        wrong_boundary.safe_boundary_ordinal = 1;
        assert!(
            wrong_boundary
                .validate_runtime_profile(&runtime_manifest)
                .is_err()
        );

        let mut missing_cursor = checkpoint(&runtime_manifest);
        missing_cursor.ordered_random_cursors.pop();
        assert!(
            missing_cursor
                .validate_runtime_profile(&runtime_manifest)
                .is_err()
        );

        let mut extra_cursor = checkpoint(&runtime_manifest);
        extra_cursor
            .ordered_random_cursors
            .push(RandomCursor::new(0x0116, 3, hash(18), 0).expect("extra cursor"));
        assert!(
            extra_cursor
                .validate_runtime_profile(&runtime_manifest)
                .is_err()
        );
    }

    #[test]
    fn malformed_and_oversized_runtime_schema_bytes_refuse() {
        let runtime_manifest = manifest();
        let bytes = runtime_manifest.encode().expect("manifest encodes");
        for truncated_length in [0, 1, 7, bytes.len() - 1] {
            assert!(
                RuntimeBuildManifest::decode(
                    &bytes[..truncated_length],
                    &CanonicalDecodeLimits::default(),
                )
                .is_err()
            );
        }
        let oversized = vec![0; MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH + 1];
        assert_eq!(
            RuntimeBuildManifest::decode(&oversized, &CanonicalDecodeLimits::default())
                .expect_err("oversized manifest refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let checkpoint = checkpoint(&runtime_manifest);
        let mut checkpoint_bytes = checkpoint.encode().expect("checkpoint encodes");
        checkpoint_bytes.push(0);
        assert!(
            CheckpointManifest::decode(&checkpoint_bytes, &CanonicalDecodeLimits::default(),)
                .is_err()
        );
    }
}
