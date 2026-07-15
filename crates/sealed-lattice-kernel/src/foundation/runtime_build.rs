use std::collections::BTreeSet;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    FoundationSchemaError, SchemaResult, read_ascii, read_hash, read_list_header,
    read_nested_tuple_list_with_budget, read_u16, read_u32, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, PrivateRandomnessDomain, RefusalReason, hash_foundation_tuple_512 as hash512,
};

pub const RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x1801;
pub const RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x1802;
pub const CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1806;
pub const CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1807;
pub const RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER: u16 = 0x1808;

pub const MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH: usize = 65_536;
pub const MAXIMUM_COPIED_EXECUTABLE_ASSET_BYTE_LENGTH: u64 = 1_572_864;
pub const MAXIMUM_RUNTIME_ASSET_BYTE_LENGTH: u64 = 8 * 1024 * 1024 - 4;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const REQUIRED_SUITE_ARTIFACT_PATH_COUNT: usize = 6;

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

fn validate_runtime_path(path: &str) -> SchemaResult<()> {
    if !path.is_ascii()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#', '\\', '%'])
        || path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "runtime path is not canonical root-relative ASCII",
        ));
    }
    Ok(())
}

fn encode_ascii_list(values: &[String]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .map(|value| CanonicalItem::ascii(value).map_err(Into::into))
        .collect::<SchemaResult<Vec<_>>>()?;
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Ascii,
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
                "runtime path-list offset overflows",
            )
        })?;
        if length_end > bytes.len() {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "runtime path-list length is truncated",
            ));
        }
        let byte_length =
            u32::from_le_bytes(bytes[offset..length_end].try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "runtime path-list length is malformed",
                )
            })?) as usize;
        let value_end = length_end.checked_add(byte_length).ok_or_else(|| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "runtime path-list value length overflows",
            )
        })?;
        if value_end > bytes.len() {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "runtime path-list value is truncated",
            ));
        }
        let value = std::str::from_utf8(&bytes[length_end..value_end]).map_err(|_| {
            schema_error(
                RefusalReason::MalformedEncoding,
                "runtime path-list value is not ASCII",
            )
        })?;
        if !value.is_ascii() {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "runtime path-list value is not ASCII",
            ));
        }
        values.push(value.to_owned());
        offset = value_end;
    }
    if offset != bytes.len() {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "runtime path-list contains trailing bytes",
        ));
    }
    Ok(values)
}

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

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
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
        validate_runtime_path(&canonical_path)?;
        if byte_length == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime asset must be nonempty",
            ));
        }
        if byte_length > MAXIMUM_RUNTIME_ASSET_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime asset exceeds the canonical hash-input ceiling",
            ));
        }
        if matches!(
            asset_role,
            RuntimeAssetRole::ApplicationModule | RuntimeAssetRole::WorkerModule
        ) && byte_length > MAXIMUM_COPIED_EXECUTABLE_ASSET_BYTE_LENGTH
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime executable asset exceeds the copied-buffer ceiling",
            ));
        }
        Ok(Self {
            asset_role,
            canonical_path,
            byte_length,
            asset_hash,
        })
    }

    pub fn derive_asset_hash(
        asset_role: RuntimeAssetRole,
        canonical_path: &str,
        exact_asset_bytes: &[u8],
    ) -> SchemaResult<Hash512> {
        validate_runtime_path(canonical_path)?;
        let byte_length = u64::try_from(exact_asset_bytes.len()).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime asset length does not fit u64",
            )
        })?;
        Ok(hash512(
            "sealed-lattice/runtime/asset/v1",
            &[
                CanonicalItem::unsigned16(asset_role.canonical_code()),
                CanonicalItem::ascii(canonical_path)?,
                CanonicalItem::unsigned64(byte_length),
                CanonicalItem::variable_bytes(exact_asset_bytes)?,
            ],
        )?)
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
            FOUNDATION_SCHEMA_VERSION,
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
                    RefusalReason::UnsupportedVersionOrSuite,
                    "runtime asset role is unassigned",
                )
            })?;
        Self::new(
            asset_role,
            read_ascii(&tuple.items[1])?.to_owned(),
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
        PrivateRandomnessDomain::from_assigned_pair(family, purpose)?;
        Ok(Self { family, purpose })
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.family, self.purpose)?;
        Ok(CanonicalTuple::new(
            CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
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
                "checkpoint state schema identifier must be nonzero",
            ));
        }
        let mut previous = None;
        for random_use in &ordered_random_uses {
            CheckpointRandomUseProfile::new(random_use.family, random_use.purpose)?;
            if previous.is_some_and(|value| value >= *random_use) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "checkpoint random uses must be strictly ordered and duplicate-free",
                ));
            }
            previous = Some(*random_use);
        }
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
        let random_uses = self
            .ordered_random_uses
            .iter()
            .map(|random_use| {
                random_use
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.safe_boundary_ordinal),
                CanonicalItem::unsigned16(self.state_schema_identifier),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &random_uses)?,
            ],
        ))
    }

    fn from_tuple(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER, 3)?;
        let random_uses = read_nested_tuple_list_with_budget(&tuple.items[2], limits, budget)?
            .iter()
            .map(CheckpointRandomUseProfile::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(
            read_u32(&tuple.items[0])?,
            read_u16(&tuple.items[1])?,
            random_uses,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple(&tuple, limits, &mut budget)
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
                "runtime operation profile must name an operation and at least one boundary",
            ));
        }
        for (expected_ordinal, boundary) in safe_boundaries.iter().enumerate() {
            CheckpointBoundaryProfile::new(
                boundary.safe_boundary_ordinal,
                boundary.state_schema_identifier,
                boundary.ordered_random_uses.clone(),
            )?;
            if usize::try_from(boundary.safe_boundary_ordinal).ok() != Some(expected_ordinal) {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "checkpoint boundaries must begin at zero and be contiguous",
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
        let boundaries = self
            .safe_boundaries
            .iter()
            .map(|boundary| {
                boundary
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.operation_kind),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &boundaries)?,
            ],
        ))
    }

    fn from_tuple(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        require_header(tuple, RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER, 2)?;
        let boundaries = read_nested_tuple_list_with_budget(&tuple.items[1], limits, budget)?
            .iter()
            .map(|boundary| CheckpointBoundaryProfile::from_tuple(boundary, limits, budget))
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(read_u16(&tuple.items[0])?, boundaries)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        Self::from_tuple(&tuple, limits, &mut budget)
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
    pub fn new(
        protocol_version: u16,
        release_identifier: String,
        suite_id: Hash512,
        suite_record_path: String,
        ordered_suite_artifact_paths: Vec<String>,
        ordered_assets: Vec<RuntimeAssetReference>,
        operation_profiles: Vec<RuntimeOperationProfile>,
    ) -> SchemaResult<Self> {
        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || release_identifier.is_empty()
            || release_identifier.len() > 256
        {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "runtime build release or protocol version is unsupported",
            ));
        }
        validate_runtime_path(&suite_record_path)?;
        if ordered_suite_artifact_paths.len() != REQUIRED_SUITE_ARTIFACT_PATH_COUNT {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime build must name exactly six suite artifacts",
            ));
        }

        let mut all_paths = BTreeSet::new();
        if !all_paths.insert(suite_record_path.as_str()) {
            return Err(schema_error(
                RefusalReason::DuplicateIdentity,
                "runtime build paths must be pairwise distinct",
            ));
        }
        for path in &ordered_suite_artifact_paths {
            validate_runtime_path(path)?;
            if !all_paths.insert(path.as_str()) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "runtime build paths must be pairwise distinct",
                ));
            }
        }

        let mut expected_asset_role = RuntimeAssetRole::ApplicationModule;
        let mut previous_asset: Option<(RuntimeAssetRole, &str)> = None;
        for asset in &ordered_assets {
            RuntimeAssetReference::new(
                asset.asset_role,
                asset.canonical_path.clone(),
                asset.byte_length,
                asset.asset_hash,
            )?;
            if asset.asset_role.canonical_code() < expected_asset_role.canonical_code()
                || previous_asset.is_some_and(|previous| {
                    previous.0 > asset.asset_role
                        || (previous.0 == asset.asset_role
                            && previous.1.as_bytes() >= asset.canonical_path.as_bytes())
                })
                || !all_paths.insert(asset.canonical_path.as_str())
            {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "runtime assets must be ordered and all runtime paths must be distinct",
                ));
            }
            if asset.asset_role == expected_asset_role {
                expected_asset_role = match expected_asset_role {
                    RuntimeAssetRole::ApplicationModule => RuntimeAssetRole::WorkerModule,
                    RuntimeAssetRole::WorkerModule => RuntimeAssetRole::WasmModule,
                    RuntimeAssetRole::WasmModule | RuntimeAssetRole::LocalAsset => {
                        RuntimeAssetRole::LocalAsset
                    }
                };
            }
            previous_asset = Some((asset.asset_role, &asset.canonical_path));
        }
        if expected_asset_role != RuntimeAssetRole::LocalAsset {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "runtime build must contain exactly one application, worker, and WASM asset",
            ));
        }

        let mut previous_operation_kind = None;
        for profile in &operation_profiles {
            RuntimeOperationProfile::new(profile.operation_kind, profile.safe_boundaries.clone())?;
            if previous_operation_kind.is_some_and(|kind| kind >= profile.operation_kind) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "runtime operation profiles must be strictly ordered and duplicate-free",
                ));
            }
            previous_operation_kind = Some(profile.operation_kind);
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
        let assets = self
            .ordered_assets
            .iter()
            .map(|asset| {
                asset
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let operation_profiles = self
            .operation_profiles
            .iter()
            .map(|profile| {
                profile
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.protocol_version),
                CanonicalItem::nonempty_ascii(&self.release_identifier)?,
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::ascii(&self.suite_record_path)?,
                encode_ascii_list(&self.ordered_suite_artifact_paths)?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &assets)?,
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &operation_profiles,
                )?,
            ],
        ))
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let bytes = self.canonical_tuple()?.encode()?;
        if bytes.len() > MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime build manifest exceeds its byte ceiling",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        if bytes.len() > MAXIMUM_RUNTIME_BUILD_MANIFEST_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "runtime build manifest exceeds its byte ceiling",
            ));
        }
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER, 7)?;
        let assets = read_nested_tuple_list_with_budget(&tuple.items[5], limits, &mut budget)?
            .iter()
            .map(RuntimeAssetReference::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        let operation_profiles =
            read_nested_tuple_list_with_budget(&tuple.items[6], limits, &mut budget)?
                .iter()
                .map(|profile| RuntimeOperationProfile::from_tuple(profile, limits, &mut budget))
                .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_ascii(&tuple.items[1])?.to_owned(),
            read_hash(&tuple.items[2])?,
            read_ascii(&tuple.items[3])?.to_owned(),
            read_ascii_list(&tuple.items[4])?,
            assets,
            operation_profiles,
        )
    }

    pub fn runtime_build_manifest_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/runtime/build-manifest/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; 64])
    }

    fn asset(role: RuntimeAssetRole, path: &str, byte: u8) -> RuntimeAssetReference {
        RuntimeAssetReference::new(role, path.to_owned(), 32, hash(byte)).expect("asset")
    }

    fn manifest() -> RuntimeBuildManifest {
        RuntimeBuildManifest::new(
            FOUNDATION_PROFILE.protocol_version,
            "release-1".to_owned(),
            hash(0x11),
            "/suite.canonical".to_owned(),
            (1..=6)
                .map(|index| format!("/artifact-{index}.canonical"))
                .collect(),
            vec![
                asset(RuntimeAssetRole::ApplicationModule, "/application.js", 0x21),
                asset(RuntimeAssetRole::WorkerModule, "/worker.js", 0x22),
                asset(RuntimeAssetRole::WasmModule, "/kernel.wasm", 0x23),
                asset(RuntimeAssetRole::LocalAsset, "/style.css", 0x24),
            ],
            vec![
                RuntimeOperationProfile::new(
                    0x1205,
                    vec![CheckpointBoundaryProfile::new(0, 0x2200, vec![]).expect("boundary")],
                )
                .expect("operation profile"),
            ],
        )
        .expect("manifest")
    }

    #[test]
    fn runtime_build_manifest_round_trips_and_hashes_every_byte() {
        let manifest = manifest();
        let encoded = manifest.encode().expect("encode");
        let decoded = RuntimeBuildManifest::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("decode");
        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded.runtime_build_manifest_hash().expect("decoded hash"),
            manifest
                .runtime_build_manifest_hash()
                .expect("manifest hash")
        );

        let mut changed = manifest;
        changed.release_identifier.push('a');
        assert_ne!(
            changed.runtime_build_manifest_hash().expect("changed hash"),
            decoded.runtime_build_manifest_hash().expect("decoded hash")
        );
    }

    #[test]
    fn runtime_build_manifest_rejects_path_asset_and_boundary_conflicts() {
        let mut duplicate_path = manifest();
        duplicate_path.ordered_suite_artifact_paths[5] = "/application.js".to_owned();
        assert!(duplicate_path.encode().is_err());

        let mut reordered_assets = manifest();
        reordered_assets.ordered_assets.swap(0, 1);
        assert!(reordered_assets.encode().is_err());

        let mut noncontiguous_boundary = manifest();
        noncontiguous_boundary.operation_profiles[0].safe_boundaries[0].safe_boundary_ordinal = 1;
        assert!(noncontiguous_boundary.encode().is_err());

        let mut bad_path = manifest();
        bad_path.suite_record_path = "/suite/../record".to_owned();
        assert!(bad_path.encode().is_err());

        let mut non_ascii_path = manifest();
        non_ascii_path.suite_record_path = "/suité.canonical".to_owned();
        assert!(non_ascii_path.encode().is_err());

        let encoded = manifest().encode().expect("manifest encodes");
        let release_byte_offset = encoded
            .windows("release-1".len())
            .position(|window| window == b"release-1")
            .expect("release bytes are present");
        let mut non_ascii_release = encoded.clone();
        non_ascii_release[release_byte_offset] = 0x80;
        assert!(
            RuntimeBuildManifest::decode(&non_ascii_release, &CanonicalDecodeLimits::default(),)
                .is_err()
        );

        let artifact_path_byte_offset = encoded
            .windows("/artifact-1.canonical".len())
            .position(|window| window == b"/artifact-1.canonical")
            .expect("artifact path bytes are present");
        let mut non_ascii_path_list = encoded;
        non_ascii_path_list[artifact_path_byte_offset + 1] = 0x80;
        assert!(
            RuntimeBuildManifest::decode(&non_ascii_path_list, &CanonicalDecodeLimits::default(),)
                .is_err()
        );
    }

    #[test]
    fn runtime_asset_hash_binds_role_path_length_and_bytes() {
        let bytes = b"runtime asset bytes";
        let expected = RuntimeAssetReference::derive_asset_hash(
            RuntimeAssetRole::WorkerModule,
            "/worker.js",
            bytes,
        )
        .expect("hash");
        assert_ne!(
            expected,
            RuntimeAssetReference::derive_asset_hash(
                RuntimeAssetRole::ApplicationModule,
                "/worker.js",
                bytes,
            )
            .expect("changed role hash")
        );
        assert_ne!(
            expected,
            RuntimeAssetReference::derive_asset_hash(
                RuntimeAssetRole::WorkerModule,
                "/worker-2.js",
                bytes,
            )
            .expect("changed path hash")
        );
    }
}
