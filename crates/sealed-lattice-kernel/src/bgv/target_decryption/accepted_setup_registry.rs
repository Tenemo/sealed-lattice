use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

use serde_json::Value;

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{SetupBinding, bindings::read_setup_binding};

struct VerifiedTargetReleaseSetupRegistry {
    bindings: BTreeMap<u32, SetupBinding>,
    next_handle: u32,
}

impl Default for VerifiedTargetReleaseSetupRegistry {
    fn default() -> Self {
        Self {
            bindings: BTreeMap::new(),
            next_handle: 1,
        }
    }
}

pub(crate) fn register_verified_target_release_setup(
    setup_package: &Value,
) -> CanonicalResult<u32> {
    let setup_binding = read_setup_binding(setup_package)?;
    let mut registry = verified_target_release_setup_registry()
        .lock()
        .map_err(|_| registry_unavailable_error())?;

    if let Some((handle, _)) = registry
        .bindings
        .iter()
        .find(|(_, existing)| existing.setup_package_hash == setup_binding.setup_package_hash)
    {
        return Ok(*handle);
    }

    let handle = registry.next_handle;
    registry.next_handle = handle.checked_add(1).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "verified target-release setup handle space is exhausted",
        )
    })?;
    registry.bindings.insert(handle, setup_binding);
    Ok(handle)
}

pub(super) fn verified_target_release_setup_binding(handle: u32) -> CanonicalResult<SetupBinding> {
    verified_target_release_setup_registry()
        .lock()
        .map_err(|_| registry_unavailable_error())?
        .bindings
        .get(&handle)
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target release requires a setup handle issued by successful accepted-setup verification",
            )
        })
}

fn verified_target_release_setup_registry() -> &'static Mutex<VerifiedTargetReleaseSetupRegistry> {
    static REGISTRY: OnceLock<Mutex<VerifiedTargetReleaseSetupRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(VerifiedTargetReleaseSetupRegistry::default()))
}

fn registry_unavailable_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "verified target-release setup registry is unavailable",
    )
}
