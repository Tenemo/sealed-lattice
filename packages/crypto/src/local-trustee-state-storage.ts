// Local trustee setup-state and sealed-material storage. Split across the
// local-trustee-state-storage/ modules by concern (constants and types,
// validation, AES-GCM primitives, envelope validation, and the encrypt/decrypt
// operations); this barrel re-exports the public surface so import paths are
// unchanged.
export type {
    EncryptedLocalTrusteeSetupMaterial,
    EncryptedLocalTrusteeSetupState,
    LocalTrusteeSetupSealedMaterialDecryptionInput,
    LocalTrusteeSetupSealedMaterialDecryptionResult,
    LocalTrusteeSetupSealedMaterialEncryptionInput,
    LocalTrusteeSetupSealedMaterialEncryptionResult,
    LocalTrusteeSetupStateSealedMaterial,
    LocalTrusteeSetupStateSealedPayload,
    LocalTrusteeStateStorageDecryptionInput,
    LocalTrusteeStateStorageDecryptionResult,
    LocalTrusteeStateStorageEncryptionInput,
    LocalTrusteeStateStorageEncryptionResult,
} from './local-trustee-state-storage/constants-and-types.js';
export {
    decryptLocalTrusteeSetupSealedMaterial,
    decryptLocalTrusteeState,
    encryptLocalTrusteeSetupSealedMaterial,
    encryptLocalTrusteeState,
} from './local-trustee-state-storage/operations.js';
