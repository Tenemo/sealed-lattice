import type { TranscriptCoreKernelCommandRuntime } from '../transcript-core-bridge/kernel-runtime.js';

export type CommonProofGenerationCheckpoint = Readonly<{
    /** Fixed canonical Rust-owned state. It contains no secret coin bytes. */
    canonicalStateBytes: Uint8Array<ArrayBuffer>;
    /** Canonical private-coin and transcript cursor manifest from Rust. */
    generationCursorManifestBytes: Uint8Array<ArrayBuffer>;
    /** Shared reset-safe attempt identity embedded once, even at zero cursors. */
    privateRandomnessStreamAttemptIdentifier: Uint8Array<ArrayBuffer>;
    safeBoundaryOrdinal: number;
    /** Stable authenticated binding for this exact generation attempt. */
    stableAttemptBindingHash: Uint8Array<ArrayBuffer>;
}>;

export type CommonProofApplicationFreshnessCoordinate = Readonly<{
    authenticatedHeadDigest: Uint8Array;
    freshnessSequence: bigint;
    storageInstanceIdentity: Uint8Array;
}>;

export type CommonProofApplicationStorageRootAccess = Readonly<{
    context: TranscriptCoreKernelCommandRuntime;
    storageRootCapability: Uint8Array;
    storageRootHandle: number;
}>;
