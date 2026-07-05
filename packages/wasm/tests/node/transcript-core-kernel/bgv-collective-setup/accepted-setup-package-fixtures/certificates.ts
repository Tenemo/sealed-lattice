import {
    setupTransportChunkSizeBytes,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { publicPrivateVssEnvelopeCommitmentSet } from './common-randomness.js';

import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

function setupPackageHashInput(setupPackage: JsonRecord): JsonRecord {
    const hashInput: JsonRecord = { ...setupPackage };
    delete hashInput.setupPackageHash;
    hashInput.privateVssEnvelopeCommitments =
        publicPrivateVssEnvelopeCommitmentSet(
            hashInput.privateVssEnvelopeCommitments as JsonRecord,
        );

    return hashInput;
}

export function rebindCollectiveSetupPackageHash(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): void {
    delete setupPackage.setupPackageHash;
    setupPackage.setupPackageHash = kernel.deriveCanonicalObjectHash({
        value: setupPackageHashInput(setupPackage),
    });
}

// The commitment sets are embedded and proof-verified in-package, so the
// transport certificate carries no streamed objects.
export function acceptedSetupTransportCertificate(
    kernel: TranscriptCoreKernel,
    parameters: BgvCollectiveSetupParametersDescription,
): JsonRecord {
    const certificate = {
        objectType: 'SetupTransportCertificate',
        objectVersion: 1,
        transportSchemeId: 'sealed-lattice-setup-binary-chunked-transport-v1',
        setupParametersHash: parameters.setupParametersHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: 0,
        totalByteLength: 0,
        storageQuotaBytes: 2_147_483_648,
        largestSingleBufferBytes: 1_572_864,
        copyCountLimit: 2,
        streamVerificationOrder: 'ascending-chunk-index',
        resumePolicy: 'chunk-index-checkpointed-by-hash',
        lazyLoadingPolicy: 'root-addressed-large-object-loading',
        transportedObjects: [],
    };

    return {
        ...certificate,
        setupTransportCertificateHash: kernel.deriveCanonicalObjectHash({
            value: certificate,
        }),
    };
}
