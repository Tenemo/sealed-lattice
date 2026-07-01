import {
    setupTransportChunkCount,
    setupTransportChunkSizeBytes,
    setupTransportTotalByteLength,
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

export function acceptedSetupTransportCertificate(
    kernel: TranscriptCoreKernel,
    parameters: BgvCollectiveSetupParametersDescription,
    vssCoefficientCommitmentMaterial: JsonRecord,
): JsonRecord {
    const vssObjectFullObjectHash = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'SetupTransportChunkManifestRoot',
            fixture: 'setup-transport-full-object-hash',
            totalByteLength: setupTransportTotalByteLength,
        },
    });
    const chunkHashes = Array.from(
        { length: setupTransportChunkCount },
        (_unused, chunkIndex) =>
            kernel.deriveCanonicalObjectHash({
                value: {
                    objectType: 'SetupTransportChunkManifestRoot',
                    fixture: 'setup-transport-chunk-hash',
                    chunkIndex,
                },
            }),
    );
    const vssObjectChunkRoot = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'SetupTransportChunkManifestRoot',
            fixture: 'setup-transport-vss-object-chunk-root',
            totalByteLength: setupTransportTotalByteLength,
        },
    });
    const transportedVssObject = {
        objectType: 'SetupTransportedObject',
        objectVersion: 1,
        objectName: 'vssCoefficientCommitmentMaterial',
        objectRole: 'public-vss-coefficient-commitment-material',
        objectRoot: String(
            vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot,
        ),
        byteLength: setupTransportTotalByteLength,
        chunkStartIndex: 0,
        chunkCount: setupTransportChunkCount,
        chunkRoot: vssObjectChunkRoot,
        chunkHashes,
        fullObjectHash: vssObjectFullObjectHash,
        encoding: 'binary',
        loadingPolicy: 'stream-verified-before-object-use',
    };
    const certificate = {
        objectType: 'SetupTransportCertificate',
        objectVersion: 1,
        transportSchemeId: 'sealed-lattice-setup-binary-chunked-transport-v1',
        setupParametersHash: parameters.setupParametersHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: setupTransportChunkCount,
        totalByteLength: setupTransportTotalByteLength,
        storageQuotaBytes: 2_147_483_648,
        largestSingleBufferBytes: 1_572_864,
        copyCountLimit: 2,
        streamVerificationOrder: 'ascending-chunk-index',
        resumePolicy: 'chunk-index-checkpointed-by-hash',
        lazyLoadingPolicy: 'root-addressed-large-object-loading',
        transportedObjects: [transportedVssObject],
    };

    return {
        ...certificate,
        setupTransportCertificateHash: kernel.deriveCanonicalObjectHash({
            value: certificate,
        }),
    };
}
