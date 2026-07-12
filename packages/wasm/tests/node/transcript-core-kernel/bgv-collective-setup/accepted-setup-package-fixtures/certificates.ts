import {
    setupTransportChunkSizeBytes,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { publicPrivateVssEnvelopeCommitmentSet } from './common-randomness.js';

import {
    binaryVssCoefficientCommitmentMaterialByteLength,
    vssCoefficientCommitmentMaterialTransportEncoding,
    type VssCoefficientCommitmentMaterialSet,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
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
    vssCoefficientCommitmentMaterial: VssCoefficientCommitmentMaterialSet,
): JsonRecord {
    const totalByteLength = binaryVssCoefficientCommitmentMaterialByteLength({
        participantCount: vssCoefficientCommitmentMaterial.participantCount,
        thresholdDegree: vssCoefficientCommitmentMaterial.thresholdDegree,
        rnsLimbCount: vssCoefficientCommitmentMaterial.rnsLimbCount,
        ringDegree: vssCoefficientCommitmentMaterial.ringDegree,
    });
    const chunkCount = Math.ceil(
        totalByteLength / setupTransportChunkSizeBytes,
    );
    const fullObjectHash = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'SetupTransportChunkManifestRoot',
            fixture: 'setup-transport-full-object-hash',
            totalByteLength,
        },
    });
    const chunkHashes = Array.from({ length: chunkCount }, (_, chunkIndex) =>
        kernel.deriveCanonicalObjectHash({
            value: {
                objectType: 'SetupTransportChunkManifestRoot',
                fixture: 'setup-transport-chunk-hash',
                chunkIndex,
            },
        }),
    );
    const chunkRoot = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'SetupTransportChunkManifest',
            chunkCount,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    });
    const certificate = {
        objectType: 'SetupTransportCertificate',
        transportSchemeId: 'sealed-lattice-setup-binary-chunked-transport',
        setupParametersHash: parameters.setupParametersHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount,
        totalByteLength,
        storageQuotaBytes: 2_147_483_648,
        largestSingleBufferBytes: 1_572_864,
        copyCountLimit: 2,
        streamVerificationOrder: 'ascending-chunk-index',
        resumePolicy: 'chunk-index-checkpointed-by-hash',
        lazyLoadingPolicy: 'root-addressed-large-object-loading',
        transportedObjects: [
            {
                objectType: 'SetupTransportedObject',
                objectName: 'vssCoefficientCommitmentMaterial',
                objectRole: 'public-vss-coefficient-commitment-material',
                objectRoot:
                    vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot,
                byteLength: totalByteLength,
                chunkStartIndex: 0,
                chunkCount,
                chunkRoot,
                chunkHashes,
                fullObjectHash,
                encoding: 'binary',
            },
        ],
    };

    return {
        ...certificate,
        setupTransportCertificateHash: kernel.deriveCanonicalObjectHash({
            value: certificate,
        }),
    };
}

export function acceptedSetupVssCoefficientCommitmentMaterialReference(
    vssCoefficientCommitmentMaterial: VssCoefficientCommitmentMaterialSet,
    setupTransportCertificate: JsonRecord,
): JsonRecord {
    const transportedObjects = setupTransportCertificate.transportedObjects;
    if (!Array.isArray(transportedObjects)) {
        throw new Error(
            'Accepted setup transport certificate must contain transported objects.',
        );
    }
    const transportedObject = transportedObjects.find(
        (candidate) =>
            (candidate as JsonRecord).objectName ===
            'vssCoefficientCommitmentMaterial',
    ) as JsonRecord | undefined;
    if (
        transportedObject?.objectRoot !==
        vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot
    ) {
        throw new Error(
            'Accepted setup transport certificate must bind the VSS coefficient commitment material root.',
        );
    }

    return {
        objectType: 'VssCoefficientCommitmentMaterialSet',
        ceremonyId: vssCoefficientCommitmentMaterial.ceremonyId,
        manifestHash: vssCoefficientCommitmentMaterial.manifestHash,
        rosterHash: vssCoefficientCommitmentMaterial.rosterHash,
        setupParametersHash:
            vssCoefficientCommitmentMaterial.setupParametersHash,
        setupEpoch: vssCoefficientCommitmentMaterial.setupEpoch,
        publicMatrixSeedHash:
            vssCoefficientCommitmentMaterial.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot,
        materialEncoding: vssCoefficientCommitmentMaterialTransportEncoding,
        participantCount: vssCoefficientCommitmentMaterial.participantCount,
        thresholdDegree: vssCoefficientCommitmentMaterial.thresholdDegree,
        rnsLimbCount: vssCoefficientCommitmentMaterial.rnsLimbCount,
        ringDegree: vssCoefficientCommitmentMaterial.ringDegree,
        materialRecordCount:
            vssCoefficientCommitmentMaterial.materialRecordCount,
        vssCoefficientCommitmentMaterialRoot:
            vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot,
        chunkCount: transportedObject.chunkCount,
        totalByteLength: transportedObject.byteLength,
        fullObjectHash: transportedObject.fullObjectHash,
        chunkRoot: transportedObject.chunkRoot,
        chunkHashes: transportedObject.chunkHashes,
    };
}
