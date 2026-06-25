import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupTransportChunkSizeBytes,
    setupTransportCopyCountLimit,
    setupTransportedObjectLoadingPolicy,
    setupTransportLargestSingleBufferBytes,
    setupTransportLazyLoadingPolicy,
    setupTransportResumePolicy,
    setupTransportStorageQuotaBytes,
    setupTransportStreamOrder,
} from './constants.js';
import { assertProtocolHash, hashField } from './field-helpers.js';
import type {
    CollectiveBgvSetupParametersForCertificates,
    JsonRecord,
    SetupCertificateTransportedObjectInput,
    SetupCertificateTransportInput,
    SetupTransportCertificate,
    SetupTransportCertificateBody,
    SetupTransportedObjectRecord,
} from './types.js';

function setupTransportChunkManifestRoot(
    input: Readonly<{
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly fullObjectHash: ProtocolHash;
    }>,
): ProtocolHash {
    return deriveCanonicalObjectHash({
        objectType: 'SetupTransportChunkManifest',
        objectVersion: 1,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: input.chunkCount,
        totalByteLength: input.totalByteLength,
        chunkHashes: input.chunkHashes,
        fullObjectHash: input.fullObjectHash,
    });
}

function transportedObjectRecords(
    transportedObjectInputs: readonly SetupCertificateTransportedObjectInput[],
): readonly SetupTransportedObjectRecord[] {
    const transportedObjects: SetupTransportedObjectRecord[] = [];
    const objectRoots = new Set<string>();
    let chunkStartIndex = 0;

    transportedObjectInputs.forEach((input, objectIndex) => {
        const objectPath = `transport.transportedObjects.${String(objectIndex)}`;
        if (input.objectName.length === 0) {
            throw new TypeError(`${objectPath}.objectName must be non-empty.`);
        }
        if (input.objectRole.length === 0) {
            throw new TypeError(`${objectPath}.objectRole must be non-empty.`);
        }
        assertProtocolHash(input.objectRoot, `${objectPath}.objectRoot`);
        assertProtocolHash(
            input.fullObjectHash,
            `${objectPath}.fullObjectHash`,
        );
        assertProtocolHash(input.chunkRoot, `${objectPath}.chunkRoot`);
        if (!Number.isSafeInteger(input.byteLength) || input.byteLength <= 0) {
            throw new TypeError(
                `${objectPath}.byteLength must be a positive safe integer.`,
            );
        }
        const expectedChunkCount = Math.ceil(
            input.byteLength / setupTransportChunkSizeBytes,
        );
        if (input.chunkHashes.length !== expectedChunkCount) {
            throw new Error(
                `${objectPath}.chunkHashes length must match byteLength and chunkSizeBytes.`,
            );
        }
        input.chunkHashes.forEach((chunkHash, chunkIndex) => {
            assertProtocolHash(
                chunkHash,
                `${objectPath}.chunkHashes.${String(chunkIndex)}`,
            );
        });
        if (objectRoots.has(input.objectRoot)) {
            throw new Error(
                'setup transport certificate transported objects must not contain duplicate object roots.',
            );
        }
        objectRoots.add(input.objectRoot);
        transportedObjects.push({
            objectType: 'SetupTransportedObject',
            objectVersion: 1,
            objectName: input.objectName,
            objectRole: input.objectRole,
            objectRoot: input.objectRoot,
            byteLength: input.byteLength,
            chunkStartIndex,
            chunkCount: expectedChunkCount,
            chunkRoot: input.chunkRoot,
            chunkHashes: input.chunkHashes,
            fullObjectHash: input.fullObjectHash,
            encoding: 'binary',
            loadingPolicy: setupTransportedObjectLoadingPolicy,
        });
        chunkStartIndex += expectedChunkCount;
    });

    return transportedObjects;
}

const setupTransportCertificateBody = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
    vssCoefficientCommitmentMaterial: JsonRecord,
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificateBody => {
    const publicVssMaterialSizeParameters =
        setupParameters.publicVssCommitmentMaterialSize;
    const transportedObjects = transportedObjectRecords([
        {
            objectName: 'vssCoefficientCommitmentMaterial',
            objectRole: 'public-vss-coefficient-commitment-material',
            objectRoot: hashField(
                vssCoefficientCommitmentMaterial,
                'vssCoefficientCommitmentMaterialRoot',
                'vssCoefficientCommitmentMaterial',
            ),
            byteLength:
                publicVssMaterialSizeParameters.fullMaterialCoefficientBytes,
            fullObjectHash: transportInput.fullObjectHash,
            chunkRoot: setupTransportChunkManifestRoot({
                chunkCount: transportInput.chunkHashes.length,
                totalByteLength:
                    publicVssMaterialSizeParameters.fullMaterialCoefficientBytes,
                chunkHashes: transportInput.chunkHashes,
                fullObjectHash: transportInput.fullObjectHash,
            }),
            chunkHashes: transportInput.chunkHashes,
        },
        ...(transportInput.transportedObjects ?? []),
    ]);
    const totalByteLength = transportedObjects.reduce(
        (accumulatedLength, transportedObject) =>
            accumulatedLength + transportedObject.byteLength,
        0,
    );
    const chunkHashes = transportedObjects.flatMap(
        (transportedObject) => transportedObject.chunkHashes,
    );
    const chunkCount = chunkHashes.length;
    const fullObjectHash = deriveCanonicalObjectHash({
        objectType: 'SetupTransportFullObjectSet',
        objectVersion: 1,
        transportedObjects: transportedObjects.map((transportedObject) => ({
            objectName: transportedObject.objectName,
            objectRole: transportedObject.objectRole,
            objectRoot: transportedObject.objectRoot,
            byteLength: transportedObject.byteLength,
            chunkStartIndex: transportedObject.chunkStartIndex,
            chunkCount: transportedObject.chunkCount,
            chunkRoot: transportedObject.chunkRoot,
            fullObjectHash: transportedObject.fullObjectHash,
        })),
        totalByteLength,
        chunkCount,
        chunkHashes,
    });
    const chunkRoot = setupTransportChunkManifestRoot({
        chunkCount,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

    return {
        objectType: 'SetupTransportCertificate',
        objectVersion: 1,
        setupParametersHash: setupParameters.setupParametersHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount,
        totalByteLength,
        storageQuotaBytes: setupTransportStorageQuotaBytes,
        largestSingleBufferBytes: setupTransportLargestSingleBufferBytes,
        copyCountLimit: setupTransportCopyCountLimit,
        streamVerificationOrder: setupTransportStreamOrder,
        resumePolicy: setupTransportResumePolicy,
        lazyLoadingPolicy: setupTransportLazyLoadingPolicy,
        transportedObjects,
        chunkHashes,
        chunkRoot,
        fullObjectHash,
    };
};

export const createSetupTransportCertificate = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
    vssCoefficientCommitmentMaterial: JsonRecord,
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificate => {
    const certificateBody = setupTransportCertificateBody(
        setupParameters,
        vssCoefficientCommitmentMaterial,
        transportInput,
    );

    return {
        ...certificateBody,
        setupTransportCertificateHash:
            deriveCanonicalObjectHash(certificateBody),
    };
};
