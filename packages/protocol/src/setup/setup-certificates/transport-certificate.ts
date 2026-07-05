import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

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
import { assertProtocolHash } from './field-helpers.js';
import type {
    CollectiveBgvSetupParametersForCertificates,
    SetupCertificateTransportedObjectInput,
    SetupCertificateTransportInput,
    SetupTransportCertificate,
    SetupTransportCertificateBody,
    SetupTransportedObjectRecord,
} from './types.js';

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
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificateBody => {
    // The transport certificate binds the companion transported objects (public-key
    // share, proof, and evaluation-key materials). The VSS coefficient commitments
    // are carried in the setup package itself, not as a separate transported object.
    const transportedObjects = transportedObjectRecords([
        ...(transportInput.transportedObjects ?? []),
    ]);
    const totalByteLength = transportedObjects.reduce(
        (accumulatedLength, transportedObject) =>
            accumulatedLength + transportedObject.byteLength,
        0,
    );
    const chunkCount = transportedObjects.reduce(
        (accumulatedChunkCount, transportedObject) =>
            accumulatedChunkCount + transportedObject.chunkCount,
        0,
    );

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
    };
};

export const createSetupTransportCertificate = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificate => {
    const certificateBody = setupTransportCertificateBody(
        setupParameters,
        transportInput,
    );

    return {
        ...certificateBody,
        setupTransportCertificateHash:
            deriveCanonicalObjectHash(certificateBody),
    };
};
