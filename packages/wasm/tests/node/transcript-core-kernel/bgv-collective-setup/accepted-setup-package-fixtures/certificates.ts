import {
    cloneJsonRecord,
    firstRosterDecryptionThreshold,
    firstRosterParticipantCount,
    jsonRecord,
    protocolHashPattern,
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
    setupPackage.setupPackageHash = kernel.deriveProtocolHash({
        namespace: 'SetupPackageHash',
        value: setupPackageHashInput(setupPackage),
    });
}

export function acceptedSetupCommitmentSecurityCertificate(
    parameters: BgvCollectiveSetupParametersDescription,
): JsonRecord {
    const acceptedCertificateTemplates = jsonRecord(
        (parameters as unknown as JsonRecord).acceptedCertificateTemplates,
        'parameters.acceptedCertificateTemplates',
    );

    return cloneJsonRecord(
        jsonRecord(
            acceptedCertificateTemplates.setupCommitmentSecurityCertificate,
            'parameters.acceptedCertificateTemplates.setupCommitmentSecurityCertificate',
        ),
    );
}

export function acceptedSetupProofAccountingCertificate(
    parameters: BgvCollectiveSetupParametersDescription,
): JsonRecord {
    const acceptedCertificateTemplates = jsonRecord(
        (parameters as unknown as JsonRecord).acceptedCertificateTemplates,
        'parameters.acceptedCertificateTemplates',
    );

    return cloneJsonRecord(
        jsonRecord(
            acceptedCertificateTemplates.setupProofAccountingCertificate,
            'parameters.acceptedCertificateTemplates.setupProofAccountingCertificate',
        ),
    );
}

export function acceptedHeSecurityCertificate(
    setupParameters: BgvCollectiveSetupParametersDescription,
): JsonRecord {
    const acceptedCertificateTemplates = jsonRecord(
        (setupParameters as unknown as JsonRecord).acceptedCertificateTemplates,
        'setupParameters.acceptedCertificateTemplates',
    );

    return cloneJsonRecord(
        jsonRecord(
            acceptedCertificateTemplates.heSecurityCertificate,
            'setupParameters.acceptedCertificateTemplates.heSecurityCertificate',
        ),
    );
}

export function acceptedSetupTransportCertificate(
    kernel: TranscriptCoreKernel,
    parameters: BgvCollectiveSetupParametersDescription,
    vssCoefficientCommitmentMaterial: JsonRecord,
): JsonRecord {
    const vssObjectFullObjectHash = kernel.deriveProtocolHash({
        namespace: 'SetupTransportChunkManifestRoot',
        value: {
            fixture: 'setup-transport-full-object-hash',
            totalByteLength: setupTransportTotalByteLength,
        },
    });
    const chunkHashes = Array.from(
        { length: setupTransportChunkCount },
        (_unused, chunkIndex) =>
            kernel.deriveProtocolHash({
                namespace: 'SetupTransportChunkManifestRoot',
                value: {
                    fixture: 'setup-transport-chunk-hash',
                    chunkIndex,
                },
            }),
    );
    const vssObjectChunkRoot = kernel.deriveProtocolHash({
        namespace: 'SetupTransportChunkManifestRoot',
        value: {
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
    // The certificate-level hashes are the verifier-recomputed aggregates over
    // the transported-object set.
    const fullObjectHash = kernel.deriveProtocolHash({
        namespace: 'SetupTransportFullObjectSetHash',
        value: {
            objectType: 'SetupTransportFullObjectSet',
            objectVersion: 1,
            transportedObjects: [
                {
                    objectName: transportedVssObject.objectName,
                    objectRole: transportedVssObject.objectRole,
                    objectRoot: transportedVssObject.objectRoot,
                    byteLength: transportedVssObject.byteLength,
                    chunkStartIndex: transportedVssObject.chunkStartIndex,
                    chunkCount: transportedVssObject.chunkCount,
                    chunkRoot: transportedVssObject.chunkRoot,
                    fullObjectHash: transportedVssObject.fullObjectHash,
                },
            ],
            totalByteLength: setupTransportTotalByteLength,
            chunkCount: setupTransportChunkCount,
            chunkHashes,
        },
    });
    const chunkRoot = kernel.deriveProtocolHash({
        namespace: 'SetupTransportChunkManifestRoot',
        value: {
            objectType: 'SetupTransportChunkManifest',
            objectVersion: 1,
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: setupTransportChunkCount,
            totalByteLength: setupTransportTotalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    });
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
        chunkHashes,
        chunkRoot,
        fullObjectHash,
    };

    return {
        ...certificate,
        setupTransportCertificateHash: kernel.deriveProtocolHash({
            namespace: 'SetupTransportCertificateHash',
            value: certificate,
        }),
    };
}

function optionalHashFromRecord(
    record: JsonRecord,
    fieldName: string,
): string | null {
    const value = record[fieldName];
    if (value === undefined) {
        return null;
    }
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new Error(`${fieldName} must be a protocol hash.`);
    }

    return value;
}

function optionalNestedHashFromRecord(
    record: JsonRecord,
    objectFieldName: string,
    hashFieldName: string,
): string | null {
    const objectValue = record[objectFieldName];
    if (
        typeof objectValue !== 'object' ||
        objectValue === null ||
        Array.isArray(objectValue)
    ) {
        return null;
    }

    return optionalHashFromRecord(objectValue as JsonRecord, hashFieldName);
}

export function acceptedActiveStaticSetupTheoremCertificate(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): JsonRecord {
    const setupContext = setupPackage.setupContext as JsonRecord;
    const certificate = {
        objectType: 'ActiveStaticSetupTheoremCertificate',
        objectVersion: 1,
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupParametersHash: setupContext.setupParametersHash,
        setupEpoch: setupContext.setupEpoch,
        adversaryModel: {
            secretConfidentialityCorruptTrusteeBound:
                firstRosterDecryptionThreshold - 1,
            fullRosterSetupCompletionRequired: true,
        },
        livenessModel: {
            model: 'secure-with-abort',
            setupCompletionQuorum: firstRosterParticipantCount,
            participantCount: firstRosterParticipantCount,
        },
        dependencyHashes: {
            setupCommitmentSecurityCertificateHash:
                setupPackage.setupCommitmentSecurityCertificateHash,
            setupTransportCertificateHash:
                setupPackage.setupTransportCertificateHash,
            setupProofAccountingCertificateHash:
                setupPackage.setupProofAccountingCertificateHash,
            heSecurityCertificateHash: setupPackage.heSecurityCertificateHash,
            setupKeyCorrectnessCertificateHash: optionalHashFromRecord(
                setupPackage,
                'setupKeyCorrectnessCertificateHash',
            ),
        },
        terminalRoots: {
            thresholdShareCommitmentRoot: optionalHashFromRecord(
                setupPackage,
                'thresholdShareCommitmentRoot',
            ),
            sameSecretProofSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'sameSecretProofs',
                'sameSecretProofSetRoot',
            ),
            publicKeyShareMaterialSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'publicKeyShareMaterial',
                'publicKeyShareMaterialSetRoot',
            ),
            publicKeyShareSuccinctProofSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'publicKeyShareSuccinctProofs',
                'publicKeyShareSuccinctProofSetRoot',
            ),
            collectivePublicKeyRoot: optionalNestedHashFromRecord(
                setupPackage,
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ),
            evaluatorKeyScheduleRoot: optionalNestedHashFromRecord(
                setupPackage,
                'evaluatorKeySchedule',
                'evaluatorKeyScheduleRoot',
            ),
            evaluationKeySetHash: optionalNestedHashFromRecord(
                setupPackage,
                'evaluationKeys',
                'evaluationKeySetHash',
            ),
            publicEvaluationKeyMaterialRoot: optionalNestedHashFromRecord(
                setupPackage,
                'evaluationKeys',
                'publicEvaluationKeyMaterialRoot',
            ),
        },
    };

    return {
        ...certificate,
        activeStaticSetupTheoremCertificateHash: kernel.deriveProtocolHash({
            namespace: 'ActiveStaticSetupTheoremCertificateHash',
            value: certificate,
        }),
    };
}
