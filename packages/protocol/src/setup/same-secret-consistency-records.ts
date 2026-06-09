import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertSetupProofChallenge,
    optionalSetupProofTboxZ34Metadata,
    transportSetupProofMaterials,
    type SetupProofChallenge,
    type SetupProofTboxZ34Metadata,
    type TransportedSetupProofMaterialSet,
} from './setup-proof-material-transport.js';
import {
    setupCommitmentProfileId,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
} from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const setupProofProfileId = 'SealedLattice-LNP-SetupProof-v1';
export const sameSecretProofFamily = 'same-secret-consistency';
const sameSecretProofBytesHashDomain =
    'sealed-lattice/setup/same-secret/lnp-proof-bytes-v1';
export const sameSecretProofVerificationStatus =
    'lnp-proof-verification-pending';
export const sameSecretLnpProofVerificationStatus =
    'lnp-same-secret-relation-verified-with-accepted-setup-proof-accounting';
export const sameSecretLnpProofModelStatus =
    'pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, centered signed 80-bit same-secret masks and responses, same-secret BDLOP commitment relation algebra, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing setup proof acceptance';
export const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
export const sameSecretBoundProofFamilies = [
    'vss-constant-relation',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;

export const sameSecretGenericKeySwitchBindingPolicy =
    'absent-unless-frozen-schedule-requires-proof-family';
export const sameSecretTargetDecryptionBindingPolicy =
    'later-target-share-must-bind-threshold-share-commitment';

export type SameSecretConstantCoefficientCommitmentRoot = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly commitmentRoot: ProtocolHash;
}>;

export type TrusteeSecretCommitmentRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
}>;

export type SameSecretConsistencyStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofVerificationStatus: typeof sameSecretProofVerificationStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly vssSourceTrusteeCommitmentRoot: ProtocolHash;
        readonly constantCoefficientCommitmentRoots: readonly SameSecretConstantCoefficientCommitmentRoot[];
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly boundSecretDependentProofFamilies: typeof sameSecretBoundProofFamilies;
        readonly genericKeySwitchBindingPolicy: typeof sameSecretGenericKeySwitchBindingPolicy;
        readonly targetDecryptionBindingPolicy: typeof sameSecretTargetDecryptionBindingPolicy;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly sameSecretRelation: typeof sameSecretRelation;
        readonly sameSecretStatementRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatementSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofVerificationStatus: typeof sameSecretProofVerificationStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoots: readonly TrusteeSecretCommitmentRootReference[];
        readonly statementRecords: readonly SameSecretConsistencyStatementRecord[];
        readonly sameSecretConsistencyRoot: ProtocolHash;
    }
>;

export type SameSecretEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type SameSecretTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type SameSecretProofByteMaterial =
    | SameSecretEmbeddedProofBytes
    | SameSecretTransportedProofBytes;

export type SameSecretProofMaterial = Readonly<
    SameSecretProofByteMaterial & {
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofVerificationStatus: typeof sameSecretLnpProofVerificationStatus;
        readonly proofModelStatus: typeof sameSecretLnpProofModelStatus;
        readonly sameSecretTboxParameterProfileHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly relationCommitmentHash: ProtocolHash;
        readonly tboxCommitmentPrefixHash: ProtocolHash;
        readonly challenge: SetupProofChallenge;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
    } & Partial<SetupProofTboxZ34Metadata>
>;

export type SameSecretProofRecord = Readonly<
    JsonRecord &
        SameSecretProofByteMaterial & {
            readonly objectType: 'SameSecretProof';
            readonly objectVersion: 1;
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly commitmentProfileId: typeof setupCommitmentProfileId;
            readonly setupProofProfileId: typeof setupProofProfileId;
            readonly proofFamily: typeof sameSecretProofFamily;
            readonly proofVerificationStatus: typeof sameSecretLnpProofVerificationStatus;
            readonly proofModelStatus: typeof sameSecretLnpProofModelStatus;
            readonly sameSecretTboxParameterProfileHash: ProtocolHash;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly setupProofBinding: JsonRecord;
            readonly statementHash: ProtocolHash;
            readonly relationCommitmentHash: ProtocolHash;
            readonly tboxCommitmentPrefixHash: ProtocolHash;
            readonly challenge: SetupProofChallenge;
            readonly proofSizeBytes: number;
            readonly proofBytesHash: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
        } & Partial<SetupProofTboxZ34Metadata>
>;

export type SameSecretProofRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sameSecretProofRoot: ProtocolHash;
}>;

export type SameSecretProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofVerificationStatus: typeof sameSecretLnpProofVerificationStatus;
        readonly proofModelStatus: typeof sameSecretLnpProofModelStatus;
        readonly sameSecretTboxParameterProfileHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
        readonly setupProofBinding: JsonRecord;
        readonly sameSecretProofRoots: readonly SameSecretProofRootReference[];
        readonly proofRecords: readonly SameSecretProofRecord[];
        readonly sameSecretProofSetRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly thresholdDegree: number;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
};

export type SameSecretProofSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly vssCoefficientCommitmentMaterial: SetupPackageVssCoefficientCommitmentMaterialSet;
    readonly setupProofBinding: JsonRecord;
    readonly sameSecretTboxParameterProfileHash: ProtocolHash;
    readonly proofMaterials: readonly SameSecretProofMaterial[];
};

export type TransportedSameSecretProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedSameSecretProofMaterialSet';
        readonly proofFamily: typeof sameSecretProofFamily;
    }
>;

export type BinaryChunkedSameSecretProofMaterialTransport = Readonly<{
    readonly proofMaterials: readonly SameSecretProofMaterial[];
    readonly transportedSameSecretProofMaterial: TransportedSameSecretProofMaterialSet;
}>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})*$/u;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertLowercaseHexBytes = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const validateInput = (input: SameSecretConsistencyStatementSetInput): void => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
    );
    assertProtocolHash(
        input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        'vssCoefficientCommitments.vssCoefficientCommitmentRoot',
    );
};

const assertSetupProofBinding = (
    setupProofBinding: JsonRecord,
    fieldName: string,
): void => {
    if (
        setupProofBinding === null ||
        typeof setupProofBinding !== 'object' ||
        Array.isArray(setupProofBinding)
    ) {
        throw new TypeError(`${fieldName} must be an object.`);
    }
};

const validateSameSecretProofMaterial = (
    material: SameSecretProofMaterial,
    expectedTboxParameterProfileHash: ProtocolHash,
    fieldName: string,
): void => {
    if (material.setupProofProfileId !== setupProofProfileId) {
        throw new Error(
            `${fieldName}.setupProofProfileId must match setup proof profile.`,
        );
    }
    if (material.proofFamily !== sameSecretProofFamily) {
        throw new Error(
            `${fieldName}.proofFamily must be same-secret consistency.`,
        );
    }
    if (
        material.proofVerificationStatus !==
        sameSecretLnpProofVerificationStatus
    ) {
        throw new Error(
            `${fieldName}.proofVerificationStatus must be the same-secret LNP verification status.`,
        );
    }
    if (material.proofModelStatus !== sameSecretLnpProofModelStatus) {
        throw new Error(
            `${fieldName}.proofModelStatus must match same-secret LNP proof model.`,
        );
    }
    if (
        material.sameSecretTboxParameterProfileHash !==
        expectedTboxParameterProfileHash
    ) {
        throw new Error(
            `${fieldName}.sameSecretTboxParameterProfileHash must match the setup proof profile.`,
        );
    }
    assertProtocolHash(
        material.sameSecretTboxParameterProfileHash,
        `${fieldName}.sameSecretTboxParameterProfileHash`,
    );
    assertNonEmptyString(
        material.trusteeIdentity,
        `${fieldName}.trusteeIdentity`,
    );
    assertNonNegativeSafeInteger(
        material.trusteeRosterPosition,
        `${fieldName}.trusteeRosterPosition`,
    );
    assertProtocolHash(material.statementHash, `${fieldName}.statementHash`);
    assertProtocolHash(
        material.relationCommitmentHash,
        `${fieldName}.relationCommitmentHash`,
    );
    assertProtocolHash(
        material.tboxCommitmentPrefixHash,
        `${fieldName}.tboxCommitmentPrefixHash`,
    );
    assertSetupProofChallenge(material.challenge, `${fieldName}.challenge`);
    optionalSetupProofTboxZ34Metadata(material, fieldName);
    assertPositiveSafeInteger(
        material.proofSizeBytes,
        `${fieldName}.proofSizeBytes`,
    );
    assertProtocolHash(material.proofBytesHash, `${fieldName}.proofBytesHash`);
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(`${fieldName}.proofBytesHex must be a string.`);
        }
        assertLowercaseHexBytes(proofBytesHex, `${fieldName}.proofBytesHex`);
        if (proofBytesHex.length / 2 !== material.proofSizeBytes) {
            throw new Error(
                `${fieldName}.proofBytesHex must match proofSizeBytes.`,
            );
        }
    } else {
        const transportedMaterial = material as SameSecretTransportedProofBytes;
        if (
            transportedMaterial.proofBytesEncoding !==
            'binary-chunked-proof-bytes'
        ) {
            throw new TypeError(
                `${fieldName}.proofBytesEncoding must be binary-chunked-proof-bytes.`,
            );
        }
        assertProtocolHash(
            transportedMaterial.proofMaterialRoot,
            `${fieldName}.proofMaterialRoot`,
        );
        assertPositiveSafeInteger(
            transportedMaterial.proofChunkSizeBytes,
            `${fieldName}.proofChunkSizeBytes`,
        );
        assertPositiveSafeInteger(
            transportedMaterial.proofChunkCount,
            `${fieldName}.proofChunkCount`,
        );
        assertPositiveSafeInteger(
            transportedMaterial.proofTotalByteLength,
            `${fieldName}.proofTotalByteLength`,
        );
        if (
            transportedMaterial.proofTotalByteLength !== material.proofSizeBytes
        ) {
            throw new Error(
                `${fieldName}.proofTotalByteLength must match proofSizeBytes.`,
            );
        }
        assertProtocolHash(
            transportedMaterial.proofFullObjectHash,
            `${fieldName}.proofFullObjectHash`,
        );
        assertProtocolHash(
            transportedMaterial.proofChunkRoot,
            `${fieldName}.proofChunkRoot`,
        );
        transportedMaterial.proofChunkHashes.forEach(
            (proofChunkHash, chunkIndex) =>
                assertProtocolHash(
                    proofChunkHash,
                    `${fieldName}.proofChunkHashes.${String(chunkIndex)}`,
                ),
        );
        if (
            transportedMaterial.proofChunkHashes.length !==
            transportedMaterial.proofChunkCount
        ) {
            throw new Error(
                `${fieldName}.proofChunkHashes must match proofChunkCount.`,
            );
        }
    }
};

const validateProofSetInput = (input: SameSecretProofSetInput): void => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertProtocolHash(
        input.sameSecretConsistency.sameSecretConsistencyRoot,
        'sameSecretConsistency.sameSecretConsistencyRoot',
    );
    assertProtocolHash(
        input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        'sameSecretConsistency.sameSecretProofFamilyBindingRoot',
    );
    assertProtocolHash(
        input.vssCoefficientCommitmentMaterial
            .vssCoefficientCommitmentMaterialRoot,
        'vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot',
    );
    if (
        input.vssCoefficientCommitmentMaterial.participantCount !==
            input.participantCount ||
        input.vssCoefficientCommitmentMaterial.rnsLimbCount !==
            input.qSharePrimes.length ||
        input.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot !==
            input.sameSecretConsistency.vssCoefficientCommitmentRoot
    ) {
        throw new Error(
            'vssCoefficientCommitmentMaterial must match the same-secret statement set.',
        );
    }
    assertSetupProofBinding(input.setupProofBinding, 'setupProofBinding');
    assertProtocolHash(
        input.sameSecretTboxParameterProfileHash,
        'sameSecretTboxParameterProfileHash',
    );
};

const sortedSourceTrusteeRecords = (
    input: SameSecretConsistencyStatementSetInput,
): VssSourceTrusteeCoefficientCommitmentRecord[] => {
    const sourceTrusteeRecords = [
        ...input.vssCoefficientCommitments.sourceTrusteeRecords,
    ].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );
    if (sourceTrusteeRecords.length !== input.participantCount) {
        throw new Error(
            'vssCoefficientCommitments.sourceTrusteeRecords must cover every participant.',
        );
    }
    sourceTrusteeRecords.forEach(
        (sourceTrusteeRecord, expectedRosterPosition) => {
            assertNonEmptyString(
                sourceTrusteeRecord.sourceTrusteeIdentity,
                'sourceTrusteeIdentity',
            );
            assertNonNegativeSafeInteger(
                sourceTrusteeRecord.sourceTrusteeRosterPosition,
                'sourceTrusteeRosterPosition',
            );
            if (
                sourceTrusteeRecord.sourceTrusteeRosterPosition !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'vssCoefficientCommitments.sourceTrusteeRecords roster positions must be contiguous from zero.',
                );
            }
            assertContextMatches(
                input.setupContext,
                sourceTrusteeRecord,
                'sourceTrusteeRecord',
            );
            assertProtocolHash(
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
                'sourceTrusteeRecord.sourceTrusteeCommitmentRoot',
            );
        },
    );

    return sourceTrusteeRecords;
};

const constantCoefficientCommitmentRoots = (
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    qSharePrimes: readonly number[],
): SameSecretConstantCoefficientCommitmentRoot[] =>
    qSharePrimes.map((rnsPrime, rnsLimbIndex) => {
        const coefficientRecord =
            sourceTrusteeRecord.coefficientCommitments.find(
                (candidateRecord: VssCoefficientCommitmentRecord) =>
                    candidateRecord.rnsLimbIndex === rnsLimbIndex &&
                    candidateRecord.rnsPrime === rnsPrime &&
                    candidateRecord.shamirCoefficientIndex === 0,
            );
        if (coefficientRecord === undefined) {
            throw new Error(
                'sourceTrusteeRecord.coefficientCommitments must include every constant coefficient commitment.',
            );
        }
        assertProtocolHash(
            coefficientRecord.commitmentRoot,
            'coefficientRecord.commitmentRoot',
        );

        return {
            rnsLimbIndex,
            rnsPrime,
            shamirCoefficientIndex: 0,
            commitmentRoot: coefficientRecord.commitmentRoot,
        };
    });

const trusteeSecretCommitmentPayload = (
    setupContext: CollectiveBgvSetupContext,
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): JsonRecord => ({
    objectType: 'TrusteeSecretCommitment',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    commitmentProfileId: setupCommitmentProfileId,
    setupProofProfileId,
    ...contextFields(setupContext),
    trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
    trusteeRosterPosition: sourceTrusteeRecord.sourceTrusteeRosterPosition,
    vssSourceTrusteeCommitmentRoot:
        sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
    secretCommitmentSource: 'vss-constant-coefficient-commitments',
    sameSecretRelation,
    constantCoefficientCommitmentRoots: constantRoots,
});

const sameSecretProofFamilyBindingPayload = (): JsonRecord => ({
    objectType: 'SameSecretProofFamilyBinding',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    proofFamily: sameSecretProofFamily,
    sameSecretRelation,
    boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
    genericKeySwitchBindingPolicy: sameSecretGenericKeySwitchBindingPolicy,
    targetDecryptionBindingPolicy: sameSecretTargetDecryptionBindingPolicy,
});

const sameSecretProofFamilyBindingRoot = (): ProtocolHash =>
    deriveProtocolHash(
        'SameSecretProofFamilyBindingRoot',
        sameSecretProofFamilyBindingPayload(),
    );

const createStatementRecord = (
    setupContext: CollectiveBgvSetupContext,
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): {
    readonly statementRecord: SameSecretConsistencyStatementRecord;
    readonly trusteeSecretCommitmentRootReference: TrusteeSecretCommitmentRootReference;
} => {
    const trusteeSecretCommitmentRoot = deriveProtocolHash(
        'TrusteeSecretCommitmentRoot',
        trusteeSecretCommitmentPayload(
            setupContext,
            sourceTrusteeRecord,
            constantRoots,
        ),
    );
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementRecordWithoutRoot = {
        objectType: 'SameSecretConsistencyStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofVerificationStatus: sameSecretProofVerificationStatus,
        ...contextFields(setupContext),
        trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
        trusteeRosterPosition: sourceTrusteeRecord.sourceTrusteeRosterPosition,
        vssSourceTrusteeCommitmentRoot:
            sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
        constantCoefficientCommitmentRoots: constantRoots,
        trusteeSecretCommitmentRoot,
        boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
        genericKeySwitchBindingPolicy: sameSecretGenericKeySwitchBindingPolicy,
        targetDecryptionBindingPolicy: sameSecretTargetDecryptionBindingPolicy,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        sameSecretRelation,
    } as const satisfies Omit<
        SameSecretConsistencyStatementRecord,
        'sameSecretStatementRoot'
    >;
    const statementRecord = {
        ...statementRecordWithoutRoot,
        sameSecretStatementRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            statementRecordWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementRecord;

    return {
        statementRecord,
        trusteeSecretCommitmentRootReference: {
            trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
            trusteeRosterPosition:
                sourceTrusteeRecord.sourceTrusteeRosterPosition,
            trusteeSecretCommitmentRoot,
        },
    };
};

export const createSameSecretConsistencyStatementSet = (
    input: SameSecretConsistencyStatementSetInput,
): SameSecretConsistencyStatementSet => {
    validateInput(input);
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementOutputs = sortedSourceTrusteeRecords(input).map(
        (sourceTrusteeRecord) =>
            createStatementRecord(
                input.setupContext,
                sourceTrusteeRecord,
                constantCoefficientCommitmentRoots(
                    sourceTrusteeRecord,
                    input.qSharePrimes,
                ),
            ),
    );
    const statementSetWithoutRoot = {
        objectType: 'SameSecretConsistencyStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofVerificationStatus: sameSecretProofVerificationStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        thresholdDegree: input.thresholdDegree,
        vssCoefficientCommitmentRoot:
            input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        trusteeSecretCommitmentRoots: statementOutputs.map(
            (output) => output.trusteeSecretCommitmentRootReference,
        ),
        statementRecords: statementOutputs.map(
            (output) => output.statementRecord,
        ),
    } as const satisfies Omit<
        SameSecretConsistencyStatementSet,
        'sameSecretConsistencyRoot'
    >;

    return {
        ...statementSetWithoutRoot,
        sameSecretConsistencyRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            statementSetWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementSet;
};

const sortedStatementRecordsForProofs = (
    input: Pick<
        SameSecretProofSetInput,
        'participantCount' | 'sameSecretConsistency'
    >,
): SameSecretConsistencyStatementRecord[] => {
    const statementRecords = [
        ...input.sameSecretConsistency.statementRecords,
    ].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (statementRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretConsistency.statementRecords must contain one statement per participant.',
        );
    }
    statementRecords.forEach((statementRecord, expectedRosterPosition) => {
        assertNonEmptyString(
            statementRecord.trusteeIdentity,
            'sameSecretConsistency.statementRecords.trusteeIdentity',
        );
        if (statementRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretConsistency.statementRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            statementRecord.sameSecretStatementRoot,
            'sameSecretConsistency.statementRecords.sameSecretStatementRoot',
        );
        assertProtocolHash(
            statementRecord.trusteeSecretCommitmentRoot,
            'sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot',
        );
        assertProtocolHash(
            statementRecord.sameSecretProofFamilyBindingRoot,
            'sameSecretConsistency.statementRecords.sameSecretProofFamilyBindingRoot',
        );
    });

    return statementRecords;
};

const sortedSameSecretProofMaterials = (
    input: Pick<
        SameSecretProofSetInput,
        | 'participantCount'
        | 'proofMaterials'
        | 'sameSecretTboxParameterProfileHash'
    >,
): SameSecretProofMaterial[] => {
    const proofMaterials = [...input.proofMaterials].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (proofMaterials.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofMaterials must contain one proof per participant.',
        );
    }
    proofMaterials.forEach((proofMaterial, expectedRosterPosition) => {
        validateSameSecretProofMaterial(
            proofMaterial,
            input.sameSecretTboxParameterProfileHash,
            `sameSecretProofMaterials.${String(expectedRosterPosition)}`,
        );
        if (proofMaterial.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofMaterials roster positions must be contiguous from zero.',
            );
        }
    });

    return proofMaterials;
};

const sameSecretProofByteMaterial = (
    material: SameSecretProofMaterial,
): SameSecretProofByteMaterial => {
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(
                'sameSecretProofMaterial.proofBytesHex must be a string.',
            );
        }
        return {
            proofBytesHex,
        };
    }

    const transportedMaterial = material as SameSecretTransportedProofBytes;

    return {
        proofBytesEncoding: transportedMaterial.proofBytesEncoding,
        proofMaterialRoot: transportedMaterial.proofMaterialRoot,
        proofChunkSizeBytes: transportedMaterial.proofChunkSizeBytes,
        proofChunkCount: transportedMaterial.proofChunkCount,
        proofTotalByteLength: transportedMaterial.proofTotalByteLength,
        proofFullObjectHash: transportedMaterial.proofFullObjectHash,
        proofChunkRoot: transportedMaterial.proofChunkRoot,
        proofChunkHashes: transportedMaterial.proofChunkHashes,
    };
};

export const createSameSecretProofSet = (
    input: SameSecretProofSetInput,
): SameSecretProofSet => {
    validateProofSetInput(input);
    const statementRecords = sortedStatementRecordsForProofs(input);
    const proofMaterials = sortedSameSecretProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const statementRecord = statementRecords[expectedRosterPosition];
            if (statementRecord === undefined) {
                throw new Error(
                    'sameSecretProofMaterials must match same-secret statement order.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !==
                    statementRecord.trusteeIdentity ||
                proofMaterial.trusteeRosterPosition !==
                    statementRecord.trusteeRosterPosition
            ) {
                throw new Error(
                    'sameSecretProofMaterials must bind the derived same-secret statements.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'SameSecretProof',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                commitmentProfileId: setupCommitmentProfileId,
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                proofVerificationStatus: sameSecretLnpProofVerificationStatus,
                proofModelStatus: sameSecretLnpProofModelStatus,
                sameSecretTboxParameterProfileHash:
                    input.sameSecretTboxParameterProfileHash,
                ...contextFields(input.setupContext),
                trusteeIdentity: statementRecord.trusteeIdentity,
                trusteeRosterPosition: statementRecord.trusteeRosterPosition,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    statementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    statementRecord.sameSecretProofFamilyBindingRoot,
                setupProofBinding: input.setupProofBinding,
                statementHash: proofMaterial.statementHash,
                relationCommitmentHash: proofMaterial.relationCommitmentHash,
                tboxCommitmentPrefixHash:
                    proofMaterial.tboxCommitmentPrefixHash,
                ...optionalSetupProofTboxZ34Metadata(
                    proofMaterial,
                    `sameSecretProofMaterials.${String(expectedRosterPosition)}`,
                ),
                challenge: proofMaterial.challenge,
                proofSizeBytes: proofMaterial.proofSizeBytes,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...sameSecretProofByteMaterial(proofMaterial),
            } as const satisfies Omit<
                SameSecretProofRecord,
                'sameSecretProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                sameSecretProofRoot: deriveProtocolHash(
                    'SameSecretProofRoot',
                    proofRecordWithoutRoot,
                ),
            } satisfies SameSecretProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'SameSecretProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofVerificationStatus: sameSecretLnpProofVerificationStatus,
        proofModelStatus: sameSecretLnpProofModelStatus,
        sameSecretTboxParameterProfileHash:
            input.sameSecretTboxParameterProfileHash,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        vssCoefficientCommitmentMaterialRoot:
            input.vssCoefficientCommitmentMaterial
                .vssCoefficientCommitmentMaterialRoot,
        setupProofBinding: input.setupProofBinding,
        sameSecretProofRoots: proofRecords.map((proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            sameSecretProofRoot: proofRecord.sameSecretProofRoot,
        })),
        proofRecords,
    } as const satisfies Omit<SameSecretProofSet, 'sameSecretProofSetRoot'>;

    return {
        ...proofSetWithoutRoot,
        sameSecretProofSetRoot: deriveProtocolHash(
            'SameSecretProofRoot',
            proofSetWithoutRoot,
        ),
    } satisfies SameSecretProofSet;
};

export const createBinaryChunkedSameSecretProofMaterialTransport = (
    proofMaterials: readonly SameSecretProofMaterial[],
): BinaryChunkedSameSecretProofMaterialTransport => {
    const transport = transportSetupProofMaterials(proofMaterials, {
        proofFamily: sameSecretProofFamily,
        proofBytesHashDomain: sameSecretProofBytesHashDomain,
        transportedSetObjectType: 'SetupTransportedSameSecretProofMaterialSet',
        transportedObjectType: 'SetupTransportedSameSecretProofMaterial',
    });

    return {
        proofMaterials: transport.proofMaterials,
        transportedSameSecretProofMaterial:
            transport.transportedProofMaterial as TransportedSameSecretProofMaterialSet,
    };
};
