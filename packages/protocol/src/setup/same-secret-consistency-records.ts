import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertContextMatches,
    assertLowercaseHexBytes,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    contextFields,
    type JsonRecord,
} from './common-fields.js';
import { type TransportedSetupProofMaterialSet } from './setup-proof-material-transport.js';
import {
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
} from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

export const sameSecretProofFamily = 'same-secret-linkage-anchor';
export const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
export const sameSecretBoundProofFamilies = [
    'vss-constant-relation',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;

export type SameSecretConstantCoefficientCommitmentRoot = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly commitmentRoot: ProtocolHash;
}>;

export type SameSecretConsistencyStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatement';
        readonly objectVersion: 1;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly vssSourceTrusteeCommitmentRoot: ProtocolHash;
        readonly constantCoefficientCommitmentRoots: readonly SameSecretConstantCoefficientCommitmentRoot[];
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly boundSecretDependentProofFamilies: typeof sameSecretBoundProofFamilies;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly sameSecretRelation: typeof sameSecretRelation;
        readonly sameSecretStatementRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatementSet';
        readonly objectVersion: 1;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
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
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly proofBytesHash: ProtocolHash;
    }
>;

export type SameSecretProofRecord = Readonly<
    JsonRecord &
        SameSecretProofByteMaterial & {
            readonly objectType: 'SameSecretProof';
            readonly objectVersion: 1;
            readonly proofFamily: typeof sameSecretProofFamily;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly ringDegree: number;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly proofBytesHash: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
        }
>;

export type SameSecretProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretProofSet';
        readonly objectVersion: 1;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
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
    readonly proofMaterials: readonly SameSecretProofMaterial[];
};

export type TransportedSameSecretProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedSameSecretProofMaterialSet';
        readonly proofFamily: typeof sameSecretProofFamily;
    }
>;

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

const validateSameSecretProofMaterial = (
    material: SameSecretProofMaterial,
    fieldName: string,
): void => {
    if (material.proofFamily !== sameSecretProofFamily) {
        throw new Error(
            `${fieldName}.proofFamily must be the same-secret linkage anchor family.`,
        );
    }
    assertNonEmptyString(
        material.trusteeIdentity,
        `${fieldName}.trusteeIdentity`,
    );
    assertNonNegativeSafeInteger(
        material.trusteeRosterPosition,
        `${fieldName}.trusteeRosterPosition`,
    );
    assertProtocolHash(material.statementHash, `${fieldName}.statementHash`);
    assertProtocolHash(material.proofBytesHash, `${fieldName}.proofBytesHash`);
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(`${fieldName}.proofBytesHex must be a string.`);
        }
        assertLowercaseHexBytes(proofBytesHex, `${fieldName}.proofBytesHex`);
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
    ...contextFields(setupContext),
    trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
    trusteeRosterPosition: sourceTrusteeRecord.sourceTrusteeRosterPosition,
    vssSourceTrusteeCommitmentRoot:
        sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
    constantCoefficientCommitmentRoots: constantRoots,
});

const sameSecretProofFamilyBindingPayload = (): JsonRecord => ({
    objectType: 'SameSecretProofFamilyBinding',
    objectVersion: 1,
    proofFamily: sameSecretProofFamily,
    sameSecretRelation,
    boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
});

const sameSecretProofFamilyBindingRoot = (): ProtocolHash =>
    deriveCanonicalObjectHash(sameSecretProofFamilyBindingPayload());

const createStatementRecord = (
    setupContext: CollectiveBgvSetupContext,
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): SameSecretConsistencyStatementRecord => {
    const trusteeSecretCommitmentRoot = deriveCanonicalObjectHash(
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
        proofFamily: sameSecretProofFamily,
        ...contextFields(setupContext),
        trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
        trusteeRosterPosition: sourceTrusteeRecord.sourceTrusteeRosterPosition,
        vssSourceTrusteeCommitmentRoot:
            sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
        constantCoefficientCommitmentRoots: constantRoots,
        trusteeSecretCommitmentRoot,
        boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        sameSecretRelation,
    } as const satisfies Omit<
        SameSecretConsistencyStatementRecord,
        'sameSecretStatementRoot'
    >;

    return {
        ...statementRecordWithoutRoot,
        sameSecretStatementRoot: deriveCanonicalObjectHash(
            statementRecordWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementRecord;
};

export const createSameSecretConsistencyStatementSet = (
    input: SameSecretConsistencyStatementSetInput,
): SameSecretConsistencyStatementSet => {
    validateInput(input);
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementRecords = sortedSourceTrusteeRecords(input).map(
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
        proofFamily: sameSecretProofFamily,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        thresholdDegree: input.thresholdDegree,
        vssCoefficientCommitmentRoot:
            input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        statementRecords,
    } as const satisfies Omit<
        SameSecretConsistencyStatementSet,
        'sameSecretConsistencyRoot'
    >;

    return {
        ...statementSetWithoutRoot,
        sameSecretConsistencyRoot: deriveCanonicalObjectHash(
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
    input: Pick<SameSecretProofSetInput, 'participantCount' | 'proofMaterials'>,
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
                proofFamily: sameSecretProofFamily,
                ...contextFields(input.setupContext),
                trusteeIdentity: statementRecord.trusteeIdentity,
                trusteeRosterPosition: statementRecord.trusteeRosterPosition,
                ringDegree: input.vssCoefficientCommitmentMaterial.ringDegree,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    statementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    statementRecord.sameSecretProofFamilyBindingRoot,
                statementHash: proofMaterial.statementHash,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...sameSecretProofByteMaterial(proofMaterial),
            } as const satisfies Omit<
                SameSecretProofRecord,
                'sameSecretProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                sameSecretProofRoot: deriveCanonicalObjectHash(
                    proofRecordWithoutRoot,
                ),
            } satisfies SameSecretProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'SameSecretProofSet',
        objectVersion: 1,
        proofFamily: sameSecretProofFamily,
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
        proofRecords,
    } as const satisfies Omit<SameSecretProofSet, 'sameSecretProofSetRoot'>;

    return {
        ...proofSetWithoutRoot,
        sameSecretProofSetRoot: deriveCanonicalObjectHash(proofSetWithoutRoot),
    } satisfies SameSecretProofSet;
};
