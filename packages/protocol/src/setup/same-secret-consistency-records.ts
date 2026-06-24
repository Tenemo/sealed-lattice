import {
    deriveProtocolHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    compactVssCommitmentBinaryFormat,
    compactVssCommitmentDevelopmentScope,
    compactVssCommitmentProfileId,
    verifyCompactVssCoefficientCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
} from './compact-vss-commitments.js';
import {
    setupProofChunkManifestRoot,
    setupProofMaterialChunkHash,
    setupProofTransportChunkSizeBytes,
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

export const setupProofProfileId = 'SealedLattice-SetupProof-v1';
export const sameSecretProofFamily = 'same-secret-linkage-anchor';
const sameSecretAnchorProofBytesHashDomain =
    'sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1';
export const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
export const sameSecretAnchorArgument =
    'one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values';
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
export const compactVssSameSecretBridgeRelation =
    'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof';
export const compactVssSameSecretBridgeProofBoundary =
    'statement binding only; same-secret bridge proof backend is not implemented yet';
export const compactVssSameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb';
export const compactVssSameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime';
export const compactVssSameSecretBridgeTargetBasisLimbOrder =
    'target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime';

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
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
    }
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
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly ringDegree: number;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly proofSizeBytes: number;
            readonly proofBytesHash: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
        }
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
        readonly proofAccountingHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
        readonly sameSecretProofRoots: readonly SameSecretProofRootReference[];
        readonly proofRecords: readonly SameSecretProofRecord[];
        readonly sameSecretProofSetRoot: ProtocolHash;
    }
>;

export type CompactVssSameSecretBridgeTargetConstantCommitmentRoot = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly coefficientCommitmentRoot: ProtocolHash;
}>;

export type CompactVssSameSecretBridgeStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSameSecretBridgeStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly compactCommitmentProfileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly targetBasisHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly dataBasisRelation: typeof sameSecretRelation;
        readonly integerSupport: typeof compactVssSameSecretBridgeIntegerSupport;
        readonly signedRepresentativeConvention: typeof compactVssSameSecretBridgeSignedRepresentativeConvention;
        readonly compactCommitmentEncoding: typeof compactVssCommitmentBinaryFormat;
        readonly targetBasisLimbOrder: typeof compactVssSameSecretBridgeTargetBasisLimbOrder;
        readonly targetConstantCoefficientCommitmentRoots: readonly CompactVssSameSecretBridgeTargetConstantCommitmentRoot[];
        readonly relation: typeof compactVssSameSecretBridgeRelation;
        readonly proofBoundary: typeof compactVssSameSecretBridgeProofBoundary;
        readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
    }
>;

export type CompactVssSameSecretBridgeStatementSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSameSecretBridgeStatementSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly compactCommitmentProfileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly targetBasisHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly compactCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly integerSupport: typeof compactVssSameSecretBridgeIntegerSupport;
        readonly signedRepresentativeConvention: typeof compactVssSameSecretBridgeSignedRepresentativeConvention;
        readonly compactCommitmentEncoding: typeof compactVssCommitmentBinaryFormat;
        readonly targetBasisLimbOrder: typeof compactVssSameSecretBridgeTargetBasisLimbOrder;
        readonly statementRecords: readonly CompactVssSameSecretBridgeStatementRecord[];
        readonly compactSameSecretBridgeStatementSetRoot: ProtocolHash;
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
    readonly proofAccountingHash: ProtocolHash;
    readonly proofMaterials: readonly SameSecretProofMaterial[];
};

export type CompactVssSameSecretBridgeStatementSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly targetBasisHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly compactCoefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
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
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertLowercaseHexBytes = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertExactString = (
    value: string,
    fieldName: string,
    expectedValue: string,
): void => {
    if (value !== expectedValue) {
        throw new TypeError(`${fieldName} is not supported.`);
    }
};

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    assertLowercaseHexBytes(hex, fieldName);
    const bytes = new Uint8Array(hex.length / 2);
    for (let offset = 0; offset < hex.length; offset += 2) {
        bytes[offset / 2] = Number.parseInt(hex.slice(offset, offset + 2), 16);
    }

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

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

const validateSameSecretProofMaterial = (
    material: SameSecretProofMaterial,
    fieldName: string,
): void => {
    if (material.setupProofProfileId !== setupProofProfileId) {
        throw new Error(
            `${fieldName}.setupProofProfileId must match setup proof profile.`,
        );
    }
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
    assertProtocolHash(input.proofAccountingHash, 'proofAccountingHash');
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
    constantCoefficientCommitmentRoots: constantRoots,
});

const sameSecretProofFamilyBindingPayload = (): JsonRecord => ({
    objectType: 'SameSecretProofFamilyBinding',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    proofFamily: sameSecretProofFamily,
    sameSecretRelation,
    anchorArgument: sameSecretAnchorArgument,
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
                setupProfileId: 'CollectiveBgvSetup-v1',
                commitmentProfileId: setupCommitmentProfileId,
                setupProofProfileId,
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
        proofAccountingHash: input.proofAccountingHash,
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

type CompactVssSourceCoefficientRecord =
    CompactVssCoefficientCommitmentSet['sourceTrusteeRecords'][number];

const sortedCompactCoefficientSourceRecordsForBridge = (
    compactCoefficientCommitmentSet: CompactVssCoefficientCommitmentSet,
): CompactVssSourceCoefficientRecord[] => {
    const sourceTrusteeRecords = [
        ...compactCoefficientCommitmentSet.sourceTrusteeRecords,
    ].sort(
        (leftRecord, rightRecord) =>
            leftRecord.sourceTrusteeRosterPosition -
            rightRecord.sourceTrusteeRosterPosition,
    );
    if (
        sourceTrusteeRecords.length !==
        compactCoefficientCommitmentSet.participantCount
    ) {
        throw new Error(
            'compact coefficient commitments must contain one source record per participant.',
        );
    }
    sourceTrusteeRecords.forEach((sourceTrusteeRecord, expectedPosition) => {
        if (
            sourceTrusteeRecord.sourceTrusteeRosterPosition !== expectedPosition
        ) {
            throw new Error(
                'compact coefficient source records must be contiguous from zero.',
            );
        }
    });

    return sourceTrusteeRecords;
};

const sortedSameSecretProofRecordsForBridge = (
    input: Pick<
        CompactVssSameSecretBridgeStatementSetInput,
        'sameSecretProofs'
    > & {
        readonly participantCount: number;
    },
): SameSecretProofRecord[] => {
    const proofRecords = [...input.sameSecretProofs.proofRecords].sort(
        (leftRecord, rightRecord) =>
            leftRecord.trusteeRosterPosition -
            rightRecord.trusteeRosterPosition,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofs.proofRecords must contain one proof per participant.',
        );
    }
    proofRecords.forEach((proofRecord, expectedPosition) => {
        assertProtocolHash(
            proofRecord.sameSecretProofRoot,
            'sameSecretProofs.proofRecords.sameSecretProofRoot',
        );
        if (proofRecord.trusteeRosterPosition !== expectedPosition) {
            throw new Error(
                'sameSecretProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
    });

    return proofRecords;
};

const targetConstantCoefficientRootsForBridge = (
    sourceTrusteeRecord: CompactVssSourceCoefficientRecord,
    targetRnsLimbCount: number,
): CompactVssSameSecretBridgeTargetConstantCommitmentRoot[] => {
    const constantRoots = sourceTrusteeRecord.coefficientCommitments.filter(
        (coefficientCommitment) =>
            coefficientCommitment.shamirCoefficientIndex === 0,
    );
    if (constantRoots.length !== targetRnsLimbCount) {
        throw new Error(
            'compact coefficient commitments must contain one target-basis constant coefficient root per RNS limb.',
        );
    }

    return constantRoots.map((coefficientCommitment, expectedRnsLimbIndex) => {
        if (coefficientCommitment.rnsLimbIndex !== expectedRnsLimbIndex) {
            throw new Error(
                'compact target-basis constant coefficient roots must be ordered by RNS limb.',
            );
        }
        assertProtocolHash(
            coefficientCommitment.coefficientCommitmentRoot,
            'compact coefficient commitment root',
        );

        return {
            rnsLimbIndex: coefficientCommitment.rnsLimbIndex,
            rnsPrime: coefficientCommitment.rnsPrime,
            shamirCoefficientIndex: 0,
            coefficientCommitmentRoot:
                coefficientCommitment.coefficientCommitmentRoot,
        };
    });
};

export const createCompactVssSameSecretBridgeStatementSet = (
    input: CompactVssSameSecretBridgeStatementSetInput,
): CompactVssSameSecretBridgeStatementSet => {
    assertProtocolHash(input.targetBasisHash, 'targetBasisHash');
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    const compactCoefficientCommitmentSet =
        verifyCompactVssCoefficientCommitmentSet({
            coefficientCommitmentSet: input.compactCoefficientCommitmentSet,
        });
    if (
        compactCoefficientCommitmentSet.publicMatrixSeedHash !==
        input.publicMatrixSeedHash
    ) {
        throw new Error(
            'compact same-secret bridge statements must use the compact coefficient matrix seed hash.',
        );
    }
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot
    ) {
        throw new Error(
            'sameSecretProofs must bind the same same-secret statement set.',
        );
    }
    if (
        input.sameSecretConsistency.participantCount !==
            compactCoefficientCommitmentSet.participantCount ||
        input.sameSecretProofs.participantCount !==
            compactCoefficientCommitmentSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge inputs must use one participant count.',
        );
    }
    const compactSourceRecords = sortedCompactCoefficientSourceRecordsForBridge(
        compactCoefficientCommitmentSet,
    );
    const sameSecretStatementRecords = sortedStatementRecordsForProofs({
        participantCount: compactCoefficientCommitmentSet.participantCount,
        sameSecretConsistency: input.sameSecretConsistency,
    });
    const sameSecretProofRecords = sortedSameSecretProofRecordsForBridge({
        participantCount: compactCoefficientCommitmentSet.participantCount,
        sameSecretProofs: input.sameSecretProofs,
    });
    const statementRecords = compactSourceRecords.map(
        (compactSourceRecord, expectedPosition) => {
            const sameSecretStatementRecord =
                sameSecretStatementRecords[expectedPosition];
            const sameSecretProofRecord =
                sameSecretProofRecords[expectedPosition];
            if (
                sameSecretStatementRecord === undefined ||
                sameSecretProofRecord === undefined
            ) {
                throw new Error(
                    'compact same-secret bridge inputs must contain matching records.',
                );
            }
            if (
                compactSourceRecord.sourceTrusteeIdentity !==
                    sameSecretStatementRecord.trusteeIdentity ||
                compactSourceRecord.sourceTrusteeRosterPosition !==
                    sameSecretStatementRecord.trusteeRosterPosition ||
                sameSecretProofRecord.trusteeIdentity !==
                    sameSecretStatementRecord.trusteeIdentity ||
                sameSecretProofRecord.trusteeRosterPosition !==
                    sameSecretStatementRecord.trusteeRosterPosition
            ) {
                throw new Error(
                    'compact same-secret bridge records must bind one trustee identity and roster position.',
                );
            }
            if (
                sameSecretProofRecord.sameSecretStatementRoot !==
                    sameSecretStatementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.trusteeSecretCommitmentRoot !==
                    sameSecretStatementRecord.trusteeSecretCommitmentRoot ||
                sameSecretProofRecord.sameSecretProofFamilyBindingRoot !==
                    sameSecretStatementRecord.sameSecretProofFamilyBindingRoot
            ) {
                throw new Error(
                    'compact same-secret bridge proof records must bind the same statement record.',
                );
            }
            const statementRecordWithoutRoot = {
                objectType: 'CompactVssSameSecretBridgeStatement',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                compactCommitmentProfileId: compactVssCommitmentProfileId,
                developmentScope: compactVssCommitmentDevelopmentScope,
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                ...contextFields(input.setupContext),
                targetBasisHash: input.targetBasisHash,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                trusteeIdentity: sameSecretStatementRecord.trusteeIdentity,
                trusteeRosterPosition:
                    sameSecretStatementRecord.trusteeRosterPosition,
                sameSecretStatementRoot:
                    sameSecretStatementRecord.sameSecretStatementRoot,
                sameSecretProofRoot: sameSecretProofRecord.sameSecretProofRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    sameSecretStatementRecord.sameSecretProofFamilyBindingRoot,
                dataBasisRelation: sameSecretRelation,
                integerSupport: compactVssSameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    compactVssSameSecretBridgeSignedRepresentativeConvention,
                compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
                targetBasisLimbOrder:
                    compactVssSameSecretBridgeTargetBasisLimbOrder,
                targetConstantCoefficientCommitmentRoots:
                    targetConstantCoefficientRootsForBridge(
                        compactSourceRecord,
                        compactCoefficientCommitmentSet.rnsLimbCount,
                    ),
                relation: compactVssSameSecretBridgeRelation,
                proofBoundary: compactVssSameSecretBridgeProofBoundary,
            } as const satisfies Omit<
                CompactVssSameSecretBridgeStatementRecord,
                'compactSameSecretBridgeStatementRoot'
            >;

            return {
                ...statementRecordWithoutRoot,
                compactSameSecretBridgeStatementRoot: deriveProtocolHash(
                    'SetupProofRecordBindingHash',
                    statementRecordWithoutRoot,
                ),
            };
        },
    );
    const statementSetWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...contextFields(input.setupContext),
        targetBasisHash: input.targetBasisHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: compactCoefficientCommitmentSet.participantCount,
        targetRnsLimbCount: compactCoefficientCommitmentSet.rnsLimbCount,
        thresholdDegree: compactCoefficientCommitmentSet.thresholdDegree,
        compactCoefficientCommitmentRoot:
            compactCoefficientCommitmentSet.coefficientCommitmentRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        statementRecords,
    } as const satisfies Omit<
        CompactVssSameSecretBridgeStatementSet,
        'compactSameSecretBridgeStatementSetRoot'
    >;

    return {
        ...statementSetWithoutRoot,
        compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementSetWithoutRoot,
        ),
    };
};

const assertEvidenceContextMatchesStatementSet = (
    statementSet: CompactVssSameSecretBridgeStatementSet,
    evidenceSet: Readonly<Record<string, unknown>>,
    evidenceSetName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (evidenceSet[fieldName] !== statementSet[fieldName]) {
            throw new Error(
                `${evidenceSetName}.${fieldName} must match the compact same-secret bridge statement set.`,
            );
        }
    }
};

const assertSameSecretEvidenceMatchesBridge = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly sameSecretConsistency?: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs?: SameSecretProofSet;
}): void => {
    if (
        (input.sameSecretConsistency === undefined) !==
        (input.sameSecretProofs === undefined)
    ) {
        throw new Error(
            'compact same-secret bridge evidence verification requires both sameSecretConsistency and sameSecretProofs.',
        );
    }
    if (
        input.sameSecretConsistency === undefined ||
        input.sameSecretProofs === undefined
    ) {
        return;
    }

    const { statementSet, sameSecretConsistency, sameSecretProofs } = input;
    assertEvidenceContextMatchesStatementSet(
        statementSet,
        sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertEvidenceContextMatchesStatementSet(
        statementSet,
        sameSecretProofs,
        'sameSecretProofs',
    );
    if (
        sameSecretConsistency.sameSecretConsistencyRoot !==
            statementSet.sameSecretConsistencyRoot ||
        sameSecretProofs.sameSecretProofSetRoot !==
            statementSet.sameSecretProofSetRoot ||
        sameSecretConsistency.sameSecretProofFamilyBindingRoot !==
            statementSet.sameSecretProofFamilyBindingRoot ||
        sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            statementSet.sameSecretProofFamilyBindingRoot ||
        sameSecretProofs.sameSecretConsistencyRoot !==
            sameSecretConsistency.sameSecretConsistencyRoot
    ) {
        throw new Error(
            'compact same-secret bridge evidence roots must match the statement set.',
        );
    }

    const {
        sameSecretConsistencyRoot: _sameSecretConsistencyRoot,
        ...sameSecretConsistencyWithoutRoot
    } = sameSecretConsistency;
    if (
        sameSecretConsistency.sameSecretConsistencyRoot !==
        deriveProtocolHash(
            'SameSecretConsistencyRoot',
            sameSecretConsistencyWithoutRoot,
        )
    ) {
        throw new Error(
            'same-secret consistency root does not match its bound statement set.',
        );
    }

    const {
        sameSecretProofSetRoot: _sameSecretProofSetRoot,
        ...sameSecretProofsWithoutRoot
    } = sameSecretProofs;
    if (
        sameSecretProofs.sameSecretProofSetRoot !==
        deriveProtocolHash('SameSecretProofRoot', sameSecretProofsWithoutRoot)
    ) {
        throw new Error(
            'same-secret proof set root does not match its bound proof records.',
        );
    }

    const sameSecretStatementRecords = sortedStatementRecordsForProofs({
        participantCount: statementSet.participantCount,
        sameSecretConsistency,
    });
    const sameSecretProofRecords = sortedSameSecretProofRecordsForBridge({
        participantCount: statementSet.participantCount,
        sameSecretProofs,
    });
    if (
        sameSecretConsistency.trusteeSecretCommitmentRoots.length !==
            statementSet.participantCount ||
        sameSecretProofs.sameSecretProofRoots.length !==
            statementSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge evidence root references must cover every participant.',
        );
    }

    statementSet.statementRecords.forEach(
        (bridgeStatement, expectedPosition) => {
            const sameSecretStatement =
                sameSecretStatementRecords[expectedPosition];
            const sameSecretProof = sameSecretProofRecords[expectedPosition];
            const trusteeSecretRootReference =
                sameSecretConsistency.trusteeSecretCommitmentRoots[
                    expectedPosition
                ];
            const sameSecretProofRootReference =
                sameSecretProofs.sameSecretProofRoots[expectedPosition];
            if (
                sameSecretStatement === undefined ||
                sameSecretProof === undefined ||
                trusteeSecretRootReference === undefined ||
                sameSecretProofRootReference === undefined
            ) {
                throw new Error(
                    'compact same-secret bridge evidence records must cover every participant.',
                );
            }

            const {
                sameSecretStatementRoot: _sameSecretStatementRoot,
                ...sameSecretStatementWithoutRoot
            } = sameSecretStatement;
            if (
                sameSecretStatement.sameSecretStatementRoot !==
                deriveProtocolHash(
                    'SameSecretConsistencyRoot',
                    sameSecretStatementWithoutRoot,
                )
            ) {
                throw new Error(
                    'same-secret statement root does not match its bound statement.',
                );
            }

            const {
                sameSecretProofRoot: _sameSecretProofRoot,
                ...sameSecretProofWithoutRoot
            } = sameSecretProof;
            if (
                sameSecretProof.sameSecretProofRoot !==
                deriveProtocolHash(
                    'SameSecretProofRoot',
                    sameSecretProofWithoutRoot,
                )
            ) {
                throw new Error(
                    'same-secret proof root does not match its bound proof record.',
                );
            }

            if (
                bridgeStatement.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                bridgeStatement.trusteeRosterPosition !== expectedPosition ||
                sameSecretProof.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                sameSecretProof.trusteeRosterPosition !== expectedPosition ||
                trusteeSecretRootReference.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                trusteeSecretRootReference.trusteeRosterPosition !==
                    expectedPosition ||
                sameSecretProofRootReference.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                sameSecretProofRootReference.trusteeRosterPosition !==
                    expectedPosition
            ) {
                throw new Error(
                    'compact same-secret bridge evidence records must bind the same trustee order.',
                );
            }

            if (
                bridgeStatement.sameSecretStatementRoot !==
                    sameSecretStatement.sameSecretStatementRoot ||
                bridgeStatement.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot ||
                bridgeStatement.sameSecretProofFamilyBindingRoot !==
                    sameSecretStatement.sameSecretProofFamilyBindingRoot ||
                sameSecretProof.sameSecretStatementRoot !==
                    sameSecretStatement.sameSecretStatementRoot ||
                sameSecretProof.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot ||
                sameSecretProof.sameSecretProofFamilyBindingRoot !==
                    sameSecretStatement.sameSecretProofFamilyBindingRoot ||
                bridgeStatement.sameSecretProofRoot !==
                    sameSecretProof.sameSecretProofRoot ||
                trusteeSecretRootReference.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot ||
                sameSecretProofRootReference.sameSecretProofRoot !==
                    sameSecretProof.sameSecretProofRoot
            ) {
                throw new Error(
                    'compact same-secret bridge evidence roots must match each bridge statement.',
                );
            }
        },
    );
};

export const verifyCompactVssSameSecretBridgeStatementSet = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly sameSecretConsistency?: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs?: SameSecretProofSet;
}): CompactVssSameSecretBridgeStatementSet => {
    const { statementSet } = input;
    assertExactString(
        statementSet.objectType,
        'compact same-secret bridge statement set objectType',
        'CompactVssSameSecretBridgeStatementSet',
    );
    if (statementSet.objectVersion !== 1) {
        throw new TypeError(
            'compact same-secret bridge statement set objectVersion is not supported.',
        );
    }
    for (const [fieldName, expectedValue] of [
        ['setupProfileId', 'CollectiveBgvSetup-v1'],
        ['compactCommitmentProfileId', compactVssCommitmentProfileId],
        ['developmentScope', compactVssCommitmentDevelopmentScope],
        ['setupProofProfileId', setupProofProfileId],
        ['proofFamily', sameSecretProofFamily],
    ] as const) {
        assertExactString(
            statementSet[fieldName],
            `compact same-secret bridge statement set ${fieldName}`,
            expectedValue,
        );
    }
    assertNonEmptyString(
        statementSet.ceremonyId,
        'compact same-secret bridge statement set ceremonyId',
    );
    assertNonEmptyString(
        statementSet.setupEpoch,
        'compact same-secret bridge statement set setupEpoch',
    );
    for (const fieldName of [
        'manifestHash',
        'rosterHash',
        'setupProfileHash',
        'qShareHash',
        'carryAwareVssShareRelationProfileHash',
        'commitmentProfileHash',
        'targetBasisHash',
        'publicMatrixSeedHash',
        'compactCoefficientCommitmentRoot',
        'sameSecretConsistencyRoot',
        'sameSecretProofSetRoot',
        'sameSecretProofFamilyBindingRoot',
    ] as const) {
        assertProtocolHash(
            statementSet[fieldName],
            `compact same-secret bridge statement set ${fieldName}`,
        );
    }
    assertPositiveSafeInteger(
        statementSet.participantCount,
        'compact same-secret bridge statement set participantCount',
    );
    assertPositiveSafeInteger(
        statementSet.targetRnsLimbCount,
        'compact same-secret bridge statement set targetRnsLimbCount',
    );
    assertPositiveSafeInteger(
        statementSet.thresholdDegree,
        'compact same-secret bridge statement set thresholdDegree',
    );
    assertExactString(
        statementSet.integerSupport,
        'compact same-secret bridge statement set integerSupport',
        compactVssSameSecretBridgeIntegerSupport,
    );
    assertExactString(
        statementSet.signedRepresentativeConvention,
        'compact same-secret bridge statement set signedRepresentativeConvention',
        compactVssSameSecretBridgeSignedRepresentativeConvention,
    );
    assertExactString(
        statementSet.compactCommitmentEncoding,
        'compact same-secret bridge statement set compactCommitmentEncoding',
        compactVssCommitmentBinaryFormat,
    );
    assertExactString(
        statementSet.targetBasisLimbOrder,
        'compact same-secret bridge statement set targetBasisLimbOrder',
        compactVssSameSecretBridgeTargetBasisLimbOrder,
    );
    if (
        statementSet.statementRecords.length !== statementSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge statement set must contain one statement per participant.',
        );
    }
    statementSet.statementRecords.forEach(
        (statementRecord, expectedPosition) => {
            assertExactString(
                statementRecord.objectType,
                'compact same-secret bridge statement objectType',
                'CompactVssSameSecretBridgeStatement',
            );
            if (statementRecord.objectVersion !== 1) {
                throw new TypeError(
                    'compact same-secret bridge statement objectVersion is not supported.',
                );
            }
            for (const [fieldName, expectedValue] of [
                ['setupProfileId', statementSet.setupProfileId],
                [
                    'compactCommitmentProfileId',
                    statementSet.compactCommitmentProfileId,
                ],
                ['developmentScope', statementSet.developmentScope],
                ['setupProofProfileId', statementSet.setupProofProfileId],
                ['proofFamily', statementSet.proofFamily],
            ] as const) {
                assertExactString(
                    statementRecord[fieldName],
                    `compact same-secret bridge statement ${fieldName}`,
                    expectedValue,
                );
            }
            for (const fieldName of setupContextFieldNames) {
                if (statementRecord[fieldName] !== statementSet[fieldName]) {
                    throw new Error(
                        `compact same-secret bridge statement ${fieldName} must match the statement set.`,
                    );
                }
            }
            if (
                statementRecord.targetBasisHash !==
                    statementSet.targetBasisHash ||
                statementRecord.publicMatrixSeedHash !==
                    statementSet.publicMatrixSeedHash
            ) {
                throw new Error(
                    'compact same-secret bridge statement target binding must match the statement set.',
                );
            }
            assertNonEmptyString(
                statementRecord.trusteeIdentity,
                'compact same-secret bridge statement trusteeIdentity',
            );
            if (statementRecord.trusteeRosterPosition !== expectedPosition) {
                throw new Error(
                    'compact same-secret bridge statement roster positions must be contiguous from zero.',
                );
            }
            for (const fieldName of [
                'sameSecretStatementRoot',
                'sameSecretProofRoot',
                'trusteeSecretCommitmentRoot',
                'sameSecretProofFamilyBindingRoot',
                'compactSameSecretBridgeStatementRoot',
            ] as const) {
                assertProtocolHash(
                    statementRecord[fieldName],
                    `compact same-secret bridge statement ${fieldName}`,
                );
            }
            if (
                statementRecord.sameSecretProofFamilyBindingRoot !==
                statementSet.sameSecretProofFamilyBindingRoot
            ) {
                throw new Error(
                    'compact same-secret bridge statement proof-family binding root must match the statement set.',
                );
            }
            assertExactString(
                statementRecord.dataBasisRelation,
                'compact same-secret bridge statement dataBasisRelation',
                sameSecretRelation,
            );
            for (const fieldName of [
                'integerSupport',
                'signedRepresentativeConvention',
                'compactCommitmentEncoding',
                'targetBasisLimbOrder',
            ] as const) {
                assertExactString(
                    statementRecord[fieldName],
                    `compact same-secret bridge statement ${fieldName}`,
                    statementSet[fieldName],
                );
            }
            assertExactString(
                statementRecord.relation,
                'compact same-secret bridge statement relation',
                compactVssSameSecretBridgeRelation,
            );
            assertExactString(
                statementRecord.proofBoundary,
                'compact same-secret bridge statement proofBoundary',
                compactVssSameSecretBridgeProofBoundary,
            );
            if (
                statementRecord.targetConstantCoefficientCommitmentRoots
                    .length !== statementSet.targetRnsLimbCount
            ) {
                throw new Error(
                    'compact same-secret bridge statement must bind one target constant root per target RNS limb.',
                );
            }
            statementRecord.targetConstantCoefficientCommitmentRoots.forEach(
                (rootRecord, expectedRnsLimbIndex) => {
                    if (
                        rootRecord.rnsLimbIndex !== expectedRnsLimbIndex ||
                        rootRecord.shamirCoefficientIndex !== 0
                    ) {
                        throw new Error(
                            'compact same-secret bridge target constant roots must use canonical coordinates.',
                        );
                    }
                    assertPositiveSafeInteger(
                        rootRecord.rnsPrime,
                        'compact same-secret bridge target constant root rnsPrime',
                    );
                    assertProtocolHash(
                        rootRecord.coefficientCommitmentRoot,
                        'compact same-secret bridge target constant root coefficientCommitmentRoot',
                    );
                },
            );
            const {
                compactSameSecretBridgeStatementRoot:
                    _compactSameSecretBridgeStatementRoot,
                ...statementRecordWithoutRoot
            } = statementRecord;
            const expectedStatementRoot = deriveProtocolHash(
                'SetupProofRecordBindingHash',
                statementRecordWithoutRoot,
            );
            if (
                statementRecord.compactSameSecretBridgeStatementRoot !==
                expectedStatementRoot
            ) {
                throw new Error(
                    'compact same-secret bridge statement root does not match its bound roots.',
                );
            }
        },
    );
    const {
        compactSameSecretBridgeStatementSetRoot:
            _compactSameSecretBridgeStatementSetRoot,
        ...statementSetWithoutRoot
    } = statementSet;
    const expectedStatementSetRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        statementSetWithoutRoot,
    );
    if (
        statementSet.compactSameSecretBridgeStatementSetRoot !==
        expectedStatementSetRoot
    ) {
        throw new Error(
            'compact same-secret bridge statement set root does not match its statements.',
        );
    }
    assertSameSecretEvidenceMatchesBridge({
        statementSet,
        sameSecretConsistency: input.sameSecretConsistency,
        sameSecretProofs: input.sameSecretProofs,
    });

    return statementSet;
};

// Move embedded anchor proof bytes into binary chunked transport, mirroring
// the kernel transported same-secret proof material flow: each material keeps
// the transport reference fields, the chunks travel in the request-side
// transported proof material set.
export const createBinaryChunkedSameSecretProofMaterialTransport = (
    proofMaterials: readonly SameSecretProofMaterial[],
): BinaryChunkedSameSecretProofMaterialTransport => {
    const transportedProofMaterials: JsonRecord[] = [];
    const transportedRecords = proofMaterials.map(
        (proofMaterial, proofIndex) => {
            const materialRecord = proofMaterial as JsonRecord;
            const proofBytesHex = materialRecord.proofBytesHex;
            if (
                typeof proofBytesHex !== 'string' ||
                proofBytesHex.length === 0
            ) {
                throw new TypeError(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must be non-empty.`,
                );
            }
            const proofBytes = bytesFromHex(
                proofBytesHex,
                `proofMaterials.${String(proofIndex)}.proofBytesHex`,
            );
            if (proofMaterial.proofSizeBytes !== proofBytes.byteLength) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofSizeBytes must match proofBytesHex.`,
                );
            }
            const expectedProofBytesHash = hash512Hex(
                sameSecretAnchorProofBytesHashDomain,
                [proofBytes],
            );
            if (proofMaterial.proofBytesHash !== expectedProofBytesHash) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHash must match proofBytesHex before transport.`,
                );
            }
            const chunks: Uint8Array[] = [];
            for (
                let chunkStart = 0;
                chunkStart < proofBytes.byteLength;
                chunkStart += setupProofTransportChunkSizeBytes
            ) {
                chunks.push(
                    proofBytes.slice(
                        chunkStart,
                        Math.min(
                            chunkStart + setupProofTransportChunkSizeBytes,
                            proofBytes.byteLength,
                        ),
                    ),
                );
            }
            if (chunks.length === 0) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must produce at least one transported chunk.`,
                );
            }
            const totalByteLength = proofBytes.byteLength;
            const fullObjectHash = setupProofMaterialFullObjectHashHex(
                sameSecretProofFamily,
                totalByteLength,
                chunks,
            );
            const chunkHashes = chunks.map((chunk, chunkIndex) =>
                setupProofMaterialChunkHash(
                    sameSecretProofFamily,
                    fullObjectHash,
                    chunkIndex,
                    chunk,
                ),
            );
            const chunkRoot = setupProofChunkManifestRoot(
                sameSecretProofFamily,
                chunkHashes,
                fullObjectHash,
                totalByteLength,
            );
            const proofMaterialRoot = deriveProtocolHash(
                'SameSecretLinkageAnchorProofMaterialRoot',
                {
                    objectType: 'SameSecretLinkageAnchorProofMaterialReference',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: sameSecretProofFamily,
                    trusteeIdentity: proofMaterial.trusteeIdentity,
                    trusteeRosterPosition: proofMaterial.trusteeRosterPosition,
                    statementHash: proofMaterial.statementHash,
                    proofSizeBytes: proofMaterial.proofSizeBytes,
                    proofBytesHash: proofMaterial.proofBytesHash,
                    chunkSizeBytes: setupProofTransportChunkSizeBytes,
                    chunkCount: chunkHashes.length,
                    totalByteLength,
                    fullObjectHash,
                    chunkRoot,
                    chunkHashes,
                },
            );
            transportedProofMaterials.push({
                objectType: 'SetupTransportedSameSecretProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                proofMaterialRoot,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: chunkHashes.length,
                totalByteLength,
                fullObjectHash,
                chunkHashes,
                chunkRoot,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            });
            const transportedMaterial = {
                ...materialRecord,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofMaterialRoot,
                proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
                proofChunkCount: chunkHashes.length,
                proofTotalByteLength: totalByteLength,
                proofFullObjectHash: fullObjectHash,
                proofChunkRoot: chunkRoot,
                proofChunkHashes: chunkHashes,
            } as JsonRecord;
            delete transportedMaterial.proofBytesHex;

            return transportedMaterial as unknown as SameSecretProofMaterial;
        },
    );

    return {
        proofMaterials: transportedRecords,
        transportedSameSecretProofMaterial: {
            objectType: 'SetupTransportedSameSecretProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: sameSecretProofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};
