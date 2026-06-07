import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupProofProfileId,
    type SameSecretProofSet,
    type SameSecretConsistencyStatementRecord,
    type SameSecretConsistencyStatementSet,
} from './same-secret-consistency-records.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const publicKeyShareProofFamily = 'public-key-share';
export const publicKeyShareProofVerificationStatus =
    'lnp-proof-verification-pending';
export const publicKeyShareLnpProofVerificationStatus =
    'lnp-public-key-share-relation-verified-claim-accounting-pending';
export const publicKeyShareLnpProofModelStatus =
    'pinned LNP tbox proof bytes, setup-proof challenge domain, binary proof-material schema, VSS-bound secret opening, centered-binomial error support, lifted no-wrap carry witnesses, public-key algebra, and fixed response bounds verified; repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting remain required before claim-bearing public-key acceptance';
export const publicKeyShareProofBindingStatus =
    'public-key-share-proof-required';
export const publicKeyShareMaterialEncoding =
    'embedded-full-public-key-share-coefficients';
export const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1';

export type PublicKeyShareCoefficientVectorHash = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly component: 'b_i';
    readonly coefficientVectorHash512: ProtocolHash;
}>;

export type PublicKeyShareContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
}>;

export type PublicKeyShareCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly component: 'b_i';
        readonly coefficientByteLength: number;
        readonly coefficientVectorHash512: ProtocolHash;
        readonly coefficientsLeHex: string;
    }
>;

export type PublicKeyShareMaterialContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
}>;

export type PublicKeyShareRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShare';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly shareComponent: 'component-zero-b_i';
        readonly rnsLimbCount: number;
        readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
        readonly proofBindingStatus: typeof publicKeyShareProofBindingStatus;
        readonly publicKeyShareRoot: ProtocolHash;
    }
>;

export type PublicKeyShareSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofBindingStatus: typeof publicKeyShareProofBindingStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly publicKeyShareRoots: readonly {
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareRoot: ProtocolHash;
        }[];
        readonly shareRecords: readonly PublicKeyShareRecord[];
        readonly publicKeyShareSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareProofRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareProof';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareProofVerificationStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly rnsLimbCount: number;
        readonly noWrapRelation: 'PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 over lifted integers';
        readonly errorSupport: 'checked-by-public-key-share-lnp-proof-set';
        readonly carryWitnessStatus: 'checked-by-public-key-share-lnp-proof-set';
        readonly proofBytesStatus: 'supplied-by-public-key-share-lnp-proof-set';
        readonly publicKeyShareProofRoot: ProtocolHash;
    }
>;

export type PublicKeyShareProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareProofVerificationStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofRoots: readonly {
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareProofRoot: ProtocolHash;
        }[];
        readonly proofRecords: readonly PublicKeyShareProofRecord[];
        readonly publicKeyShareProofSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofModelStatus: typeof publicKeyShareLnpProofModelStatus;
        readonly materialEncoding: typeof publicKeyShareMaterialEncoding;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareRoot: ProtocolHash;
        readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
        readonly publicKeyShareMaterialRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareMaterialRoot: ProtocolHash;
}>;

export type PublicKeyShareMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofModelStatus: typeof publicKeyShareLnpProofModelStatus;
        readonly materialEncoding: typeof publicKeyShareMaterialEncoding;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareLnpEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type PublicKeyShareLnpTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type PublicKeyShareLnpProofByteMaterial =
    | PublicKeyShareLnpEmbeddedProofBytes
    | PublicKeyShareLnpTransportedProofBytes;

export type PublicKeyShareLnpProofMaterial = Readonly<
    PublicKeyShareLnpProofByteMaterial & {
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareLnpProofVerificationStatus;
        readonly proofModelStatus: typeof publicKeyShareLnpProofModelStatus;
        readonly publicKeyShareTboxParameterProfileHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly relationCommitmentHash: ProtocolHash;
        readonly tboxCommitmentPrefixHash: ProtocolHash;
        readonly challenge: number;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
    }
>;

export type PublicKeyShareLnpProofRecord = Readonly<
    JsonRecord &
        PublicKeyShareLnpProofByteMaterial & {
            readonly objectType: 'PublicKeyShareLnpProof';
            readonly objectVersion: 1;
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly setupProofProfileId: typeof setupProofProfileId;
            readonly proofFamily: typeof publicKeyShareProofFamily;
            readonly proofVerificationStatus: typeof publicKeyShareLnpProofVerificationStatus;
            readonly proofModelStatus: typeof publicKeyShareLnpProofModelStatus;
            readonly setupProofBinding: JsonRecord;
            readonly publicKeyShareTboxParameterProfileHash: ProtocolHash;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareRoot: ProtocolHash;
            readonly publicKeyShareProofRoot: ProtocolHash;
            readonly publicKeyShareMaterialRoot: ProtocolHash;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly relationCommitmentHash: ProtocolHash;
            readonly tboxCommitmentPrefixHash: ProtocolHash;
            readonly challenge: number;
            readonly proofSizeBytes: number;
            readonly proofBytesHash: ProtocolHash;
            readonly publicKeyShareLnpProofRoot: ProtocolHash;
        }
>;

export type PublicKeyShareLnpProofRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareLnpProofRoot: ProtocolHash;
}>;

export type PublicKeyShareLnpProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareLnpProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareLnpProofVerificationStatus;
        readonly proofModelStatus: typeof publicKeyShareLnpProofModelStatus;
        readonly setupProofBinding: JsonRecord;
        readonly publicKeyShareTboxParameterProfileHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareLnpProofRoots: readonly PublicKeyShareLnpProofRootReference[];
        readonly proofRecords: readonly PublicKeyShareLnpProofRecord[];
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
    }
>;

export type CollectivePublicKeySourceShareMaterialRoot = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareRoot: ProtocolHash;
    readonly publicKeyShareMaterialRoot: ProtocolHash;
}>;

export type CollectivePublicKeyCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly component: 'b';
        readonly coefficientByteLength: number;
        readonly coefficientVectorHash512: ProtocolHash;
        readonly coefficientsLeHex: string;
    }
>;

export type CollectivePublicKey = Readonly<
    JsonRecord & {
        readonly objectType: 'CollectivePublicKey';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareLnpProofVerificationStatus;
        readonly proofModelStatus: typeof publicKeyShareLnpProofModelStatus;
        readonly aggregationStatus: 'lnp-proof-aggregated-claim-accounting-pending';
        readonly materialEncoding: 'embedded-full-collective-public-key-coefficients';
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sourceShareMaterialRoots: readonly CollectivePublicKeySourceShareMaterialRoot[];
        readonly aggregateCoefficientVectorsByLimb: readonly CollectivePublicKeyCoefficientVectorMaterial[];
        readonly collectivePublicKeyRoot: ProtocolHash;
    }
>;

export type CollectivePublicKeyInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly ringDegree: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: PublicKeyShareMaterialSet;
    readonly publicKeyShareLnpProofs: PublicKeyShareLnpProofSet;
}>;

export type PublicKeyShareSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly shareContributions: readonly PublicKeyShareContributionInput[];
};

export type PublicKeyShareProofSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions'
> & {
    readonly publicKeyShares: PublicKeyShareSet;
};

export type PublicKeyShareMaterialSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions' | 'sameSecretConsistency'
> & {
    readonly ringDegree: number;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialContributions: readonly PublicKeyShareMaterialContributionInput[];
};

export type PublicKeyShareLnpProofSetInput = Omit<
    PublicKeyShareProofSetInput,
    'sameSecretConsistency'
> & {
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: PublicKeyShareMaterialSet;
    readonly setupProofBinding: JsonRecord;
    readonly publicKeyShareTboxParameterProfileHash: ProtocolHash;
    readonly proofMaterials: readonly PublicKeyShareLnpProofMaterial[];
};

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})*$/u;
const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

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

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
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

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    assertLowercaseHexBytes(hex, fieldName);
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const coefficientVectorFromLittleEndianHex = (
    coefficientsLeHex: string,
    expectedCoefficientCount: number,
    fieldName: string,
): readonly number[] => {
    const coefficientBytes = bytesFromHex(coefficientsLeHex, fieldName);
    if (coefficientBytes.byteLength !== expectedCoefficientCount * 8) {
        throw new Error(
            `${fieldName} byte length must match the material ring degree.`,
        );
    }

    return Array.from(
        { length: expectedCoefficientCount },
        (_unused, coefficientIndex) => {
            let coefficient = 0n;
            for (let byteOffset = 7; byteOffset >= 0; byteOffset -= 1) {
                coefficient <<= 8n;
                coefficient |= BigInt(
                    coefficientBytes[coefficientIndex * 8 + byteOffset] ?? 0,
                );
            }
            if (coefficient > BigInt(Number.MAX_SAFE_INTEGER)) {
                throw new Error(
                    `${fieldName} contains a coefficient outside the JavaScript safe integer range.`,
                );
            }

            return Number(coefficient);
        },
    );
};

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (!Number.isSafeInteger(coefficient) || coefficient < 0) {
            throw new TypeError(
                'coefficient vector entries must be non-negative safe integers.',
            );
        }
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const coefficientVectorHash512 = (coefficients: readonly number[]): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const coefficientVectorToLittleEndianHex = (
    coefficients: readonly number[],
): string => bytesToHex(coefficientVectorBytes(coefficients));

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
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
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const sortedByRosterPosition = <
    RecordValue extends { readonly trusteeRosterPosition: number },
>(
    records: readonly RecordValue[],
): RecordValue[] =>
    [...records].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );

const statementRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareSetInput,
        'participantCount' | 'sameSecretConsistency' | 'setupContext'
    >,
): ReadonlyMap<number, SameSecretConsistencyStatementRecord> => {
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertProtocolHash(
        input.sameSecretConsistency.sameSecretConsistencyRoot,
        'sameSecretConsistency.sameSecretConsistencyRoot',
    );
    const sortedStatements = sortedByRosterPosition(
        input.sameSecretConsistency.statementRecords,
    );
    if (sortedStatements.length !== input.participantCount) {
        throw new Error(
            'sameSecretConsistency.statementRecords must contain every participant.',
        );
    }
    const statementsByRosterPosition = new Map<
        number,
        SameSecretConsistencyStatementRecord
    >();
    sortedStatements.forEach((statementRecord, expectedRosterPosition) => {
        assertNonEmptyString(
            statementRecord.trusteeIdentity,
            'sameSecretStatement.trusteeIdentity',
        );
        if (statementRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretConsistency.statementRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            statementRecord.sameSecretStatementRoot,
            'sameSecretStatement.sameSecretStatementRoot',
        );
        assertProtocolHash(
            statementRecord.trusteeSecretCommitmentRoot,
            'sameSecretStatement.trusteeSecretCommitmentRoot',
        );
        statementsByRosterPosition.set(
            statementRecord.trusteeRosterPosition,
            statementRecord,
        );
    });

    return statementsByRosterPosition;
};

const validateCommonInput = (
    input: Pick<
        PublicKeyShareSetInput,
        | 'participantCount'
        | 'qSharePrimes'
        | 'publicMatrixSeedHash'
        | 'publicKeyCrpRoot'
        | 'publicAPolynomialRoot'
    >,
): void => {
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
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertProtocolHash(input.publicKeyCrpRoot, 'publicKeyCrpRoot');
    assertProtocolHash(input.publicAPolynomialRoot, 'publicAPolynomialRoot');
};

const validateShareContribution = (
    contribution: PublicKeyShareContributionInput,
    expectedRosterPosition: number,
    qSharePrimes: readonly number[],
): void => {
    assertNonEmptyString(contribution.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        contribution.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    if (contribution.trusteeRosterPosition !== expectedRosterPosition) {
        throw new Error(
            'shareContributions roster positions must be contiguous from zero.',
        );
    }
    if (
        contribution.shareCoefficientVectorHash512ByLimb.length !==
        qSharePrimes.length
    ) {
        throw new Error(
            'shareCoefficientVectorHash512ByLimb must contain one entry for every Q_share limb.',
        );
    }
    contribution.shareCoefficientVectorHash512ByLimb.forEach(
        (coefficientHash, rnsLimbIndex) => {
            if (
                coefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                coefficientHash.rnsPrime !== qSharePrimes[rnsLimbIndex]
            ) {
                throw new Error(
                    'shareCoefficientVectorHash512ByLimb entries must follow Q_share order.',
                );
            }
            if (coefficientHash.component !== 'b_i') {
                throw new Error(
                    'shareCoefficientVectorHash512ByLimb component must be b_i.',
                );
            }
            assertProtocolHash(
                coefficientHash.coefficientVectorHash512,
                'shareCoefficientVectorHash512ByLimb.coefficientVectorHash512',
            );
        },
    );
};

export const createPublicKeyShareSet = (
    input: PublicKeyShareSetInput,
): PublicKeyShareSet => {
    validateCommonInput(input);
    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareContributions = sortedByRosterPosition(input.shareContributions);
    if (shareContributions.length !== input.participantCount) {
        throw new Error(
            'shareContributions must contain one public-key share per participant.',
        );
    }
    const shareRecords = shareContributions.map(
        (contribution, expectedRosterPosition) => {
            validateShareContribution(
                contribution,
                expectedRosterPosition,
                input.qSharePrimes,
            );
            const sameSecretStatement = statementsByRosterPosition.get(
                contribution.trusteeRosterPosition,
            );
            if (sameSecretStatement === undefined) {
                throw new Error(
                    'shareContributions must reference an accepted same-secret statement.',
                );
            }
            if (
                sameSecretStatement.trusteeIdentity !==
                contribution.trusteeIdentity
            ) {
                throw new Error(
                    'shareContributions trusteeIdentity must match same-secret statements.',
                );
            }
            const shareRecordWithoutRoot = {
                objectType: 'PublicKeyShare',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                ...contextFields(input.setupContext),
                trusteeIdentity: contribution.trusteeIdentity,
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                sameSecretStatementRoot:
                    sameSecretStatement.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatement.trusteeSecretCommitmentRoot,
                shareComponent: 'component-zero-b_i',
                rnsLimbCount: input.qSharePrimes.length,
                shareCoefficientVectorHash512ByLimb:
                    contribution.shareCoefficientVectorHash512ByLimb,
                proofBindingStatus: publicKeyShareProofBindingStatus,
            } as const satisfies Omit<
                PublicKeyShareRecord,
                'publicKeyShareRoot'
            >;

            return {
                ...shareRecordWithoutRoot,
                publicKeyShareRoot: deriveProtocolHash(
                    'PublicKeyShareRoot',
                    shareRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareRecord;
        },
    );
    const shareSetWithoutRoot = {
        objectType: 'PublicKeyShareSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofBindingStatus: publicKeyShareProofBindingStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        publicKeyShareRoots: shareRecords.map((shareRecord) => ({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
        })),
        shareRecords,
    } as const satisfies Omit<PublicKeyShareSet, 'publicKeyShareSetRoot'>;

    return {
        ...shareSetWithoutRoot,
        publicKeyShareSetRoot: deriveProtocolHash(
            'PublicKeyShareRoot',
            shareSetWithoutRoot,
        ),
    } satisfies PublicKeyShareSet;
};

export const createPublicKeyShareProofSet = (
    input: PublicKeyShareProofSetInput,
): PublicKeyShareProofSet => {
    validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    if (
        input.publicKeyShares.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShares.publicKeyCrpRoot !== input.publicKeyCrpRoot ||
        input.publicKeyShares.publicAPolynomialRoot !==
            input.publicAPolynomialRoot ||
        input.publicKeyShares.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot
    ) {
        throw new Error(
            'publicKeyShares must bind the same common randomness and same-secret roots.',
        );
    }
    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareRecords = sortedByRosterPosition(
        input.publicKeyShares.shareRecords,
    );
    if (shareRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one share per participant.',
        );
    }
    const proofRecords = shareRecords.map(
        (shareRecord, expectedRosterPosition) => {
            if (shareRecord.trusteeRosterPosition !== expectedRosterPosition) {
                throw new Error(
                    'publicKeyShares.shareRecords roster positions must be contiguous from zero.',
                );
            }
            const sameSecretStatement = statementsByRosterPosition.get(
                shareRecord.trusteeRosterPosition,
            );
            if (sameSecretStatement === undefined) {
                throw new Error(
                    'publicKeyShares.shareRecords must reference an accepted same-secret statement.',
                );
            }
            if (
                shareRecord.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                shareRecord.sameSecretStatementRoot !==
                    sameSecretStatement.sameSecretStatementRoot ||
                shareRecord.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot
            ) {
                throw new Error(
                    'publicKeyShares.shareRecords must bind the accepted same-secret statement.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'PublicKeyShareProof',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofVerificationStatus: publicKeyShareProofVerificationStatus,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                sameSecretStatementRoot:
                    sameSecretStatement.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatement.trusteeSecretCommitmentRoot,
                rnsLimbCount: input.qSharePrimes.length,
                noWrapRelation:
                    'PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 over lifted integers',
                errorSupport: 'checked-by-public-key-share-lnp-proof-set',
                carryWitnessStatus: 'checked-by-public-key-share-lnp-proof-set',
                proofBytesStatus: 'supplied-by-public-key-share-lnp-proof-set',
            } as const satisfies Omit<
                PublicKeyShareProofRecord,
                'publicKeyShareProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                publicKeyShareProofRoot: deriveProtocolHash(
                    'PublicKeyShareProofRoot',
                    proofRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofVerificationStatus: publicKeyShareProofVerificationStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofRoots: proofRecords.map((proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            publicKeyShareProofRoot: proofRecord.publicKeyShareProofRoot,
        })),
        proofRecords,
    } as const satisfies Omit<
        PublicKeyShareProofSet,
        'publicKeyShareProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        publicKeyShareProofSetRoot: deriveProtocolHash(
            'PublicKeyShareProofRoot',
            proofSetWithoutRoot,
        ),
    } satisfies PublicKeyShareProofSet;
};

const publicKeyShareRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareMaterialSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShares'
    >,
): ReadonlyMap<number, PublicKeyShareRecord> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertProtocolHash(
        input.publicKeyShares.publicKeyShareSetRoot,
        'publicKeyShares.publicKeyShareSetRoot',
    );
    const shareRecords = sortedByRosterPosition(
        input.publicKeyShares.shareRecords,
    );
    if (shareRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one share per participant.',
        );
    }
    const recordsByRosterPosition = new Map<number, PublicKeyShareRecord>();
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        if (shareRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShares.shareRecords roster positions must be contiguous from zero.',
            );
        }
        assertNonEmptyString(
            shareRecord.trusteeIdentity,
            'publicKeyShares.shareRecords.trusteeIdentity',
        );
        assertProtocolHash(
            shareRecord.publicKeyShareRoot,
            'publicKeyShares.shareRecords.publicKeyShareRoot',
        );
        recordsByRosterPosition.set(
            shareRecord.trusteeRosterPosition,
            shareRecord,
        );
    });

    return recordsByRosterPosition;
};

const validatePublicKeyShareMaterialContribution = (
    contribution: PublicKeyShareMaterialContributionInput,
    expectedRosterPosition: number,
    input: PublicKeyShareMaterialSetInput,
    shareRecord: PublicKeyShareRecord,
): readonly PublicKeyShareCoefficientVectorMaterial[] => {
    assertNonEmptyString(contribution.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        contribution.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    if (
        contribution.trusteeRosterPosition !== expectedRosterPosition ||
        contribution.trusteeIdentity !== shareRecord.trusteeIdentity
    ) {
        throw new Error(
            'publicKeyShareMaterialContributions must match accepted public-key share records.',
        );
    }
    if (
        contribution.shareCoefficientVectorsByLimb.length !==
        input.qSharePrimes.length
    ) {
        throw new Error(
            'publicKeyShareMaterialContributions must contain one coefficient vector per Q_share limb.',
        );
    }

    return contribution.shareCoefficientVectorsByLimb.map(
        (coefficientVector, rnsLimbIndex) => {
            const rnsPrime = input.qSharePrimes[rnsLimbIndex];
            if (
                rnsPrime === undefined ||
                coefficientVector.rnsLimbIndex !== rnsLimbIndex ||
                coefficientVector.rnsPrime !== rnsPrime ||
                coefficientVector.component !== 'b_i'
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions limb metadata must follow Q_share order.',
                );
            }
            if (
                coefficientVector.coefficientByteLength !==
                input.ringDegree * 8
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficient byte length must match ringDegree.',
                );
            }
            assertProtocolHash(
                coefficientVector.coefficientVectorHash512,
                'publicKeyShareMaterialContributions.coefficientVectorHash512',
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientVector.coefficientsLeHex,
                input.ringDegree,
                'publicKeyShareMaterialContributions.coefficientsLeHex',
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficients must be canonical residues.',
                );
            }
            const coefficientVectorHash =
                coefficientVectorHash512(coefficients);
            const shareCoefficientHash =
                shareRecord.shareCoefficientVectorHash512ByLimb[rnsLimbIndex];
            if (
                coefficientVector.coefficientVectorHash512 !==
                    coefficientVectorHash ||
                shareCoefficientHash?.coefficientVectorHash512 !==
                    coefficientVectorHash ||
                shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                shareCoefficientHash.rnsPrime !== rnsPrime ||
                shareCoefficientHash.component !== 'b_i'
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficient hash must match the accepted share record.',
                );
            }

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b_i',
                coefficientByteLength: coefficientVector.coefficientByteLength,
                coefficientVectorHash512: coefficientVectorHash,
                coefficientsLeHex: coefficientVector.coefficientsLeHex,
            };
        },
    );
};

export const createPublicKeyShareMaterialSet = (
    input: PublicKeyShareMaterialSetInput,
): PublicKeyShareMaterialSet => {
    validateCommonInput(input);
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    if (
        input.publicKeyShares.participantCount !== input.participantCount ||
        input.publicKeyShares.rnsLimbCount !== input.qSharePrimes.length ||
        input.publicKeyShares.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShares.publicKeyCrpRoot !== input.publicKeyCrpRoot ||
        input.publicKeyShares.publicAPolynomialRoot !==
            input.publicAPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShares must bind the same public-key material input.',
        );
    }
    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const materialContributions = sortedByRosterPosition(
        input.materialContributions,
    );
    if (materialContributions.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterialContributions must contain one contribution per participant.',
        );
    }
    const shareMaterialRecords = materialContributions.map(
        (contribution, expectedRosterPosition) => {
            const shareRecord = shareRecords.get(expectedRosterPosition);
            if (shareRecord === undefined) {
                throw new Error(
                    'publicKeyShareMaterialContributions must reference accepted public-key share records.',
                );
            }
            const shareCoefficientVectorsByLimb =
                validatePublicKeyShareMaterialContribution(
                    contribution,
                    expectedRosterPosition,
                    input,
                    shareRecord,
                );
            const materialRecordWithoutRoot = {
                objectType: 'PublicKeyShareMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofModelStatus: publicKeyShareLnpProofModelStatus,
                materialEncoding: publicKeyShareMaterialEncoding,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                rnsLimbCount: input.qSharePrimes.length,
                ringDegree: input.ringDegree,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                shareCoefficientVectorsByLimb,
            } as const satisfies Omit<
                PublicKeyShareMaterialRecord,
                'publicKeyShareMaterialRoot'
            >;

            return {
                ...materialRecordWithoutRoot,
                publicKeyShareMaterialRoot: deriveProtocolHash(
                    'PublicKeyShareRoot',
                    materialRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareMaterialRecord;
        },
    );
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofModelStatus: publicKeyShareLnpProofModelStatus,
        materialEncoding: publicKeyShareMaterialEncoding,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots: shareMaterialRecords.map(
            (materialRecord) => ({
                trusteeIdentity: materialRecord.trusteeIdentity,
                trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                publicKeyShareMaterialRoot:
                    materialRecord.publicKeyShareMaterialRoot,
            }),
        ),
        shareMaterialRecords,
    } as const satisfies Omit<
        PublicKeyShareMaterialSet,
        'publicKeyShareMaterialSetRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        publicKeyShareMaterialSetRoot: deriveProtocolHash(
            'PublicKeyShareRoot',
            materialSetWithoutRoot,
        ),
    } satisfies PublicKeyShareMaterialSet;
};

const assertCollectivePublicKeySourceBindings = (
    input: CollectivePublicKeyInput,
): void => {
    validateCommonInput(input);
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
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
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareLnpProofs,
        'publicKeyShareLnpProofs',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot ||
        input.publicKeyShares.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareLnpProofs.sameSecretProofSetRoot !==
            input.sameSecretProofs.sameSecretProofSetRoot ||
        input.publicKeyShareLnpProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareLnpProofs.publicKeyShareProofSetRoot !==
            input.publicKeyShareProofs.publicKeyShareProofSetRoot ||
        input.publicKeyShareLnpProofs.publicKeyShareMaterialSetRoot !==
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot
    ) {
        throw new Error(
            'collective public key sources must bind the accepted public-key proof chain.',
        );
    }
    if (
        input.publicKeyShareMaterial.participantCount !==
            input.participantCount ||
        input.publicKeyShareMaterial.rnsLimbCount !==
            input.qSharePrimes.length ||
        input.publicKeyShareMaterial.ringDegree !== input.ringDegree ||
        input.publicKeyShareMaterial.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShareMaterial.publicKeyCrpRoot !==
            input.publicKeyCrpRoot ||
        input.publicKeyShareMaterial.publicAPolynomialRoot !==
            input.publicAPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShareMaterial must bind the collective public-key profile and common randomness.',
        );
    }
};

export const createCollectivePublicKey = (
    input: CollectivePublicKeyInput,
): CollectivePublicKey => {
    assertCollectivePublicKeySourceBindings(input);
    const materialRecords = sortedByRosterPosition(
        input.publicKeyShareMaterial.shareMaterialRecords,
    );
    if (materialRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial must contain one material record per participant.',
        );
    }
    const aggregateCoefficientsByLimb = input.qSharePrimes.map(() =>
        Array.from({ length: input.ringDegree }, () => 0),
    );
    const sourceShareMaterialRoots = materialRecords.map(
        (materialRecord, expectedRosterPosition) => {
            if (
                materialRecord.trusteeRosterPosition !==
                    expectedRosterPosition ||
                materialRecord.rnsLimbCount !== input.qSharePrimes.length ||
                materialRecord.ringDegree !== input.ringDegree ||
                materialRecord.shareCoefficientVectorsByLimb.length !==
                    input.qSharePrimes.length
            ) {
                throw new Error(
                    'publicKeyShareMaterial records must match the collective public-key profile.',
                );
            }
            materialRecord.shareCoefficientVectorsByLimb.forEach(
                (coefficientVector, rnsLimbIndex) => {
                    const rnsPrime = input.qSharePrimes[rnsLimbIndex];
                    const aggregateCoefficients =
                        aggregateCoefficientsByLimb[rnsLimbIndex];
                    if (
                        rnsPrime === undefined ||
                        aggregateCoefficients === undefined ||
                        coefficientVector.rnsLimbIndex !== rnsLimbIndex ||
                        coefficientVector.rnsPrime !== rnsPrime ||
                        coefficientVector.component !== 'b_i' ||
                        coefficientVector.coefficientByteLength !==
                            input.ringDegree * 8
                    ) {
                        throw new Error(
                            'publicKeyShareMaterial coefficient vector metadata must match Q_share order.',
                        );
                    }
                    const coefficients = coefficientVectorFromLittleEndianHex(
                        coefficientVector.coefficientsLeHex,
                        input.ringDegree,
                        'publicKeyShareMaterial.shareCoefficientVectorsByLimb.coefficientsLeHex',
                    );
                    if (
                        coefficients.some(
                            (coefficient) => coefficient >= rnsPrime,
                        ) ||
                        coefficientVector.coefficientVectorHash512 !==
                            coefficientVectorHash512(coefficients)
                    ) {
                        throw new Error(
                            'publicKeyShareMaterial coefficient vectors must be canonical and hash-bound.',
                        );
                    }
                    coefficients.forEach((coefficient, coefficientIndex) => {
                        aggregateCoefficients[coefficientIndex] =
                            (aggregateCoefficients[coefficientIndex] +
                                coefficient) %
                            rnsPrime;
                    });
                },
            );

            return {
                trusteeIdentity: materialRecord.trusteeIdentity,
                trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                publicKeyShareRoot: materialRecord.publicKeyShareRoot,
                publicKeyShareMaterialRoot:
                    materialRecord.publicKeyShareMaterialRoot,
            };
        },
    );
    const aggregateCoefficientVectorsByLimb = aggregateCoefficientsByLimb.map(
        (coefficients, rnsLimbIndex) => {
            const rnsPrime = input.qSharePrimes[rnsLimbIndex];
            if (rnsPrime === undefined) {
                throw new Error('Q_share prime is missing for aggregate limb.');
            }

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b',
                coefficientByteLength: input.ringDegree * 8,
                coefficientVectorHash512:
                    coefficientVectorHash512(coefficients),
                coefficientsLeHex:
                    coefficientVectorToLittleEndianHex(coefficients),
            } as const satisfies CollectivePublicKeyCoefficientVectorMaterial;
        },
    );
    const collectivePublicKeyWithoutRoot = {
        objectType: 'CollectivePublicKey',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofVerificationStatus: publicKeyShareLnpProofVerificationStatus,
        proofModelStatus: publicKeyShareLnpProofModelStatus,
        aggregationStatus: 'lnp-proof-aggregated-claim-accounting-pending',
        materialEncoding: 'embedded-full-collective-public-key-coefficients',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        publicKeyShareMaterialSetRoot:
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        publicKeyShareLnpProofSetRoot:
            input.publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot,
        sourceShareMaterialRoots,
        aggregateCoefficientVectorsByLimb,
    } as const satisfies Omit<CollectivePublicKey, 'collectivePublicKeyRoot'>;

    return {
        ...collectivePublicKeyWithoutRoot,
        collectivePublicKeyRoot: deriveProtocolHash(
            'CollectivePublicKeyRoot',
            collectivePublicKeyWithoutRoot,
        ),
    } satisfies CollectivePublicKey;
};

const publicKeyShareProofRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareLnpProofSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShareProofs'
    >,
): ReadonlyMap<number, PublicKeyShareProofRecord> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertProtocolHash(
        input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        'publicKeyShareProofs.publicKeyShareProofSetRoot',
    );
    const proofRecords = sortedByRosterPosition(
        input.publicKeyShareProofs.proofRecords,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareProofs.proofRecords must contain one proof statement per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        PublicKeyShareProofRecord
    >();
    proofRecords.forEach((proofRecord, expectedRosterPosition) => {
        if (proofRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            proofRecord.publicKeyShareProofRoot,
            'publicKeyShareProofs.proofRecords.publicKeyShareProofRoot',
        );
        recordsByRosterPosition.set(
            proofRecord.trusteeRosterPosition,
            proofRecord,
        );
    });

    return recordsByRosterPosition;
};

const sameSecretProofRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareLnpProofSetInput,
        | 'setupContext'
        | 'participantCount'
        | 'sameSecretConsistency'
        | 'sameSecretProofs'
    >,
): ReadonlyMap<number, SameSecretProofSet['proofRecords'][number]> => {
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot
    ) {
        throw new Error(
            'sameSecretProofs must bind the accepted same-secret statement set.',
        );
    }
    assertProtocolHash(
        input.sameSecretProofs.sameSecretProofSetRoot,
        'sameSecretProofs.sameSecretProofSetRoot',
    );
    const proofRecords = sortedByRosterPosition(
        input.sameSecretProofs.proofRecords,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofs.proofRecords must contain one proof per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        SameSecretProofSet['proofRecords'][number]
    >();
    proofRecords.forEach((proofRecord, expectedRosterPosition) => {
        if (proofRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            proofRecord.sameSecretProofRoot,
            'sameSecretProofs.proofRecords.sameSecretProofRoot',
        );
        recordsByRosterPosition.set(
            proofRecord.trusteeRosterPosition,
            proofRecord,
        );
    });

    return recordsByRosterPosition;
};

const publicKeyShareMaterialRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareLnpProofSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShareMaterial'
    >,
): ReadonlyMap<number, PublicKeyShareMaterialRecord> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    assertProtocolHash(
        input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        'publicKeyShareMaterial.publicKeyShareMaterialSetRoot',
    );
    const materialRecords = sortedByRosterPosition(
        input.publicKeyShareMaterial.shareMaterialRecords,
    );
    if (materialRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial.shareMaterialRecords must contain one material record per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        PublicKeyShareMaterialRecord
    >();
    materialRecords.forEach((materialRecord, expectedRosterPosition) => {
        if (materialRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareMaterial.shareMaterialRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            materialRecord.publicKeyShareMaterialRoot,
            'publicKeyShareMaterial.shareMaterialRecords.publicKeyShareMaterialRoot',
        );
        recordsByRosterPosition.set(
            materialRecord.trusteeRosterPosition,
            materialRecord,
        );
    });

    return recordsByRosterPosition;
};

const validatePublicKeyShareLnpProofMaterial = (
    material: PublicKeyShareLnpProofMaterial,
    expectedTboxParameterProfileHash: ProtocolHash,
    fieldName: string,
): void => {
    if (material.setupProofProfileId !== setupProofProfileId) {
        throw new Error(
            `${fieldName}.setupProofProfileId must match setup proof profile.`,
        );
    }
    if (material.proofFamily !== publicKeyShareProofFamily) {
        throw new Error(`${fieldName}.proofFamily must be public-key share.`);
    }
    if (
        material.proofVerificationStatus !==
        publicKeyShareLnpProofVerificationStatus
    ) {
        throw new Error(
            `${fieldName}.proofVerificationStatus must be the public-key share LNP verification status.`,
        );
    }
    if (material.proofModelStatus !== publicKeyShareLnpProofModelStatus) {
        throw new Error(
            `${fieldName}.proofModelStatus must match public-key share LNP proof model.`,
        );
    }
    if (
        material.publicKeyShareTboxParameterProfileHash !==
        expectedTboxParameterProfileHash
    ) {
        throw new Error(
            `${fieldName}.publicKeyShareTboxParameterProfileHash must match the setup proof profile.`,
        );
    }
    assertProtocolHash(
        material.publicKeyShareTboxParameterProfileHash,
        `${fieldName}.publicKeyShareTboxParameterProfileHash`,
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
    assertNonNegativeSafeInteger(material.challenge, `${fieldName}.challenge`);
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
        const transportedMaterial =
            material as PublicKeyShareLnpTransportedProofBytes;
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

const publicKeyShareLnpProofByteMaterial = (
    material: PublicKeyShareLnpProofMaterial,
): PublicKeyShareLnpProofByteMaterial => {
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(
                'publicKeyShareLnpProofMaterial.proofBytesHex must be a string.',
            );
        }
        return {
            proofBytesHex,
        };
    }

    const transportedMaterial =
        material as PublicKeyShareLnpTransportedProofBytes;

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

const sortedPublicKeyShareLnpProofMaterials = (
    input: Pick<
        PublicKeyShareLnpProofSetInput,
        | 'participantCount'
        | 'proofMaterials'
        | 'publicKeyShareTboxParameterProfileHash'
    >,
): PublicKeyShareLnpProofMaterial[] => {
    const proofMaterials = [...input.proofMaterials].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (proofMaterials.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareLnpProofMaterials must contain one proof per participant.',
        );
    }
    proofMaterials.forEach((proofMaterial, expectedRosterPosition) => {
        validatePublicKeyShareLnpProofMaterial(
            proofMaterial,
            input.publicKeyShareTboxParameterProfileHash,
            `publicKeyShareLnpProofMaterials.${String(expectedRosterPosition)}`,
        );
        if (proofMaterial.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareLnpProofMaterials roster positions must be contiguous from zero.',
            );
        }
    });

    return proofMaterials;
};

export const createPublicKeyShareLnpProofSet = (
    input: PublicKeyShareLnpProofSetInput,
): PublicKeyShareLnpProofSet => {
    validateCommonInput(input);
    assertSetupProofBinding(input.setupProofBinding, 'setupProofBinding');
    assertProtocolHash(
        input.publicKeyShareTboxParameterProfileHash,
        'publicKeyShareTboxParameterProfileHash',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    if (
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'public-key LNP proofs must bind the accepted public-key share, proof statement, and material roots.',
        );
    }
    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const proofStatementRecords =
        publicKeyShareProofRecordsByRosterPosition(input);
    const sameSecretProofRecords =
        sameSecretProofRecordsByRosterPosition(input);
    const materialRecords =
        publicKeyShareMaterialRecordsByRosterPosition(input);
    const proofMaterials = sortedPublicKeyShareLnpProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const statementRecord = statementsByRosterPosition.get(
                expectedRosterPosition,
            );
            const shareRecord = shareRecords.get(expectedRosterPosition);
            const proofStatementRecord = proofStatementRecords.get(
                expectedRosterPosition,
            );
            const sameSecretProofRecord = sameSecretProofRecords.get(
                expectedRosterPosition,
            );
            const materialRecord = materialRecords.get(expectedRosterPosition);
            if (
                statementRecord === undefined ||
                shareRecord === undefined ||
                proofStatementRecord === undefined ||
                sameSecretProofRecord === undefined ||
                materialRecord === undefined
            ) {
                throw new Error(
                    'publicKeyShareLnpProofMaterials must match accepted setup records.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !== shareRecord.trusteeIdentity ||
                proofStatementRecord.publicKeyShareRoot !==
                    shareRecord.publicKeyShareRoot ||
                materialRecord.publicKeyShareRoot !==
                    shareRecord.publicKeyShareRoot ||
                shareRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                proofStatementRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.trusteeSecretCommitmentRoot !==
                    statementRecord.trusteeSecretCommitmentRoot
            ) {
                throw new Error(
                    'publicKeyShareLnpProofMaterials must bind accepted public-key and same-secret records.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'PublicKeyShareLnpProof',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofVerificationStatus:
                    publicKeyShareLnpProofVerificationStatus,
                proofModelStatus: publicKeyShareLnpProofModelStatus,
                setupProofBinding: input.setupProofBinding,
                publicKeyShareTboxParameterProfileHash:
                    input.publicKeyShareTboxParameterProfileHash,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                publicKeyShareProofRoot:
                    proofStatementRecord.publicKeyShareProofRoot,
                publicKeyShareMaterialRoot:
                    materialRecord.publicKeyShareMaterialRoot,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    statementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    sameSecretProofRecord.sameSecretProofFamilyBindingRoot,
                sameSecretProofRoot: sameSecretProofRecord.sameSecretProofRoot,
                statementHash: proofMaterial.statementHash,
                relationCommitmentHash: proofMaterial.relationCommitmentHash,
                tboxCommitmentPrefixHash:
                    proofMaterial.tboxCommitmentPrefixHash,
                challenge: proofMaterial.challenge,
                proofSizeBytes: proofMaterial.proofSizeBytes,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...publicKeyShareLnpProofByteMaterial(proofMaterial),
            } as const satisfies Omit<
                PublicKeyShareLnpProofRecord,
                'publicKeyShareLnpProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                publicKeyShareLnpProofRoot: deriveProtocolHash(
                    'PublicKeyShareProofRoot',
                    proofRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareLnpProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareLnpProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofVerificationStatus: publicKeyShareLnpProofVerificationStatus,
        proofModelStatus: publicKeyShareLnpProofModelStatus,
        setupProofBinding: input.setupProofBinding,
        publicKeyShareTboxParameterProfileHash:
            input.publicKeyShareTboxParameterProfileHash,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        publicKeyShareMaterialSetRoot:
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        publicKeyShareLnpProofRoots: proofRecords.map((proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            publicKeyShareLnpProofRoot: proofRecord.publicKeyShareLnpProofRoot,
        })),
        proofRecords,
    } as const satisfies Omit<
        PublicKeyShareLnpProofSet,
        'publicKeyShareLnpProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        publicKeyShareLnpProofSetRoot: deriveProtocolHash(
            'PublicKeyShareProofRoot',
            proofSetWithoutRoot,
        ),
    } satisfies PublicKeyShareLnpProofSet;
};
