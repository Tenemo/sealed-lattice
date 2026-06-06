import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupProofProfileId,
    type SameSecretConsistencyStatementRecord,
    type SameSecretConsistencyStatementSet,
} from './same-secret-consistency-records.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const publicKeyShareProofFamily = 'public-key-share';
export const publicKeyShareProofVerificationStatus =
    'lnp-proof-verification-pending';
export const publicKeyShareProofBindingStatus =
    'public-key-share-proof-required';

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
        readonly errorSupport: 'accepted-error-support-pending-certificate';
        readonly carryWitnessStatus: 'bounded-lifted-carry-proof-pending';
        readonly proofBytesStatus: 'not-accepted-until-setup-proof-verifier';
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

const protocolHashPattern = /^[0-9a-f]{128}$/u;
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
                errorSupport: 'accepted-error-support-pending-certificate',
                carryWitnessStatus: 'bounded-lifted-carry-proof-pending',
                proofBytesStatus: 'not-accepted-until-setup-proof-verifier',
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
