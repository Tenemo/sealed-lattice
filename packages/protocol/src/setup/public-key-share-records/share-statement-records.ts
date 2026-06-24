import { deriveProtocolHash } from '@sealed-lattice/crypto';

import {
    setupProofProfileId,
    type SameSecretConsistencyStatementRecord,
} from '../same-secret-consistency-records.js';

import {
    publicKeyShareProofBindingStatus,
    publicKeyShareProofFamily,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareProofRecord,
    type PublicKeyShareProofSet,
    type PublicKeyShareProofSetInput,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
    type PublicKeyShareSetInput,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertContextMatches,
    contextFields,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';

export const statementRecordsByRosterPosition = (
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
                errorSupport: 'checked-by-public-key-share-succinct-proof-set',
                proofBytesStatus:
                    'supplied-by-public-key-share-succinct-proof-set',
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

export const publicKeyShareRecordsByRosterPosition = (
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
