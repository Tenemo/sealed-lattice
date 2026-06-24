import { describe, expect, it } from 'vitest';

import { deriveProtocolHash } from '#packages/crypto/src/index';
import {
    compactVssCommitmentBinaryFormat,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageRecipientApprovalBoundary,
    compactVssShareLinkageShamirEvaluationRule,
    computeCompactVssCommitmentFromOpening,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssCoefficientCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageStatement,
} from '#packages/protocol/src/setup/compact-vss-commitments';
import {
    compactVssSameSecretBridgeIntegerSupport,
    compactVssSameSecretBridgeSignedRepresentativeConvention,
    compactVssSameSecretBridgeTargetBasisLimbOrder,
    verifyCompactVssSameSecretBridgeStatementSet,
    type CompactVssSameSecretBridgeStatementRecord,
    type CompactVssSameSecretBridgeStatementSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    TranscriptCoreKernelCommandError,
    type BgvCompactVssCommitmentOpeningInput,
} from '#packages/wasm/src/transcript-core-bridge';

const compactVssOpening = (): BgvCompactVssCommitmentOpeningInput => ({
    commitmentRole: 'aggregate-threshold-share',
    commitmentContext: {
        objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
        objectVersion: 1,
        ceremonyId: 'compact-vss-wasm-test',
        manifestHash: '1'.repeat(128),
        rosterHash: '2'.repeat(128),
        setupProfileHash: '3'.repeat(128),
        qShareHash: '4'.repeat(128),
        carryAwareVssShareRelationProfileHash: '5'.repeat(128),
        commitmentProfileHash: '6'.repeat(128),
        setupEpoch: 'setup-epoch',
        recipientIdentity: 'trustee-1',
        recipientRosterPosition: 0,
        rnsLimbIndex: 0,
        rnsPrime: 97,
    },
    publicMatrixSeedHash: '7'.repeat(128),
    rnsLimbIndex: 0,
    rnsPrime: 97,
    ringDegree: 8,
    messageCoefficients: [1, 2, 3, 4, 5, 6, 7, 8],
    randomnessByColumn: [
        [0, 1, -1, 2, -2, 3, -3, 4],
        [5, -5, 6, -6, 7, -7, 8, -8],
    ],
});

const compactShareLinkageStatement = (): CompactVssShareLinkageStatement => {
    const sourceStatementRecords = [0, 1].map((sourceTrusteeRosterPosition) => {
        const sourceStatementWithoutRoot = {
            objectType: 'CompactVssShareLinkageSourceStatement',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            ceremonyId: 'compact-vss-wasm-test',
            manifestHash: '1'.repeat(128),
            rosterHash: '2'.repeat(128),
            setupProfileHash: '3'.repeat(128),
            qShareHash: '4'.repeat(128),
            carryAwareVssShareRelationProfileHash: '5'.repeat(128),
            commitmentProfileHash: '6'.repeat(128),
            setupEpoch: 'setup-epoch',
            publicMatrixSeedHash: '7'.repeat(128),
            targetBasisHash: '8'.repeat(128),
            sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
            sourceTrusteeRosterPosition,
            participantCount: 2,
            targetRnsLimbCount: 2,
            thresholdDegree: 2,
            coefficientCommitmentRoot: '9'.repeat(128),
            sourceCoefficientCommitmentRoot:
                sourceTrusteeRosterPosition === 0
                    ? 'c'.repeat(128)
                    : 'd'.repeat(128),
            sourceRecipientShareCommitmentRoot:
                sourceTrusteeRosterPosition === 0
                    ? 'e'.repeat(128)
                    : 'f'.repeat(128),
            aggregateThresholdCommitmentRoot: 'b'.repeat(128),
            relation:
                'recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments',
            proofBatchingRule: compactVssShareLinkageProofBatchingRule,
            shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
            aggregateThresholdRule:
                compactVssShareLinkageAggregateThresholdRule,
            commonKeyRule: compactVssShareLinkageCommonKeyRule,
            recipientApprovalBoundary:
                compactVssShareLinkageRecipientApprovalBoundary,
            proofBoundary:
                'statement binding only; zero-knowledge linkage proof backend is not implemented yet',
        };

        return {
            ...sourceStatementWithoutRoot,
            sourceStatementRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                sourceStatementWithoutRoot,
            ),
        };
    });
    const statementWithoutRoot = {
        objectType: 'CompactVssShareLinkageStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
        developmentScope: 'development-only-not-certified-for-production-use',
        ceremonyId: 'compact-vss-wasm-test',
        manifestHash: '1'.repeat(128),
        rosterHash: '2'.repeat(128),
        setupProfileHash: '3'.repeat(128),
        qShareHash: '4'.repeat(128),
        carryAwareVssShareRelationProfileHash: '5'.repeat(128),
        commitmentProfileHash: '6'.repeat(128),
        setupEpoch: 'setup-epoch',
        publicMatrixSeedHash: '7'.repeat(128),
        targetBasisHash: '8'.repeat(128),
        participantCount: 2,
        targetRnsLimbCount: 2,
        thresholdDegree: 2,
        coefficientCommitmentRoot: '9'.repeat(128),
        recipientShareCommitmentRoot: 'a'.repeat(128),
        aggregateThresholdCommitmentRoot: 'b'.repeat(128),
        relation:
            'recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments',
        proofBatchingRule: compactVssShareLinkageProofBatchingRule,
        shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
        aggregateThresholdRule: compactVssShareLinkageAggregateThresholdRule,
        commonKeyRule: compactVssShareLinkageCommonKeyRule,
        recipientApprovalBoundary:
            compactVssShareLinkageRecipientApprovalBoundary,
        proofBoundary:
            'statement binding only; zero-knowledge linkage proof backend is not implemented yet',
        sourceStatementRecords,
    };

    return {
        ...statementWithoutRoot,
        statementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementWithoutRoot,
        ),
    } as CompactVssShareLinkageStatement;
};

type CompactVssSourceCoefficientCommitments =
    CompactVssCoefficientCommitmentSet['sourceTrusteeRecords'][number];
type CompactVssCoefficientCommitment =
    CompactVssSourceCoefficientCommitments['coefficientCommitments'][number];
type CompactVssSourceRecipientShareCommitments =
    CompactVssRecipientShareCommitmentSet['sourceTrusteeRecords'][number];
type CompactVssRecipientShareCommitment =
    CompactVssSourceRecipientShareCommitments['recipientShareCommitments'][number];
type CompactVssAggregateThresholdCommitment =
    CompactVssAggregateThresholdCommitmentSet['recipientRecords'][number];

const compactVssTestHash = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    domainOffset: number,
): string =>
    (
        (sourceTrusteeRosterPosition * 4 +
            rnsLimbIndex * 2 +
            shamirCoefficientIndex +
            domainOffset) %
        16
    )
        .toString(16)
        .repeat(128);

const compactCoefficientCommitment = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): CompactVssCoefficientCommitment => ({
    objectType: 'CompactVssCoefficientCommitment',
    objectVersion: 1,
    profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
    developmentScope: 'development-only-not-certified-for-production-use',
    sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
    sourceTrusteeRosterPosition,
    publicMatrixSeedHash: '7'.repeat(128),
    rnsLimbIndex,
    rnsPrime: rnsLimbIndex === 0 ? 97 : 193,
    shamirCoefficientIndex,
    coefficientCommitmentRoot: compactVssTestHash(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        0,
    ),
    coefficientVectorHash512: compactVssTestHash(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        1,
    ),
});

const compactSourceCoefficientRecord = (
    sourceTrusteeRosterPosition: number,
): CompactVssSourceCoefficientCommitments => {
    const coefficientCommitments = [0, 1].flatMap((rnsLimbIndex) =>
        [0, 1].map((shamirCoefficientIndex) =>
            compactCoefficientCommitment(
                sourceTrusteeRosterPosition,
                rnsLimbIndex,
                shamirCoefficientIndex,
            ),
        ),
    );
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceCoefficientCommitments',
        objectVersion: 1,
        profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
        developmentScope: 'development-only-not-certified-for-production-use',
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash: '7'.repeat(128),
        coefficientCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactCoefficientCommitmentSet =
    (): CompactVssCoefficientCommitmentSet => {
        const sourceTrusteeRecords = [
            compactSourceCoefficientRecord(0),
            compactSourceCoefficientRecord(1),
        ];
        const setWithoutRoot = {
            objectType: 'CompactVssCoefficientCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            publicMatrixSeedHash: '7'.repeat(128),
            participantCount: 2,
            rnsLimbCount: 2,
            thresholdDegree: 2,
            ringDegree: 8,
            sourceTrusteeRecords,
        } as const;

        return {
            ...setWithoutRoot,
            coefficientCommitmentRoot: deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                setWithoutRoot,
            ),
        };
    };

const compactRecipientShareCommitment = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssRecipientShareCommitment => ({
    objectType: 'CompactVssRecipientShareCommitment',
    objectVersion: 1,
    profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
    developmentScope: 'development-only-not-certified-for-production-use',
    sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
    sourceTrusteeRosterPosition,
    recipientIdentity: `recipient-${recipientRosterPosition}`,
    recipientRosterPosition,
    recipientTrusteePoint: recipientRosterPosition + 1,
    rnsLimbIndex,
    rnsPrime: rnsLimbIndex === 0 ? 97 : 193,
    shareCommitmentRoot: compactVssTestHash(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        recipientRosterPosition,
        0,
    ),
    shareOpeningRoot: compactVssTestHash(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        recipientRosterPosition,
        1,
    ),
    shareVectorHash512: compactVssTestHash(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        recipientRosterPosition,
        2,
    ),
});

const compactSourceRecipientShareRecord = (
    sourceTrusteeRosterPosition: number,
): CompactVssSourceRecipientShareCommitments => {
    const recipientShareCommitments = [0, 1].flatMap(
        (recipientRosterPosition) =>
            [0, 1].map((rnsLimbIndex) =>
                compactRecipientShareCommitment(
                    sourceTrusteeRosterPosition,
                    recipientRosterPosition,
                    rnsLimbIndex,
                ),
            ),
    );
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceRecipientShareCommitments',
        objectVersion: 1,
        profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
        developmentScope: 'development-only-not-certified-for-production-use',
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        recipientShareCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceRecipientShareCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactRecipientShareCommitmentSet =
    (): CompactVssRecipientShareCommitmentSet => {
        const sourceTrusteeRecords = [
            compactSourceRecipientShareRecord(0),
            compactSourceRecipientShareRecord(1),
        ];
        const setWithoutRoot = {
            objectType: 'CompactVssRecipientShareCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            publicMatrixSeedHash: '7'.repeat(128),
            participantCount: 2,
            rnsLimbCount: 2,
            ringDegree: 8,
            sourceTrusteeRecords,
        } as const;

        return {
            ...setWithoutRoot,
            recipientShareCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                setWithoutRoot,
            ),
        };
    };

const compactAggregateThresholdCommitment = (
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssAggregateThresholdCommitment => ({
    objectType: 'CompactVssAggregateThresholdCommitment',
    objectVersion: 1,
    profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
    developmentScope: 'development-only-not-certified-for-production-use',
    recipientIdentity: `recipient-${recipientRosterPosition}`,
    recipientRosterPosition,
    recipientTrusteePoint: recipientRosterPosition + 1,
    rnsLimbIndex,
    rnsPrime: rnsLimbIndex === 0 ? 97 : 193,
    aggregateCommitmentRoot: compactVssTestHash(
        recipientRosterPosition,
        rnsLimbIndex,
        0,
        3,
    ),
    aggregateOpeningRoot: compactVssTestHash(
        recipientRosterPosition,
        rnsLimbIndex,
        0,
        4,
    ),
    sourceShareCommitmentRoots: [
        compactVssTestHash(0, rnsLimbIndex, recipientRosterPosition, 0),
        compactVssTestHash(1, rnsLimbIndex, recipientRosterPosition, 0),
    ],
});

const compactAggregateThresholdCommitmentSet =
    (): CompactVssAggregateThresholdCommitmentSet => {
        const recipientRecords = [0, 1].flatMap((recipientRosterPosition) =>
            [0, 1].map((rnsLimbIndex) =>
                compactAggregateThresholdCommitment(
                    recipientRosterPosition,
                    rnsLimbIndex,
                ),
            ),
        );
        const setWithoutRoot = {
            objectType: 'CompactVssAggregateThresholdCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            publicMatrixSeedHash: '7'.repeat(128),
            participantCount: 2,
            rnsLimbCount: 2,
            ringDegree: 8,
            recipientRecords,
        } as const;

        return {
            ...setWithoutRoot,
            aggregateThresholdCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                setWithoutRoot,
            ),
        };
    };

const compactSameSecretBridgeStatementRecord = (
    trusteeRosterPosition: number,
): CompactVssSameSecretBridgeStatementRecord => {
    const statementWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId:
            'SealedLattice-CompactLinearCommitment-Development-v1',
        developmentScope: 'development-only-not-certified-for-production-use',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ceremonyId: 'compact-vss-wasm-test',
        manifestHash: '1'.repeat(128),
        rosterHash: '2'.repeat(128),
        setupProfileHash: '3'.repeat(128),
        qShareHash: '4'.repeat(128),
        carryAwareVssShareRelationProfileHash: '5'.repeat(128),
        commitmentProfileHash: '6'.repeat(128),
        setupEpoch: 'setup-epoch',
        targetBasisHash: '7'.repeat(128),
        publicMatrixSeedHash: '8'.repeat(128),
        trusteeIdentity: `trustee-${trusteeRosterPosition}`,
        trusteeRosterPosition,
        sameSecretStatementRoot:
            trusteeRosterPosition === 0 ? '9'.repeat(128) : 'a'.repeat(128),
        sameSecretProofRoot:
            trusteeRosterPosition === 0 ? 'b'.repeat(128) : 'c'.repeat(128),
        trusteeSecretCommitmentRoot:
            trusteeRosterPosition === 0 ? 'd'.repeat(128) : 'e'.repeat(128),
        sameSecretProofFamilyBindingRoot: 'f'.repeat(128),
        dataBasisRelation:
            'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        targetConstantCoefficientCommitmentRoots: [
            {
                rnsLimbIndex: 0,
                rnsPrime: 97,
                shamirCoefficientIndex: 0,
                coefficientCommitmentRoot:
                    trusteeRosterPosition === 0
                        ? 'a'.repeat(128)
                        : 'b'.repeat(128),
            },
            {
                rnsLimbIndex: 1,
                rnsPrime: 193,
                shamirCoefficientIndex: 0,
                coefficientCommitmentRoot:
                    trusteeRosterPosition === 0
                        ? 'c'.repeat(128)
                        : 'd'.repeat(128),
            },
        ],
        relation:
            'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof',
        proofBoundary:
            'statement binding only; same-secret bridge proof backend is not implemented yet',
    } as const;

    return {
        ...statementWithoutRoot,
        compactSameSecretBridgeStatementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementWithoutRoot,
        ),
    };
};

const compactSameSecretBridgeStatementSet =
    (): CompactVssSameSecretBridgeStatementSet => {
        const statementRecords = [
            compactSameSecretBridgeStatementRecord(0),
            compactSameSecretBridgeStatementRecord(1),
        ];
        const statementSetWithoutRoot = {
            objectType: 'CompactVssSameSecretBridgeStatementSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            compactCommitmentProfileId:
                'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: 'same-secret-linkage-anchor',
            ceremonyId: 'compact-vss-wasm-test',
            manifestHash: '1'.repeat(128),
            rosterHash: '2'.repeat(128),
            setupProfileHash: '3'.repeat(128),
            qShareHash: '4'.repeat(128),
            carryAwareVssShareRelationProfileHash: '5'.repeat(128),
            commitmentProfileHash: '6'.repeat(128),
            setupEpoch: 'setup-epoch',
            targetBasisHash: '7'.repeat(128),
            publicMatrixSeedHash: '8'.repeat(128),
            participantCount: 2,
            targetRnsLimbCount: 2,
            thresholdDegree: 4,
            compactCoefficientCommitmentRoot: '9'.repeat(128),
            sameSecretConsistencyRoot: 'a'.repeat(128),
            sameSecretProofSetRoot: 'b'.repeat(128),
            sameSecretProofFamilyBindingRoot: 'f'.repeat(128),
            integerSupport: compactVssSameSecretBridgeIntegerSupport,
            signedRepresentativeConvention:
                compactVssSameSecretBridgeSignedRepresentativeConvention,
            compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
            targetBasisLimbOrder:
                compactVssSameSecretBridgeTargetBasisLimbOrder,
            statementRecords,
        } as const;

        return {
            ...statementSetWithoutRoot,
            compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                statementSetWithoutRoot,
            ),
        };
    };

describe('compact VSS commitment kernel commands', () => {
    it('match the TypeScript compact commitment implementation', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const opening = compactVssOpening();
        const protocolComputation =
            computeCompactVssCommitmentFromOpening(opening);

        const kernelComputation =
            kernel.computeCompactVssCommitmentFromOpening(opening);

        expect(kernelComputation.operation).toBe(
            'computeCompactVssCommitmentFromOpening',
        );
        expect(kernelComputation.encodedCommitmentByteLength).toBe(384);
        expect(kernelComputation.commitmentRoot).toBe(
            protocolComputation.commitmentRoot,
        );
        expect(kernelComputation.openingRoot).toBe(
            protocolComputation.openingRoot,
        );
        expect(kernelComputation.commitmentContextHash).toBe(
            protocolComputation.commitmentContextHash,
        );
        expect(kernelComputation.commitment).toEqual(
            protocolComputation.commitment,
        );

        const verification = kernel.verifyCompactVssCommitmentOpening({
            opening,
            expectedCommitmentRoot: protocolComputation.commitmentRoot,
        });
        expect(verification).toMatchObject({
            operation: 'verifyCompactVssCommitmentOpening',
            commitmentRoot: protocolComputation.commitmentRoot,
            openingRoot: protocolComputation.openingRoot,
        });

        expect(() =>
            kernel.verifyCompactVssCommitmentOpening({
                opening: {
                    ...opening,
                    messageCoefficients: [
                        ...opening.messageCoefficients.slice(0, 3),
                        12,
                        ...opening.messageCoefficients.slice(4),
                    ],
                },
                expectedCommitmentRoot: protocolComputation.commitmentRoot,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact share-linkage statement roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const statement = compactShareLinkageStatement();
        const protocolStatement = verifyCompactVssShareLinkageStatement({
            statement,
        });

        const verification = kernel.verifyCompactVssShareLinkageStatement({
            statement,
        });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssShareLinkageStatement',
            statementRoot: protocolStatement.statementRoot,
            publicMatrixSeedHash: protocolStatement.publicMatrixSeedHash,
            targetBasisHash: protocolStatement.targetBasisHash,
            coefficientCommitmentRoot:
                protocolStatement.coefficientCommitmentRoot,
            recipientShareCommitmentRoot:
                protocolStatement.recipientShareCommitmentRoot,
            aggregateThresholdCommitmentRoot:
                protocolStatement.aggregateThresholdCommitmentRoot,
            participantCount: protocolStatement.participantCount,
            targetRnsLimbCount: protocolStatement.targetRnsLimbCount,
            thresholdDegree: protocolStatement.thresholdDegree,
            proofBatchingRule: compactVssShareLinkageProofBatchingRule,
            shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
            aggregateThresholdRule:
                compactVssShareLinkageAggregateThresholdRule,
            commonKeyRule: compactVssShareLinkageCommonKeyRule,
            recipientApprovalBoundary:
                compactVssShareLinkageRecipientApprovalBoundary,
        });

        expect(() =>
            kernel.verifyCompactVssShareLinkageStatement({
                statement: {
                    ...statement,
                    aggregateThresholdCommitmentRoot: 'c'.repeat(128),
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact coefficient commitment set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const coefficientCommitmentSet = compactCoefficientCommitmentSet();
        const protocolCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
            coefficientCommitmentSet,
        });

        const verification = kernel.verifyCompactVssCoefficientCommitmentSet({
            coefficientCommitmentSet,
        });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssCoefficientCommitmentSet',
            coefficientCommitmentRoot:
                protocolCommitmentSet.coefficientCommitmentRoot,
            publicMatrixSeedHash: protocolCommitmentSet.publicMatrixSeedHash,
            participantCount: protocolCommitmentSet.participantCount,
            rnsLimbCount: protocolCommitmentSet.rnsLimbCount,
            thresholdDegree: protocolCommitmentSet.thresholdDegree,
            ringDegree: protocolCommitmentSet.ringDegree,
        });

        const [firstSourceRecord, secondSourceRecord] =
            coefficientCommitmentSet.sourceTrusteeRecords;
        if (
            firstSourceRecord === undefined ||
            secondSourceRecord === undefined
        ) {
            throw new Error(
                'compact coefficient commitment set must include two source records',
            );
        }
        const targetCoefficient = secondSourceRecord.coefficientCommitments[2];
        if (targetCoefficient === undefined) {
            throw new Error(
                'compact coefficient source record must include the target coefficient',
            );
        }

        expect(() =>
            kernel.verifyCompactVssCoefficientCommitmentSet({
                coefficientCommitmentSet: {
                    ...coefficientCommitmentSet,
                    sourceTrusteeRecords: [
                        firstSourceRecord,
                        {
                            ...secondSourceRecord,
                            coefficientCommitments: [
                                ...secondSourceRecord.coefficientCommitments.slice(
                                    0,
                                    2,
                                ),
                                {
                                    ...targetCoefficient,
                                    coefficientCommitmentRoot: '0'.repeat(128),
                                },
                                ...secondSourceRecord.coefficientCommitments.slice(
                                    3,
                                ),
                            ],
                        },
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact recipient-share commitment set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const recipientShareCommitmentSet =
            compactRecipientShareCommitmentSet();
        const protocolCommitmentSet =
            verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet,
            });

        const verification = kernel.verifyCompactVssRecipientShareCommitmentSet(
            {
                recipientShareCommitmentSet,
            },
        );

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssRecipientShareCommitmentSet',
            recipientShareCommitmentRoot:
                protocolCommitmentSet.recipientShareCommitmentRoot,
            publicMatrixSeedHash: protocolCommitmentSet.publicMatrixSeedHash,
            participantCount: protocolCommitmentSet.participantCount,
            rnsLimbCount: protocolCommitmentSet.rnsLimbCount,
            ringDegree: protocolCommitmentSet.ringDegree,
        });

        const [firstSourceRecord, secondSourceRecord] =
            recipientShareCommitmentSet.sourceTrusteeRecords;
        if (
            firstSourceRecord === undefined ||
            secondSourceRecord === undefined
        ) {
            throw new Error(
                'compact recipient-share commitment set must include two source records',
            );
        }
        const firstRecipientShareCommitment =
            firstSourceRecord.recipientShareCommitments[0];
        const targetRecipientShareCommitment =
            firstSourceRecord.recipientShareCommitments[1];
        if (
            firstRecipientShareCommitment === undefined ||
            targetRecipientShareCommitment === undefined
        ) {
            throw new Error(
                'compact recipient-share source record must include the target share',
            );
        }

        expect(() =>
            kernel.verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet: {
                    ...recipientShareCommitmentSet,
                    sourceTrusteeRecords: [
                        {
                            ...firstSourceRecord,
                            recipientShareCommitments: [
                                firstRecipientShareCommitment,
                                {
                                    ...targetRecipientShareCommitment,
                                    shareCommitmentRoot: 'f'.repeat(128),
                                },
                                ...firstSourceRecord.recipientShareCommitments.slice(
                                    2,
                                ),
                            ],
                        },
                        secondSourceRecord,
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact aggregate-threshold commitment set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const aggregateThresholdCommitmentSet =
            compactAggregateThresholdCommitmentSet();
        const protocolCommitmentSet =
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet,
            });

        const verification =
            kernel.verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet,
            });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssAggregateThresholdCommitmentSet',
            aggregateThresholdCommitmentRoot:
                protocolCommitmentSet.aggregateThresholdCommitmentRoot,
            publicMatrixSeedHash: protocolCommitmentSet.publicMatrixSeedHash,
            participantCount: protocolCommitmentSet.participantCount,
            rnsLimbCount: protocolCommitmentSet.rnsLimbCount,
            ringDegree: protocolCommitmentSet.ringDegree,
        });

        const [firstRecipientRecord, ...remainingRecipientRecords] =
            aggregateThresholdCommitmentSet.recipientRecords;
        if (firstRecipientRecord === undefined) {
            throw new Error(
                'compact aggregate-threshold commitment set must include one recipient record',
            );
        }

        expect(() =>
            kernel.verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet: {
                    ...aggregateThresholdCommitmentSet,
                    recipientRecords: [
                        {
                            ...firstRecipientRecord,
                            aggregateCommitmentRoot: 'f'.repeat(128),
                        },
                        ...remainingRecipientRecords,
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact same-secret bridge statement-set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const statementSet = compactSameSecretBridgeStatementSet();
        const protocolStatementSet =
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet,
            });

        const verification =
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet,
            });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssSameSecretBridgeStatementSet',
            compactSameSecretBridgeStatementSetRoot:
                protocolStatementSet.compactSameSecretBridgeStatementSetRoot,
            participantCount: protocolStatementSet.participantCount,
            targetRnsLimbCount: protocolStatementSet.targetRnsLimbCount,
            thresholdDegree: protocolStatementSet.thresholdDegree,
            targetBasisHash: protocolStatementSet.targetBasisHash,
            publicMatrixSeedHash: protocolStatementSet.publicMatrixSeedHash,
            compactCoefficientCommitmentRoot:
                protocolStatementSet.compactCoefficientCommitmentRoot,
            sameSecretConsistencyRoot:
                protocolStatementSet.sameSecretConsistencyRoot,
            sameSecretProofSetRoot: protocolStatementSet.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                protocolStatementSet.sameSecretProofFamilyBindingRoot,
            integerSupport: compactVssSameSecretBridgeIntegerSupport,
            signedRepresentativeConvention:
                compactVssSameSecretBridgeSignedRepresentativeConvention,
            compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
            targetBasisLimbOrder:
                compactVssSameSecretBridgeTargetBasisLimbOrder,
        });

        const [firstStatementRecord, ...remainingStatementRecords] =
            statementSet.statementRecords;
        if (firstStatementRecord === undefined) {
            throw new Error(
                'compact same-secret bridge statement set must include one statement record',
            );
        }
        const [firstTargetConstantRoot, ...remainingTargetConstantRoots] =
            firstStatementRecord.targetConstantCoefficientCommitmentRoots;
        if (firstTargetConstantRoot === undefined) {
            throw new Error(
                'compact same-secret bridge statement must include one target constant root',
            );
        }

        expect(() =>
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: {
                    ...statementSet,
                    statementRecords: [
                        {
                            ...firstStatementRecord,
                            targetConstantCoefficientCommitmentRoots: [
                                {
                                    ...firstTargetConstantRoot,
                                    coefficientCommitmentRoot: '0'.repeat(128),
                                },
                                ...remainingTargetConstantRoots,
                            ],
                        },
                        ...remainingStatementRecords,
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });
});
