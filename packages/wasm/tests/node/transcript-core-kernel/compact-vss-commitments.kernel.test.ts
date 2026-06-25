import { describe, expect, it } from 'vitest';

import { deriveProtocolHash } from '#packages/crypto/src/index';
import {
    combineCompactVssCommitments,
    compactVssCommitmentDevelopmentScope,
    compactVssCommitmentBinaryFormat,
    compactVssEncodedCommitmentByteLength,
    compactVssCommitmentProfileId,
    compactVssCommitmentRandomnessColumnCount,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageRecipientApprovalBoundary,
    compactVssShareLinkageShamirEvaluationRule,
    computeCompactVssCommitmentFromOpening,
    decodeCompactVssCommitmentBody,
    encodeCompactVssCommitmentBody,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssCoefficientCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentRole,
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

const writeTestLittleEndianU64 = (
    bytes: Uint8Array,
    offset: number,
    value: number,
): void => {
    let remainingValue = BigInt(value);
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        bytes[offset + byteIndex] = Number(remainingValue & 0xffn);
        remainingValue >>= 8n;
    }
};

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

const compactVssParticipantCount = 2;
const compactVssRnsLimbCount = 2;
const compactVssThresholdDegree = 2;
const compactVssRingDegree = 8;

const compactVssPublicMatrixSeedHash = (): string => '7'.repeat(128);

const compactVssRnsPrime = (rnsLimbIndex: number): number =>
    rnsLimbIndex === 0 ? 97 : 193;

const compactVssSeed = (seedParts: readonly number[]): number =>
    seedParts.reduce((seed, seedPart) => seed * 31 + seedPart + 1, 0);

const compactVssTestHashFromSeed = (
    seed: number,
    domainOffset: number,
): string => ((seed + domainOffset) % 16).toString(16).repeat(128);

const compactVssMessageCoefficients = (
    seed: number,
    modulus: number,
): number[] =>
    Array.from(
        { length: compactVssRingDegree },
        (_unused, coefficientIndex) =>
            (seed * 17 + (coefficientIndex + 1) * 19) % modulus,
    );

const compactVssRandomnessByColumn = (seed: number): number[][] =>
    Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unusedColumn, columnIndex) =>
            Array.from(
                { length: compactVssRingDegree },
                (_unusedCoefficient, coefficientIndex) => {
                    const magnitude =
                        (seed + columnIndex * 11 + coefficientIndex * 7) % 29;
                    return (seed + columnIndex + coefficientIndex) % 2 === 0
                        ? magnitude
                        : -magnitude;
                },
            ),
    );

const compactVssTestCommitment = (
    commitmentRole: CompactVssCommitmentRole,
    rnsLimbIndex: number,
    rnsPrime: number,
    seedParts: readonly number[],
): ReturnType<typeof computeCompactVssCommitmentFromOpening> => {
    const seed = compactVssSeed(seedParts);

    return computeCompactVssCommitmentFromOpening({
        commitmentRole,
        commitmentContext: {
            objectType: 'CompactVssTestCommitmentContext',
            objectVersion: 1,
            commitmentRole,
            seedHash: compactVssTestHashFromSeed(seed, 9),
        },
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
        rnsLimbIndex,
        rnsPrime,
        ringDegree: compactVssRingDegree,
        messageCoefficients: compactVssMessageCoefficients(seed, rnsPrime),
        messageCoefficientBound: rnsPrime,
        randomnessByColumn: compactVssRandomnessByColumn(seed),
    });
};

const compactCoefficientCommitment = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): CompactVssCoefficientCommitment => {
    const rnsPrime = compactVssRnsPrime(rnsLimbIndex);
    const commitment = compactVssTestCommitment(
        'coefficient',
        rnsLimbIndex,
        rnsPrime,
        [sourceTrusteeRosterPosition, rnsLimbIndex, shamirCoefficientIndex, 0],
    );

    return {
        objectType: 'CompactVssCoefficientCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
        rnsLimbIndex,
        rnsPrime,
        shamirCoefficientIndex,
        coefficientCommitmentRoot: commitment.commitmentRoot,
        coefficientVectorHash512: commitment.commitment.messageVectorHash512,
        commitment: commitment.commitment,
    };
};

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
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
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
            profileId: compactVssCommitmentProfileId,
            developmentScope: compactVssCommitmentDevelopmentScope,
            publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
            participantCount: compactVssParticipantCount,
            rnsLimbCount: compactVssRnsLimbCount,
            thresholdDegree: compactVssThresholdDegree,
            ringDegree: compactVssRingDegree,
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
): CompactVssRecipientShareCommitment => {
    const rnsPrime = compactVssRnsPrime(rnsLimbIndex);
    const commitment = compactVssTestCommitment(
        'recipient-share',
        rnsLimbIndex,
        rnsPrime,
        [sourceTrusteeRosterPosition, recipientRosterPosition, rnsLimbIndex, 1],
    );

    return {
        objectType: 'CompactVssRecipientShareCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        recipientIdentity: `recipient-${recipientRosterPosition}`,
        recipientRosterPosition,
        recipientTrusteePoint: recipientRosterPosition + 1,
        rnsLimbIndex,
        rnsPrime,
        shareCommitmentRoot: commitment.commitmentRoot,
        shareOpeningRoot: commitment.openingRoot,
        shareVectorHash512: commitment.commitment.messageVectorHash512,
        commitment: commitment.commitment,
    };
};

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
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
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
            profileId: compactVssCommitmentProfileId,
            developmentScope: compactVssCommitmentDevelopmentScope,
            publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
            participantCount: compactVssParticipantCount,
            rnsLimbCount: compactVssRnsLimbCount,
            ringDegree: compactVssRingDegree,
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

const compactSourceShareRecordsForRecipient = (
    recipientSet: CompactVssRecipientShareCommitmentSet,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssRecipientShareCommitment[] => {
    const recipientShareRecordIndex =
        recipientRosterPosition * compactVssRnsLimbCount + rnsLimbIndex;

    return recipientSet.sourceTrusteeRecords.map((sourceRecord) => {
        const recipientShareRecord =
            sourceRecord.recipientShareCommitments[recipientShareRecordIndex];
        if (recipientShareRecord === undefined) {
            throw new Error(
                'compact VSS fixture recipient-share record is missing.',
            );
        }

        return recipientShareRecord;
    });
};

const compactAggregateCommitmentBody = (
    recipientRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
    sourceShareRecords: readonly CompactVssRecipientShareCommitment[],
): ReturnType<typeof combineCompactVssCommitments>['commitment'] => {
    const seed = compactVssSeed([recipientRosterPosition, rnsLimbIndex, 4]);

    return combineCompactVssCommitments({
        commitmentRole: 'aggregate-threshold-share',
        commitmentContext: {
            objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
            objectVersion: 1,
            recipientIdentity: `recipient-${recipientRosterPosition}`,
            recipientRosterPosition,
            recipientTrusteePoint: recipientRosterPosition + 1,
            rnsLimbIndex,
            rnsPrime,
        },
        combinedMessageVectorHash512: compactVssTestHashFromSeed(seed, 1),
        combinedOpeningRandomnessHash512: compactVssTestHashFromSeed(seed, 2),
        terms: sourceShareRecords.map((sourceShareRecord) => ({
            commitment: sourceShareRecord.commitment,
            scalar: 1,
        })),
    }).commitment;
};

const compactAggregateThresholdCommitment = (
    recipientSet: CompactVssRecipientShareCommitmentSet,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssAggregateThresholdCommitment => {
    const rnsPrime = compactVssRnsPrime(rnsLimbIndex);
    const sourceShareRecords = compactSourceShareRecordsForRecipient(
        recipientSet,
        recipientRosterPosition,
        rnsLimbIndex,
    );
    const commitment = compactAggregateCommitmentBody(
        recipientRosterPosition,
        rnsLimbIndex,
        rnsPrime,
        sourceShareRecords,
    );

    return {
        objectType: 'CompactVssAggregateThresholdCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        recipientIdentity: `recipient-${recipientRosterPosition}`,
        recipientRosterPosition,
        recipientTrusteePoint: recipientRosterPosition + 1,
        rnsLimbIndex,
        rnsPrime,
        aggregateCommitmentRoot: deriveProtocolHash(
            'SetupCommitmentRoot',
            commitment,
        ),
        aggregateOpeningRoot: compactVssTestHashFromSeed(
            compactVssSeed([recipientRosterPosition, rnsLimbIndex, 3]),
            0,
        ),
        commitment,
        sourceShareCommitmentRoots: sourceShareRecords.map(
            (sourceShareRecord) => sourceShareRecord.shareCommitmentRoot,
        ),
    };
};

const compactAggregateThresholdCommitmentSet =
    (): CompactVssAggregateThresholdCommitmentSet => {
        const recipientSet = compactRecipientShareCommitmentSet();
        const recipientRecords = [0, 1].flatMap((recipientRosterPosition) =>
            [0, 1].map((rnsLimbIndex) =>
                compactAggregateThresholdCommitment(
                    recipientSet,
                    recipientRosterPosition,
                    rnsLimbIndex,
                ),
            ),
        );
        const setWithoutRoot = {
            objectType: 'CompactVssAggregateThresholdCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            developmentScope: compactVssCommitmentDevelopmentScope,
            publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
            participantCount: compactVssParticipantCount,
            rnsLimbCount: compactVssRnsLimbCount,
            ringDegree: compactVssRingDegree,
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

        const protocolCommitmentBodyBytes = encodeCompactVssCommitmentBody(
            protocolComputation.commitment,
        );
        const kernelCommitmentBodyEncoding =
            kernel.encodeCompactVssCommitmentBody({
                commitment: kernelComputation.commitment,
            });
        const compactCommitmentBodyMetadata: CompactVssCommitmentBodyMetadata =
            {
                commitmentRole: protocolComputation.commitment.commitmentRole,
                commitmentContextHash:
                    protocolComputation.commitment.commitmentContextHash,
                publicMatrixSeedHash:
                    protocolComputation.commitment.publicMatrixSeedHash,
                rnsLimbIndex: protocolComputation.commitment.rnsLimbIndex,
                rnsPrime: protocolComputation.commitment.rnsPrime,
                ringDegree: protocolComputation.commitment.ringDegree,
                messageVectorHash512:
                    protocolComputation.commitment.messageVectorHash512,
                openingRandomnessHash512:
                    protocolComputation.commitment.openingRandomnessHash512,
            };

        expect(kernelCommitmentBodyEncoding).toMatchObject({
            operation: 'encodeCompactVssCommitmentBody',
            binaryFormat: compactVssCommitmentBinaryFormat,
            encodedCommitmentByteLength:
                compactVssEncodedCommitmentByteLength(),
        });
        expect(kernelCommitmentBodyEncoding.commitmentBodyBytes).toEqual(
            protocolCommitmentBodyBytes,
        );

        const kernelCommitmentBodyDecoding =
            kernel.decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes:
                    kernelCommitmentBodyEncoding.commitmentBodyBytes,
            });
        expect(kernelCommitmentBodyDecoding).toMatchObject({
            operation: 'decodeCompactVssCommitmentBody',
            commitmentRoot: protocolComputation.commitmentRoot,
        });
        expect(kernelCommitmentBodyDecoding.commitment).toEqual(
            decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes: protocolCommitmentBodyBytes,
            }),
        );

        expect(() =>
            kernel.decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes:
                    kernelCommitmentBodyEncoding.commitmentBodyBytes.slice(
                        0,
                        -8,
                    ),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const outOfRangeCommitmentBodyBytes =
            kernelCommitmentBodyEncoding.commitmentBodyBytes.slice();
        const firstCommitmentLimb =
            protocolComputation.commitment.commitmentLimbs[0];
        if (firstCommitmentLimb === undefined) {
            throw new Error(
                'compact VSS fixture is missing a commitment limb.',
            );
        }
        writeTestLittleEndianU64(
            outOfRangeCommitmentBodyBytes,
            0,
            firstCommitmentLimb.modulus,
        );
        expect(() =>
            kernel.decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes: outOfRangeCommitmentBodyBytes,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

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

    it('accepts carried aggregate messages within the explicit coefficient bound', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const opening = {
            ...compactVssOpening(),
            messageCoefficients: [1, 2, 98, 4, 5, 6, 7, 8],
            messageCoefficientBound: 194,
        } satisfies BgvCompactVssCommitmentOpeningInput;
        const protocolComputation =
            computeCompactVssCommitmentFromOpening(opening);

        const kernelComputation =
            kernel.computeCompactVssCommitmentFromOpening(opening);

        expect(kernelComputation.commitmentRoot).toBe(
            protocolComputation.commitmentRoot,
        );
        expect(kernelComputation.openingRoot).toBe(
            protocolComputation.openingRoot,
        );

        expect(
            kernel.verifyCompactVssCommitmentOpening({
                opening,
                expectedCommitmentRoot: protocolComputation.commitmentRoot,
            }).commitmentRoot,
        ).toBe(protocolComputation.commitmentRoot);

        expect(() =>
            kernel.computeCompactVssCommitmentFromOpening({
                ...opening,
                messageCoefficients: [
                    ...opening.messageCoefficients.slice(0, 3),
                    194,
                    ...opening.messageCoefficients.slice(4),
                ],
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
