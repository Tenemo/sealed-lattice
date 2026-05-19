import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { BallotProofStatement } from '@sealed-lattice/types';

import ballotFieldLinearProofBackendVectorsJson from '../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json';
import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentLinearProofProjection,
    buildBallotProofComponentProofStatementPlans,
    buildBallotProofRecordGenerationRequest,
    buildBallotProofSparseComponentLinearProofStatement,
    buildPackedFieldSparseComponentLinearProofStatement,
    buildBallotProofStructuredReceiverEncryptionProofStatement,
    buildEncodedScoreFieldLinearProofProjection,
    type BallotProofComponentProjectionWitness,
    type BallotProofRecordGenerationProofContracts,
    type BallotProofRecordGenerationRandomness,
    type BallotProofRecordGenerationRequest,
} from '../../src/ballot-privacy/ballot-proof-linear-statement';
import {
    buildBallotProofStatement,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    type BallotPrivacyRelationCompilerInput,
} from '../../src/ballot-privacy/index';
import {
    createFixtureRandomnessSource,
    createShareCommitmentPolynomialVector,
    deriveShareCommitmentBodyDigest,
    generateReceiverState,
} from '../../src/ballot-privacy/lattice-primitives';
import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyRelationBackendPublicContext,
} from '../../src/ballot-privacy/relation-backend-lowering';

const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-proof-record-generation-fixture',
    });

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const encodedShareVectorForScores = (
    scores: readonly number[],
): readonly number[] =>
    scores.flatMap((score) => [score, ...oneHotScore(score)]);

const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionModulus = 12_289;
const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
const receiverShareRepresentativeBitLength = 17;
const receiverOpeningRandomnessBitLength = 12;
const receiverOpeningEncodingOffset = 1_024;

type ProofParameterSet = {
    readonly coefficientModulus: string;
    readonly proofSystemRingDegree: 64;
    readonly profileId: string;
    readonly relation: 'A*w + t = 0';
    readonly ringDegree: number;
    readonly source: string;
    readonly statementColumns: number;
    readonly statementRows: number;
    readonly witnessL2BoundSquared: number;
};

type ProofEncoding = Record<string, unknown> & {
    readonly profileId: string;
    readonly shortResponseVectorLength: number;
    readonly source: string;
};
export type BallotProofRecordGenerationFixture = {
    readonly proofContracts: BallotProofRecordGenerationProofContracts;
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly randomness: BallotProofRecordGenerationRandomness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly request: BallotProofRecordGenerationRequest;
    readonly statement: BallotProofStatement;
};

type BallotProofRecordGenerationFixtureOptions = {
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly topOptionCount: number;
};

export const cloneJsonValue = <Value>(value: Value): Value =>
    JSON.parse(JSON.stringify(value)) as Value;

const shareCommitmentOpeningForReceiver = (
    receiverRosterPosition: number,
): readonly number[] =>
    Array.from(
        { length: 64 },
        (_unusedValue, openingCoordinateIndex) =>
            ((receiverRosterPosition + openingCoordinateIndex) % 5) - 2,
    );

const unsignedBits = (value: number, bitLength: number): readonly number[] =>
    Array.from(
        { length: bitLength },
        (_unusedValue, bitIndex) => (value >> bitIndex) & 1,
    );

const receiverPayloadPlaintextBitsForTest = (input: {
    readonly openingRandomness: readonly number[];
    readonly receiverShareVector: readonly number[];
}): readonly number[] => [
    ...input.receiverShareVector.flatMap((shareRepresentative) =>
        unsignedBits(shareRepresentative, receiverShareRepresentativeBitLength),
    ),
    ...input.openingRandomness.flatMap((openingCoordinate) =>
        unsignedBits(
            openingCoordinate + receiverOpeningEncodingOffset,
            receiverOpeningRandomnessBitLength,
        ),
    ),
];

const zeroReceiverEncryptionVector = (): readonly (readonly number[])[] =>
    Array.from({ length: receiverEncryptionModuleRank }, () =>
        Array.from({ length: receiverEncryptionModuleDegree }, () => 0),
    );

const zeroReceiverEncryptionPolynomial = (): readonly number[] =>
    Array.from({ length: receiverEncryptionModuleDegree }, () => 0);

const deterministicReceiverPayloadCiphertextForTest = (input: {
    readonly plaintextBits: readonly number[];
    readonly receiverEncryptionProfileDigest: string;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
}): {
    readonly ciphertextBodyDigest: string;
    readonly ciphertextChunkDigest: string;
    readonly ciphertextChunks: readonly {
        readonly chunkIndex: number;
        readonly firstCiphertextVector: readonly (readonly number[])[];
        readonly secondCiphertextPolynomial: readonly number[];
    }[];
    readonly plaintextBitLength: number;
    readonly receiverPayloadCiphertextRoot: string;
    readonly receiverPayloadDigest: string;
    readonly witness: NonNullable<
        BallotProofComponentProjectionWitness['receiverEncryptionWitnesses']
    >[number];
} => {
    const ciphertextChunks = Array.from(
        {
            length: Math.ceil(
                input.plaintextBits.length / receiverEncryptionModuleDegree,
            ),
        },
        (_unusedValue, chunkIndex) => ({
            chunkIndex,
            firstCiphertextVector: zeroReceiverEncryptionVector(),
            secondCiphertextPolynomial: Array.from(
                { length: receiverEncryptionModuleDegree },
                (_unusedCoefficient, coefficientIndex) =>
                    input.plaintextBits[
                        chunkIndex * receiverEncryptionModuleDegree +
                            coefficientIndex
                    ] === 1
                        ? receiverEncryptionMessageScale
                        : 0,
            ),
        }),
    );
    const ciphertextBodyDigest = deriveProtocolDigest(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfileDigest,
        },
    );
    const receiverPayloadCiphertextRoot = deriveProtocolDigest(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextBodyDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );
    const receiverPayloadDigest = deriveProtocolDigest(
        'ReceiverPayloadDigest',
        {
            receiverIdentity: input.receiverIdentity,
            receiverPayloadCiphertextRoot,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );

    return {
        ciphertextBodyDigest,
        ciphertextChunkDigest: deriveProtocolDigest('ChallengeDomainDigest', {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            purpose: 'ballot-proof-record-generation-fixture-ciphertext',
        }),
        ciphertextChunks,
        plaintextBitLength: input.plaintextBits.length,
        receiverPayloadCiphertextRoot,
        receiverPayloadDigest,
        witness: {
            chunkWitnesses: ciphertextChunks.map((ciphertextChunk) => ({
                chunkIndex: ciphertextChunk.chunkIndex,
                encryptionRandomnessVector: zeroReceiverEncryptionVector(),
                firstNoiseVector: zeroReceiverEncryptionVector(),
                secondNoisePolynomial: zeroReceiverEncryptionPolynomial(),
            })),
            receiverRosterPosition: input.receiverRosterPosition,
        },
    };
};

const singleReceiverRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients: Array.from(
        { length: 11 },
        () => [] as const,
    ),
    normalizedScores: [5],
    optionCount: 1,
    pvssThreshold: 1,
    receivers: [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: [5, ...oneHotScore(5)],
        },
    ],
    rosterSize: 1,
    scoreOneHotWitnesses: [oneHotScore(5)],
});

export const mandatoryProfileRelationInput =
    (): BallotPrivacyRelationCompilerInput => {
        const optionCount = 20;
        const pvssThreshold = 7;
        const normalizedScores = Array.from(
            { length: optionCount },
            (_unusedValue, optionIndex) => (optionIndex % 10) + 1,
        );
        const encodedShareVector =
            encodedShareVectorForScores(normalizedScores);
        const encodedCoordinateShamirCoefficients = encodedShareVector.map(
            () =>
                Array.from(
                    { length: pvssThreshold - 1 },
                    () => 0,
                ) as readonly number[],
        );

        return {
            encodedCoordinateShamirCoefficients,
            normalizedScores,
            optionCount,
            pvssThreshold,
            receivers: Array.from(
                { length: optionCount },
                (_unusedValue, receiverIndex) => ({
                    receiverIdentity: `receiver-${receiverIndex + 1}`,
                    receiverRosterPosition: receiverIndex + 1,
                    receiverShareVector: encodedShareVector,
                }),
            ),
            rosterSize: optionCount,
            scoreOneHotWitnesses: normalizedScores.map((score) =>
                oneHotScore(score),
            ),
        };
    };

const publicContextAndProjectionWitness = (
    relationInput: BallotPrivacyRelationCompilerInput,
): {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
} => {
    const profileSet = createBallotPrivacyProfileSet();
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const baseContext = {
        actionContextDigest: digest('action-context'),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        ceremonyId: 'ceremony-proof-record-generation',
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        manifestDigest: digest('manifest'),
        pollSpecDigest: digest('poll-spec'),
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        receiverKeyProofRoot: digest('receiver-key-proof-root'),
        receiverKeyRoot: digest('receiver-key-root'),
        rosterDigest: digest('roster'),
        rosterExternalAcceptanceDigest: digest('external-acceptance'),
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
    };
    const receiverRecords = relationInput.receivers.map((receiver) => {
        const openingRandomness = shareCommitmentOpeningForReceiver(
            receiver.receiverRosterPosition,
        );
        const commitmentPolynomialVector =
            createShareCommitmentPolynomialVector({
                opening: {
                    openingRandomness,
                },
                receiverShareVector: receiver.receiverShareVector,
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
                shareVectorWidth: relationInput.optionCount * 11,
            });
        const receiverState = generateReceiverState({
            ceremonyId: baseContext.ceremonyId,
            manifestDigest: baseContext.manifestDigest,
            randomnessSource: createFixtureRandomnessSource(
                `receiver-key-${receiver.receiverRosterPosition}`,
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
            recoveryEpoch: 0,
            rosterDigest: baseContext.rosterDigest,
        });
        const encryptedPayload = deterministicReceiverPayloadCiphertextForTest({
            plaintextBits: receiverPayloadPlaintextBitsForTest({
                openingRandomness,
                receiverShareVector: receiver.receiverShareVector,
            }),
            receiverEncryptionProfileDigest:
                baseContext.receiverEncryptionProfileDigest,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
        });

        return {
            commitmentPolynomialVector,
            encryptedPayload,
            openingRandomness,
            receiver,
            receiverState,
        };
    });

    return {
        projectionWitness: {
            receiverEncryptionWitnesses: receiverRecords.map(
                ({ encryptedPayload, receiver }) => ({
                    chunkWitnesses: encryptedPayload.witness.chunkWitnesses,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
            receiverPayloadPlaintexts: receiverRecords.map(
                ({ openingRandomness, receiver }) => ({
                    openingRandomness,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                    receiverShareVector: receiver.receiverShareVector,
                }),
            ),
            shareCommitmentOpenings: receiverRecords.map(
                ({ openingRandomness, receiver }) => ({
                    openingRandomness,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        },
        publicContext: {
            ...baseContext,
            receiverPayloads: receiverRecords.map(
                ({ encryptedPayload, receiver }) => ({
                    ciphertextBodyDigest: encryptedPayload.ciphertextBodyDigest,
                    ciphertextChunkCount:
                        encryptedPayload.ciphertextChunks.length,
                    ciphertextChunkDigest:
                        encryptedPayload.ciphertextChunkDigest,
                    ciphertextChunks: encryptedPayload.ciphertextChunks,
                    plaintextBitLength: encryptedPayload.plaintextBitLength,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverPayloadCiphertextRoot:
                        encryptedPayload.receiverPayloadCiphertextRoot,
                    receiverPayloadDigest:
                        encryptedPayload.receiverPayloadDigest,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
            receiverPublicKeys: receiverRecords.map(
                ({ receiver, receiverState }) => ({
                    keyMaterialDigest:
                        receiverState.receiverPublicKey.keyMaterialDigest,
                    publicKeyVector:
                        receiverState.publicKeyMaterial.publicKeyVector,
                    publicMatrixSeedDigest:
                        receiverState.publicKeyMaterial.publicMatrixSeedDigest,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverPublicKeyDigest:
                        receiverState.receiverPublicKey.receiverPublicKeyDigest,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
            shareCommitments: receiverRecords.map(
                ({ commitmentPolynomialVector, receiver }) => {
                    const commitmentBodyDigest =
                        deriveShareCommitmentBodyDigest({
                            commitmentPolynomialVector,
                            shareCommitmentProfileDigest:
                                baseContext.shareCommitmentProfileDigest,
                        });

                    return {
                        commitmentBodyDigest,
                        commitmentPolynomialVector,
                        commitmentPolynomialVectorDigest: deriveProtocolDigest(
                            'ChallengeDomainDigest',
                            {
                                commitmentPolynomialVector,
                                purpose:
                                    'ballot-proof-record-generation-fixture-share-commitment',
                            },
                        ),
                        receiverIdentity: receiver.receiverIdentity,
                        receiverRosterPosition: receiver.receiverRosterPosition,
                        shareCommitmentDigest: deriveProtocolDigest(
                            'ShareCommitmentDigest',
                            {
                                commitmentBodyDigest,
                                receiverIdentity: receiver.receiverIdentity,
                                receiverRosterPosition:
                                    receiver.receiverRosterPosition,
                            },
                        ),
                    };
                },
            ),
        },
    };
};

const ballotProofStatement = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly topOptionCount: number;
}): BallotProofStatement =>
    buildBallotProofStatement({
        actionContextDigest: input.publicContext.actionContextDigest,
        aggregateInputEncodingProfileDigest:
            input.publicContext.aggregateInputEncodingProfileDigest,
        ballotPackageDigest: digest('ballot-package'),
        ballotProofProfileDigest: input.publicContext.ballotProofProfileDigest,
        ballotScoreEncodingProfileDigest:
            input.publicContext.ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            input.publicContext.ballotShareLayoutProfileDigest,
        ceremonyId: input.publicContext.ceremonyId,
        duplicateBallotPolicyDigest: digest('duplicate-ballot-policy'),
        encodedAggregateLayoutDigest:
            input.publicContext.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            input.publicContext.encodedShareVectorLayoutDigest,
        manifestDigest: input.publicContext.manifestDigest,
        optionCount: input.relationInput.optionCount,
        pollSpecDigest: input.publicContext.pollSpecDigest,
        receiverEncryptionProfileDigest:
            input.publicContext.receiverEncryptionProfileDigest,
        receiverKeyProofRoot: input.publicContext.receiverKeyProofRoot,
        receiverKeyRoot: input.publicContext.receiverKeyRoot,
        receiverPayloads: input.publicContext.receiverPayloads.map(
            (receiverPayload) => ({
                receiverIdentity: receiverPayload.receiverIdentity,
                receiverPayloadCiphertextRoot:
                    receiverPayload.receiverPayloadCiphertextRoot,
                receiverPayloadDigest: receiverPayload.receiverPayloadDigest,
                receiverRosterPosition: receiverPayload.receiverRosterPosition,
            }),
        ),
        receiverPublicKeys: input.publicContext.receiverPublicKeys.map(
            (receiverPublicKey) => ({
                receiverIdentity: receiverPublicKey.receiverIdentity,
                receiverPublicKeyDigest:
                    receiverPublicKey.receiverPublicKeyDigest,
                receiverRosterPosition:
                    receiverPublicKey.receiverRosterPosition,
            }),
        ),
        rosterDigest: input.publicContext.rosterDigest,
        rosterExternalAcceptanceDigest:
            input.publicContext.rosterExternalAcceptanceDigest,
        scoreDomainDigest: digest('score-domain'),
        scoreMembershipProfileDigest:
            input.publicContext.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            input.publicContext.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            input.publicContext.shareCommitmentProfileDigest,
        shareCommitments: input.publicContext.shareCommitments.map(
            (shareCommitment) => ({
                receiverIdentity: shareCommitment.receiverIdentity,
                receiverRosterPosition: shareCommitment.receiverRosterPosition,
                shareCommitmentDigest: shareCommitment.shareCommitmentDigest,
            }),
        ),
        thresholdProfileDigest: digest('threshold-profile'),
        tiePolicyDigest: digest('tie-policy'),
        topOptionCount: input.topOptionCount,
        voterIdentityDigest: digest('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyDigest: digest('voter-signing-key'),
    });

const createProofEncoding = (input: {
    readonly profileId: string;
    readonly shortResponseVectorLength: number;
    readonly source: string;
}): ProofEncoding => {
    const baseEncoding = cloneJsonValue(
        (
            ballotFieldLinearProofBackendVectorsJson as {
                readonly proofEncoding: Record<string, unknown>;
            }
        ).proofEncoding,
    );
    delete baseEncoding.expectedProofSizeBytes;

    return {
        ...baseEncoding,
        profileId: input.profileId,
        shortResponseVectorLength: input.shortResponseVectorLength,
        source: input.source,
    };
};

const createParameterSet = (input: {
    readonly coefficientModulus: string;
    readonly profileId: string;
    readonly ringDegree: number;
    readonly source: string;
    readonly statementColumns: number;
    readonly statementRows: number;
    readonly witnessL2BoundSquared: number;
}): ProofParameterSet => ({
    coefficientModulus: input.coefficientModulus,
    profileId: input.profileId,
    proofSystemRingDegree: 64,
    relation: 'A*w + t = 0',
    ringDegree: input.ringDegree,
    source: input.source,
    statementColumns: input.statementColumns,
    statementRows: input.statementRows,
    witnessL2BoundSquared: input.witnessL2BoundSquared,
});

const componentParameterProfileIds: Readonly<
    Record<BallotPrivacyBackendProofComponentId, string>
> = {
    'payload-plaintext-field-component':
        'payload-plaintext-field-linear-compatibility-v1',
    'receiver-encryption-component':
        'receiver-encryption-linear-compatibility-v1',
    'receiver-key-binding-component':
        'receiver-key-binding-linear-compatibility-v1',
    'score-and-shamir-field-component':
        'encoded-score-field-linear-compatibility-v1',
    'share-commitment-component': 'share-commitment-linear-compatibility-v1',
};

const componentEncodingProfileIds: Readonly<
    Record<BallotPrivacyBackendProofComponentId, string>
> = {
    'payload-plaintext-field-component':
        'payload-plaintext-field-linear-proof-encoding-v1',
    'receiver-encryption-component':
        'receiver-encryption-linear-proof-encoding-v1',
    'receiver-key-binding-component':
        'receiver-encryption-linear-proof-encoding-v1',
    'score-and-shamir-field-component':
        'encoded-score-field-linear-proof-encoding-v1',
    'share-commitment-component': 'share-commitment-linear-proof-encoding-v1',
};

const componentProofContracts = (input: {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly statement: BallotProofStatement;
}): BallotProofRecordGenerationProofContracts => {
    const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    });
    if (!loweringResult.ok) {
        throw new Error('Fixture relation should lower.');
    }
    const componentBundleStatement = buildBallotProofComponentBundleStatement({
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        loweredStatement: loweringResult.statement,
    });
    const componentPlans = buildBallotProofComponentProofStatementPlans({
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        componentBundleStatement,
        loweredStatement: loweringResult.statement,
    });
    const componentStatementById = new Map(
        componentBundleStatement.componentStatements.map(
            (componentStatement) => [
                componentStatement.componentId,
                componentStatement,
            ],
        ),
    );
    const componentPlanById = new Map(
        componentPlans.map((componentPlan) => [
            componentPlan.componentId,
            componentPlan,
        ]),
    );
    const proofEncodings = {} as Record<
        BallotPrivacyBackendProofComponentId,
        ProofEncoding
    >;
    const proofParameterSets = {} as Record<
        BallotPrivacyBackendProofComponentId,
        ProofParameterSet
    >;
    const putContract = (
        componentId: BallotPrivacyBackendProofComponentId,
        inputContract: {
            readonly coefficientModulus: string;
            readonly ringDegree: number;
            readonly statementColumns: number;
            readonly statementRows: number;
            readonly witnessL2BoundSquared: number;
        },
    ): void => {
        proofParameterSets[componentId] = createParameterSet({
            coefficientModulus: inputContract.coefficientModulus,
            profileId: componentParameterProfileIds[componentId],
            ringDegree: inputContract.ringDegree,
            source: `sealed-lattice/linear-proof/${componentId}-fixture-parameters-v1`,
            statementColumns: inputContract.statementColumns,
            statementRows: inputContract.statementRows,
            witnessL2BoundSquared: inputContract.witnessL2BoundSquared,
        });
        proofEncodings[componentId] = createProofEncoding({
            profileId: componentEncodingProfileIds[componentId],
            shortResponseVectorLength:
                inputContract.statementColumns *
                    (inputContract.ringDegree / 64) +
                1,
            source: `sealed-lattice/linear-proof/${componentId}-fixture-encoding-v1`,
        });
    };
    if (input.relationInput.optionCount === 1) {
        const scoreProjection = buildEncodedScoreFieldLinearProofProjection({
            ballotProofStatementDigest:
                input.statement.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
            parameterProfileId:
                componentParameterProfileIds[
                    'score-and-shamir-field-component'
                ],
            relationInput: input.relationInput,
            sourceRingDegree: 64,
            witnessL2BoundSquared: '65536',
        });
        putContract('score-and-shamir-field-component', {
            coefficientModulus:
                scoreProjection.linearStatement.coefficientModulus,
            ringDegree: scoreProjection.linearStatement.ringDegree,
            statementColumns: scoreProjection.linearStatement.statementColumns,
            statementRows: scoreProjection.linearStatement.statementRows,
            witnessL2BoundSquared: Number(
                scoreProjection.linearStatement.witnessL2BoundSquared,
            ),
        });
    } else {
        const scoreSparseStatement =
            buildPackedFieldSparseComponentLinearProofStatement({
                ballotProofStatementDigest:
                    input.statement.ballotProofStatementDigest,
                componentId: 'score-and-shamir-field-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    componentParameterProfileIds[
                        'score-and-shamir-field-component'
                    ],
                relationInput: input.relationInput,
                sourceRingDegree: 64,
                witnessL2BoundSquared: '65536',
            });
        putContract('score-and-shamir-field-component', {
            coefficientModulus: scoreSparseStatement.coefficientModulus,
            ringDegree: scoreSparseStatement.sourceRingDegree,
            statementColumns: scoreSparseStatement.statementColumns,
            statementRows: scoreSparseStatement.statementRows,
            witnessL2BoundSquared: Number(
                scoreSparseStatement.witnessL2BoundSquared,
            ),
        });
    }
    for (const componentId of [
        'payload-plaintext-field-component',
        'share-commitment-component',
    ] as const) {
        const ringDegree = 64;
        const witnessL2BoundSquared =
            componentId === 'payload-plaintext-field-component'
                ? '65536'
                : '1048576';
        const sparseStatement =
            componentId === 'payload-plaintext-field-component' &&
            input.relationInput.optionCount > 1
                ? buildPackedFieldSparseComponentLinearProofStatement({
                      ballotProofStatementDigest:
                          input.statement.ballotProofStatementDigest,
                      componentId,
                      loweredStatement: loweringResult.statement,
                      parameterProfileId:
                          componentParameterProfileIds[componentId],
                      relationInput: input.relationInput,
                      sourceRingDegree: 64,
                      witnessL2BoundSquared,
                  })
                : buildBallotProofSparseComponentLinearProofStatement({
                      ballotProofStatementDigest:
                          input.statement.ballotProofStatementDigest,
                      componentId,
                      loweredStatement: loweringResult.statement,
                      parameterProfileId:
                          componentParameterProfileIds[componentId],
                      sourceRingDegree: ringDegree,
                      witnessL2BoundSquared,
                  });
        if (input.relationInput.optionCount === 1) {
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementDigest:
                    input.statement.ballotProofStatementDigest,
                componentId,
                loweredStatement: loweringResult.statement,
                parameterProfileId: componentParameterProfileIds[componentId],
                projectionWitness: input.projectionWitness,
                relationInput: input.relationInput,
                sourceRingDegree: ringDegree,
                witnessL2BoundSquared,
            });
        }
        putContract(componentId, {
            coefficientModulus: sparseStatement.coefficientModulus,
            ringDegree: sparseStatement.sourceRingDegree,
            statementColumns: sparseStatement.statementColumns,
            statementRows: sparseStatement.statementRows,
            witnessL2BoundSquared: Number(
                sparseStatement.witnessL2BoundSquared,
            ),
        });
    }
    const receiverEncryptionStatement =
        buildBallotProofStructuredReceiverEncryptionProofStatement({
            ballotProofStatementDigest:
                input.statement.ballotProofStatementDigest,
            componentStatement:
                componentStatementById.get('receiver-encryption-component') ??
                (() => {
                    throw new Error(
                        'Receiver-encryption component statement should exist.',
                    );
                })(),
            loweredStatement: loweringResult.statement,
            parameterProfileId:
                componentParameterProfileIds['receiver-encryption-component'],
            witnessL2BoundSquared: '65536',
        });
    putContract('receiver-encryption-component', {
        coefficientModulus: receiverEncryptionStatement.coefficientModulus,
        ringDegree: receiverEncryptionStatement.sourceRingDegree,
        statementColumns: receiverEncryptionStatement.statementColumns,
        statementRows: receiverEncryptionStatement.statementRows,
        witnessL2BoundSquared: Number(
            receiverEncryptionStatement.witnessL2BoundSquared,
        ),
    });
    const receiverKeyPlan = componentPlanById.get(
        'receiver-key-binding-component',
    );
    if (receiverKeyPlan === undefined) {
        throw new Error('Receiver-key component plan should exist.');
    }
    putContract('receiver-key-binding-component', {
        coefficientModulus: receiverKeyPlan.coefficientModulus,
        ringDegree: 64,
        statementColumns: 1,
        statementRows: 1,
        witnessL2BoundSquared: 65_536,
    });

    return {
        ballotProofEncoding: createProofEncoding({
            profileId: 'full-encoded-score-ballot-linear-proof-encoding-v1',
            shortResponseVectorLength: 2,
            source: 'sealed-lattice/linear-proof/full-ballot-fixture-encoding-v1',
        }),
        ballotProofParameterSet: createParameterSet({
            coefficientModulus: '65537',
            profileId: 'full-encoded-score-ballot-linear-compatibility-v1',
            ringDegree: 64,
            source: 'sealed-lattice/linear-proof/full-ballot-fixture-parameters-v1',
            statementColumns: 1,
            statementRows: 1,
            witnessL2BoundSquared: 65_536,
        }),
        componentProofEncodings: proofEncodings,
        componentProofParameterSets: proofParameterSets,
    };
};

const deterministicRandomness = (): BallotProofRecordGenerationRandomness => ({
    componentProverRandomnessHexes: {
        'payload-plaintext-field-component': 'a2'.repeat(32),
        'receiver-encryption-component': 'a4'.repeat(32),
        'score-and-shamir-field-component': '07'.repeat(32),
        'share-commitment-component': '0c'.repeat(32),
    },
    componentPublicRandomnessHexes: {
        'payload-plaintext-field-component': '22'.repeat(32),
        'receiver-encryption-component': '44'.repeat(32),
        'receiver-key-binding-component': '55'.repeat(32),
        'score-and-shamir-field-component': '11'.repeat(32),
        'share-commitment-component': '33'.repeat(32),
    },
    proverRandomnessHex: '07'.repeat(32),
    publicRandomnessHex: '00'.repeat(32),
});

const createBallotProofRecordGenerationFixtureWithOptions = (
    options: BallotProofRecordGenerationFixtureOptions,
): BallotProofRecordGenerationFixture => {
    const relationInput = options.relationInput;
    const { projectionWitness, publicContext: contextWithoutStatement } =
        publicContextAndProjectionWitness(relationInput);
    const statement = ballotProofStatement({
        publicContext: contextWithoutStatement,
        relationInput,
        topOptionCount: options.topOptionCount,
    });
    const publicContext = {
        ...contextWithoutStatement,
        ballotProofStatementDigest: statement.ballotProofStatementDigest,
    };
    const proofContracts = componentProofContracts({
        projectionWitness,
        publicContext,
        relationInput,
        statement,
    });
    const randomness = deterministicRandomness();
    const request = buildBallotProofRecordGenerationRequest({
        proofContracts,
        projectionWitness,
        publicContext,
        randomness,
        relationInput,
        statement,
    });

    if (
        request.componentProofInputs.length !==
        ballotPrivacyBackendProofComponentOrder.length
    ) {
        throw new Error('Fixture request should include all components.');
    }

    return {
        proofContracts,
        projectionWitness,
        publicContext,
        randomness,
        relationInput,
        request,
        statement,
    };
};

export const createBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixtureWithOptions({
            relationInput: singleReceiverRelationInput(),
            topOptionCount: 1,
        });

export const createMandatoryProfileBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixtureWithOptions({
            relationInput: mandatoryProfileRelationInput(),
            topOptionCount: 20,
        });

export const createMandatoryProfileBallotProofRecordBenchmarkFixture =
    (): BallotProofRecordGenerationFixture =>
        createMandatoryProfileBallotProofRecordGenerationFixture();

export const createWasmBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixture();
