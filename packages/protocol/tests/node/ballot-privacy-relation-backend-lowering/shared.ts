// Shared ballot privacy relation lowering fixtures.
import { deriveProtocolDigest } from '@sealed-lattice/crypto';

import { type BallotProofComponentProjectionWitness } from '../../../src/ballot-privacy/ballot-proof-linear-statement';
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    type BallotPrivacyRelationCompilerInput,
} from '../../../src/ballot-privacy/index';
import {
    createFixtureRandomnessSource,
    createShareCommitmentPolynomialVector,
    deriveShareCommitmentBodyDigest,
    generateReceiverState,
} from '../../../src/ballot-privacy/lattice-primitives';
import {
    receiverEncryptionMessageScale,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
} from '../../../src/ballot-privacy/protocol-parameters';
import { type BallotPrivacyRelationBackendPublicContext } from '../../../src/ballot-privacy/relation-backend-lowering';

const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-privacy-relation-lowering-test',
    });

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const encodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

const encodedCoordinateShamirCoefficients =
    (): readonly (readonly number[])[] => [
        [65_536],
        ...Array.from({ length: 10 }, () => [0] as const),
        [9],
        ...Array.from({ length: 10 }, () => [0] as const),
    ];

type BackendProofComponentView = {
    readonly componentDigest: string;
    readonly componentId: string;
    readonly rowBatchNames: readonly string[];
    readonly variableColumnIndices: readonly number[];
};

const validRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients: encodedCoordinateShamirCoefficients(),
    normalizedScores: [7, 3],
    optionCount: 2,
    pvssThreshold: 2,
    receivers: [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: 'receiver-3',
            receiverRosterPosition: 3,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 4,
                secondOptionScoreShare: 30,
            }),
        },
    ],
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(7), oneHotScore(3)],
});

const singleOptionRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients: [
        [2],
        ...Array.from({ length: 10 }, () => [0] as const),
    ],
    normalizedScores: [5],
    optionCount: 1,
    pvssThreshold: 2,
    receivers: [1, 2, 3].map((receiverRosterPosition) => ({
        receiverIdentity: `receiver-${receiverRosterPosition}`,
        receiverRosterPosition,
        receiverShareVector: [
            5 + 2 * receiverRosterPosition,
            ...oneHotScore(5),
        ],
    })),
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(5)],
});

const shareCommitmentOpeningForReceiver = (
    receiverRosterPosition: number,
): readonly number[] =>
    Array.from(
        { length: shareCommitmentOpeningDimension },
        (_unusedValue, openingCoordinateIndex) =>
            ((receiverRosterPosition + openingCoordinateIndex) % 5) - 2,
    );

const receiverOpeningEncodingOffset = 1_024;

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
    const chunkCount = Math.ceil(
        input.plaintextBits.length / receiverEncryptionModuleDegree,
    );
    const ciphertextChunks = Array.from(
        { length: chunkCount },
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
            receiverPayloadCiphertextRoot,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );

    return {
        ciphertextBodyDigest,
        ciphertextChunkDigest: deriveProtocolDigest('ChallengeDomainDigest', {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            purpose: 'ballot-privacy-test-receiver-ciphertext-chunks',
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

const projectionWitness = (
    relationInput: BallotPrivacyRelationCompilerInput = validRelationInput(),
): BallotProofComponentProjectionWitness => ({
    receiverPayloadPlaintexts: relationInput.receivers.map((receiver) => ({
        openingRandomness: shareCommitmentOpeningForReceiver(
            receiver.receiverRosterPosition,
        ),
        receiverRosterPosition: receiver.receiverRosterPosition,
        receiverShareVector: receiver.receiverShareVector,
    })),
    shareCommitmentOpenings: relationInput.receivers.map((receiver) => ({
        openingRandomness: shareCommitmentOpeningForReceiver(
            receiver.receiverRosterPosition,
        ),
        receiverRosterPosition: receiver.receiverRosterPosition,
    })),
});

const publicContext = (
    relationInput: BallotPrivacyRelationCompilerInput = validRelationInput(),
): BallotPrivacyRelationBackendPublicContext => {
    const profileSet = createBallotPrivacyProfileSet();
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = relationInput.receivers.map((receiver) => ({
        receiverIdentity: receiver.receiverIdentity,
        receiverRosterPosition: receiver.receiverRosterPosition,
    }));

    return {
        actionContextDigest: digest('action-context'),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        ballotProofStatementDigest: digest('ballot-proof-statement'),
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        ceremonyId: 'ceremony-relation-lowering',
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
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPayloadCiphertextRoot: digest(
                `receiver-payload-ciphertext-root-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadDigest: digest(
                `receiver-payload-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPublicKeyDigest: digest(
                `receiver-public-key-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterDigest: digest('roster'),
        rosterExternalAcceptanceDigest: digest('external-acceptance'),
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        shareCommitments: relationInput.receivers.map((receiver) => {
            const commitmentPolynomialVector =
                createShareCommitmentPolynomialVector({
                    opening: {
                        openingRandomness: shareCommitmentOpeningForReceiver(
                            receiver.receiverRosterPosition,
                        ),
                    },
                    receiverShareVector: receiver.receiverShareVector,
                    shareCommitmentProfile: profileSet.shareCommitmentProfile,
                    shareVectorWidth: relationInput.optionCount * 11,
                });
            const commitmentBodyDigest = deriveShareCommitmentBodyDigest({
                commitmentPolynomialVector,
                shareCommitmentProfileDigest:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileDigest,
            });

            return {
                commitmentBodyDigest,
                commitmentPolynomialVector,
                commitmentPolynomialVectorDigest: deriveProtocolDigest(
                    'ChallengeDomainDigest',
                    {
                        commitmentPolynomialVector,
                        purpose:
                            'ballot-privacy-test-share-commitment-polynomial-vector',
                    },
                ),
                receiverIdentity: receiver.receiverIdentity,
                receiverRosterPosition: receiver.receiverRosterPosition,
                shareCommitmentDigest: digest(
                    `share-commitment-${receiver.receiverRosterPosition}`,
                ),
            };
        }),
    };
};

const explicitReceiverEncryptionFixture = (
    relationInput: BallotPrivacyRelationCompilerInput = singleOptionRelationInput(),
): {
    readonly context: BallotPrivacyRelationBackendPublicContext;
    readonly projectionWitness: BallotProofComponentProjectionWitness;
} => {
    const profileSet = createBallotPrivacyProfileSet();
    const context = publicContext(relationInput);
    const encryptedReceiverRecords = relationInput.receivers.map((receiver) => {
        const receiverState = generateReceiverState({
            ceremonyId: context.ceremonyId,
            manifestDigest: context.manifestDigest,
            randomnessSource: createFixtureRandomnessSource(
                `receiver-key-${receiver.receiverRosterPosition}`,
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
            recoveryEpoch: 0,
            rosterDigest: context.rosterDigest,
        });
        const encryptedPayload = deterministicReceiverPayloadCiphertextForTest({
            plaintextBits: receiverPayloadPlaintextBitsForTest({
                openingRandomness: shareCommitmentOpeningForReceiver(
                    receiver.receiverRosterPosition,
                ),
                receiverShareVector: receiver.receiverShareVector,
            }),
            receiverEncryptionProfileDigest:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileDigest,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
        });

        return {
            encryptedPayload,
            receiver,
            receiverState,
        };
    });

    return {
        context: {
            ...context,
            receiverPayloads: encryptedReceiverRecords.map(
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
            receiverPublicKeys: encryptedReceiverRecords.map(
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
        },
        projectionWitness: {
            ...projectionWitness(relationInput),
            receiverEncryptionWitnesses: encryptedReceiverRecords.map(
                ({ encryptedPayload, receiver }) => ({
                    chunkWitnesses: encryptedPayload.witness.chunkWitnesses,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        },
    };
};

export {
    digest,
    shareCommitmentModulus,
    validRelationInput,
    singleOptionRelationInput,
    shareCommitmentOpeningForReceiver,
    receiverEncryptionModuleRank,
    projectionWitness,
    publicContext,
    explicitReceiverEncryptionFixture,
};
export type { BackendProofComponentView };
