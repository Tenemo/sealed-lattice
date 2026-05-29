// Shared ballot privacy relation lowering fixtures.
import { deriveProtocolHash } from '@sealed-lattice/crypto';

import { type BallotProofComponentProjectionWitness } from '#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement';
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    type BallotPrivacyRelationCompilerInput,
} from '#packages/protocol/src/ballot-privacy/index';
import {
    createFixtureRandomnessSource,
    createShareCommitmentPolynomialVector,
    deriveShareCommitmentBodyHash,
    generateReceiverState,
} from '#packages/protocol/src/ballot-privacy/lattice-primitives';
import {
    receiverEncryptionMessageScale,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
} from '#packages/protocol/src/ballot-privacy/protocol-parameters';
import { type BallotPrivacyRelationBackendPublicContext } from '#packages/protocol/src/ballot-privacy/relation-backend-lowering';

const hash = (label: string): string =>
    deriveProtocolHash('ChallengeDomainHash', {
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
    readonly componentHash: string;
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

const minimumOptionRelationInput = (): BallotPrivacyRelationCompilerInput =>
    validRelationInput();

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
    readonly receiverEncryptionProfileHash: string;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
}): {
    readonly ciphertextBodyHash: string;
    readonly ciphertextChunkHash: string;
    readonly ciphertextChunks: readonly {
        readonly chunkIndex: number;
        readonly firstCiphertextVector: readonly (readonly number[])[];
        readonly secondCiphertextPolynomial: readonly number[];
    }[];
    readonly plaintextBitLength: number;
    readonly receiverPayloadCiphertextRoot: string;
    readonly receiverPayloadHash: string;
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
    const ciphertextBodyHash = deriveProtocolHash(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            receiverEncryptionProfileHash: input.receiverEncryptionProfileHash,
        },
    );
    const receiverPayloadCiphertextRoot = deriveProtocolHash(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextBodyHash,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );
    const receiverPayloadHash = deriveProtocolHash('ReceiverPayloadHash', {
        receiverPayloadCiphertextRoot,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
    });

    return {
        ciphertextBodyHash,
        ciphertextChunkHash: deriveProtocolHash('ChallengeDomainHash', {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            purpose: 'ballot-privacy-test-receiver-ciphertext-chunks',
        }),
        ciphertextChunks,
        plaintextBitLength: input.plaintextBits.length,
        receiverPayloadCiphertextRoot,
        receiverPayloadHash,
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
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: relationInput.optionCount,
    });
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = relationInput.receivers.map((receiver) => ({
        receiverIdentity: receiver.receiverIdentity,
        receiverRosterPosition: receiver.receiverRosterPosition,
    }));

    return {
        actionContextHash: hash('action-context'),
        aggregateInputEncodingProfileHash:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileHash,
        ballotProofProfileHash:
            profileSet.ballotProofProfile.ballotProofProfileHash,
        ballotProofStatementHash: hash('ballot-proof-statement'),
        ballotScoreEncodingProfileHash:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileHash,
        ceremonyId: 'ceremony-relation-lowering',
        encodedAggregateLayoutHash:
            profileSet.encodedAggregateLayoutProfile.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutHash,
        manifestHash: hash('manifest'),
        pollSpecHash: hash('poll-spec'),
        receiverEncryptionProfileHash:
            profileSet.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverKeyProofRoot: hash('receiver-key-proof-root'),
        receiverKeyRoot: hash('receiver-key-root'),
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPayloadCiphertextRoot: hash(
                `receiver-payload-ciphertext-root-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadHash: hash(
                `receiver-payload-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPublicKeyHash: hash(
                `receiver-public-key-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterHash: hash('roster'),
        rosterExternalAcceptanceHash: hash('external-acceptance'),
        scoreMembershipProfileHash:
            profileSet.scoreMembershipProfile.scoreMembershipProfileHash,
        shareCommitmentMessageBoundCertHash:
            certificate.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash:
            profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
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
            const commitmentBodyHash = deriveShareCommitmentBodyHash({
                commitmentPolynomialVector,
                shareCommitmentProfileHash:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileHash,
            });

            return {
                commitmentBodyHash,
                commitmentPolynomialVector,
                commitmentPolynomialVectorHash: deriveProtocolHash(
                    'ChallengeDomainHash',
                    {
                        commitmentPolynomialVector,
                        purpose:
                            'ballot-privacy-test-share-commitment-polynomial-vector',
                    },
                ),
                receiverIdentity: receiver.receiverIdentity,
                receiverRosterPosition: receiver.receiverRosterPosition,
                shareCommitmentHash: hash(
                    `share-commitment-${receiver.receiverRosterPosition}`,
                ),
            };
        }),
    };
};

const explicitReceiverEncryptionFixture = (
    relationInput: BallotPrivacyRelationCompilerInput = minimumOptionRelationInput(),
): {
    readonly context: BallotPrivacyRelationBackendPublicContext;
    readonly projectionWitness: BallotProofComponentProjectionWitness;
} => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: relationInput.optionCount,
    });
    const context = publicContext(relationInput);
    const encryptedReceiverRecords = relationInput.receivers.map((receiver) => {
        const receiverState = generateReceiverState({
            ceremonyId: context.ceremonyId,
            manifestHash: context.manifestHash,
            randomnessSource: createFixtureRandomnessSource(
                `receiver-key-${receiver.receiverRosterPosition}`,
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
            recoveryEpoch: 0,
            rosterHash: context.rosterHash,
        });
        const encryptedPayload = deterministicReceiverPayloadCiphertextForTest({
            plaintextBits: receiverPayloadPlaintextBitsForTest({
                openingRandomness: shareCommitmentOpeningForReceiver(
                    receiver.receiverRosterPosition,
                ),
                receiverShareVector: receiver.receiverShareVector,
            }),
            receiverEncryptionProfileHash:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileHash,
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
                    ciphertextBodyHash: encryptedPayload.ciphertextBodyHash,
                    ciphertextChunkCount:
                        encryptedPayload.ciphertextChunks.length,
                    ciphertextChunkHash: encryptedPayload.ciphertextChunkHash,
                    ciphertextChunks: encryptedPayload.ciphertextChunks,
                    plaintextBitLength: encryptedPayload.plaintextBitLength,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverPayloadCiphertextRoot:
                        encryptedPayload.receiverPayloadCiphertextRoot,
                    receiverPayloadHash: encryptedPayload.receiverPayloadHash,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
            receiverPublicKeys: encryptedReceiverRecords.map(
                ({ receiver, receiverState }) => ({
                    keyMaterialHash:
                        receiverState.receiverPublicKey.keyMaterialHash,
                    publicKeyVector:
                        receiverState.publicKeyMaterial.publicKeyVector,
                    publicMatrixSeedHash:
                        receiverState.publicKeyMaterial.publicMatrixSeedHash,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverPublicKeyHash:
                        receiverState.receiverPublicKey.receiverPublicKeyHash,
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
    hash,
    shareCommitmentModulus,
    validRelationInput,
    minimumOptionRelationInput,
    shareCommitmentOpeningForReceiver,
    receiverEncryptionModuleRank,
    projectionWitness,
    publicContext,
    explicitReceiverEncryptionFixture,
};
export type { BackendProofComponentView };
