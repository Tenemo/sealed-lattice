import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofStatement,
    ReceiverKeyProofRootEvidence,
    ReceiverPayload,
    ShareCommitment,
} from '@sealed-lattice/types';

import {
    type BallotProofComponentProjectionWitness,
    type BallotProofRecordGenerationProofContracts,
    type BallotProofRecordGenerationRandomness,
    type BallotProofRecordGenerationRequest,
} from '../../../src/ballot-privacy/ballot-proof-linear-statement';
import {
    buildBallotProofStatement,
    createBallotPrivacyProfileSet,
    createReceiverKeyProofRootEvidence,
    createReceiverPayloadShell,
    createShareCommitmentMessageBoundCert,
    createShareCommitmentShell,
    deriveClaimBearingBallotPackageDigest,
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
    shareCommitmentOpeningDimension,
} from '../../../src/ballot-privacy/protocol-parameters';
import { type BallotPrivacyRelationBackendPublicContext } from '../../../src/ballot-privacy/relation-backend-lowering';
import {
    deriveThresholdProfile,
    deriveThresholdProfileDigest,
} from '../../../src/lifecycle/thresholds';

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
    readonly claimBearingReceiverPayloads: readonly ReceiverPayload[];
    readonly claimBearingShareCommitments: readonly ShareCommitment[];
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly randomness: BallotProofRecordGenerationRandomness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly request: BallotProofRecordGenerationRequest;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly statement: BallotProofStatement;
};

type BallotProofRecordGenerationFixtureOptions = {
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly topOptionCount: number;
    readonly casualMicroRosterAcknowledged?: boolean;
    readonly unsafeSmallRosterAcknowledged?: boolean;
};

export const cloneJsonValue = <Value>(value: Value): Value =>
    JSON.parse(JSON.stringify(value)) as Value;

const shareCommitmentOpeningForReceiver = (
    receiverRosterPosition: number,
): readonly number[] =>
    Array.from(
        { length: shareCommitmentOpeningDimension },
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

const minimumCasualMicroRosterSize = 3;
const maximumCasualMicroRosterSize = 9;
const minimumVariantRosterSize = 3;
const maximumVariantRosterSize = 20;
const minimumVariantOptionCount = 2;
const maximumVariantOptionCount = 20;

const casualMicroRosterRelationInput = (
    rosterSize = minimumCasualMicroRosterSize,
): BallotPrivacyRelationCompilerInput => {
    if (
        !Number.isSafeInteger(rosterSize) ||
        rosterSize < minimumCasualMicroRosterSize ||
        rosterSize > maximumCasualMicroRosterSize
    ) {
        throw new RangeError(
            'Casual micro-roster fixtures require roster size 3 to 9.',
        );
    }

    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: true,
        rosterSize,
    });
    const normalizedScores = [5, 7];
    const encodedShareVector = encodedShareVectorForScores(normalizedScores);
    const shamirCoefficientWidth = thresholdProfile.pvssThreshold - 1;

    return {
        encodedCoordinateShamirCoefficients: encodedShareVector.map(
            () =>
                Array.from(
                    { length: shamirCoefficientWidth },
                    () => 0,
                ) as readonly number[],
        ),
        normalizedScores,
        optionCount: normalizedScores.length,
        pvssThreshold: thresholdProfile.pvssThreshold,
        receivers: Array.from(
            { length: rosterSize },
            (_unusedValue, receiverIndex) => ({
                receiverIdentity: `receiver-${receiverIndex + 1}`,
                receiverRosterPosition: receiverIndex + 1,
                receiverShareVector: encodedShareVector,
            }),
        ),
        rosterSize,
        scoreOneHotWitnesses: normalizedScores.map((score) =>
            oneHotScore(score),
        ),
    };
};

export const mandatoryProfileRelationInput =
    (): BallotPrivacyRelationCompilerInput => {
        return variantRelationInput({ optionCount: 20, rosterSize: 20 });
    };

const variantRelationInput = (input: {
    readonly optionCount: number;
    readonly rosterSize: number;
}): BallotPrivacyRelationCompilerInput => {
    if (
        !Number.isSafeInteger(input.rosterSize) ||
        input.rosterSize < minimumVariantRosterSize ||
        input.rosterSize > maximumVariantRosterSize
    ) {
        throw new RangeError(
            'M9 variant fixtures require roster size 3 to 20.',
        );
    }
    if (
        !Number.isSafeInteger(input.optionCount) ||
        input.optionCount < minimumVariantOptionCount ||
        input.optionCount > maximumVariantOptionCount
    ) {
        throw new RangeError(
            'M9 variant fixtures require option count 2 to 20.',
        );
    }

    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged:
            input.rosterSize < minimumCasualMicroRosterSize ||
            input.rosterSize <= maximumCasualMicroRosterSize,
        rosterSize: input.rosterSize,
    });
    const normalizedScores = Array.from(
        { length: input.optionCount },
        (_unusedValue, optionIndex) => (optionIndex % 10) + 1,
    );
    const encodedShareVector = encodedShareVectorForScores(normalizedScores);
    const encodedCoordinateShamirCoefficients = encodedShareVector.map(
        () =>
            Array.from(
                { length: thresholdProfile.pvssThreshold - 1 },
                () => 0,
            ) as readonly number[],
    );

    return {
        encodedCoordinateShamirCoefficients,
        normalizedScores,
        optionCount: input.optionCount,
        pvssThreshold: thresholdProfile.pvssThreshold,
        receivers: Array.from(
            { length: input.rosterSize },
            (_unusedValue, receiverIndex) => ({
                receiverIdentity: `receiver-${receiverIndex + 1}`,
                receiverRosterPosition: receiverIndex + 1,
                receiverShareVector: encodedShareVector,
            }),
        ),
        rosterSize: input.rosterSize,
        scoreOneHotWitnesses: normalizedScores.map((score) =>
            oneHotScore(score),
        ),
    };
};

const thresholdProfileDigestForRelationInput = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): string => {
    const isMicroRoster =
        input.relationInput.rosterSize <= maximumCasualMicroRosterSize;
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: isMicroRoster,
        rosterSize: input.relationInput.rosterSize,
    });

    return deriveThresholdProfileDigest({
        maxRosterSize: maximumVariantRosterSize,
        minRosterSize: minimumVariantRosterSize,
        pollSpecDigest: input.publicContext.pollSpecDigest,
        rosterDigest: input.publicContext.rosterDigest,
        rosterPolicy: 'OpenLinkPublicRoster',
        smallRosterPolicy: isMicroRoster
            ? 'AllowMicroRoster'
            : 'ForbidMicroRoster',
        thresholdProfile,
        thresholdProfileFamily: 'BalancedDefault',
    });
};

const publicContextAndProjectionWitness = (
    relationInput: BallotPrivacyRelationCompilerInput,
): {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
} => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: relationInput.optionCount,
    });
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
        payloadContextDigest: digest('payload-context'),
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
                ({ encryptedPayload, receiver, receiverState }) => {
                    const receiverPayloadShell = createReceiverPayloadShell({
                        ceremonyId: baseContext.ceremonyId,
                        ciphertextBodyDigest:
                            encryptedPayload.ciphertextBodyDigest,
                        manifestDigest: baseContext.manifestDigest,
                        payloadContextDigest: baseContext.payloadContextDigest,
                        pollSpecDigest: baseContext.pollSpecDigest,
                        receiverEncryptionProfileDigest:
                            baseContext.receiverEncryptionProfileDigest,
                        receiverIdentity: receiver.receiverIdentity,
                        receiverPublicKeyDigest:
                            receiverState.receiverPublicKey
                                .receiverPublicKeyDigest,
                        receiverRosterPosition: receiver.receiverRosterPosition,
                        rosterDigest: baseContext.rosterDigest,
                        voterIdentityDigest: digest('voter-1'),
                    });

                    return {
                        ...receiverPayloadShell,
                        ciphertextChunkCount:
                            encryptedPayload.ciphertextChunks.length,
                        ciphertextChunkDigest:
                            encryptedPayload.ciphertextChunkDigest,
                        ciphertextChunks: encryptedPayload.ciphertextChunks,
                        plaintextBitLength: encryptedPayload.plaintextBitLength,
                    };
                },
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
                    const shareCommitmentShell = createShareCommitmentShell({
                        ceremonyId: baseContext.ceremonyId,
                        commitmentBodyDigest,
                        commitmentPolynomialVector,
                        manifestDigest: baseContext.manifestDigest,
                        receiverIdentity: receiver.receiverIdentity,
                        receiverRosterPosition: receiver.receiverRosterPosition,
                        rosterDigest: baseContext.rosterDigest,
                        shareCommitmentProfileDigest:
                            baseContext.shareCommitmentProfileDigest,
                        shareVectorWidth: receiver.receiverShareVector.length,
                    });

                    return {
                        ...shareCommitmentShell,
                        commitmentBodyDigest,
                        commitmentPolynomialVectorDigest: deriveProtocolDigest(
                            'ChallengeDomainDigest',
                            {
                                commitmentPolynomialVector,
                                purpose:
                                    'ballot-proof-record-generation-fixture-share-commitment',
                            },
                        ),
                    };
                },
            ),
        },
    };
};

const claimBearingReceiverPayloadShells = (
    publicContext: BallotPrivacyRelationBackendPublicContext,
): readonly ReceiverPayload[] =>
    publicContext.receiverPayloads.map((receiverPayload) => {
        const payload = receiverPayload as Record<string, unknown>;

        return {
            ciphertextBodyDigest: payload.ciphertextBodyDigest as string,
            ceremonyId: payload.ceremonyId as string,
            manifestDigest: payload.manifestDigest as string,
            objectType: 'ReceiverPayload',
            objectVersion: 1,
            payloadContextDigest: payload.payloadContextDigest as string,
            pollSpecDigest: payload.pollSpecDigest as string,
            receiverEncryptionProfileDigest:
                payload.receiverEncryptionProfileDigest as string,
            receiverIdentity: payload.receiverIdentity as string,
            receiverPayloadCiphertextRoot:
                payload.receiverPayloadCiphertextRoot as string,
            receiverPayloadDigest: payload.receiverPayloadDigest as string,
            receiverPublicKeyDigest: payload.receiverPublicKeyDigest as string,
            receiverRosterPosition: payload.receiverRosterPosition as number,
            rosterDigest: payload.rosterDigest as string,
            voterIdentityDigest: payload.voterIdentityDigest as string,
        };
    });

const claimBearingShareCommitmentShells = (
    publicContext: BallotPrivacyRelationBackendPublicContext,
): readonly ShareCommitment[] =>
    publicContext.shareCommitments.map((shareCommitment) => {
        const commitment = shareCommitment as Record<string, unknown>;

        return {
            ceremonyId: commitment.ceremonyId as string,
            commitmentBodyDigest: commitment.commitmentBodyDigest as string,
            commitmentPolynomialVector:
                commitment.commitmentPolynomialVector as readonly (readonly string[])[],
            manifestDigest: commitment.manifestDigest as string,
            objectType: 'ShareCommitment',
            objectVersion: 1,
            receiverIdentity: commitment.receiverIdentity as string,
            receiverRosterPosition: commitment.receiverRosterPosition as number,
            rosterDigest: commitment.rosterDigest as string,
            shareCommitmentDigest: commitment.shareCommitmentDigest as string,
            shareCommitmentProfileDigest:
                commitment.shareCommitmentProfileDigest as string,
            shareVectorWidth: commitment.shareVectorWidth as number,
        };
    });

const receiverKeyProofRootEvidence = (
    publicContext: BallotPrivacyRelationBackendPublicContext,
): ReceiverKeyProofRootEvidence =>
    createReceiverKeyProofRootEvidence({
        acceptedReceiverKeyProofCount: publicContext.receiverPublicKeys.length,
        ceremonyId: publicContext.ceremonyId,
        evidenceStatus: 'ReceiverKeyProofRootAccepted',
        manifestDigest: publicContext.manifestDigest,
        receiverKeyProofRoot: publicContext.receiverKeyProofRoot,
        receiverKeyRoot: publicContext.receiverKeyRoot,
        receiverPublicKeys: publicContext.receiverPublicKeys.map(
            (receiverPublicKey) => ({
                receiverIdentity: receiverPublicKey.receiverIdentity,
                receiverPublicKeyDigest:
                    receiverPublicKey.receiverPublicKeyDigest,
                receiverRosterPosition:
                    receiverPublicKey.receiverRosterPosition,
            }),
        ),
        rosterDigest: publicContext.rosterDigest,
    });

const ballotProofStatement = (input: {
    readonly claimBearingReceiverPayloads: readonly ReceiverPayload[];
    readonly claimBearingShareCommitments: readonly ShareCommitment[];
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly topOptionCount: number;
}): BallotProofStatement => {
    const statementInput = {
        actionContextDigest: input.publicContext.actionContextDigest,
        aggregateInputEncodingProfileDigest:
            input.publicContext.aggregateInputEncodingProfileDigest,
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
        thresholdProfileDigest: thresholdProfileDigestForRelationInput({
            publicContext: input.publicContext,
            relationInput: input.relationInput,
        }),
        tiePolicyDigest: digest('tie-policy'),
        topOptionCount: input.topOptionCount,
        voterIdentityDigest: digest('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyDigest: digest('voter-signing-key'),
    };
    const placeholderStatement = buildBallotProofStatement({
        ...statementInput,
        ballotPackageDigest: digest('ballot-package-placeholder'),
    });
    const ballotPackageDigest = deriveClaimBearingBallotPackageDigest({
        ballotProofStatement: placeholderStatement,
        receiverKeyProofRootEvidence: input.receiverKeyProofRootEvidence,
        receiverPayloads: input.claimBearingReceiverPayloads,
        shareCommitments: input.claimBearingShareCommitments,
    });

    return buildBallotProofStatement({
        ...statementInput,
        ballotPackageDigest,
    });
};

export {
    casualMicroRosterRelationInput,
    variantRelationInput,
    publicContextAndProjectionWitness,
    claimBearingReceiverPayloadShells,
    claimBearingShareCommitmentShells,
    receiverKeyProofRootEvidence,
    ballotProofStatement,
};
export type {
    ProofParameterSet,
    ProofEncoding,
    BallotProofRecordGenerationFixtureOptions,
};
