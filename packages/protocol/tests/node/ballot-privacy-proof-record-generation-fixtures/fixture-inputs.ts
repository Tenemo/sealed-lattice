import { deriveProtocolHash } from '@sealed-lattice/crypto';
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
} from '#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement';
import {
    buildBallotProofStatement,
    createBallotPrivacyProfileSet,
    createReceiverKeyProofRootEvidence,
    createReceiverPayloadShell,
    createShareCommitmentMessageBoundCert,
    createShareCommitmentShell,
    deriveClaimBearingBallotPackageHash,
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
    shareCommitmentOpeningDimension,
} from '#packages/protocol/src/ballot-privacy/protocol-parameters';
import { type BallotPrivacyRelationBackendPublicContext } from '#packages/protocol/src/ballot-privacy/relation-backend-lowering';
import {
    deriveThresholdProfile,
    deriveThresholdProfileHash,
} from '#packages/protocol/src/lifecycle/thresholds';

const hash = (label: string): string =>
    deriveProtocolHash('ChallengeDomainHash', {
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
        receiverIdentity: input.receiverIdentity,
        receiverPayloadCiphertextRoot,
        receiverRosterPosition: input.receiverRosterPosition,
    });

    return {
        ciphertextBodyHash,
        ciphertextChunkHash: deriveProtocolHash('ChallengeDomainHash', {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            purpose: 'ballot-proof-record-generation-fixture-ciphertext',
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
            'Encrypted aggregate bridge variant fixtures require roster size 3 to 20.',
        );
    }
    if (
        !Number.isSafeInteger(input.optionCount) ||
        input.optionCount < minimumVariantOptionCount ||
        input.optionCount > maximumVariantOptionCount
    ) {
        throw new RangeError(
            'Encrypted aggregate bridge variant fixtures require option count 2 to 20.',
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

export const mandatoryProfileRelationInput =
    (): BallotPrivacyRelationCompilerInput => {
        return variantRelationInput({ optionCount: 20, rosterSize: 20 });
    };

const thresholdProfileHashForRelationInput = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): string => {
    const isMicroRoster =
        input.relationInput.rosterSize <= maximumCasualMicroRosterSize;
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: isMicroRoster,
        rosterSize: input.relationInput.rosterSize,
    });

    return deriveThresholdProfileHash({
        maxRosterSize: maximumVariantRosterSize,
        minRosterSize: minimumVariantRosterSize,
        pollSpecHash: input.publicContext.pollSpecHash,
        rosterHash: input.publicContext.rosterHash,
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
        actionContextHash: hash('action-context'),
        aggregateInputEncodingProfileHash:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileHash,
        ballotProofProfileHash:
            profileSet.ballotProofProfile.ballotProofProfileHash,
        ballotScoreEncodingProfileHash:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileHash,
        ceremonyId: 'ceremony-proof-record-generation',
        encodedAggregateLayoutHash:
            profileSet.encodedAggregateLayoutProfile.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutHash,
        manifestHash: hash('manifest'),
        payloadContextHash: hash('payload-context'),
        pollSpecHash: hash('poll-spec'),
        receiverEncryptionProfileHash:
            profileSet.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverKeyProofRoot: hash('receiver-key-proof-root'),
        receiverKeyRoot: hash('receiver-key-root'),
        rosterHash: hash('roster'),
        rosterExternalAcceptanceHash: hash('external-acceptance'),
        scoreMembershipProfileHash:
            profileSet.scoreMembershipProfile.scoreMembershipProfileHash,
        shareCommitmentMessageBoundCertHash:
            certificate.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash:
            profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
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
            manifestHash: baseContext.manifestHash,
            randomnessSource: createFixtureRandomnessSource(
                `receiver-key-${receiver.receiverRosterPosition}`,
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
            recoveryEpoch: 0,
            rosterHash: baseContext.rosterHash,
        });
        const encryptedPayload = deterministicReceiverPayloadCiphertextForTest({
            plaintextBits: receiverPayloadPlaintextBitsForTest({
                openingRandomness,
                receiverShareVector: receiver.receiverShareVector,
            }),
            receiverEncryptionProfileHash:
                baseContext.receiverEncryptionProfileHash,
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
                        ciphertextBodyHash: encryptedPayload.ciphertextBodyHash,
                        manifestHash: baseContext.manifestHash,
                        payloadContextHash: baseContext.payloadContextHash,
                        pollSpecHash: baseContext.pollSpecHash,
                        receiverEncryptionProfileHash:
                            baseContext.receiverEncryptionProfileHash,
                        receiverIdentity: receiver.receiverIdentity,
                        receiverPublicKeyHash:
                            receiverState.receiverPublicKey
                                .receiverPublicKeyHash,
                        receiverRosterPosition: receiver.receiverRosterPosition,
                        rosterHash: baseContext.rosterHash,
                        voterIdentityHash: hash('voter-1'),
                    });

                    return {
                        ...receiverPayloadShell,
                        ciphertextChunkCount:
                            encryptedPayload.ciphertextChunks.length,
                        ciphertextChunkHash:
                            encryptedPayload.ciphertextChunkHash,
                        ciphertextChunks: encryptedPayload.ciphertextChunks,
                        plaintextBitLength: encryptedPayload.plaintextBitLength,
                    };
                },
            ),
            receiverPublicKeys: receiverRecords.map(
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
            shareCommitments: receiverRecords.map(
                ({ commitmentPolynomialVector, receiver }) => {
                    const commitmentBodyHash = deriveShareCommitmentBodyHash({
                        commitmentPolynomialVector,
                        shareCommitmentProfileHash:
                            baseContext.shareCommitmentProfileHash,
                    });
                    const shareCommitmentShell = createShareCommitmentShell({
                        ceremonyId: baseContext.ceremonyId,
                        commitmentBodyHash,
                        commitmentPolynomialVector,
                        manifestHash: baseContext.manifestHash,
                        receiverIdentity: receiver.receiverIdentity,
                        receiverRosterPosition: receiver.receiverRosterPosition,
                        rosterHash: baseContext.rosterHash,
                        shareCommitmentProfileHash:
                            baseContext.shareCommitmentProfileHash,
                        shareVectorWidth: receiver.receiverShareVector.length,
                    });

                    return {
                        ...shareCommitmentShell,
                        commitmentBodyHash,
                        commitmentPolynomialVectorHash: deriveProtocolHash(
                            'ChallengeDomainHash',
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
            ciphertextBodyHash: payload.ciphertextBodyHash as string,
            ceremonyId: payload.ceremonyId as string,
            manifestHash: payload.manifestHash as string,
            objectType: 'ReceiverPayload',
            objectVersion: 1,
            payloadContextHash: payload.payloadContextHash as string,
            pollSpecHash: payload.pollSpecHash as string,
            receiverEncryptionProfileHash:
                payload.receiverEncryptionProfileHash as string,
            receiverIdentity: payload.receiverIdentity as string,
            receiverPayloadCiphertextRoot:
                payload.receiverPayloadCiphertextRoot as string,
            receiverPayloadHash: payload.receiverPayloadHash as string,
            receiverPublicKeyHash: payload.receiverPublicKeyHash as string,
            receiverRosterPosition: payload.receiverRosterPosition as number,
            rosterHash: payload.rosterHash as string,
            voterIdentityHash: payload.voterIdentityHash as string,
        };
    });

const claimBearingShareCommitmentShells = (
    publicContext: BallotPrivacyRelationBackendPublicContext,
): readonly ShareCommitment[] =>
    publicContext.shareCommitments.map((shareCommitment) => {
        const commitment = shareCommitment as Record<string, unknown>;

        return {
            ceremonyId: commitment.ceremonyId as string,
            commitmentBodyHash: commitment.commitmentBodyHash as string,
            commitmentPolynomialVector:
                commitment.commitmentPolynomialVector as readonly (readonly string[])[],
            manifestHash: commitment.manifestHash as string,
            objectType: 'ShareCommitment',
            objectVersion: 1,
            receiverIdentity: commitment.receiverIdentity as string,
            receiverRosterPosition: commitment.receiverRosterPosition as number,
            rosterHash: commitment.rosterHash as string,
            shareCommitmentHash: commitment.shareCommitmentHash as string,
            shareCommitmentProfileHash:
                commitment.shareCommitmentProfileHash as string,
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
        manifestHash: publicContext.manifestHash,
        receiverKeyProofRoot: publicContext.receiverKeyProofRoot,
        receiverKeyRoot: publicContext.receiverKeyRoot,
        receiverPublicKeys: publicContext.receiverPublicKeys.map(
            (receiverPublicKey) => ({
                receiverIdentity: receiverPublicKey.receiverIdentity,
                receiverPublicKeyHash: receiverPublicKey.receiverPublicKeyHash,
                receiverRosterPosition:
                    receiverPublicKey.receiverRosterPosition,
            }),
        ),
        rosterHash: publicContext.rosterHash,
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
        actionContextHash: input.publicContext.actionContextHash,
        aggregateInputEncodingProfileHash:
            input.publicContext.aggregateInputEncodingProfileHash,
        ballotProofProfileHash: input.publicContext.ballotProofProfileHash,
        ballotScoreEncodingProfileHash:
            input.publicContext.ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash:
            input.publicContext.ballotShareLayoutProfileHash,
        ceremonyId: input.publicContext.ceremonyId,
        duplicateBallotPolicyHash: hash('duplicate-ballot-policy'),
        encodedAggregateLayoutHash:
            input.publicContext.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash:
            input.publicContext.encodedShareVectorLayoutHash,
        manifestHash: input.publicContext.manifestHash,
        optionCount: input.relationInput.optionCount,
        pollSpecHash: input.publicContext.pollSpecHash,
        receiverEncryptionProfileHash:
            input.publicContext.receiverEncryptionProfileHash,
        receiverKeyProofRoot: input.publicContext.receiverKeyProofRoot,
        receiverKeyRoot: input.publicContext.receiverKeyRoot,
        receiverPayloads: input.publicContext.receiverPayloads.map(
            (receiverPayload) => ({
                receiverIdentity: receiverPayload.receiverIdentity,
                receiverPayloadCiphertextRoot:
                    receiverPayload.receiverPayloadCiphertextRoot,
                receiverPayloadHash: receiverPayload.receiverPayloadHash,
                receiverRosterPosition: receiverPayload.receiverRosterPosition,
            }),
        ),
        receiverPublicKeys: input.publicContext.receiverPublicKeys.map(
            (receiverPublicKey) => ({
                receiverIdentity: receiverPublicKey.receiverIdentity,
                receiverPublicKeyHash: receiverPublicKey.receiverPublicKeyHash,
                receiverRosterPosition:
                    receiverPublicKey.receiverRosterPosition,
            }),
        ),
        rosterHash: input.publicContext.rosterHash,
        rosterExternalAcceptanceHash:
            input.publicContext.rosterExternalAcceptanceHash,
        scoreDomainHash: hash('score-domain'),
        scoreMembershipProfileHash:
            input.publicContext.scoreMembershipProfileHash,
        shareCommitmentMessageBoundCertHash:
            input.publicContext.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash:
            input.publicContext.shareCommitmentProfileHash,
        shareCommitments: input.publicContext.shareCommitments.map(
            (shareCommitment) => ({
                receiverIdentity: shareCommitment.receiverIdentity,
                receiverRosterPosition: shareCommitment.receiverRosterPosition,
                shareCommitmentHash: shareCommitment.shareCommitmentHash,
            }),
        ),
        thresholdProfileHash: thresholdProfileHashForRelationInput({
            publicContext: input.publicContext,
            relationInput: input.relationInput,
        }),
        tiePolicyHash: hash('tie-policy'),
        topOptionCount: input.topOptionCount,
        voterIdentityHash: hash('voter-1'),
        voterRosterPosition: 1,
        voterSigningKeyHash: hash('voter-signing-key'),
    };
    const placeholderStatement = buildBallotProofStatement({
        ...statementInput,
        ballotPackageHash: hash('ballot-package-placeholder'),
    });
    const ballotPackageHash = deriveClaimBearingBallotPackageHash({
        ballotProofStatement: placeholderStatement,
        receiverKeyProofRootEvidence: input.receiverKeyProofRootEvidence,
        receiverPayloads: input.claimBearingReceiverPayloads,
        shareCommitments: input.claimBearingShareCommitments,
    });

    return buildBallotProofStatement({
        ...statementInput,
        ballotPackageHash,
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
