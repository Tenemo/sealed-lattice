import {
    buildBallotProofComponentLinearProofProjection,
    verifyBallotProofComponentExplicitRows,
    type BallotProofComponentBundleStatement,
    type BallotProofComponentProjectionWitness,
} from "../../../packages/protocol/src/ballot-privacy/ballot-proof-linear-statement.js";
import {
    denseCoefficientCountForComponentProofStatement,
    proofStatementFormatForComponent,
    sourceRingDegreeForComponentProofStatement,
} from "../../../packages/protocol/src/ballot-privacy/ballot-proof-linear-statement/component-proof-plan-policy.js";
import { rowBatchesForComponent } from "../../../packages/protocol/src/ballot-privacy/ballot-proof-linear-statement/component-statement-builder.js";
import { deriveProtocolDigest } from "../../../packages/crypto/src/digests.js";
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
} from "../../../packages/protocol/src/ballot-privacy/profiles.js";
import {
    createFixtureRandomnessSource,
    createShareCommitmentPolynomialVector,
    deriveShareCommitmentBodyDigest,
    generateReceiverState,
} from "../../../packages/protocol/src/ballot-privacy/lattice-primitives.js";
import {
    ballotPrivacyMandatoryOptionCount,
    ballotPrivacyMandatoryReceiverCount,
    ballotPrivacyMandatoryShareVectorWidth,
    ballotPrivacyMandatoryThreshold,
    receiverEncryptionMessageScale,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    shareCommitmentOpeningDimension,
} from "../../../packages/protocol/src/ballot-privacy/protocol-parameters.js";
import type {
    BallotPrivacyLoweredLinearRelationStatement,
    BallotPrivacyRelationBackendPublicContext,
} from "../../../packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type { BallotPrivacyRelationCompilerInput } from "../../../packages/protocol/src/ballot-privacy/relation-compiler.js";

import type { EncodedBallotRelationVectorCase } from "./vector-case-types.mjs";

export const digest = (label: string): string =>
    deriveProtocolDigest("ChallengeDomainDigest", {
        label,
        purpose: "encoded-ballot-linear-relation-vector",
    });

export const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const encodedShareVectorForScores = (
    scores: readonly number[],
): readonly number[] =>
    scores.flatMap((score) => [score, ...oneHotScore(score)]);

const miniEncodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

const miniEncodedCoordinateShamirCoefficients =
    (): readonly (readonly number[])[] => [
        [65_536],
        ...Array.from({ length: 10 }, () => [0] as const),
        [9],
        ...Array.from({ length: 10 }, () => [0] as const),
    ];

export const miniRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients:
        miniEncodedCoordinateShamirCoefficients(),
    normalizedScores: [7, 3],
    optionCount: 2,
    pvssThreshold: 2,
    receivers: [
        {
            receiverIdentity: "receiver-1",
            receiverRosterPosition: 1,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: "receiver-2",
            receiverRosterPosition: 2,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: "receiver-3",
            receiverRosterPosition: 3,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 4,
                secondOptionScoreShare: 30,
            }),
        },
    ],
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(7), oneHotScore(3)],
});

export const singleOptionRelationInput =
    (): BallotPrivacyRelationCompilerInput => ({
        encodedCoordinateShamirCoefficients: [
            [2],
            ...Array.from({ length: 10 }, () => [0] as const),
        ],
        normalizedScores: [5],
        optionCount: 1,
        pvssThreshold: 2,
        receivers: Array.from({ length: 3 }, (_unusedValue, receiverOffset) => {
            const receiverRosterPosition = receiverOffset + 1;

            return {
                receiverIdentity: `receiver-${receiverRosterPosition}`,
                receiverRosterPosition,
                receiverShareVector: [
                    5 + 2 * receiverRosterPosition,
                    ...oneHotScore(5),
                ],
            };
        }),
        rosterSize: 3,
        scoreOneHotWitnesses: [oneHotScore(5)],
    });

export const mandatoryRelationInput =
    (): BallotPrivacyRelationCompilerInput => {
        const scores = Array.from(
            { length: ballotPrivacyMandatoryOptionCount },
            (_unusedValue, optionIndex) => (optionIndex % 10) + 1,
        );
        const shareVector = encodedShareVectorForScores(scores);

        return {
            encodedCoordinateShamirCoefficients: Array.from(
                { length: ballotPrivacyMandatoryShareVectorWidth },
                () => [0, 0, 0, 0, 0, 0] as const,
            ),
            normalizedScores: scores,
            optionCount: ballotPrivacyMandatoryOptionCount,
            pvssThreshold: ballotPrivacyMandatoryThreshold,
            receivers: Array.from(
                { length: ballotPrivacyMandatoryReceiverCount },
                (_unusedValue, receiverOffset) => ({
                    receiverIdentity: `receiver-${receiverOffset + 1}`,
                    receiverRosterPosition: receiverOffset + 1,
                    receiverShareVector: shareVector,
                }),
            ),
            rosterSize: ballotPrivacyMandatoryReceiverCount,
            scoreOneHotWitnesses: scores.map((score) => oneHotScore(score)),
        };
    };

const shareCommitmentOpeningForReceiver = (
    receiverRosterPosition: number,
): readonly number[] =>
    Array.from(
        { length: shareCommitmentOpeningDimension },
        (_unusedValue, openingCoordinateIndex) =>
            ((receiverRosterPosition + openingCoordinateIndex) % 5) - 2,
    );

const receiverOpeningEncodingOffset = 1_024;

const unsignedBits = (value: number, bitLength: number): readonly number[] => {
    if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        BigInt(value) >= 1n << BigInt(bitLength)
    ) {
        throw new RangeError(
            `Unsigned plaintext value ${String(value)} does not fit ${String(bitLength)} bits.`,
        );
    }
    const integerValue = BigInt(value);

    return Array.from({ length: bitLength }, (_unusedValue, bitIndex) =>
        Number((integerValue >> BigInt(bitIndex)) & 1n),
    );
};

const receiverPayloadPlaintextBitsForRelation = (input: {
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

const deterministicReceiverPayloadCiphertext = (input: {
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
        BallotProofComponentProjectionWitness["receiverEncryptionWitnesses"]
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
        "ReceiverPayloadCiphertextRoot",
        {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfileDigest,
        },
    );
    const receiverPayloadCiphertextRoot = deriveProtocolDigest(
        "ReceiverPayloadCiphertextRoot",
        {
            ciphertextBodyDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );
    const receiverPayloadDigest = deriveProtocolDigest(
        "ReceiverPayloadDigest",
        {
            receiverPayloadCiphertextRoot,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );

    return {
        ciphertextBodyDigest,
        ciphertextChunkDigest: deriveProtocolDigest("ChallengeDomainDigest", {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            purpose: "ballot-privacy-vector-receiver-ciphertext-chunks",
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

export const publicContextForRoster = (
    relationInput: BallotPrivacyRelationCompilerInput,
    includeShareCommitmentPolynomialVectors: boolean,
): BallotPrivacyRelationBackendPublicContext => {
    const profileSet = createBallotPrivacyProfileSet();
    const rosterSize = relationInput.rosterSize;
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: Math.max(20, rosterSize),
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = relationInput.receivers.map((receiver) => ({
        receiverIdentity: receiver.receiverIdentity,
        receiverRosterPosition: receiver.receiverRosterPosition,
    }));

    return {
        actionContextDigest: digest(`action-context-${rosterSize}`),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        ballotProofStatementDigest: digest(
            `ballot-proof-statement-${rosterSize}`,
        ),
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        ceremonyId: `encoded-relation-vector-${rosterSize}`,
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        manifestDigest: digest(`manifest-${rosterSize}`),
        pollSpecDigest: digest(`poll-spec-${rosterSize}`),
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        receiverKeyProofRoot: digest(`receiver-key-proof-root-${rosterSize}`),
        receiverKeyRoot: digest(`receiver-key-root-${rosterSize}`),
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ciphertextBodyDigest: digest(
                `receiver-payload-ciphertext-body-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ciphertextChunkCount: 1,
            ciphertextChunkDigest: digest(
                `receiver-payload-ciphertext-chunks-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            plaintextBitLength: 704,
            ...receiverReference,
            receiverPayloadCiphertextRoot: digest(
                `receiver-payload-ciphertext-root-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadDigest: digest(
                `receiver-payload-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            keyMaterialDigest: digest(
                `receiver-public-key-material-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            publicMatrixSeedDigest: digest(
                `receiver-public-matrix-seed-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ...receiverReference,
            receiverPublicKeyDigest: digest(
                `receiver-public-key-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterDigest: digest(`roster-${rosterSize}`),
        rosterExternalAcceptanceDigest: digest(
            `roster-external-acceptance-${rosterSize}`,
        ),
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        shareCommitments: relationInput.receivers.map((receiver) => {
            if (!includeShareCommitmentPolynomialVectors) {
                return {
                    commitmentBodyDigest: digest(
                        `share-commitment-body-${rosterSize}-${receiver.receiverRosterPosition}`,
                    ),
                    commitmentPolynomialVectorDigest: digest(
                        `share-commitment-polynomial-vector-${rosterSize}-${receiver.receiverRosterPosition}`,
                    ),
                    receiverIdentity: receiver.receiverIdentity,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                    shareCommitmentDigest: digest(
                        `share-commitment-${rosterSize}-${receiver.receiverRosterPosition}`,
                    ),
                };
            }
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
                    "ChallengeDomainDigest",
                    {
                        commitmentPolynomialVector,
                        purpose:
                            "ballot-privacy-vector-share-commitment-polynomial-vector",
                    },
                ),
                receiverIdentity: receiver.receiverIdentity,
                receiverRosterPosition: receiver.receiverRosterPosition,
                shareCommitmentDigest: digest(
                    `share-commitment-${rosterSize}-${receiver.receiverRosterPosition}`,
                ),
            };
        }),
    };
};

export const traceDimensions = (
    relationInput: BallotPrivacyRelationCompilerInput,
) => ({
    optionCount: relationInput.optionCount,
    pvssThreshold: relationInput.pvssThreshold,
    rosterSize: relationInput.rosterSize,
    shareVectorWidth: relationInput.optionCount * 11,
});

export const summarizeStatement = (
    statement: BallotPrivacyLoweredLinearRelationStatement,
): NonNullable<EncodedBallotRelationVectorCase["loweredStatementSummary"]> => {
    const lastAlgebraicRow =
        statement.algebraicRows[statement.algebraicRows.length - 1];
    const firstBackendRowBatch = statement.backendStatement.rowBatches[0];
    const lastBackendRowBatch =
        statement.backendStatement.rowBatches[
            statement.backendStatement.rowBatches.length - 1
        ];
    const proofComponents = statement.backendStatement
        .proofComponents as unknown as readonly unknown[];
    const lastProofComponent = proofComponents[proofComponents.length - 1];
    const lastBound = statement.bounds[statement.bounds.length - 1];
    const lastLinearRow = statement.linearRows[statement.linearRows.length - 1];

    return {
        algebraicRowCount: statement.algebraicRows.length,
        backendColumnCount: statement.backendStatement.columnCount,
        backendDigestExpandedRowCount:
            statement.backendStatement.digestExpandedRowCount,
        backendExplicitRowCount: statement.backendStatement.explicitRowCount,
        backendProofComponentCount: proofComponents.length,
        backendRowBatchCount: statement.backendStatement.rowBatches.length,
        backendRowCount: statement.backendStatement.rowCount,
        backendStatementDigest:
            statement.backendStatement.backendStatementDigest,
        backendStatementFormat:
            statement.backendStatement.backendStatementFormat,
        boundCount: statement.bounds.length,
        encodedCoordinateCount: statement.encodedCoordinateCount,
        firstAlgebraicRow: statement.algebraicRows[0],
        firstBackendRowBatch,
        firstProofComponent: proofComponents[0],
        firstBound: statement.bounds[0],
        firstLinearRow: statement.linearRows[0],
        lastAlgebraicRow,
        lastBackendRowBatch,
        lastBound,
        lastProofComponent,
        lastLinearRow,
        linearRowCount: statement.linearRows.length,
        optionCount: statement.optionCount,
        relationStatementDigest: statement.relationStatementDigest,
        relationStatementFormat: statement.relationStatementFormat,
        rosterSize: statement.rosterSize,
        shareVectorWidth: statement.shareVectorWidth,
        variableCount: statement.variables.length,
    };
};

export const summarizeComponentBundle = (
    componentBundleStatement: BallotProofComponentBundleStatement,
): NonNullable<EncodedBallotRelationVectorCase["componentBundleSummary"]> => {
    const lastComponentStatement =
        componentBundleStatement.componentStatements[
            componentBundleStatement.componentStatements.length - 1
        ];

    if (lastComponentStatement === undefined) {
        throw new Error("Component bundle statement must not be empty.");
    }

    return {
        bundleCoverage: componentBundleStatement.bundleCoverage,
        componentBundleStatementDigest:
            componentBundleStatement.componentBundleStatementDigest,
        componentCount: componentBundleStatement.componentStatements.length,
        explicitComponentCount:
            componentBundleStatement.componentStatements.filter(
                (componentStatement) =>
                    componentStatement.proofLoweringStatus ===
                    "explicitRowsAvailable",
            ).length,
        firstComponentStatement:
            componentBundleStatement.componentStatements[0] ??
            lastComponentStatement,
        lastComponentStatement,
        pendingComponentIds: componentBundleStatement.componentStatements
            .filter(
                (componentStatement) =>
                    componentStatement.proofLoweringStatus !==
                    "explicitRowsAvailable",
            )
            .map((componentStatement) => componentStatement.componentId),
        requiredComponentIds: componentBundleStatement.requiredComponentIds,
    };
};

export const projectionWitnessForRelationInput = (
    relationInput: BallotPrivacyRelationCompilerInput,
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

export const explicitReceiverEncryptionContextForRelation = (
    relationInput: BallotPrivacyRelationCompilerInput,
): {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
} => {
    const profileSet = createBallotPrivacyProfileSet();
    const publicContext = publicContextForRoster(relationInput, true);
    const encryptedReceiverRecords = relationInput.receivers.map((receiver) => {
        const receiverState = generateReceiverState({
            ceremonyId: publicContext.ceremonyId,
            manifestDigest: publicContext.manifestDigest,
            randomnessSource: createFixtureRandomnessSource(
                `encoded-relation-vector-receiver-key-${receiver.receiverRosterPosition}`,
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
            recoveryEpoch: 0,
            rosterDigest: publicContext.rosterDigest,
        });
        const openingRandomness = shareCommitmentOpeningForReceiver(
            receiver.receiverRosterPosition,
        );
        const encryptedPayload = deterministicReceiverPayloadCiphertext({
            plaintextBits: receiverPayloadPlaintextBitsForRelation({
                openingRandomness,
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
        projectionWitness: {
            ...projectionWitnessForRelationInput(relationInput),
            receiverEncryptionWitnesses: encryptedReceiverRecords.map(
                ({ encryptedPayload, receiver }) => ({
                    chunkWitnesses: encryptedPayload.witness.chunkWitnesses,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        },
        publicContext: {
            ...publicContext,
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
    };
};

export const componentProjectionSummaries = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): NonNullable<
    EncodedBallotRelationVectorCase["componentProjectionSummaries"]
> => {
    const explicitComponentProfiles = [
        {
            componentId: "score-and-shamir-field-component",
            parameterProfileId:
                "encoded-score-field-linear-projection-summary-v1",
            witnessL2BoundSquared: "65536",
        },
        {
            componentId: "payload-plaintext-field-component",
            parameterProfileId:
                "payload-plaintext-field-linear-projection-summary-v1",
            witnessL2BoundSquared: "65536",
        },
        {
            componentId: "share-commitment-component",
            parameterProfileId: "share-commitment-linear-projection-summary-v1",
            witnessL2BoundSquared: "1048576",
        },
    ] as const;

    return explicitComponentProfiles.map((profile) => {
        const projection = buildBallotProofComponentLinearProofProjection({
            ballotProofStatementDigest:
                input.publicContext.ballotProofStatementDigest,
            componentId: profile.componentId,
            loweredStatement: input.loweredStatement,
            parameterProfileId: profile.parameterProfileId,
            projectionWitness:
                input.projectionWitness ??
                projectionWitnessForRelationInput(input.relationInput),
            relationInput: input.relationInput,
            sourceRingDegree: 1,
            witnessL2BoundSquared: profile.witnessL2BoundSquared,
        });

        return {
            coefficientModulus: projection.linearStatement.coefficientModulus,
            componentId: projection.componentId,
            linearStatementDigest: projection.linearStatement.statementDigest,
            matrixDigest: projection.linearStatement.statementMatrixDigest,
            parameterProfileId: profile.parameterProfileId,
            projectionCoverage: projection.linearStatement.projectionCoverage,
            ringDegree: projection.linearStatement.ringDegree,
            sourceBackendColumnCount:
                projection.sourceBackendColumnIndices.length,
            sourceRowBatchNames: projection.sourceRowBatchNames,
            statementColumns: projection.linearStatement.statementColumns,
            statementRows: projection.linearStatement.statementRows,
            targetVectorDigest: projection.linearStatement.targetVectorDigest,
            witnessL2BoundSquared: profile.witnessL2BoundSquared,
        };
    });
};

const denseMatrixOracleStatusForComponent = (input: {
    readonly componentId: string;
    readonly proofStatementFormat: string;
}): NonNullable<
    EncodedBallotRelationVectorCase["componentProofReadinessManifests"]
>[number]["denseMatrixOracleStatus"] => {
    if (
        input.proofStatementFormat === "dense-polynomial-matrix-linear-proof-v1"
    ) {
        return "available-for-small-field-component";
    }
    if (
        input.proofStatementFormat ===
            "structured-module-sis-share-commitment-v1" ||
        input.proofStatementFormat === "structured-module-lwe-linear-proof-v1"
    ) {
        return "not-applicable-for-structured-component";
    }
    if (input.proofStatementFormat === "public-zero-witness-binding-check-v1") {
        return "not-applicable-for-public-zero-witness-component";
    }

    return "blocked-pending-sparse-proof-statement";
};

export const componentProofReadinessManifests = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): NonNullable<
    EncodedBallotRelationVectorCase["componentProofReadinessManifests"]
> =>
    input.loweredStatement.backendStatement.proofComponents.map((component) => {
        const componentRowBatches = rowBatchesForComponent({
            component,
            loweredStatement: input.loweredStatement,
        });
        const recommendedSourceRingDegree =
            sourceRingDegreeForComponentProofStatement(component.componentId);
        const proofStatementFormat = proofStatementFormatForComponent({
            component,
            rowBatches: componentRowBatches,
        });

        return {
            coefficientModulus: component.coefficientModulus,
            componentId: component.componentId,
            denseCoefficientCount:
                denseCoefficientCountForComponentProofStatement({
                    rowCount: component.rowCount,
                    sourceRingDegree: recommendedSourceRingDegree,
                    variableColumnCount: component.variableColumnCount,
                }),
            denseMatrixOracleStatus: denseMatrixOracleStatusForComponent({
                componentId: component.componentId,
                proofStatementFormat,
            }),
            objectType: "BallotProofComponentProofReadinessManifest",
            objectVersion: 1,
            proofLoweringStatus: component.proofLoweringStatus,
            proofStatementFormat,
            recommendedSourceRingDegree,
            rowBatchNames: component.rowBatchNames,
            rowCount: component.rowCount,
            variableColumnCount: component.variableColumnCount,
        };
    });

export const proofReadinessSummary = (
    manifests: NonNullable<
        EncodedBallotRelationVectorCase["componentProofReadinessManifests"]
    >,
): NonNullable<EncodedBallotRelationVectorCase["proofReadinessSummary"]> => ({
    denseMatrixOracleComponentCount: manifests.filter(
        (manifest) =>
            manifest.denseMatrixOracleStatus ===
            "available-for-small-field-component",
    ).length,
    fullComponentProofBytesAvailable: false,
    publicZeroWitnessComponentCount: manifests.filter(
        (manifest) =>
            manifest.denseMatrixOracleStatus ===
            "not-applicable-for-public-zero-witness-component",
    ).length,
    sparseOrStructuredComponentCount: manifests.filter(
        (manifest) =>
            manifest.denseMatrixOracleStatus ===
                "blocked-pending-sparse-proof-statement" ||
            manifest.denseMatrixOracleStatus ===
                "not-applicable-for-structured-component",
    ).length,
    totalComponentCount: manifests.length,
});

export const explicitComponentVerificationSummaries = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): NonNullable<
    EncodedBallotRelationVectorCase["explicitComponentVerificationSummaries"]
> =>
    (
        [
            "score-and-shamir-field-component",
            "payload-plaintext-field-component",
            "share-commitment-component",
            "receiver-encryption-component",
            "receiver-key-binding-component",
        ] as const
    ).map((componentId) => {
        const verification = verifyBallotProofComponentExplicitRows({
            componentId,
            loweredStatement: input.loweredStatement,
            projectionWitness: input.projectionWitness,
            relationInput: input.relationInput,
        });

        return {
            checkedRowBatchNames: verification.checkedRowBatchNames,
            componentId: verification.componentId,
            rowCount: verification.rowCount,
            verificationStatus: verification.verificationStatus,
        };
    });
