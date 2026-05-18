import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { deriveProtocolDigest } from "../../packages/crypto/src/digests.js";
import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentLinearProofProjection,
    buildBallotProofComponentProofStatementPlans,
    verifyBallotProofComponentExplicitRows,
    type BallotProofComponentBundleStatement,
    type BallotProofComponentProofStatementPlan,
    type BallotProofComponentStatement,
    type BallotProofComponentProjectionWitness,
} from "../../packages/protocol/src/ballot-privacy/ballot-proof-linear-statement.js";
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
} from "../../packages/protocol/src/ballot-privacy/profiles.js";
import {
    createFixtureRandomnessSource,
    createShareCommitmentPolynomialVector,
    deriveShareCommitmentBodyDigest,
    generateReceiverState,
} from "../../packages/protocol/src/ballot-privacy/lattice-primitives.js";
import { lowerBallotPrivacyRelationToBackendStatement } from "../../packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type {
    BallotPrivacyLoweredLinearRelationStatement,
    BallotPrivacyRelationBackendLoweringResult,
    BallotPrivacyRelationBackendPublicContext,
} from "../../packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type { BallotPrivacyRelationCompilerInput } from "../../packages/protocol/src/ballot-privacy/relation-compiler.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const outputPath = path.resolve(
    repoRoot,
    "test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json",
);

interface EncodedBallotRelationVectorCase {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly expectedOutcome: "accept" | "reject";
    readonly compilerAccepted: boolean;
    readonly componentProjectionSummaries?: readonly {
        readonly coefficientModulus: string;
        readonly componentId: string;
        readonly linearStatementDigest: string;
        readonly matrixDigest: string;
        readonly parameterProfileId: string;
        readonly projectionCoverage: string;
        readonly ringDegree: number;
        readonly sourceBackendColumnCount: number;
        readonly sourceRowBatchNames: readonly string[];
        readonly statementColumns: number;
        readonly statementRows: number;
        readonly targetVectorDigest: string;
        readonly witnessL2BoundSquared: string;
    }[];
    readonly componentProofReadinessManifests?: readonly {
        readonly coefficientModulus: string;
        readonly componentId: string;
        readonly denseCoefficientCount: string | null;
        readonly denseMatrixOracleStatus:
            | "available-for-small-field-component"
            | "blocked-pending-sparse-proof-statement"
            | "not-applicable-for-structured-component"
            | "not-applicable-for-public-zero-witness-component";
        readonly objectType: "BallotProofComponentProofReadinessManifest";
        readonly objectVersion: 1;
        readonly proofLoweringStatus: string;
        readonly proofStatementFormat:
            | "dense-polynomial-matrix-linear-proof-v1"
            | "sparse-polynomial-matrix-linear-proof-v1"
            | "structured-module-lwe-linear-proof-v1"
            | "public-zero-witness-binding-check-v1";
        readonly recommendedSourceRingDegree: number | null;
        readonly rowBatchNames: readonly string[];
        readonly rowCount: number;
        readonly variableColumnCount: number;
    }[];
    readonly componentProofStatementPlans?: readonly BallotProofComponentProofStatementPlan[];
    readonly proofReadinessSummary?: {
        readonly denseMatrixOracleComponentCount: number;
        readonly fullComponentProofBytesAvailable: false;
        readonly publicZeroWitnessComponentCount: number;
        readonly sparseOrStructuredComponentCount: number;
        readonly totalComponentCount: number;
    };
    readonly explicitComponentVerificationSummaries?: readonly {
        readonly checkedRowBatchNames: readonly string[];
        readonly componentId: string;
        readonly rowCount: number;
        readonly verificationStatus: "explicitRowsSatisfied";
    }[];
    readonly componentBundleStatement?: BallotProofComponentBundleStatement;
    readonly componentBundleSummary?: {
        readonly bundleCoverage: string;
        readonly componentBundleStatementDigest: string;
        readonly componentCount: number;
        readonly explicitComponentCount: number;
        readonly firstComponentStatement: BallotProofComponentStatement;
        readonly lastComponentStatement: BallotProofComponentStatement;
        readonly pendingComponentIds: readonly string[];
        readonly requiredComponentIds: readonly string[];
    };
    readonly loweredStatement?: BallotPrivacyLoweredLinearRelationStatement;
    readonly loweredStatementSummary?: {
        readonly algebraicRowCount: number;
        readonly backendColumnCount: number;
        readonly backendDigestExpandedRowCount: number;
        readonly backendExplicitRowCount: number;
        readonly backendProofComponentCount: number;
        readonly backendRowBatchCount: number;
        readonly backendRowCount: number;
        readonly backendStatementDigest: string;
        readonly backendStatementFormat: string;
        readonly boundCount: number;
        readonly encodedCoordinateCount: number;
        readonly firstBackendRowBatch: unknown;
        readonly firstProofComponent: unknown;
        readonly firstAlgebraicRow: unknown;
        readonly firstBound: unknown;
        readonly firstLinearRow: unknown;
        readonly lastAlgebraicRow: unknown;
        readonly lastBackendRowBatch: unknown;
        readonly lastBound: unknown;
        readonly lastProofComponent: unknown;
        readonly lastLinearRow: unknown;
        readonly linearRowCount: number;
        readonly optionCount: number;
        readonly relationStatementDigest: string;
        readonly relationStatementFormat: string;
        readonly rosterSize: number;
        readonly shareVectorWidth: number;
        readonly variableCount: number;
    };
    readonly refusalMessages?: readonly string[];
    readonly trace: {
        readonly expectedLogicalRejectionLayer?:
            | "relation-compiler"
            | "backend-statement-preflight";
        readonly optionCount: number;
        readonly rosterSize: number;
        readonly pvssThreshold: number;
        readonly shareVectorWidth: number;
        readonly relationStatementDigest?: string;
        readonly baselineRelationStatementDigest?: string;
        readonly expectedDigestChanged?: true;
    };
}

const digest = (label: string): string =>
    deriveProtocolDigest("ChallengeDomainDigest", {
        label,
        purpose: "encoded-ballot-linear-relation-vector",
    });

const oneHotScore = (score: number): readonly number[] =>
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

const miniRelationInput = (): BallotPrivacyRelationCompilerInput => ({
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

const singleOptionRelationInput = (): BallotPrivacyRelationCompilerInput => ({
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

const mandatoryRelationInput = (): BallotPrivacyRelationCompilerInput => {
    const scores = Array.from(
        { length: 20 },
        (_unusedValue, optionIndex) => (optionIndex % 10) + 1,
    );
    const shareVector = encodedShareVectorForScores(scores);

    return {
        encodedCoordinateShamirCoefficients: Array.from(
            { length: 220 },
            () => [0, 0, 0, 0, 0, 0] as const,
        ),
        normalizedScores: scores,
        optionCount: 20,
        pvssThreshold: 7,
        receivers: Array.from(
            { length: 20 },
            (_unusedValue, receiverOffset) => ({
                receiverIdentity: `receiver-${receiverOffset + 1}`,
                receiverRosterPosition: receiverOffset + 1,
                receiverShareVector: shareVector,
            }),
        ),
        rosterSize: 20,
        scoreOneHotWitnesses: scores.map((score) => oneHotScore(score)),
    };
};

const shareCommitmentOpeningForReceiver = (
    receiverRosterPosition: number,
): readonly number[] =>
    Array.from(
        { length: 64 },
        (_unusedValue, openingCoordinateIndex) =>
            ((receiverRosterPosition + openingCoordinateIndex) % 5) - 2,
    );

const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionModulus = 12_289;
const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
const receiverShareRepresentativeBitLength = 17;
const receiverOpeningRandomnessBitLength = 12;
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

const publicContextForRoster = (
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

const traceDimensions = (
    relationInput: BallotPrivacyRelationCompilerInput,
) => ({
    optionCount: relationInput.optionCount,
    pvssThreshold: relationInput.pvssThreshold,
    rosterSize: relationInput.rosterSize,
    shareVectorWidth: relationInput.optionCount * 11,
});

const summarizeStatement = (
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

const summarizeComponentBundle = (
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

const projectionWitnessForRelationInput = (
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

const explicitReceiverEncryptionContextForRelation = (
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

const componentProjectionSummaries = (input: {
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

const sourceRingDegreeForComponent = (input: {
    readonly coefficientModulus: string;
    readonly componentId: string;
}): number | null => {
    if (input.componentId === "share-commitment-component") {
        return 256;
    }
    if (
        input.componentId === "score-and-shamir-field-component" ||
        input.componentId === "payload-plaintext-field-component"
    ) {
        return 64;
    }
    if (input.componentId === "receiver-encryption-component") {
        return 256;
    }
    if (input.componentId === "receiver-key-binding-component") {
        return null;
    }

    throw new Error(`Unknown proof component ${input.componentId}.`);
};

const denseCoefficientCountForComponent = (input: {
    readonly componentId: string;
    readonly coefficientModulus: string;
    readonly rowCount: number;
    readonly variableColumnCount: number;
}): string | null => {
    const sourceRingDegree = sourceRingDegreeForComponent(input);
    if (sourceRingDegree === null || input.variableColumnCount === 0) {
        return null;
    }

    return (
        BigInt(input.rowCount) *
        BigInt(input.variableColumnCount) *
        BigInt(sourceRingDegree)
    ).toString();
};

const proofStatementFormatForComponent = (input: {
    readonly componentId: string;
    readonly rowBatchNames: readonly string[];
    readonly variableColumnCount: number;
}): NonNullable<
    EncodedBallotRelationVectorCase["componentProofReadinessManifests"]
>[number]["proofStatementFormat"] => {
    if (input.componentId === "receiver-encryption-component") {
        return "structured-module-lwe-linear-proof-v1";
    }
    if (
        input.componentId === "receiver-key-binding-component" &&
        input.variableColumnCount === 0
    ) {
        return "public-zero-witness-binding-check-v1";
    }
    if (
        input.rowBatchNames.length === 1 &&
        input.rowBatchNames[0] === "encoded_score_field_rows"
    ) {
        return "dense-polynomial-matrix-linear-proof-v1";
    }

    return "sparse-polynomial-matrix-linear-proof-v1";
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
        input.proofStatementFormat === "structured-module-lwe-linear-proof-v1"
    ) {
        return "not-applicable-for-structured-component";
    }
    if (input.proofStatementFormat === "public-zero-witness-binding-check-v1") {
        return "not-applicable-for-public-zero-witness-component";
    }

    return "blocked-pending-sparse-proof-statement";
};

const componentProofReadinessManifests = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): NonNullable<
    EncodedBallotRelationVectorCase["componentProofReadinessManifests"]
> =>
    input.loweredStatement.backendStatement.proofComponents.map((component) => {
        const recommendedSourceRingDegree = sourceRingDegreeForComponent({
            coefficientModulus: component.coefficientModulus,
            componentId: component.componentId,
        });
        const proofStatementFormat = proofStatementFormatForComponent({
            componentId: component.componentId,
            rowBatchNames: component.rowBatchNames,
            variableColumnCount: component.variableColumnCount,
        });

        return {
            coefficientModulus: component.coefficientModulus,
            componentId: component.componentId,
            denseCoefficientCount: denseCoefficientCountForComponent({
                coefficientModulus: component.coefficientModulus,
                componentId: component.componentId,
                rowCount: component.rowCount,
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

const proofReadinessSummary = (
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

const explicitComponentVerificationSummaries = (input: {
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

const acceptingCase = (input: {
    readonly baselineRelationStatementDigest?: string;
    readonly caseName: string;
    readonly description: string;
    readonly expectedDigestChanged?: true;
    readonly includeComponentProjectionSummaries?: boolean;
    readonly includeExplicitComponentVerificationSummaries?: boolean;
    readonly includeFullStatement: boolean;
    readonly mutation?: string;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): EncodedBallotRelationVectorCase => {
    const result: BallotPrivacyRelationBackendLoweringResult =
        lowerBallotPrivacyRelationToBackendStatement({
            publicContext: input.publicContext,
            relationInput: input.relationInput,
        });
    if (!result.ok) {
        throw new Error(
            `${input.caseName} was expected to lower but refused: ${result.refusedObjects.map((refusal) => refusal.message).join("; ")}`,
        );
    }
    const componentBundleStatement = buildBallotProofComponentBundleStatement({
        ballotProofStatementDigest:
            input.publicContext.ballotProofStatementDigest,
        loweredStatement: result.statement,
    });
    const proofReadinessManifests =
        input.includeExplicitComponentVerificationSummaries
            ? componentProofReadinessManifests({
                  loweredStatement: result.statement,
              })
            : undefined;
    const componentProofStatementPlans =
        input.includeExplicitComponentVerificationSummaries
            ? buildBallotProofComponentProofStatementPlans({
                  ballotProofStatementDigest:
                      input.publicContext.ballotProofStatementDigest,
                  componentBundleStatement,
                  loweredStatement: result.statement,
              })
            : undefined;

    return {
        caseName: input.caseName,
        compilerAccepted: true,
        componentBundleStatement: input.includeFullStatement
            ? componentBundleStatement
            : undefined,
        componentBundleSummary: input.includeFullStatement
            ? undefined
            : summarizeComponentBundle(componentBundleStatement),
        componentProjectionSummaries: input.includeComponentProjectionSummaries
            ? componentProjectionSummaries({
                  loweredStatement: result.statement,
                  projectionWitness: input.projectionWitness,
                  publicContext: input.publicContext,
                  relationInput: input.relationInput,
              })
            : undefined,
        componentProofReadinessManifests: proofReadinessManifests,
        componentProofStatementPlans,
        explicitComponentVerificationSummaries:
            input.includeExplicitComponentVerificationSummaries
                ? explicitComponentVerificationSummaries({
                      loweredStatement: result.statement,
                      projectionWitness:
                          input.projectionWitness ??
                          projectionWitnessForRelationInput(
                              input.relationInput,
                          ),
                      relationInput: input.relationInput,
                  })
                : undefined,
        description: input.description,
        expectedOutcome: "accept",
        loweredStatement: input.includeFullStatement
            ? result.statement
            : undefined,
        loweredStatementSummary: input.includeFullStatement
            ? undefined
            : summarizeStatement(result.statement),
        mutation: input.mutation ?? "none",
        proofReadinessSummary:
            proofReadinessManifests === undefined
                ? undefined
                : proofReadinessSummary(proofReadinessManifests),
        trace: {
            baselineRelationStatementDigest:
                input.baselineRelationStatementDigest,
            expectedDigestChanged: input.expectedDigestChanged,
            ...traceDimensions(input.relationInput),
            relationStatementDigest: result.statement.relationStatementDigest,
        },
    };
};

const cloneJson = <ValueType,>(value: ValueType): ValueType =>
    JSON.parse(JSON.stringify(value)) as ValueType;

const backendPreflightRejectingCase = (input: {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly mutateStatement: (
        statement: BallotPrivacyLoweredLinearRelationStatement,
    ) => BallotPrivacyLoweredLinearRelationStatement;
}): EncodedBallotRelationVectorCase => {
    const result: BallotPrivacyRelationBackendLoweringResult =
        lowerBallotPrivacyRelationToBackendStatement({
            publicContext: input.publicContext,
            relationInput: input.relationInput,
        });
    if (!result.ok) {
        throw new Error(
            `${input.caseName} needs a compiler-accepted baseline but refused: ${result.refusedObjects.map((refusal) => refusal.message).join("; ")}`,
        );
    }
    const mutatedStatement = input.mutateStatement(cloneJson(result.statement));

    return {
        caseName: input.caseName,
        compilerAccepted: true,
        description: input.description,
        expectedOutcome: "reject",
        loweredStatement: mutatedStatement,
        mutation: input.mutation,
        trace: {
            ...traceDimensions(input.relationInput),
            expectedLogicalRejectionLayer: "backend-statement-preflight",
        },
    };
};

const digestChangingPublicContextCases = (input: {
    readonly baselineRelationStatementDigest: string;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): readonly EncodedBallotRelationVectorCase[] => [
    acceptingCase({
        baselineRelationStatementDigest: input.baselineRelationStatementDigest,
        caseName: "wrong-share-commitment-target-changes-digest",
        description:
            "A substituted share commitment target changes the lowered relation digest.",
        expectedDigestChanged: true,
        includeFullStatement: false,
        mutation: "wrong-share-commitment-target",
        publicContext: {
            ...input.publicContext,
            shareCommitments: input.publicContext.shareCommitments.map(
                (shareCommitment) =>
                    shareCommitment.receiverRosterPosition === 2
                        ? {
                              ...shareCommitment,
                              commitmentBodyDigest: digest(
                                  "changed-share-commitment-body",
                              ),
                          }
                        : shareCommitment,
            ),
        },
        relationInput: input.relationInput,
    }),
    acceptingCase({
        baselineRelationStatementDigest: input.baselineRelationStatementDigest,
        caseName: "wrong-receiver-payload-target-changes-digest",
        description:
            "A substituted receiver payload ciphertext target changes the lowered relation digest.",
        expectedDigestChanged: true,
        includeFullStatement: false,
        mutation: "wrong-receiver-payload-target",
        publicContext: {
            ...input.publicContext,
            receiverPayloads: input.publicContext.receiverPayloads.map(
                (receiverPayload) =>
                    receiverPayload.receiverRosterPosition === 2
                        ? {
                              ...receiverPayload,
                              ciphertextChunkDigest: digest(
                                  "changed-receiver-payload-ciphertext-chunk",
                              ),
                          }
                        : receiverPayload,
            ),
        },
        relationInput: input.relationInput,
    }),
    acceptingCase({
        baselineRelationStatementDigest: input.baselineRelationStatementDigest,
        caseName: "wrong-receiver-key-target-changes-digest",
        description:
            "A substituted receiver key target changes the lowered relation digest.",
        expectedDigestChanged: true,
        includeFullStatement: false,
        mutation: "wrong-receiver-key-target",
        publicContext: {
            ...input.publicContext,
            receiverPublicKeys: input.publicContext.receiverPublicKeys.map(
                (receiverPublicKey) =>
                    receiverPublicKey.receiverRosterPosition === 2
                        ? {
                              ...receiverPublicKey,
                              keyMaterialDigest: digest(
                                  "changed-receiver-key-material",
                              ),
                          }
                        : receiverPublicKey,
            ),
        },
        relationInput: input.relationInput,
    }),
];

interface MutableBackendStatementView {
    readonly proofComponents: {
        componentId: string;
    }[];
    readonly rowBatches: {
        readonly rows?: {
            readonly terms: { coefficient: string }[];
            target: string;
        }[];
    }[];
    readonly variableColumns: { columnIndex: number }[];
    readonly bounds: { absoluteMaximum?: string }[];
}

const backendPreflightMutationCases = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): readonly EncodedBallotRelationVectorCase[] => [
    backendPreflightRejectingCase({
        caseName: "backend-matrix-row-mutation-rejects",
        description:
            "A changed backend sparse matrix coefficient fails canonical preflight.",
        mutateStatement: (statement) => {
            const backendStatement =
                statement.backendStatement as unknown as MutableBackendStatementView;
            const firstExplicitRow = backendStatement.rowBatches[0]?.rows?.[0];
            if (firstExplicitRow === undefined) {
                throw new Error("backend matrix mutation target is missing");
            }
            firstExplicitRow.terms[0].coefficient = "2";

            return statement;
        },
        mutation: "backend-matrix-row",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
    backendPreflightRejectingCase({
        caseName: "backend-target-vector-mutation-rejects",
        description:
            "A changed backend target vector entry fails canonical preflight.",
        mutateStatement: (statement) => {
            const backendStatement =
                statement.backendStatement as unknown as MutableBackendStatementView;
            const firstExplicitRow = backendStatement.rowBatches[0]?.rows?.[0];
            if (firstExplicitRow === undefined) {
                throw new Error("backend target mutation target is missing");
            }
            firstExplicitRow.target = "2";

            return statement;
        },
        mutation: "backend-target-vector",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
    backendPreflightRejectingCase({
        caseName: "backend-bound-mutation-rejects",
        description: "A changed backend bound fails canonical preflight.",
        mutateStatement: (statement) => {
            const backendStatement =
                statement.backendStatement as unknown as MutableBackendStatementView;
            const quotientBound = backendStatement.bounds.find((bound) =>
                String(
                    (bound as { readonly boundName?: unknown }).boundName,
                ).includes("shamir_quotients"),
            );
            if (quotientBound === undefined) {
                throw new Error("backend bound mutation target is missing");
            }
            quotientBound.absoluteMaximum = "1";

            return statement;
        },
        mutation: "backend-bound",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
    backendPreflightRejectingCase({
        caseName: "backend-proof-component-mutation-rejects",
        description:
            "A changed backend proof-component assignment fails canonical preflight.",
        mutateStatement: (statement) => {
            const backendStatement =
                statement.backendStatement as unknown as MutableBackendStatementView;
            const firstComponent = backendStatement.proofComponents[0];
            if (firstComponent === undefined) {
                throw new Error(
                    "backend proof component mutation target is missing",
                );
            }
            firstComponent.componentId = "receiver-key-binding-component";

            return statement;
        },
        mutation: "backend-proof-component",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
    backendPreflightRejectingCase({
        caseName: "backend-variable-order-mutation-rejects",
        description:
            "A changed backend variable-column order fails canonical preflight.",
        mutateStatement: (statement) => {
            const backendStatement =
                statement.backendStatement as unknown as MutableBackendStatementView;
            if (backendStatement.variableColumns.length < 2) {
                throw new Error("backend variable mutation target is missing");
            }
            backendStatement.variableColumns[0].columnIndex = 1;

            return statement;
        },
        mutation: "backend-variable-order",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
    backendPreflightRejectingCase({
        caseName: "noncanonical-backend-coefficient-rejects",
        description:
            "A backend coefficient with a leading zero fails canonical preflight.",
        mutateStatement: (statement) => {
            const backendStatement =
                statement.backendStatement as unknown as MutableBackendStatementView;
            const firstExplicitRow = backendStatement.rowBatches[0]?.rows?.[0];
            if (firstExplicitRow === undefined) {
                throw new Error(
                    "backend coefficient mutation target is missing",
                );
            }
            firstExplicitRow.terms[0].coefficient = "01";

            return statement;
        },
        mutation: "noncanonical-backend-coefficient",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
    backendPreflightRejectingCase({
        caseName: "truncated-backend-statement-rejects",
        description:
            "A backend statement missing row batches fails canonical preflight.",
        mutateStatement: (statement) => {
            delete (
                statement.backendStatement as unknown as {
                    rowBatches?: unknown;
                }
            ).rowBatches;

            return statement;
        },
        mutation: "truncated-backend-statement",
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    }),
];

const rejectingCase = (input: {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): EncodedBallotRelationVectorCase => {
    const result: BallotPrivacyRelationBackendLoweringResult =
        lowerBallotPrivacyRelationToBackendStatement({
            publicContext: input.publicContext,
            relationInput: input.relationInput,
        });
    if (result.ok) {
        throw new Error(`${input.caseName} was expected to reject.`);
    }

    return {
        caseName: input.caseName,
        compilerAccepted: false,
        description: input.description,
        expectedOutcome: "reject",
        mutation: input.mutation,
        refusalMessages: result.refusedObjects.map(
            (refusal) => refusal.message,
        ),
        trace: {
            ...traceDimensions(input.relationInput),
            expectedLogicalRejectionLayer: "relation-compiler",
        },
    };
};

const mutatedMiniRelationInputs = (
    baseInput: BallotPrivacyRelationCompilerInput,
): readonly {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}[] => [
    {
        caseName: "score-zero-rejects",
        description: "Score zero fails the frozen score-domain relation.",
        mutation: "score-0",
        relationInput: {
            ...baseInput,
            normalizedScores: [0, 3],
            scoreOneHotWitnesses: [oneHotScore(1), oneHotScore(3)],
        },
    },
    {
        caseName: "score-eleven-rejects",
        description: "Score eleven fails the frozen score-domain relation.",
        mutation: "score-11",
        relationInput: {
            ...baseInput,
            normalizedScores: [11, 3],
            scoreOneHotWitnesses: [oneHotScore(10), oneHotScore(3)],
        },
    },
    {
        caseName: "malformed-one-hot-rejects",
        description: "Two active bucket entries fail one-hot membership.",
        mutation: "two-active-buckets",
        relationInput: {
            ...baseInput,
            scoreOneHotWitnesses: [
                [0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
                oneHotScore(3),
            ],
        },
    },
    {
        caseName: "signed-cancellation-one-hot-rejects",
        description:
            "Signed cancellation fails boolean one-hot membership even when a linear reconstruction can be made to look small.",
        mutation: "signed-cancellation",
        relationInput: {
            ...baseInput,
            scoreOneHotWitnesses: [
                [0, 0, -1, 0, 2, 0, 0, 0, 0, 0],
                oneHotScore(3),
            ],
        },
    },
    {
        caseName: "wrong-quotient-rejects",
        description: "A mutated receiver share fails the quotient equation.",
        mutation: "wrong-quotient",
        relationInput: {
            ...baseInput,
            receivers: baseInput.receivers.map((receiver) =>
                receiver.receiverRosterPosition === 2
                    ? {
                          ...receiver,
                          receiverShareVector: receiver.receiverShareVector.map(
                              (shareRepresentative, coordinateIndex) =>
                                  coordinateIndex === 0
                                      ? shareRepresentative + 1
                                      : shareRepresentative,
                          ),
                      }
                    : receiver,
            ),
        },
    },
    {
        caseName: "wrong-degree-rejects",
        description:
            "A coefficient row with degree equal to the threshold fails.",
        mutation: "wrong-degree",
        relationInput: {
            ...baseInput,
            encodedCoordinateShamirCoefficients: [
                [65_536, 1],
                ...baseInput.encodedCoordinateShamirCoefficients.slice(1),
            ],
        },
    },
    {
        caseName: "omitted-receiver-rejects",
        description: "Omitting one receiver fails coverage.",
        mutation: "omitted-receiver",
        relationInput: {
            ...baseInput,
            receivers: baseInput.receivers.slice(0, 2),
        },
    },
    {
        caseName: "duplicate-receiver-rejects",
        description:
            "Duplicating a receiver roster position fails receiver coverage.",
        mutation: "duplicate-receiver",
        relationInput: {
            ...baseInput,
            receivers: [
                baseInput.receivers[0],
                {
                    ...baseInput.receivers[1],
                    receiverRosterPosition: 1,
                },
                baseInput.receivers[2],
            ],
        },
    },
    {
        caseName: "nonzero-padding-rejects",
        description: "Nonzero share-vector padding fails closed.",
        mutation: "nonzero-padding",
        relationInput: {
            ...baseInput,
            receivers: baseInput.receivers.map((receiver) =>
                receiver.receiverRosterPosition === 3
                    ? {
                          ...receiver,
                          receiverShareVector: [
                              ...receiver.receiverShareVector,
                              1,
                          ],
                      }
                    : receiver,
            ),
        },
    },
];

const main = async (): Promise<void> => {
    const miniInput = miniRelationInput();
    const fullExplicitMiniInput = singleOptionRelationInput();
    const mandatoryInput = mandatoryRelationInput();
    const miniPublicContext = publicContextForRoster(miniInput, true);
    const miniDigestExpandedPublicContext = publicContextForRoster(
        miniInput,
        false,
    );
    const mandatoryPublicContext = publicContextForRoster(
        mandatoryInput,
        false,
    );
    const miniAcceptingCase = acceptingCase({
        caseName: "mini-encoded-ballot-relation",
        description:
            "Mini encoded-score ballot relation with three receivers and two options.",
        includeFullStatement: true,
        publicContext: miniDigestExpandedPublicContext,
        relationInput: miniInput,
    });
    const miniExplicitShareCommitmentCase = acceptingCase({
        caseName: "mini-encoded-ballot-share-commitment-explicit-relation",
        description:
            "Mini encoded-score ballot relation with explicit share commitment backend rows.",
        includeComponentProjectionSummaries: true,
        includeFullStatement: false,
        publicContext: miniPublicContext,
        relationInput: miniInput,
    });
    const fullExplicitMiniContext =
        explicitReceiverEncryptionContextForRelation(fullExplicitMiniInput);
    const fullExplicitMiniCase = acceptingCase({
        caseName: "mini-encoded-ballot-full-explicit-relation",
        description:
            "Mini encoded-score ballot relation with explicit share commitments, receiver ciphertext chunks, and receiver public keys for all five proof components.",
        includeComponentProjectionSummaries: true,
        includeExplicitComponentVerificationSummaries: true,
        includeFullStatement: false,
        projectionWitness: fullExplicitMiniContext.projectionWitness,
        publicContext: fullExplicitMiniContext.publicContext,
        relationInput: fullExplicitMiniInput,
    });
    const miniBaselineDigest =
        miniExplicitShareCommitmentCase.trace.relationStatementDigest ?? "";
    const cases: EncodedBallotRelationVectorCase[] = [
        miniAcceptingCase,
        miniExplicitShareCommitmentCase,
        fullExplicitMiniCase,
        acceptingCase({
            caseName: "mandatory-profile-encoded-ballot-relation",
            description:
                "Mandatory encoded-score ballot relation shape with twenty receivers and twenty options.",
            includeFullStatement: false,
            publicContext: mandatoryPublicContext,
            relationInput: mandatoryInput,
        }),
        ...digestChangingPublicContextCases({
            baselineRelationStatementDigest: miniBaselineDigest,
            publicContext: miniPublicContext,
            relationInput: miniInput,
        }),
        ...backendPreflightMutationCases({
            publicContext: miniDigestExpandedPublicContext,
            relationInput: miniInput,
        }),
        ...mutatedMiniRelationInputs(miniInput).map((mutationCase) =>
            rejectingCase({
                ...mutationCase,
                publicContext: miniPublicContext,
            }),
        ),
    ];
    const vectorFile = {
        cases,
        generatedBy:
            "tsx --tsconfig tsconfig.base.json tools/ballot-privacy-vectors/generate-encoded-relation-vectors.mts",
        generationStatus: "generated",
        objectType: "BallotPrivacyEncodedBallotLinearRelationVectors",
        objectVersion: 1,
        profileId: "encoded-ballot-linear-relation-v1",
        requiredCaseNames: cases.map((vectorCase) => vectorCase.caseName),
        statementFormat: "SparseIntegerRowsModuloGF65537WithBoundGadgets-v1",
    };

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(vectorFile)}\n`);
};

void main();
