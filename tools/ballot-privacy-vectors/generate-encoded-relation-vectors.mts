import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { deriveProtocolDigest } from "../../packages/crypto/src/digests.js";
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
} from "../../packages/protocol/src/ballot-privacy/profiles.js";
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
    readonly loweredStatement?: BallotPrivacyLoweredLinearRelationStatement;
    readonly loweredStatementSummary?: {
        readonly algebraicRowCount: number;
        readonly backendColumnCount: number;
        readonly backendDigestExpandedRowCount: number;
        readonly backendExplicitRowCount: number;
        readonly backendRowBatchCount: number;
        readonly backendRowCount: number;
        readonly backendStatementDigest: string;
        readonly backendStatementFormat: string;
        readonly boundCount: number;
        readonly encodedCoordinateCount: number;
        readonly firstBackendRowBatch: unknown;
        readonly firstAlgebraicRow: unknown;
        readonly firstBound: unknown;
        readonly firstLinearRow: unknown;
        readonly lastAlgebraicRow: unknown;
        readonly lastBackendRowBatch: unknown;
        readonly lastBound: unknown;
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

const publicContextForRoster = (
    rosterSize: number,
): BallotPrivacyRelationBackendPublicContext => {
    const profileSet = createBallotPrivacyProfileSet();
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: Math.max(20, rosterSize),
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = Array.from(
        { length: rosterSize },
        (_unusedValue, receiverOffset) => ({
            receiverIdentity: `receiver-${receiverOffset + 1}`,
            receiverRosterPosition: receiverOffset + 1,
        }),
    );

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
        shareCommitments: receiverReferences.map((receiverReference) => ({
            commitmentBodyDigest: digest(
                `share-commitment-body-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            commitmentPolynomialVectorDigest: digest(
                `share-commitment-polynomial-vector-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ...receiverReference,
            shareCommitmentDigest: digest(
                `share-commitment-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
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
    const lastBound = statement.bounds[statement.bounds.length - 1];
    const lastLinearRow = statement.linearRows[statement.linearRows.length - 1];

    return {
        algebraicRowCount: statement.algebraicRows.length,
        backendColumnCount: statement.backendStatement.columnCount,
        backendDigestExpandedRowCount:
            statement.backendStatement.digestExpandedRowCount,
        backendExplicitRowCount: statement.backendStatement.explicitRowCount,
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
        firstBound: statement.bounds[0],
        firstLinearRow: statement.linearRows[0],
        lastAlgebraicRow,
        lastBackendRowBatch,
        lastBound,
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

const acceptingCase = (input: {
    readonly baselineRelationStatementDigest?: string;
    readonly caseName: string;
    readonly description: string;
    readonly expectedDigestChanged?: true;
    readonly includeFullStatement: boolean;
    readonly mutation?: string;
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

    return {
        caseName: input.caseName,
        compilerAccepted: true,
        description: input.description,
        expectedOutcome: "accept",
        loweredStatement: input.includeFullStatement
            ? result.statement
            : undefined,
        loweredStatementSummary: input.includeFullStatement
            ? undefined
            : summarizeStatement(result.statement),
        mutation: input.mutation ?? "none",
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
    const mandatoryInput = mandatoryRelationInput();
    const miniPublicContext = publicContextForRoster(miniInput.rosterSize);
    const mandatoryPublicContext = publicContextForRoster(
        mandatoryInput.rosterSize,
    );
    const miniAcceptingCase = acceptingCase({
        caseName: "mini-encoded-ballot-relation",
        description:
            "Mini encoded-score ballot relation with three receivers and two options.",
        includeFullStatement: true,
        publicContext: miniPublicContext,
        relationInput: miniInput,
    });
    const miniBaselineDigest =
        miniAcceptingCase.trace.relationStatementDigest ?? "";
    const cases: EncodedBallotRelationVectorCase[] = [
        miniAcceptingCase,
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
            publicContext: miniPublicContext,
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
    await writeFile(outputPath, `${JSON.stringify(vectorFile, null, 4)}\n`);
};

void main();
