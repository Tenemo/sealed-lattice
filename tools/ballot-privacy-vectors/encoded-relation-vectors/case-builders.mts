import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentProofStatementPlans,
    type BallotProofComponentProjectionWitness,
} from "../../../packages/protocol/src/ballot-privacy/ballot-proof-linear-statement.js";
import { lowerBallotPrivacyRelationToBackendStatement } from "../../../packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type {
    BallotPrivacyLoweredLinearRelationStatement,
    BallotPrivacyRelationBackendLoweringResult,
    BallotPrivacyRelationBackendPublicContext,
} from "../../../packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type { BallotPrivacyRelationCompilerInput } from "../../../packages/protocol/src/ballot-privacy/relation-compiler.js";

import {
    componentProjectionSummaries,
    componentProofReadinessManifests,
    digest,
    explicitComponentVerificationSummaries,
    explicitReceiverEncryptionContextForRelation,
    mandatoryRelationInput,
    miniRelationInput,
    projectionWitnessForRelationInput,
    proofReadinessSummary,
    publicContextForRoster,
    singleOptionRelationInput,
    summarizeComponentBundle,
    summarizeStatement,
    traceDimensions,
} from "./relation-fixtures-and-summaries.mjs";
import { mutatedMiniRelationInputs } from "./case-relation-input-mutations.mjs";
import type { EncodedBallotRelationVectorCase } from "./vector-case-types.mjs";

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

export const buildEncodedBallotRelationVectorCases =
    (): EncodedBallotRelationVectorCase[] => {
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
        return cases;
    };
