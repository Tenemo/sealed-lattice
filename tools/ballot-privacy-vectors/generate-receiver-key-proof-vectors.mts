import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { deriveProtocolDigest } from "../../packages/crypto/src/digests.js";
import { createReceiverEncryptionPublicKeyShell } from "../../packages/protocol/src/ballot-privacy/objects.js";
import { createBallotPrivacyProfileSet } from "../../packages/protocol/src/ballot-privacy/profiles.js";
import {
    createFixtureRandomnessSource,
    createReceiverKeyProof,
    generateReceiverState,
    type ReceiverEncryptionSecretState,
} from "../../packages/protocol/src/ballot-privacy/lattice-primitives.js";
import {
    createReceiverKeyProofBackendStatement,
    type ReceiverKeyProofBackendStatement,
} from "../../packages/protocol/src/ballot-privacy/receiver-key-backend-statement.js";
import {
    createReceiverKeyLinearProofStatement,
    type ReceiverKeyLinearProofStatement,
} from "../../packages/protocol/src/ballot-privacy/receiver-key-linear-statement.js";
import type {
    ProtocolDigest,
    ReceiverEncryptionPublicKey,
    ReceiverKeyProof,
} from "../../packages/types/src/index.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const outputPath = path.resolve(
    repoRoot,
    "test-vectors/ballot-privacy/receiver-key-proof-vectors.json",
);

interface ReceiverKeyProofVectorCase {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly expectedOutcome: "accept" | "reject";
    readonly proofConstructionAccepted: boolean;
    readonly receiverPublicKey?: ReceiverEncryptionPublicKey;
    readonly receiverKeyProof?: ReceiverKeyProof;
    readonly backendStatement?: ReceiverKeyProofBackendStatement;
    readonly linearStatement?: ReceiverKeyLinearProofStatement;
    readonly refusalMessages?: readonly string[];
    readonly trace: {
        readonly expectedLogicalRejectionLayer?:
            | "receiver-key-proof-construction"
            | "backend-statement-preflight"
            | "linear-statement-preflight"
            | "receiver-key-proof-shell";
        readonly backendStatementDigest?: ProtocolDigest;
        readonly baselineBackendStatementDigest?: ProtocolDigest;
        readonly linearStatementDigest?: ProtocolDigest;
        readonly baselineLinearStatementDigest?: ProtocolDigest;
        readonly expectedDigestChanged?: true;
    };
}

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest("ChallengeDomainDigest", {
        label,
        purpose: "receiver-key-proof-vector",
    });

const fixtureRandomness = createFixtureRandomnessSource(
    "receiver-key-proof-vectors",
);

const deepClone = <Value,>(value: Value): Value =>
    JSON.parse(JSON.stringify(value)) as Value;

const mutateProtocolDigest = (
    label: string,
    previousDigest?: ProtocolDigest,
): ProtocolDigest => {
    const candidate = digest(label);

    return candidate === previousDigest
        ? digest(`${label}-alternate`)
        : candidate;
};

const baselineInput = () => {
    const profileSet = createBallotPrivacyProfileSet();
    const receiverState = generateReceiverState({
        ceremonyId: "ceremony-receiver-key-vectors",
        manifestDigest: digest("manifest"),
        randomnessSource: fixtureRandomness,
        receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
        receiverIdentity: "receiver-1",
        receiverRosterPosition: 1,
        recoveryEpoch: 0,
        rosterDigest: digest("roster"),
    });
    const backendStatement = createReceiverKeyProofBackendStatement({
        publicKeyMaterial: receiverState.publicKeyMaterial,
        receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
        receiverPublicKey: receiverState.receiverPublicKey,
    });
    const linearStatement = createReceiverKeyLinearProofStatement({
        publicKeyMaterial: receiverState.publicKeyMaterial,
        receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
        receiverPublicKey: receiverState.receiverPublicKey,
    });
    const receiverKeyProof = createReceiverKeyProof({
        publicKeyMaterial: receiverState.publicKeyMaterial,
        receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
        receiverPublicKey: receiverState.receiverPublicKey,
        secretState: receiverState.secretState,
    });

    return {
        backendStatement,
        linearStatement,
        profileSet,
        receiverKeyProof,
        receiverState,
    };
};

const acceptingCase = (input: {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly receiverKeyProof: ReceiverKeyProof;
    readonly backendStatement: ReceiverKeyProofBackendStatement;
    readonly linearStatement: ReceiverKeyLinearProofStatement;
    readonly baselineBackendStatementDigest?: ProtocolDigest;
    readonly baselineLinearStatementDigest?: ProtocolDigest;
}): ReceiverKeyProofVectorCase => ({
    backendStatement: input.backendStatement,
    caseName: input.caseName,
    description: input.description,
    expectedOutcome: "accept",
    mutation: input.mutation,
    proofConstructionAccepted: true,
    linearStatement: input.linearStatement,
    receiverKeyProof: input.receiverKeyProof,
    receiverPublicKey: input.receiverPublicKey,
    trace: {
        backendStatementDigest: input.backendStatement.backendStatementDigest,
        linearStatementDigest: input.linearStatement.statementDigest,
        ...(input.baselineBackendStatementDigest === undefined
            ? {}
            : {
                  baselineBackendStatementDigest:
                      input.baselineBackendStatementDigest,
                  expectedDigestChanged: true as const,
              }),
        ...(input.baselineLinearStatementDigest === undefined
            ? {}
            : {
                  baselineLinearStatementDigest:
                      input.baselineLinearStatementDigest,
                  expectedDigestChanged: true as const,
              }),
    },
});

const constructionRejectingCase = (
    caseName: string,
    description: string,
    mutation: string,
    createProof: () => void,
): ReceiverKeyProofVectorCase => {
    try {
        createProof();
    } catch (error) {
        return {
            caseName,
            description,
            expectedOutcome: "reject",
            mutation,
            proofConstructionAccepted: false,
            refusalMessages: [
                error instanceof Error
                    ? error.message
                    : "Receiver-key proof construction rejected the vector.",
            ],
            trace: {
                expectedLogicalRejectionLayer:
                    "receiver-key-proof-construction",
            },
        };
    }

    throw new Error(
        `${caseName} unexpectedly constructed a receiver-key proof.`,
    );
};

const backendPreflightRejectingCase = (input: {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly receiverKeyProof: ReceiverKeyProof;
    readonly backendStatement: ReceiverKeyProofBackendStatement;
    readonly linearStatement: ReceiverKeyLinearProofStatement;
}): ReceiverKeyProofVectorCase => ({
    backendStatement: input.backendStatement,
    caseName: input.caseName,
    description: input.description,
    expectedOutcome: "reject",
    mutation: input.mutation,
    proofConstructionAccepted: true,
    linearStatement: input.linearStatement,
    receiverKeyProof: input.receiverKeyProof,
    receiverPublicKey: input.receiverPublicKey,
    trace: {
        backendStatementDigest: input.backendStatement.backendStatementDigest,
        linearStatementDigest: input.linearStatement.statementDigest,
        expectedLogicalRejectionLayer: "backend-statement-preflight",
    },
});

const linearPreflightRejectingCase = (input: {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly receiverKeyProof: ReceiverKeyProof;
    readonly backendStatement: ReceiverKeyProofBackendStatement;
    readonly linearStatement: ReceiverKeyLinearProofStatement;
}): ReceiverKeyProofVectorCase => ({
    backendStatement: input.backendStatement,
    caseName: input.caseName,
    description: input.description,
    expectedOutcome: "reject",
    mutation: input.mutation,
    proofConstructionAccepted: true,
    linearStatement: input.linearStatement,
    receiverKeyProof: input.receiverKeyProof,
    receiverPublicKey: input.receiverPublicKey,
    trace: {
        backendStatementDigest: input.backendStatement.backendStatementDigest,
        expectedLogicalRejectionLayer: "linear-statement-preflight",
        linearStatementDigest: input.linearStatement.statementDigest,
    },
});

const proofShellRejectingCase = (input: {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly receiverKeyProof: ReceiverKeyProof;
    readonly backendStatement: ReceiverKeyProofBackendStatement;
    readonly linearStatement: ReceiverKeyLinearProofStatement;
}): ReceiverKeyProofVectorCase => ({
    backendStatement: input.backendStatement,
    caseName: input.caseName,
    description: input.description,
    expectedOutcome: "reject",
    mutation: input.mutation,
    proofConstructionAccepted: true,
    linearStatement: input.linearStatement,
    receiverKeyProof: input.receiverKeyProof,
    receiverPublicKey: input.receiverPublicKey,
    trace: {
        backendStatementDigest: input.backendStatement.backendStatementDigest,
        linearStatementDigest: input.linearStatement.statementDigest,
        expectedLogicalRejectionLayer: "receiver-key-proof-shell",
    },
});

const mutateSecretCoefficient = (
    secretState: ReceiverEncryptionSecretState,
    replacement: number,
): ReceiverEncryptionSecretState => ({
    errorVector: secretState.errorVector,
    secretVector: secretState.secretVector.map((polynomial, polynomialIndex) =>
        polynomialIndex === 0
            ? polynomial.map((coefficient, coefficientIndex) =>
                  coefficientIndex === 0 ? replacement : coefficient,
              )
            : polynomial,
    ),
});

const mutateErrorCoefficient = (
    secretState: ReceiverEncryptionSecretState,
    replacement: number,
): ReceiverEncryptionSecretState => ({
    errorVector: secretState.errorVector.map((polynomial, polynomialIndex) =>
        polynomialIndex === 0
            ? polynomial.map((coefficient, coefficientIndex) =>
                  coefficientIndex === 0 ? replacement : coefficient,
              )
            : polynomial,
    ),
    secretVector: secretState.secretVector,
});

const cases = (): readonly ReceiverKeyProofVectorCase[] => {
    const baseline = baselineInput();
    const changedManifest = (() => {
        const changedReceiverState = generateReceiverState({
            ceremonyId: "ceremony-receiver-key-vectors",
            manifestDigest: digest("manifest-changed"),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile:
                baseline.profileSet.receiverEncryptionProfile,
            receiverIdentity: "receiver-1",
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest("roster"),
        });
        const backendStatement = createReceiverKeyProofBackendStatement({
            publicKeyMaterial: changedReceiverState.publicKeyMaterial,
            receiverEncryptionProfile:
                baseline.profileSet.receiverEncryptionProfile,
            receiverPublicKey: changedReceiverState.receiverPublicKey,
        });
        const linearStatement = createReceiverKeyLinearProofStatement({
            publicKeyMaterial: changedReceiverState.publicKeyMaterial,
            receiverEncryptionProfile:
                baseline.profileSet.receiverEncryptionProfile,
            receiverPublicKey: changedReceiverState.receiverPublicKey,
        });
        const receiverKeyProof = createReceiverKeyProof({
            publicKeyMaterial: changedReceiverState.publicKeyMaterial,
            receiverEncryptionProfile:
                baseline.profileSet.receiverEncryptionProfile,
            receiverPublicKey: changedReceiverState.receiverPublicKey,
            secretState: changedReceiverState.secretState,
        });

        return {
            backendStatement,
            linearStatement,
            receiverKeyProof,
            receiverPublicKey: changedReceiverState.receiverPublicKey,
        };
    })();
    const baselineReceiverPublicKey = baseline.receiverState.receiverPublicKey;
    const wrongKeyMaterialReceiverPublicKey =
        createReceiverEncryptionPublicKeyShell({
            ceremonyId: baselineReceiverPublicKey.ceremonyId,
            keyMaterialDigest: mutateProtocolDigest(
                "wrong-key-material",
                baselineReceiverPublicKey.keyMaterialDigest,
            ),
            manifestDigest: baselineReceiverPublicKey.manifestDigest,
            receiverEncryptionProfileDigest:
                baselineReceiverPublicKey.receiverEncryptionProfileDigest,
            receiverIdentity: baselineReceiverPublicKey.receiverIdentity,
            receiverRosterPosition:
                baselineReceiverPublicKey.receiverRosterPosition,
            recoveryEpoch: baselineReceiverPublicKey.recoveryEpoch,
            rosterDigest: baselineReceiverPublicKey.rosterDigest,
        });
    const wrongSecretReplacement =
        baseline.receiverState.secretState.secretVector[0]?.[0] === 2 ? 1 : 2;
    const clonedNoncanonicalStatement = deepClone(baseline.backendStatement);
    const noncanonicalBackendStatement = {
        ...clonedNoncanonicalStatement,
        rowBatches: [
            {
                ...clonedNoncanonicalStatement.rowBatches[0],
                modulus: "012289",
            },
        ],
    } as unknown as ReceiverKeyProofBackendStatement;
    const mutatedMatrixDigestStatement = {
        ...deepClone(baseline.backendStatement),
        matrixDigest: mutateProtocolDigest(
            "mutated-receiver-key-matrix-digest",
            baseline.backendStatement.matrixDigest,
        ),
    };
    const missingBoundStatement = {
        ...deepClone(baseline.backendStatement),
        bounds: [baseline.backendStatement.bounds[0]],
    } as unknown as ReceiverKeyProofBackendStatement;
    const mutatedLinearMatrixStatement = {
        ...deepClone(baseline.linearStatement),
        statementMatrixCoefficients:
            baseline.linearStatement.statementMatrixCoefficients.map(
                (matrixRow, rowIndex) =>
                    rowIndex === 0
                        ? matrixRow.map((polynomial, columnIndex) =>
                              columnIndex === 0
                                  ? polynomial.map(
                                        (coefficient, coefficientIndex) =>
                                            coefficientIndex === 0
                                                ? (coefficient + 1) % 12_289
                                                : coefficient,
                                    )
                                  : polynomial,
                          )
                        : matrixRow,
            ),
    } as unknown as ReceiverKeyLinearProofStatement;
    const mutatedLinearTargetStatement = {
        ...deepClone(baseline.linearStatement),
        targetVectorCoefficients:
            baseline.linearStatement.targetVectorCoefficients.map(
                (polynomial, rowIndex) =>
                    rowIndex === 0
                        ? polynomial.map((coefficient, coefficientIndex) =>
                              coefficientIndex === 0
                                  ? (coefficient + 1) % 12_289
                                  : coefficient,
                          )
                        : polynomial,
            ),
    } as unknown as ReceiverKeyLinearProofStatement;
    const mutatedProofRoot = {
        ...baseline.receiverKeyProof,
        proofRoot: mutateProtocolDigest(
            "mutated-receiver-key-proof-root",
            baseline.receiverKeyProof.proofRoot,
        ),
    };

    return [
        acceptingCase({
            backendStatement: baseline.backendStatement,
            caseName: "valid-receiver-key-proof-backend-statement",
            description:
                "A roster-bound receiver key proof shell, linear statement, and backend statement pass public preflight.",
            linearStatement: baseline.linearStatement,
            mutation: "none",
            receiverKeyProof: baseline.receiverKeyProof,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
        acceptingCase({
            backendStatement: changedManifest.backendStatement,
            baselineBackendStatementDigest:
                baseline.backendStatement.backendStatementDigest,
            baselineLinearStatementDigest:
                baseline.linearStatement.statementDigest,
            caseName: "changed-manifest-changes-backend-statement-digest",
            description:
                "Changing the manifest produces different accepted receiver-key backend and linear statement digests.",
            linearStatement: changedManifest.linearStatement,
            mutation: "manifestDigest",
            receiverKeyProof: changedManifest.receiverKeyProof,
            receiverPublicKey: changedManifest.receiverPublicKey,
        }),
        constructionRejectingCase(
            "wrong-ceremony-rejects",
            "A receiver public key with a mutated ceremony is rejected before a backend statement is issued.",
            "receiverPublicKey.ceremonyId",
            () =>
                createReceiverKeyProofBackendStatement({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: {
                        ...baseline.receiverState.receiverPublicKey,
                        ceremonyId: "wrong-ceremony",
                    },
                }),
        ),
        constructionRejectingCase(
            "wrong-roster-digest-rejects",
            "A receiver public key with a mutated roster digest is rejected before a backend statement is issued.",
            "receiverPublicKey.rosterDigest",
            () =>
                createReceiverKeyProofBackendStatement({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: {
                        ...baseline.receiverState.receiverPublicKey,
                        rosterDigest: digest("wrong-roster"),
                    },
                }),
        ),
        constructionRejectingCase(
            "wrong-recovery-epoch-rejects",
            "A receiver public key with a mutated recovery epoch is rejected before a backend statement is issued.",
            "receiverPublicKey.recoveryEpoch",
            () =>
                createReceiverKeyProofBackendStatement({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: {
                        ...baseline.receiverState.receiverPublicKey,
                        recoveryEpoch: 1,
                    },
                }),
        ),
        constructionRejectingCase(
            "wrong-public-matrix-seed-rejects",
            "A substituted public matrix seed is rejected before a backend statement is issued.",
            "publicKeyMaterial.publicMatrixSeedDigest",
            () =>
                createReceiverKeyProofBackendStatement({
                    publicKeyMaterial: {
                        ...baseline.receiverState.publicKeyMaterial,
                        publicMatrixSeedDigest: digest("wrong-matrix-seed"),
                    },
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: baseline.receiverState.receiverPublicKey,
                }),
        ),
        constructionRejectingCase(
            "wrong-key-material-digest-rejects",
            "A receiver key with a canonical but mismatched key material digest is rejected.",
            "receiverPublicKey.keyMaterialDigest",
            () =>
                createReceiverKeyProofBackendStatement({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: wrongKeyMaterialReceiverPublicKey,
                }),
        ),
        constructionRejectingCase(
            "oversize-secret-witness-rejects",
            "A receiver-key witness with an out-of-bound secret coefficient is rejected before proof creation.",
            "secretState.secretVector[0][0]",
            () =>
                void createReceiverKeyProof({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: baseline.receiverState.receiverPublicKey,
                    secretState: mutateSecretCoefficient(
                        baseline.receiverState.secretState,
                        3,
                    ),
                }),
        ),
        constructionRejectingCase(
            "oversize-error-witness-rejects",
            "A receiver-key witness with an out-of-bound error coefficient is rejected before proof creation.",
            "secretState.errorVector[0][0]",
            () =>
                void createReceiverKeyProof({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: baseline.receiverState.receiverPublicKey,
                    secretState: mutateErrorCoefficient(
                        baseline.receiverState.secretState,
                        -3,
                    ),
                }),
        ),
        constructionRejectingCase(
            "wrong-secret-equation-rejects",
            "A short but substituted secret vector is rejected because it no longer satisfies the public-key equation.",
            "secretState.secretVector[0][0]",
            () =>
                void createReceiverKeyProof({
                    publicKeyMaterial: baseline.receiverState.publicKeyMaterial,
                    receiverEncryptionProfile:
                        baseline.profileSet.receiverEncryptionProfile,
                    receiverPublicKey: baseline.receiverState.receiverPublicKey,
                    secretState: mutateSecretCoefficient(
                        baseline.receiverState.secretState,
                        wrongSecretReplacement,
                    ),
                }),
        ),
        backendPreflightRejectingCase({
            backendStatement: noncanonicalBackendStatement,
            caseName: "noncanonical-backend-modulus-rejects",
            description:
                "A receiver-key backend statement with a noncanonical decimal modulus is rejected by preflight.",
            mutation: "backendStatement.rowBatches[0].modulus",
            linearStatement: baseline.linearStatement,
            receiverKeyProof: baseline.receiverKeyProof,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
        backendPreflightRejectingCase({
            backendStatement: mutatedMatrixDigestStatement,
            caseName: "mutated-backend-matrix-digest-rejects",
            description:
                "A receiver-key backend statement with a mutated matrix digest is rejected by preflight.",
            mutation: "backendStatement.matrixDigest",
            linearStatement: baseline.linearStatement,
            receiverKeyProof: baseline.receiverKeyProof,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
        backendPreflightRejectingCase({
            backendStatement: missingBoundStatement,
            caseName: "missing-backend-bound-rejects",
            description:
                "A receiver-key backend statement missing one short-vector bound is rejected by preflight.",
            mutation: "backendStatement.bounds",
            linearStatement: baseline.linearStatement,
            receiverKeyProof: baseline.receiverKeyProof,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
        linearPreflightRejectingCase({
            backendStatement: baseline.backendStatement,
            caseName: "mutated-linear-statement-matrix-rejects",
            description:
                "A receiver-key linear statement with a mutated matrix coefficient is rejected by preflight.",
            linearStatement: mutatedLinearMatrixStatement,
            mutation: "linearStatement.statementMatrixCoefficients[0][0][0]",
            receiverKeyProof: baseline.receiverKeyProof,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
        linearPreflightRejectingCase({
            backendStatement: baseline.backendStatement,
            caseName: "mutated-linear-statement-target-rejects",
            description:
                "A receiver-key linear statement with a mutated target coefficient is rejected by preflight.",
            linearStatement: mutatedLinearTargetStatement,
            mutation: "linearStatement.targetVectorCoefficients[0][0]",
            receiverKeyProof: baseline.receiverKeyProof,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
        proofShellRejectingCase({
            backendStatement: baseline.backendStatement,
            caseName: "mutated-proof-root-rejects",
            description:
                "A receiver-key proof shell with a mutated proof root is rejected before backend acceptance.",
            linearStatement: baseline.linearStatement,
            mutation: "receiverKeyProof.proofRoot",
            receiverKeyProof: mutatedProofRoot,
            receiverPublicKey: baseline.receiverState.receiverPublicKey,
        }),
    ];
};

const main = async (): Promise<void> => {
    const vectorFile = {
        cases: cases(),
        generationStatus: "generated",
        objectType: "ReceiverKeyProofBackendStatementVectors",
        objectVersion: 1,
        profileId: "receiver-key-proof-backend-statement-v1",
        requiredCaseNames: [
            "valid-receiver-key-proof-backend-statement",
            "changed-manifest-changes-backend-statement-digest",
            "wrong-ceremony-rejects",
            "wrong-roster-digest-rejects",
            "wrong-recovery-epoch-rejects",
            "wrong-public-matrix-seed-rejects",
            "wrong-key-material-digest-rejects",
            "oversize-secret-witness-rejects",
            "oversize-error-witness-rejects",
            "wrong-secret-equation-rejects",
            "noncanonical-backend-modulus-rejects",
            "mutated-backend-matrix-digest-rejects",
            "missing-backend-bound-rejects",
            "mutated-linear-statement-matrix-rejects",
            "mutated-linear-statement-target-rejects",
            "mutated-proof-root-rejects",
        ],
        statementFormat:
            "SparseSignedIntegerBackendStatement-v1 + receiver-key-linear-module-lwe-statement-v1",
        vectorProvenance: {
            generator:
                "tools/ballot-privacy-vectors/generate-receiver-key-proof-vectors.mts",
            secretWitnessMaterialIncluded: false,
            publicKeyCoefficientMaterialIncluded: true,
        },
    };

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(vectorFile, null, 4)}\n`);
};

await main();
