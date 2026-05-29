// Portable mandatory-profile ballot proof-record benchmark shared by the Node and
// browser proof-benchmark lanes so both runtimes exercise the same generation,
// component-projection, and negative-path verification flow.
import { expect } from 'vitest';

import {
    type BallotPrivacyKernelVerification,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge';
import { createMandatoryProfileBallotProofRecordBenchmarkFixture } from '#tests/support/ballot-privacy-proof-record-generation-fixtures';
import {
    runTimedTestStep,
    type TimedTestStepMetric,
} from '#tests/support/timed-test-steps';

const mandatoryProfileProofRecordCheckpointNames = {
    generatedProofRecord:
        'transcript-core-kernel-mandatory-profile-proof-record-generated-proof-record',
    loweredStatements:
        'transcript-core-kernel-mandatory-profile-proof-record-lowered-statements',
    relationRequest:
        'transcript-core-kernel-mandatory-profile-proof-record-relation-request',
    verificationReport:
        'transcript-core-kernel-mandatory-profile-proof-record-verification-report',
} as const;

// Structural checkpoint store so the Node lane can inject filesystem-backed
// resumable checkpoints while the browser lane runs without any filesystem.
type MandatoryProfileProofRecordCheckpointStore = {
    readonly read?: (checkpointName: string) => unknown;
    readonly write?: (checkpointName: string, value: unknown) => void;
};

const cloneJsonValue = <Value>(value: Value): Value =>
    JSON.parse(JSON.stringify(value)) as Value;

const expectRefusalMessage = (
    verification: BallotPrivacyKernelVerification,
    expectedMessage: string,
): void => {
    expect(
        verification.refusedObjects.map((refusal) => refusal.message),
    ).toEqual(
        expect.arrayContaining([expect.stringContaining(expectedMessage)]),
    );
};

const checkpointRecord = (
    checkpointName: string,
    payload: unknown,
): Record<string, unknown> => ({
    checkpointName,
    payload,
    schemaVersion: 1,
});

const checkpointPayload = (value: unknown, checkpointName: string): unknown => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return undefined;
    }
    const record = value as Record<string, unknown>;

    return record.schemaVersion === 1 &&
        record.checkpointName === checkpointName
        ? record.payload
        : undefined;
};

export const runMandatoryProfileProofRecordBenchmark = (input: {
    readonly checkpoints?: MandatoryProfileProofRecordCheckpointStore;
    readonly kernel: TranscriptCoreKernel;
    readonly resumeFromCheckpoints?: boolean;
}): {
    readonly generation: ReturnType<
        TranscriptCoreKernel['generateBallotProofRecord']
    >;
    readonly steps: readonly TimedTestStepMetric[];
} => {
    const { checkpoints, kernel } = input;
    const resumeFromCheckpoints = input.resumeFromCheckpoints ?? false;
    const steps: TimedTestStepMetric[] = [];

    const fixture = runTimedTestStep(
        steps,
        'build mandatory proof relation request',
        () => createMandatoryProfileBallotProofRecordBenchmarkFixture(),
    );
    const { request } = fixture;
    checkpoints?.write?.(
        mandatoryProfileProofRecordCheckpointNames.relationRequest,
        checkpointRecord(
            mandatoryProfileProofRecordCheckpointNames.relationRequest,
            {
                publicContext: fixture.publicContext,
                request,
            },
        ),
    );
    checkpoints?.write?.(
        mandatoryProfileProofRecordCheckpointNames.loweredStatements,
        checkpointRecord(
            mandatoryProfileProofRecordCheckpointNames.loweredStatements,
            {
                componentBundleStatement: request.componentBundleStatement,
                componentProofInputs: request.componentProofInputs,
                linearStatement: request.linearStatement,
                statement: request.statement,
            },
        ),
    );
    const generationCheckpoint = checkpointPayload(
        checkpoints?.read?.(
            mandatoryProfileProofRecordCheckpointNames.generatedProofRecord,
        ),
        mandatoryProfileProofRecordCheckpointNames.generatedProofRecord,
    );
    const checkpointGeneration =
        typeof generationCheckpoint === 'object' &&
        generationCheckpoint !== null &&
        !Array.isArray(generationCheckpoint)
            ? (generationCheckpoint as Record<string, unknown>).generation
            : undefined;
    const reuseGenerationCheckpoint =
        resumeFromCheckpoints &&
        typeof checkpointGeneration === 'object' &&
        checkpointGeneration !== null &&
        !Array.isArray(checkpointGeneration);
    const generation = runTimedTestStep(
        steps,
        reuseGenerationCheckpoint
            ? 'load mandatory proof record checkpoint'
            : 'generate mandatory proof record',
        () =>
            reuseGenerationCheckpoint
                ? checkpointGeneration
                : kernel.generateBallotProofRecord(request),
        { reusedCheckpoint: reuseGenerationCheckpoint },
    ) as ReturnType<TranscriptCoreKernel['generateBallotProofRecord']>;
    checkpoints?.write?.(
        mandatoryProfileProofRecordCheckpointNames.generatedProofRecord,
        checkpointRecord(
            mandatoryProfileProofRecordCheckpointNames.generatedProofRecord,
            {
                generation,
            },
        ),
    );

    expect(generation).toMatchObject({
        ok: true,
        backendAvailable: true,
        generatedProofBytes: true,
        operation: 'generateBallotProofRecord',
        unresolvedReason: null,
    });
    expect(generation.statusLabels).toEqual(
        expect.arrayContaining([
            'BallotComponentProofBundleGenerated',
            'BallotProofRecordGenerated',
            'BallotProofRecordGeneratedProofVerified',
        ]),
    );
    expect(generation.verification).toMatchObject({
        ok: true,
        operation: 'verifyBallotProof',
        unresolvedReason: null,
    });
    const componentProofInputs = generation.componentProofInputs as readonly {
        readonly componentId: string;
        readonly proofBytesHex: string;
        readonly proofStatement: {
            readonly sourceColumnPackings?: readonly unknown[];
            readonly statementColumns?: number;
        };
        readonly proofStatementFormat: string;
    }[];
    expect(
        componentProofInputs.map((proofInput) => [
            proofInput.componentId,
            proofInput.proofStatementFormat,
        ]),
    ).toEqual([
        [
            'score-and-shamir-field-component',
            'sparse-polynomial-matrix-linear-proof-v1',
        ],
        [
            'payload-plaintext-field-component',
            'sparse-polynomial-matrix-linear-proof-v1',
        ],
        [
            'share-commitment-component',
            'structured-module-sis-share-commitment-v1',
        ],
        [
            'receiver-encryption-component',
            'structured-module-lwe-linear-proof-v1',
        ],
        ['receiver-key-binding-component', 'public-binding-check-only-v1'],
    ]);
    for (const componentId of [
        'score-and-shamir-field-component',
        'payload-plaintext-field-component',
    ]) {
        const proofInput = componentProofInputs.find(
            (candidate) => candidate.componentId === componentId,
        );
        expect(proofInput?.proofStatement.sourceColumnPackings).toHaveLength(
            proofInput?.proofStatement.statementColumns ?? -1,
        );
        expect(proofInput?.proofBytesHex).toMatch(/^[0-9a-f]+$/u);
    }

    const proofVerificationInput: Parameters<
        TranscriptCoreKernel['verifyBallotProof']
    >[0] = runTimedTestStep(
        steps,
        'build mandatory proof verification input',
        () => ({
            ballotProof: generation.ballotProof,
            componentBundleStatement: request.componentBundleStatement,
            componentProofBundle: generation.componentProofBundle,
            componentProofInputs: generation.componentProofInputs,
            linearStatement: request.linearStatement,
            parameterSet: generation.parameterSet,
            proofBytesHex: generation.proofBytesHex,
            proofEncoding: generation.proofEncoding,
            publicRandomnessHex: request.publicRandomnessHex,
            statement: request.statement,
        }),
    );
    const verifyMutatedProofRecord = (
        patch: Partial<
            Parameters<TranscriptCoreKernel['verifyBallotProof']>[0]
        >,
    ): BallotPrivacyKernelVerification =>
        kernel.verifyBallotProof({
            ...proofVerificationInput,
            ...patch,
        });
    const expectProofRecordRefusal = (
        patch: Partial<
            Parameters<TranscriptCoreKernel['verifyBallotProof']>[0]
        >,
        expectedMessage: string,
    ): void => {
        const verification = verifyMutatedProofRecord(patch);

        expect(verification).toMatchObject({
            ok: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expectRefusalMessage(verification, expectedMessage);
    };
    const mutateStatement = (
        mutator: (statement: Record<string, unknown>) => void,
    ): Record<string, unknown> => {
        const statement = cloneJsonValue(
            request.statement as Record<string, unknown>,
        );
        mutator(statement);

        return statement;
    };
    const mutateBallotProof = (
        mutator: (ballotProof: Record<string, unknown>) => void,
    ): Record<string, unknown> => {
        const ballotProof = cloneJsonValue(
            generation.ballotProof as Record<string, unknown>,
        );
        mutator(ballotProof);

        return ballotProof;
    };
    const mutateComponentProofInputs = (
        mutator: (
            componentProofInputs: Record<string, unknown>[],
        ) => void | readonly unknown[],
    ): readonly unknown[] => {
        const mutatedComponentProofInputs = cloneJsonValue(
            generation.componentProofInputs ?? [],
        ) as Record<string, unknown>[];
        const mutationResult = mutator(mutatedComponentProofInputs);

        return mutationResult ?? mutatedComponentProofInputs;
    };

    expectProofRecordRefusal(
        {
            statement: mutateStatement((statement) => {
                statement.manifestHash = kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
                    value: {
                        purpose: 'mandatory-proof-record-negative-test',
                        label: 'wrong-manifest',
                    },
                });
            }),
        },
        'Ballot proof statement hash does not match its canonical payload.',
    );
    expectProofRecordRefusal(
        {
            statement: mutateStatement((statement) => {
                statement.rosterExternalAcceptanceHash =
                    kernel.deriveProtocolHash({
                        namespace: 'ChallengeDomainHash',
                        value: {
                            purpose: 'mandatory-proof-record-negative-test',
                            label: 'wrong-roster-acceptance',
                        },
                    });
            }),
        },
        'Ballot proof statement hash does not match its canonical payload.',
    );
    expectProofRecordRefusal(
        {
            proofBytesHex: String(generation.proofBytesHex).slice(0, -2),
        },
        'Ballot proof byte length does not match the proof record.',
    );
    expectProofRecordRefusal(
        {
            ballotProof: mutateBallotProof((ballotProof) => {
                ballotProof.challengeHash = kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
                    value: {
                        purpose: 'mandatory-proof-record-negative-test',
                        label: 'wrong-proof-challenge',
                    },
                });
            }),
        },
        'Ballot proof challenge hash does not match the statement and proof roots.',
    );
    expectProofRecordRefusal(
        {
            componentProofInputs: mutateComponentProofInputs(
                (mutatedComponentProofInputs) => {
                    mutatedComponentProofInputs[0] = {
                        ...mutatedComponentProofInputs[0],
                        proofBytesHex: 'ff'.repeat(
                            String(
                                mutatedComponentProofInputs[0]?.proofBytesHex,
                            ).length / 2,
                        ),
                    };
                },
            ),
        },
        'Ballot proof component proof bytes do not match the proof record hash.',
    );
    expectProofRecordRefusal(
        {
            componentProofInputs: mutateComponentProofInputs(
                (mutatedComponentProofInputs) => {
                    const scoreInput = mutatedComponentProofInputs[0] ?? {};
                    scoreInput.proofStatement = {
                        ...(scoreInput.proofStatement as Record<
                            string,
                            unknown
                        >),
                        sourceColumnPackings: [],
                    };
                    mutatedComponentProofInputs[0] = scoreInput;
                },
            ),
        },
        'Ballot proof component proof statement hash for score-and-shamir-field-component does not match its canonical payload.',
    );
    expectProofRecordRefusal(
        {
            componentProofInputs: mutateComponentProofInputs(
                (mutatedComponentProofInputs) => {
                    const shareCommitmentInput =
                        mutatedComponentProofInputs[2] ?? {};
                    const proofStatement = cloneJsonValue(
                        shareCommitmentInput.proofStatement as Record<
                            string,
                            unknown
                        >,
                    );
                    const receiverRows = proofStatement.receiverRows as Record<
                        string,
                        unknown
                    >[];
                    const firstReceiverRow = receiverRows[0] ?? {};
                    firstReceiverRow.commitmentPolynomialVector = [];
                    receiverRows[0] = firstReceiverRow;
                    proofStatement.receiverRows = receiverRows;
                    shareCommitmentInput.proofStatement = proofStatement;
                    mutatedComponentProofInputs[2] = shareCommitmentInput;
                },
            ),
        },
        'Ballot proof component proof statement hash for share-commitment-component does not match its canonical payload.',
    );
    expectProofRecordRefusal(
        {
            componentProofInputs: mutateComponentProofInputs(
                (mutatedComponentProofInputs) => {
                    const receiverEncryptionInput =
                        mutatedComponentProofInputs[3] ?? {};
                    const proofStatement = cloneJsonValue(
                        receiverEncryptionInput.proofStatement as Record<
                            string,
                            unknown
                        >,
                    );
                    const receiverRows = proofStatement.receiverRows as Record<
                        string,
                        unknown
                    >[];
                    const firstReceiverRow = receiverRows[0] ?? {};
                    firstReceiverRow.ciphertextChunks = [];
                    receiverRows[0] = firstReceiverRow;
                    proofStatement.receiverRows = receiverRows;
                    receiverEncryptionInput.proofStatement = proofStatement;
                    mutatedComponentProofInputs[3] = receiverEncryptionInput;
                },
            ),
        },
        'Ballot proof component proof statement hash for receiver-encryption-component does not match its canonical payload.',
    );
    expectProofRecordRefusal(
        {
            componentProofInputs: mutateComponentProofInputs(
                (mutatedComponentProofInputs) =>
                    mutatedComponentProofInputs.slice(0, -1),
            ),
        },
        'Ballot proof component proof inputs must contain exactly the required components.',
    );
    checkpoints?.write?.(
        mandatoryProfileProofRecordCheckpointNames.verificationReport,
        checkpointRecord(
            mandatoryProfileProofRecordCheckpointNames.verificationReport,
            {
                mandatoryProofRecordSteps: steps,
                proofVerificationInput,
            },
        ),
    );

    return {
        generation,
        steps,
    };
};
