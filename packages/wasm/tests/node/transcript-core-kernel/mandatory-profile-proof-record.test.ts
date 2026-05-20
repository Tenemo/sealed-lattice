// This file is one focused part of the split test suite.
import { describe, expect, it } from 'vitest';

import { createMandatoryProfileBallotProofRecordBenchmarkFixture } from '../../../../../tests/support/ballot-privacy-proof-record-generation-fixtures';
import {
    createJsonCheckpointStore,
    shouldResumeFromTestCheckpoints,
} from '../../../../../tests/support/node-test-checkpoints';
import { runTimedTestStep } from '../../../../../tests/support/timed-test-steps';
import { loadTranscriptCoreKernel } from '../../../src/index';
import {
    type BallotPrivacyKernelVerification,
    type TranscriptCoreKernel,
} from '../../../src/transcript-core-bridge';

import { cloneJsonValue, expectRefusalMessage } from './shared.js';

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

describe('transcript-core kernel in Node', () => {
    it('generates a mandatory-profile ballot proof record with packed field components through WASM', async () => {
        const steps: {
            readonly durationMs: number;
            readonly name: string;
            readonly reusedCheckpoint?: boolean;
        }[] = [];
        const checkpointStore = createJsonCheckpointStore();
        const checkpointRecord = (
            checkpointName: string,
            payload: unknown,
        ): Record<string, unknown> => ({
            checkpointName,
            payload,
            schemaVersion: 1,
        });
        const checkpointPayload = (
            value: unknown,
            checkpointName: string,
        ): unknown => {
            if (
                typeof value !== 'object' ||
                value === null ||
                Array.isArray(value)
            ) {
                return undefined;
            }

            const record = value as Record<string, unknown>;

            return record.schemaVersion === 1 &&
                record.checkpointName === checkpointName
                ? record.payload
                : undefined;
        };
        const kernel = await loadTranscriptCoreKernel();
        const fixture = runTimedTestStep(
            steps,
            'build mandatory proof relation request',
            () => createMandatoryProfileBallotProofRecordBenchmarkFixture(),
        );
        const { request } = fixture;
        checkpointStore.write(
            mandatoryProfileProofRecordCheckpointNames.relationRequest,
            checkpointRecord(
                mandatoryProfileProofRecordCheckpointNames.relationRequest,
                {
                    publicContext: fixture.publicContext,
                    request,
                },
            ),
        );
        checkpointStore.write(
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
            checkpointStore.read(
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
            shouldResumeFromTestCheckpoints() &&
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
        checkpointStore.write(
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
        const componentProofInputs =
            generation.componentProofInputs as readonly {
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
            [
                'receiver-key-binding-component',
                'public-zero-witness-binding-check-v1',
            ],
        ]);
        for (const componentId of [
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
        ]) {
            const proofInput = componentProofInputs.find(
                (candidate) => candidate.componentId === componentId,
            );
            expect(
                proofInput?.proofStatement.sourceColumnPackings,
            ).toHaveLength(proofInput?.proofStatement.statementColumns ?? -1);
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
                    statement.manifestDigest = kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            purpose: 'mandatory-proof-record-negative-test',
                            label: 'wrong-manifest',
                        },
                    });
                }),
            },
            'Ballot proof statement digest does not match its canonical payload.',
        );
        expectProofRecordRefusal(
            {
                statement: mutateStatement((statement) => {
                    statement.rosterExternalAcceptanceDigest =
                        kernel.deriveProtocolDigest({
                            namespace: 'ChallengeDomainDigest',
                            value: {
                                purpose: 'mandatory-proof-record-negative-test',
                                label: 'wrong-roster-acceptance',
                            },
                        });
                }),
            },
            'Ballot proof statement digest does not match its canonical payload.',
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
                    ballotProof.challengeDigest = kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            purpose: 'mandatory-proof-record-negative-test',
                            label: 'wrong-proof-challenge',
                        },
                    });
                }),
            },
            'Ballot proof challenge digest does not match the statement and proof roots.',
        );
        expectProofRecordRefusal(
            {
                componentProofInputs: mutateComponentProofInputs(
                    (mutatedComponentProofInputs) => {
                        mutatedComponentProofInputs[0] = {
                            ...mutatedComponentProofInputs[0],
                            proofBytesHex: 'ff'.repeat(
                                String(
                                    mutatedComponentProofInputs[0]
                                        ?.proofBytesHex,
                                ).length / 2,
                            ),
                        };
                    },
                ),
            },
            'Ballot proof component proof bytes do not match the proof record digest.',
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
            'Ballot proof component proof statement digest for score-and-shamir-field-component does not match its canonical payload.',
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
                        const receiverRows =
                            proofStatement.receiverRows as Record<
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
            'Ballot proof component proof statement digest for share-commitment-component does not match its canonical payload.',
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
                        const receiverRows =
                            proofStatement.receiverRows as Record<
                                string,
                                unknown
                            >[];
                        const firstReceiverRow = receiverRows[0] ?? {};
                        firstReceiverRow.ciphertextChunks = [];
                        receiverRows[0] = firstReceiverRow;
                        proofStatement.receiverRows = receiverRows;
                        receiverEncryptionInput.proofStatement = proofStatement;
                        mutatedComponentProofInputs[3] =
                            receiverEncryptionInput;
                    },
                ),
            },
            'Ballot proof component proof statement digest for receiver-encryption-component does not match its canonical payload.',
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
        checkpointStore.write(
            mandatoryProfileProofRecordCheckpointNames.verificationReport,
            checkpointRecord(
                mandatoryProfileProofRecordCheckpointNames.verificationReport,
                {
                    mandatoryProofRecordSteps: steps,
                    proofVerificationInput,
                },
            ),
        );
        console.info(
            JSON.stringify({
                event: 'mandatory-proof-record-test-steps',
                steps,
            }),
        );
    }, 900_000);
});
