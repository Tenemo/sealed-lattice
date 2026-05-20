// This file is one focused part of the split test suite.
import { describe, expect, it } from 'vitest';

import { createEncodedScoreFieldBallotProofRecordFixture } from './encoded-score-field-ballot-proof-record-fixture.js';
import { cloneJsonValue } from './shared.js';

describe('transcript-core kernel in Node', () => {
    it('rejects encoded-score field-only ballot proof records after WASM proof verification', async () => {
        const {
            componentIds,
            createBallotProof,
            createComponentBundleStatement,
            createComponentProofBundle,
            createComponentProofInputs,
            createComponentProofRecord,
            createComponentProofStatement,
            digest,
            incompleteComponentBundleStatement,
            kernel,
            mutatedBallotProof,
            mutatedLinearStatement,
            proofBoundToIncompleteComponentBundle,
            proofBytesHex,
            publicRandomnessHex,
            statement,
            validBallotProof,
            validLinearStatement,
            validProofCase,
        } = await createEncodedScoreFieldBallotProofRecordFixture();

        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const relabeledEncodedLinearStatement =
            cloneJsonValue(validLinearStatement);
        delete relabeledEncodedLinearStatement.statementDigest;
        relabeledEncodedLinearStatement.projectionCoverage =
            'full-encoded-score-ballot-relation';
        relabeledEncodedLinearStatement.statementDigest =
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    payload: relabeledEncodedLinearStatement,
                    purpose: 'ballot-proof-linear-proof-statement-v1',
                },
            });
        const relabeledEncodedBallotProof = createBallotProof(
            statement,
            relabeledEncodedLinearStatement,
        );
        const relabeledEncodedVerification = kernel.verifyBallotProof({
            ballotProof: relabeledEncodedBallotProof,
            linearStatement: relabeledEncodedLinearStatement,
            parameterSet: validProofCase.parameterSet,
            proofBytesHex,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(relabeledEncodedVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            relabeledEncodedVerification.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'dedicated full-relation parameter profile',
                ),
            ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToIncompleteComponentBundle,
                    componentBundleStatement:
                        incompleteComponentBundleStatement,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'component bundle is still incomplete',
                    ),
                ),
        ).toBe(true);

        const fullComponentBundleStatement = createComponentBundleStatement(
            validLinearStatement,
            statement,
            {
                fullCoverage: true,
            },
        );
        const fullComponentStatements =
            fullComponentBundleStatement.componentStatements as readonly Record<
                string,
                unknown
            >[];
        const componentProofs = componentIds.map(
            (componentId, componentIndex) =>
                createComponentProofRecord(
                    validLinearStatement,
                    statement,
                    fullComponentStatements[componentIndex] ?? {},
                    componentId,
                ),
        );
        const componentProofInputs =
            createComponentProofInputs(componentProofs);
        const componentProofBundle = createComponentProofBundle(
            fullComponentBundleStatement,
            componentProofs,
        );
        const proofBoundToComponentBundleWithoutProofBundle = createBallotProof(
            statement,
            validLinearStatement,
            fullComponentBundleStatement,
        );
        const proofBoundToComponentProofBundle = createBallotProof(
            statement,
            validLinearStatement,
            fullComponentBundleStatement,
            componentProofBundle,
        );

        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentBundleWithoutProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'requires a component proof bundle',
                    ),
                ),
        ).toBe(true);
        const validComponentBundlePreflight = kernel.verifyBallotProof({
            ballotProof: proofBoundToComponentProofBundle,
            componentBundleStatement: fullComponentBundleStatement,
            componentProofBundle,
            componentProofInputs,
            linearStatement: validLinearStatement,
            parameterSet: validProofCase.parameterSet,
            proofBytesHex,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex,
            statement,
        });
        expect(
            validComponentBundlePreflight.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'component proof bundle has an invalid canonical shape',
                ),
            ),
        ).toBe(false);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'requires public proof inputs for every component proof',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    componentProofInputs: componentProofInputs.map(
                        (componentProofInput, componentIndex) =>
                            componentIndex === 0
                                ? {
                                      ...componentProofInput,
                                      proofBytesHex: 'ff'.repeat(
                                          String(
                                              componentProofInput.proofBytesHex,
                                          ).length / 2,
                                      ),
                                  }
                                : componentProofInput,
                    ),
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'proof bytes do not match the proof record digest',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    componentProofInputs: componentProofInputs.map(
                        (componentProofInput, componentIndex) =>
                            componentIndex === 0
                                ? {
                                      ...componentProofInput,
                                      componentProofStatementDigest: digest(
                                          'wrong-component-proof-statement',
                                      ),
                                  }
                                : componentProofInput,
                    ),
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'proof statement for score-and-shamir-field-component does not match the proof record',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    componentProofInputs: componentProofInputs.map(
                        (componentProofInput, componentIndex) =>
                            componentIndex === 3
                                ? {
                                      ...componentProofInput,
                                      proofStatement:
                                          createComponentProofStatement({
                                              componentId: String(
                                                  componentProofInput.componentId,
                                              ),
                                              componentProofStatementDigest:
                                                  digest(
                                                      'wrong-supplied-component-proof-statement-canonical-digest',
                                                  ),
                                              componentStatementDigest: String(
                                                  componentProofInput.statementDigest,
                                              ),
                                              proofStatementFormat: String(
                                                  componentProofInput.proofStatementFormat,
                                              ),
                                          }),
                                  }
                                : componentProofInput,
                    ),
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'proof statement digest for receiver-encryption-component does not match its canonical payload',
                    ),
                ),
        ).toBe(true);
        const reorderedComponentProofBundle = createComponentProofBundle(
            fullComponentBundleStatement,
            [...componentProofs].reverse(),
        );
        const reorderedComponentProofInputs = createComponentProofInputs(
            [...componentProofs].reverse(),
        );
        const proofBoundToReorderedComponentProofBundle = createBallotProof(
            statement,
            validLinearStatement,
            fullComponentBundleStatement,
            reorderedComponentProofBundle,
        );

        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToReorderedComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle: reorderedComponentProofBundle,
                    componentProofInputs: reorderedComponentProofInputs,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes('invalid canonical shape'),
                ),
        ).toBe(true);
        const wrongComponentStatementProofs = [
            createComponentProofRecord(
                validLinearStatement,
                statement,
                { componentStatementDigest: digest('wrong-component') },
                componentIds[0] ?? 'score-and-shamir-field-component',
            ),
            ...componentProofs.slice(1),
        ];
        const wrongComponentStatementProofBundle = createComponentProofBundle(
            fullComponentBundleStatement,
            wrongComponentStatementProofs,
        );
        const wrongComponentStatementProofInputs = createComponentProofInputs(
            wrongComponentStatementProofs,
        );
        const proofBoundToWrongComponentStatementProofBundle =
            createBallotProof(
                statement,
                validLinearStatement,
                fullComponentBundleStatement,
                wrongComponentStatementProofBundle,
            );

        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToWrongComponentStatementProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle: wrongComponentStatementProofBundle,
                    componentProofInputs: wrongComponentStatementProofInputs,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'not bound to the supplied component statement',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel.verifyBallotProof({
                ballotProof: mutatedBallotProof,
                linearStatement: mutatedLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'InvalidFixture',
        });
        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex: proofBytesHex.slice(0, -2),
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });
});
