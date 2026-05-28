// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

import type { NamedFixture } from './shared.js';
import {
    cloneJsonValue,
    findFixture,
    linearProofBackendVectors,
} from './shared.js';

describe('transcript-core kernel in Node', () => {
    it('rejects field-incomplete ballot records after WASM linear proof verification', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const linearProofCases =
            linearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = findFixture(
            linearProofCases,
            'valid-small-linear-proof',
        );
        const mutatedTargetCase = findFixture(
            linearProofCases,
            'mutated-target-vector',
        );
        const proofBytesHex = String(validProofCase.proofHex);
        const publicRandomnessHex = String(validProofCase.publicRandomnessHex);
        const proofSizeBytes = proofBytesHex.length / 2;
        const validParameterSet = {
            ...cloneJsonValue(
                validProofCase.parameterSet as Record<string, unknown>,
            ),
            expectedProofSizeBytes: proofSizeBytes,
        };
        const validProofEncoding = {
            ...cloneJsonValue(
                validProofCase.proofEncoding as Record<string, unknown>,
            ),
            expectedProofSizeBytes: proofSizeBytes,
        };
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose: 'ballot-proof-record-wasm-test',
                },
            });
        const createStatement = (): Record<string, unknown> => {
            const receiverReferences = Array.from(
                { length: 20 },
                (_unusedValue, receiverIndex) => {
                    const receiverRosterPosition = receiverIndex + 1;

                    return {
                        receiverIdentity: `receiver-${receiverRosterPosition}`,
                        receiverRosterPosition,
                    };
                },
            );
            const statementPayload = {
                actionContextDigest: digest('action-context'),
                aggregateInputEncodingProfileDigest: digest(
                    'aggregate-input-encoding-profile',
                ),
                ballotPackageDigest: digest('ballot-package'),
                ballotProofProfileDigest: digest('ballot-proof-profile'),
                ballotScoreEncodingProfileDigest: digest(
                    'ballot-score-encoding-profile',
                ),
                ballotShareLayoutProfileDigest: digest(
                    'ballot-share-layout-profile',
                ),
                ceremonyId: 'ceremony-ballot-proof-record',
                challengeDomainDigest: digest('challenge-domain'),
                duplicateBallotPolicyDigest: digest('duplicate-policy'),
                encodedAggregateLayoutDigest: digest(
                    'encoded-aggregate-layout',
                ),
                encodedShareVectorLayoutDigest: digest(
                    'encoded-share-vector-layout',
                ),
                manifestDigest: digest('manifest'),
                objectType: 'BallotProofStatement',
                objectVersion: 1,
                optionCount: 20,
                pollSpecDigest: digest('poll-spec'),
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverKeyProofRoot: digest('receiver-key-proof-root'),
                receiverKeyRoot: digest('receiver-key-root'),
                receiverPayloads: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPayloadCiphertextRoot: digest(
                            `receiver-ciphertext-${receiverReference.receiverRosterPosition}`,
                        ),
                        receiverPayloadDigest: digest(
                            `receiver-payload-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                receiverPublicKeys: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPublicKeyDigest: digest(
                            `receiver-public-key-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                rosterDigest: digest('roster'),
                rosterExternalAcceptanceDigest: digest('external-acceptance'),
                scoreDomainDigest: digest('score-domain'),
                scoreMembershipProfileDigest: digest(
                    'score-membership-profile',
                ),
                shareCommitmentMessageBoundCertDigest: digest(
                    'share-commitment-bound-cert',
                ),
                shareCommitmentProfileDigest: digest(
                    'share-commitment-profile',
                ),
                shareCommitments: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        shareCommitmentDigest: digest(
                            `share-commitment-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                shareVectorWidth: 220,
                thresholdProfileDigest: digest('threshold-profile'),
                tiePolicyDigest: digest('tie-policy'),
                topOptionCount: 3,
                voterIdentityDigest: digest('voter-1'),
                voterRosterPosition: 1,
                voterSigningKeyDigest: digest('voter-signing-key'),
            };

            return {
                ...statementPayload,
                ballotProofStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofStatementDigest',
                    value: statementPayload,
                }),
            };
        };
        const createLinearStatement = (
            statement: Record<string, unknown>,
            targetVectorCoefficients: unknown,
        ): Record<string, unknown> => {
            const linearStatementPayload = {
                backendStatementDigest: digest('backend-statement'),
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                coefficientModulus: '4294962689',
                objectType: 'BallotProofLinearProofStatement',
                objectVersion: 1,
                parameterProfileId: String(
                    (validParameterSet as Record<string, unknown>).profileId,
                ),
                relation: 'A*w + t = 0',
                relationStatementDigest: digest('relation-statement'),
                ringDegree: 256,
                statementColumns: 8,
                statementMatrixCoefficients:
                    validProofCase.statementMatrixCoefficients,
                statementMatrixDigest: digest('statement-matrix'),
                statementRows: 4,
                targetCoefficientRepresentation:
                    validProofCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorDigest: digest('target-vector'),
                witnessL2BoundSquared: '2048',
            };

            return {
                ...linearStatementPayload,
                statementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: linearStatementPayload,
                        purpose: 'ballot-proof-linear-proof-statement-v1',
                    },
                }),
            };
        };
        const createBallotProof = (
            statement: Record<string, unknown>,
            linearStatement: Record<string, unknown>,
            componentBundleStatement?: Record<string, unknown>,
            componentProofBundle?: Record<string, unknown>,
            parameterSet: Record<string, unknown> = validParameterSet,
            proofEncoding: Record<string, unknown> = validProofEncoding,
        ): Record<string, unknown> => {
            const proofBytesDigest = kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'BallotProofRecordDigest',
                value: {
                    linearStatementDigest: linearStatement.statementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    publicRandomnessDigest,
                    purpose: 'ballot-proof-linear-proof-record-root-v1',
                },
            });
            const proofPayloadWithoutChallenge = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofProfileDigest: statement.ballotProofProfileDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                ...(componentBundleStatement === undefined
                    ? {}
                    : {
                          componentBundleStatementDigest:
                              componentBundleStatement.componentBundleStatementDigest,
                      }),
                ...(componentProofBundle === undefined
                    ? {}
                    : {
                          componentProofBundleDigest:
                              componentProofBundle.componentProofBundleDigest,
                      }),
                linearStatementDigest: linearStatement.statementDigest,
                objectType: 'BallotProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes,
                publicRandomnessDigest,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                statementMatrixDigest: linearStatement.statementMatrixDigest,
                targetVectorDigest: linearStatement.targetVectorDigest,
            };
            const challengeDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    backendStatementDigest:
                        proofPayloadWithoutChallenge.backendStatementDigest,
                    ballotProofStatementDigest:
                        statement.ballotProofStatementDigest,
                    challengeDomainDigest: statement.challengeDomainDigest,
                    ...(componentBundleStatement === undefined
                        ? {}
                        : {
                              componentBundleStatementDigest:
                                  componentBundleStatement.componentBundleStatementDigest,
                          }),
                    ...(componentProofBundle === undefined
                        ? {}
                        : {
                              componentProofBundleDigest:
                                  componentProofBundle.componentProofBundleDigest,
                          }),
                    linearStatementDigest:
                        proofPayloadWithoutChallenge.linearStatementDigest,
                    proofBytesDigest:
                        proofPayloadWithoutChallenge.proofBytesDigest,
                    proofEncodingProfileDigest:
                        proofPayloadWithoutChallenge.proofEncodingProfileDigest,
                    proofParameterSetDigest:
                        proofPayloadWithoutChallenge.proofParameterSetDigest,
                    proofRoot: proofPayloadWithoutChallenge.proofRoot,
                    publicRandomnessDigest:
                        proofPayloadWithoutChallenge.publicRandomnessDigest,
                    relationStatementDigest:
                        proofPayloadWithoutChallenge.relationStatementDigest,
                    statementMatrixDigest:
                        proofPayloadWithoutChallenge.statementMatrixDigest,
                    targetVectorDigest:
                        proofPayloadWithoutChallenge.targetVectorDigest,
                },
            });
            const proofPayload = {
                ...proofPayloadWithoutChallenge,
                challengeDigest,
            };

            return {
                ...proofPayload,
                ballotProofRecordDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofRecordDigest',
                    value: proofPayload,
                }),
            };
        };
        const statement = createStatement();
        const validLinearStatement = createLinearStatement(
            statement,
            validProofCase.targetVectorCoefficients,
        );
        const validBallotProof = createBallotProof(
            statement,
            validLinearStatement,
        );
        const mutatedLinearStatement = createLinearStatement(
            statement,
            mutatedTargetCase.targetVectorCoefficients,
        );
        const mutatedBallotProof = createBallotProof(
            statement,
            mutatedLinearStatement,
        );

        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validParameterSet,
                proofBytesHex,
                proofEncoding: validProofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const sizeUnboundParameterSet = {
            ...validParameterSet,
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        const sizeUnboundParameterBallotProof = createBallotProof(
            statement,
            validLinearStatement,
            undefined,
            undefined,
            sizeUnboundParameterSet,
            validProofEncoding,
        );
        const sizeUnboundParameterVerification = kernel.verifyBallotProof({
            ballotProof: sizeUnboundParameterBallotProof,
            linearStatement: validLinearStatement,
            parameterSet: sizeUnboundParameterSet,
            proofBytesHex,
            proofEncoding: validProofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(sizeUnboundParameterVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            sizeUnboundParameterVerification.refusedObjects.some((refusal) =>
                refusal.message.includes('byte length'),
            ),
        ).toBe(true);

        const sizeUnboundProofEncoding = {
            ...validProofEncoding,
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        const sizeUnboundEncodingBallotProof = createBallotProof(
            statement,
            validLinearStatement,
            undefined,
            undefined,
            validParameterSet,
            sizeUnboundProofEncoding,
        );
        const sizeUnboundEncodingVerification = kernel.verifyBallotProof({
            ballotProof: sizeUnboundEncodingBallotProof,
            linearStatement: validLinearStatement,
            parameterSet: validParameterSet,
            proofBytesHex,
            proofEncoding: sizeUnboundProofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(sizeUnboundEncodingVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            sizeUnboundEncodingVerification.refusedObjects.some((refusal) =>
                refusal.message.includes('byte length'),
            ),
        ).toBe(true);

        const relabeledLinearStatement = cloneJsonValue(validLinearStatement);
        delete relabeledLinearStatement.statementDigest;
        relabeledLinearStatement.projectionCoverage =
            'full-encoded-score-ballot-relation';
        relabeledLinearStatement.statementDigest = kernel.deriveProtocolDigest({
            namespace: 'ChallengeDomainDigest',
            value: {
                payload: relabeledLinearStatement,
                purpose: 'ballot-proof-linear-proof-statement-v1',
            },
        });
        const relabeledBallotProof = createBallotProof(
            statement,
            relabeledLinearStatement,
        );
        const relabeledVerification = kernel.verifyBallotProof({
            ballotProof: relabeledBallotProof,
            linearStatement: relabeledLinearStatement,
            parameterSet: validParameterSet,
            proofBytesHex,
            proofEncoding: validProofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(relabeledVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            relabeledVerification.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'dedicated full-relation parameter profile',
                ),
            ),
        ).toBe(true);
        expect(
            kernel.verifyBallotProof({
                ballotProof: mutatedBallotProof,
                linearStatement: mutatedLinearStatement,
                parameterSet: validParameterSet,
                proofBytesHex,
                proofEncoding: validProofEncoding,
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
                parameterSet: validParameterSet,
                proofBytesHex: proofBytesHex.slice(0, -2),
                proofEncoding: validProofEncoding,
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
