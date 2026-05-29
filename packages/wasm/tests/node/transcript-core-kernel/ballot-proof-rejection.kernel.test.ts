// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import type { NamedFixture } from './shared.js';
import {
    cloneJsonValue,
    findFixture,
    linearProofBackendVectors,
} from './shared.js';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

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
        const hash = (label: string): string =>
            kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
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
                actionContextHash: hash('action-context'),
                aggregateInputEncodingProfileHash: hash(
                    'aggregate-input-encoding-profile',
                ),
                ballotPackageHash: hash('ballot-package'),
                ballotProofProfileHash: hash('ballot-proof-profile'),
                ballotScoreEncodingProfileHash: hash(
                    'ballot-score-encoding-profile',
                ),
                ballotShareLayoutProfileHash: hash(
                    'ballot-share-layout-profile',
                ),
                ceremonyId: 'ceremony-ballot-proof-record',
                challengeDomainHash: hash('challenge-domain'),
                duplicateBallotPolicyHash: hash('duplicate-policy'),
                encodedAggregateLayoutHash: hash('encoded-aggregate-layout'),
                encodedShareVectorLayoutHash: hash(
                    'encoded-share-vector-layout',
                ),
                manifestHash: hash('manifest'),
                objectType: 'BallotProofStatement',
                objectVersion: 1,
                optionCount: 20,
                pollSpecHash: hash('poll-spec'),
                receiverEncryptionProfileHash: hash(
                    'receiver-encryption-profile',
                ),
                receiverKeyProofRoot: hash('receiver-key-proof-root'),
                receiverKeyRoot: hash('receiver-key-root'),
                receiverPayloads: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPayloadCiphertextRoot: hash(
                            `receiver-ciphertext-${receiverReference.receiverRosterPosition}`,
                        ),
                        receiverPayloadHash: hash(
                            `receiver-payload-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                receiverPublicKeys: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPublicKeyHash: hash(
                            `receiver-public-key-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                rosterHash: hash('roster'),
                rosterExternalAcceptanceHash: hash('external-acceptance'),
                scoreDomainHash: hash('score-domain'),
                scoreMembershipProfileHash: hash('score-membership-profile'),
                shareCommitmentMessageBoundCertHash: hash(
                    'share-commitment-bound-cert',
                ),
                shareCommitmentProfileHash: hash('share-commitment-profile'),
                shareCommitments: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        shareCommitmentHash: hash(
                            `share-commitment-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                shareVectorWidth: 220,
                thresholdProfileHash: hash('threshold-profile'),
                tiePolicyHash: hash('tie-policy'),
                topOptionCount: 3,
                voterIdentityHash: hash('voter-1'),
                voterRosterPosition: 1,
                voterSigningKeyHash: hash('voter-signing-key'),
            };

            return {
                ...statementPayload,
                ballotProofStatementHash: kernel.deriveProtocolHash({
                    namespace: 'BallotProofStatementHash',
                    value: statementPayload,
                }),
            };
        };
        const createLinearStatement = (
            statement: Record<string, unknown>,
            targetVectorCoefficients: unknown,
        ): Record<string, unknown> => {
            const linearStatementPayload = {
                backendStatementHash: hash('backend-statement'),
                ballotProofStatementHash: statement.ballotProofStatementHash,
                coefficientModulus: '4294962689',
                objectType: 'BallotProofLinearProofStatement',
                objectVersion: 1,
                parameterProfileId: String(
                    (validParameterSet as Record<string, unknown>).profileId,
                ),
                relation: 'A*w + t = 0',
                relationStatementHash: hash('relation-statement'),
                ringDegree: 256,
                statementColumns: 8,
                statementMatrixCoefficients:
                    validProofCase.statementMatrixCoefficients,
                statementMatrixHash: hash('statement-matrix'),
                statementRows: 4,
                targetCoefficientRepresentation:
                    validProofCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorHash: hash('target-vector'),
                witnessL2BoundSquared: '2048',
            };

            return {
                ...linearStatementPayload,
                statementHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
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
            const proofBytesHash = kernel.deriveProtocolHash({
                namespace: 'ProofBytesHash',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    publicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolHash({
                namespace: 'BallotProofRecordHash',
                value: {
                    linearStatementHash: linearStatement.statementHash,
                    proofBytesHash,
                    proofEncodingProfileHash,
                    proofParameterSetHash,
                    publicRandomnessHash,
                    purpose: 'ballot-proof-linear-proof-record-root-v1',
                },
            });
            const proofPayloadWithoutChallenge = {
                backendStatementHash: linearStatement.backendStatementHash,
                ballotProofProfileHash: statement.ballotProofProfileHash,
                ballotProofStatementHash: statement.ballotProofStatementHash,
                ...(componentBundleStatement === undefined
                    ? {}
                    : {
                          componentBundleStatementHash:
                              componentBundleStatement.componentBundleStatementHash,
                      }),
                ...(componentProofBundle === undefined
                    ? {}
                    : {
                          componentProofBundleHash:
                              componentProofBundle.componentProofBundleHash,
                      }),
                linearStatementHash: linearStatement.statementHash,
                objectType: 'BallotProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesHash,
                proofEncodingProfileHash,
                proofParameterSetHash,
                proofRoot,
                proofSizeBytes,
                publicRandomnessHash,
                relationStatementHash: linearStatement.relationStatementHash,
                statementMatrixHash: linearStatement.statementMatrixHash,
                targetVectorHash: linearStatement.targetVectorHash,
            };
            const challengeHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    backendStatementHash:
                        proofPayloadWithoutChallenge.backendStatementHash,
                    ballotProofStatementHash:
                        statement.ballotProofStatementHash,
                    challengeDomainHash: statement.challengeDomainHash,
                    ...(componentBundleStatement === undefined
                        ? {}
                        : {
                              componentBundleStatementHash:
                                  componentBundleStatement.componentBundleStatementHash,
                          }),
                    ...(componentProofBundle === undefined
                        ? {}
                        : {
                              componentProofBundleHash:
                                  componentProofBundle.componentProofBundleHash,
                          }),
                    linearStatementHash:
                        proofPayloadWithoutChallenge.linearStatementHash,
                    proofBytesHash: proofPayloadWithoutChallenge.proofBytesHash,
                    proofEncodingProfileHash:
                        proofPayloadWithoutChallenge.proofEncodingProfileHash,
                    proofParameterSetHash:
                        proofPayloadWithoutChallenge.proofParameterSetHash,
                    proofRoot: proofPayloadWithoutChallenge.proofRoot,
                    publicRandomnessHash:
                        proofPayloadWithoutChallenge.publicRandomnessHash,
                    relationStatementHash:
                        proofPayloadWithoutChallenge.relationStatementHash,
                    statementMatrixHash:
                        proofPayloadWithoutChallenge.statementMatrixHash,
                    targetVectorHash:
                        proofPayloadWithoutChallenge.targetVectorHash,
                    purpose: 'ballot-proof-challenge-v1',
                },
            });
            const proofPayload = {
                ...proofPayloadWithoutChallenge,
                challengeHash,
            };

            return {
                ...proofPayload,
                ballotProofRecordHash: kernel.deriveProtocolHash({
                    namespace: 'BallotProofRecordHash',
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
        delete relabeledLinearStatement.statementHash;
        relabeledLinearStatement.projectionCoverage =
            'full-encoded-score-ballot-relation';
        relabeledLinearStatement.statementHash = kernel.deriveProtocolHash({
            namespace: 'ChallengeDomainHash',
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
