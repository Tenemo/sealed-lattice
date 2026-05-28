// This file is one targeted part of the split test suite.
import type { BallotPrivacyRosterProfileEvidence } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createBallotPrivacyProfileSet,
    createBallotProofRecordShell,
    createReceiverEncryptionPublicKeyShell,
    createReceiverKeyProofShell,
    createReceiverPayloadShell,
    createShareCommitmentShell,
    deriveBallotPrivacyRosterProfileEvidenceHash,
    deriveBallotProofEncodingProfileHash,
    deriveBallotProofParameterSetHash,
    deriveBallotProofPublicRandomnessHash,
    deriveProofBytesHash,
    verifyBallotProof,
} from '../../../src/ballot-privacy/index';

import {
    createComponentProofBundleFixture,
    createComponentProofStatementFixture,
    createComponentProofVerificationInputsFixture,
    createStatement,
    createStructurallyBoundObjects,
    hash,
    requiredComponentIds,
} from './shared.js';

const createDynamicRosterProfileEvidence = (
    input: Pick<
        BallotPrivacyRosterProfileEvidence,
        'frozenRosterSize' | 'optionCount' | 'thresholdProfileHash'
    >,
): BallotPrivacyRosterProfileEvidence => {
    const payload = {
        dynamicRosterProfileCertificateHash: hash(
            'dynamic-roster-profile-certificate',
        ),
        frozenRosterSize: input.frozenRosterSize,
        objectType: 'BallotPrivacyRosterProfileEvidence' as const,
        objectVersion: 1 as const,
        optionCount: input.optionCount,
        profileFamily: 'BalancedDefault' as const,
        proofStatementShape: 'EncodedScoreBallotProof-v1' as const,
        receiverCoverageProfile: 'AllFrozenRosterReceivers' as const,
        thresholdProfileHash: input.thresholdProfileHash,
    };

    return {
        ...payload,
        rosterProfileEvidenceHash:
            deriveBallotPrivacyRosterProfileEvidenceHash(payload),
    };
};

const casualMicroRosterSizes = [3, 4, 5, 6, 7, 8, 9] as const;

describe('ballot privacy proof object boundary', () => {
    it('derives production-shaped receiver key, payload, and commitment shells without witness material', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverPublicKey = createReceiverEncryptionPublicKeyShell({
            ceremonyId: 'ceremony-1',
            manifestHash: hash('manifest'),
            rosterHash: hash('roster'),
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            receiverEncryptionProfileHash:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileHash,
            keyMaterialHash: hash('receiver-key-material'),
        });
        const receiverKeyProof = createReceiverKeyProofShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestHash: receiverPublicKey.manifestHash,
            rosterHash: receiverPublicKey.rosterHash,
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            recoveryEpoch: receiverPublicKey.recoveryEpoch,
            receiverPublicKeyHash: receiverPublicKey.receiverPublicKeyHash,
            receiverEncryptionProfileHash:
                receiverPublicKey.receiverEncryptionProfileHash,
            proofBackend: 'LocalLinearLatticeRelation',
            proofRoot: hash('receiver-key-proof-root'),
        });
        const receiverPayload = createReceiverPayloadShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestHash: receiverPublicKey.manifestHash,
            rosterHash: receiverPublicKey.rosterHash,
            pollSpecHash: hash('poll-spec'),
            voterIdentityHash: hash('voter-1'),
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            receiverPublicKeyHash: receiverPublicKey.receiverPublicKeyHash,
            receiverEncryptionProfileHash:
                receiverPublicKey.receiverEncryptionProfileHash,
            payloadContextHash: hash('payload-context'),
            ciphertextBodyHash: hash('ciphertext-body'),
        });
        const shareCommitment = createShareCommitmentShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestHash: receiverPublicKey.manifestHash,
            rosterHash: receiverPublicKey.rosterHash,
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            shareCommitmentProfileHash:
                profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
            shareVectorWidth:
                profileSet.shareCommitmentProfile.shareVectorWidth,
            commitmentBodyHash: hash('share-commitment-body'),
        });

        expect(receiverPublicKey.receiverPublicKeyHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverKeyProof.receiverKeyProofRoot).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverPayload.receiverPayloadHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(receiverPayload).not.toHaveProperty('receiverShareVector');
        expect(receiverPayload).not.toHaveProperty('shareCommitmentOpening');
        expect(shareCommitment.shareCommitmentHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(shareCommitment).not.toHaveProperty('openingRandomness');
    });

    it('builds a deterministic statement that binds every public transcript input', () => {
        const statement = createStatement();
        const changedStatement = createStatement({
            manifestHash: hash('changed-manifest'),
        });

        expect(statement.objectType).toBe('BallotProofStatement');
        expect(statement.shareVectorWidth).toBe(220);
        expect(statement.ballotScoreEncodingProfileHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.ballotShareLayoutProfileHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.aggregateInputEncodingProfileHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.encodedShareVectorLayoutHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.encodedAggregateLayoutHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.ballotProofStatementHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(statement.challengeDomainHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(changedStatement.ballotProofStatementHash).not.toBe(
            statement.ballotProofStatementHash,
        );
        expect(changedStatement.challengeDomainHash).toBe(
            statement.challengeDomainHash,
        );
    });

    it('binds the encoded-score layout Hashes into the challenge domain and proof record', () => {
        const statement = createStatement();
        const changedLayoutStatement = createStatement({
            encodedShareVectorLayoutHash: hash(
                'changed-encoded-share-vector-layout',
            ),
        });
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: hash('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedLayoutProofRecord = createBallotProofRecordShell({
            statement: changedLayoutStatement,
            relationStatementHash: hash('changed-relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: hash('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(changedLayoutStatement.challengeDomainHash).not.toBe(
            statement.challengeDomainHash,
        );
        expect(changedLayoutStatement.ballotProofStatementHash).not.toBe(
            statement.ballotProofStatementHash,
        );
        expect(changedLayoutProofRecord.challengeHash).not.toBe(
            proofRecord.challengeHash,
        );
    });

    it('binds proof shell challenge to statement and proof roots', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: hash('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('relation-statement'),
            proofRoot: hash('changed-proof-root'),
            proofBytesHash: hash('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedRelationProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('changed-relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: hash('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(proofRecord.objectType).toBe('BallotProofRecord');
        expect(proofRecord.ballotProofStatementHash).toBe(
            statement.ballotProofStatementHash,
        );
        expect(proofRecord.relationStatementHash).toBe(
            hash('relation-statement'),
        );
        expect(proofRecord.challengeHash).not.toBe(
            changedProofRecord.challengeHash,
        );
        expect(proofRecord.challengeHash).not.toBe(
            changedRelationProofRecord.challengeHash,
        );
        expect(proofRecord.ballotProofRecordHash).not.toBe(
            changedProofRecord.ballotProofRecordHash,
        );
    });

    it('binds ballot proof records to complete linear backend proof metadata', () => {
        const statement = createStatement();
        const proofBytesHex = '001122aabbcc';
        const proofEncoding = {
            profileId: 'ballot-proof-linear-proof-encoding-v1',
        };
        const parameterSet = {
            profileId: 'ballot-proof-linear-parameter-set-v1',
        };
        const publicRandomnessHex = '00'.repeat(32);
        const proofRecord = createBallotProofRecordShell({
            backendStatementHash: hash('ballot-backend-statement'),
            linearStatementHash: hash('ballot-linear-statement'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofEncodingProfileHash: deriveBallotProofEncodingProfileHash({
                proofEncoding,
            }),
            proofParameterSetHash: deriveBallotProofParameterSetHash({
                parameterSet,
            }),
            proofRoot: hash('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessHash: deriveBallotProofPublicRandomnessHash({
                publicRandomnessHex,
            }),
            relationStatementHash: hash('relation-statement'),
            statement,
            statementMatrixHash: hash('ballot-statement-matrix'),
            targetVectorHash: hash('ballot-target-vector'),
        });
        const changedRandomnessProofRecord = createBallotProofRecordShell({
            backendStatementHash: hash('ballot-backend-statement'),
            linearStatementHash: hash('ballot-linear-statement'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofEncodingProfileHash: deriveBallotProofEncodingProfileHash({
                proofEncoding,
            }),
            proofParameterSetHash: deriveBallotProofParameterSetHash({
                parameterSet,
            }),
            proofRoot: hash('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessHash: deriveBallotProofPublicRandomnessHash({
                publicRandomnessHex: '11'.repeat(32),
            }),
            relationStatementHash: hash('relation-statement'),
            statement,
            statementMatrixHash: hash('ballot-statement-matrix'),
            targetVectorHash: hash('ballot-target-vector'),
        });
        const incompleteBackendMetadataProofRecord =
            createBallotProofRecordShell({
                linearStatementHash: hash('ballot-linear-statement'),
                proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
                proofRoot: hash('ballot-proof-root'),
                proofSizeBytes: proofBytesHex.length / 2,
                relationStatementHash: hash('relation-statement'),
                statement,
            });

        expect(proofRecord.backendStatementHash).toBe(
            hash('ballot-backend-statement'),
        );
        expect(proofRecord.proofParameterSetHash).toBe(
            deriveBallotProofParameterSetHash({ parameterSet }),
        );
        expect(proofRecord.challengeHash).not.toBe(
            changedRandomnessProofRecord.challengeHash,
        );
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({
                ballotProof: incompleteBackendMetadataProofRecord,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('binds ballot proof records to ordered component proof bundles', () => {
        const statement = createStatement();
        const proofBytesHex = '001122aabbcc';
        const componentProofBundle =
            createComponentProofBundleFixture(statement);
        const componentProofInputs =
            createComponentProofVerificationInputsFixture(componentProofBundle);
        const proofRecord = createBallotProofRecordShell({
            backendStatementHash: componentProofBundle.backendStatementHash,
            componentBundleStatementHash:
                componentProofBundle.componentBundleStatementHash,
            componentProofBundleHash:
                componentProofBundle.componentProofBundleHash,
            linearStatementHash: hash('component-linear-statement'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofEncodingProfileHash: hash('ballot-proof-encoding'),
            proofParameterSetHash: hash('ballot-proof-parameters'),
            proofRoot: hash('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessHash: hash('ballot-proof-randomness'),
            relationStatementHash: componentProofBundle.relationStatementHash,
            statement,
            statementMatrixHash: hash('ballot-statement-matrix'),
            targetVectorHash: hash('ballot-target-vector'),
        });
        const reorderedComponentProofBundle = createComponentProofBundleFixture(
            statement,
            [...requiredComponentIds].reverse(),
        );
        const reorderedComponentProofInputs =
            createComponentProofVerificationInputsFixture(
                reorderedComponentProofBundle,
            );
        const reorderedProofRecord = createBallotProofRecordShell({
            backendStatementHash:
                reorderedComponentProofBundle.backendStatementHash,
            componentBundleStatementHash:
                reorderedComponentProofBundle.componentBundleStatementHash,
            componentProofBundleHash:
                reorderedComponentProofBundle.componentProofBundleHash,
            linearStatementHash: hash('component-linear-statement'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofEncodingProfileHash: hash('ballot-proof-encoding'),
            proofParameterSetHash: hash('ballot-proof-parameters'),
            proofRoot: hash('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessHash: hash('ballot-proof-randomness'),
            relationStatementHash:
                reorderedComponentProofBundle.relationStatementHash,
            statement,
            statementMatrixHash: hash('ballot-statement-matrix'),
            targetVectorHash: hash('ballot-target-vector'),
        });

        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                componentProofInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
            refusedObjects: [
                expect.objectContaining({
                    code: 'OperationUnavailable',
                }),
            ],
        });
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                ballotProof: {
                    ...proofRecord,
                    componentProofBundleHash: hash(
                        'wrong-component-proof-bundle',
                    ),
                },
                componentProofBundle,
                componentProofInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                ballotProof: reorderedProofRecord,
                componentProofBundle: reorderedComponentProofBundle,
                componentProofInputs: reorderedComponentProofInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });

        const wrongProofBytesInputs = componentProofInputs.map(
            (componentProofInput, componentIndex) =>
                componentIndex === 0
                    ? {
                          ...componentProofInput,
                          proofBytesHex: 'ff'.repeat(
                              componentProofInput.proofBytesHex.length / 2,
                          ),
                      }
                    : componentProofInput,
        );
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                componentProofInputs: wrongProofBytesInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });

        const wrongComponentProofStatementInputs = componentProofInputs.map(
            (componentProofInput, componentIndex) =>
                componentIndex === 0
                    ? {
                          ...componentProofInput,
                          componentProofStatementHash: hash(
                              'wrong-component-proof-statement',
                          ),
                      }
                    : componentProofInput,
        );
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                componentProofInputs: wrongComponentProofStatementInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });

        const missingComponentProofStatementInputs = componentProofInputs.map(
            (componentProofInput, componentIndex) => {
                if (componentIndex !== 0) {
                    return componentProofInput;
                }
                const mutableProofInput: Record<string, unknown> = {
                    ...componentProofInput,
                };
                delete mutableProofInput.componentProofStatementHash;

                return mutableProofInput as typeof componentProofInput;
            },
        );
        const missingComponentProofStatementResult = verifyBallotProof({
            ballotProof: proofRecord,
            componentProofBundle,
            componentProofInputs: missingComponentProofStatementInputs,
            proofBytesHex,
            statement,
        });
        expect(missingComponentProofStatementResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            missingComponentProofStatementResult.refusedObjects.some(
                (refusal) =>
                    refusal.message.includes(
                        'must be bound to a component proof statement hash',
                    ),
            ),
        ).toBe(true);

        const componentProofBundleWithoutStatementHash = {
            ...componentProofBundle,
        };
        delete (
            componentProofBundleWithoutStatementHash as Record<string, unknown>
        ).ballotProofStatementHash;
        const missingBundleStatementHashResult = verifyBallotProof({
            ballotProof: proofRecord,
            componentProofBundle:
                componentProofBundleWithoutStatementHash as typeof componentProofBundle,
            componentProofInputs,
            proofBytesHex,
            statement,
        });
        expect(missingBundleStatementHashResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            missingBundleStatementHashResult.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'component proof bundle has an invalid canonical shape',
                ),
            ),
        ).toBe(true);

        const publicZeroWithProofBytesInputs = componentProofInputs.map(
            (componentProofInput) =>
                componentProofInput.componentId ===
                'receiver-key-binding-component'
                    ? {
                          ...componentProofInput,
                          proofBytesHex: '00',
                      }
                    : componentProofInput,
        );
        const publicZeroWithProofBytesResult = verifyBallotProof({
            ballotProof: proofRecord,
            componentProofBundle,
            componentProofInputs: publicZeroWithProofBytesInputs,
            proofBytesHex,
            statement,
        });
        expect(publicZeroWithProofBytesResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            publicZeroWithProofBytesResult.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'proof bytes for receiver-key-binding-component must be empty',
                ),
            ),
        ).toBe(true);

        const wrongReceiverEncryptionFormatInputs = componentProofInputs.map(
            (componentProofInput) =>
                componentProofInput.componentId ===
                'receiver-encryption-component'
                    ? {
                          ...componentProofInput,
                          proofStatementFormat:
                              'sparse-polynomial-matrix-linear-proof-v1' as const,
                      }
                    : componentProofInput,
        );
        const wrongReceiverEncryptionFormatResult = verifyBallotProof({
            ballotProof: proofRecord,
            componentProofBundle,
            componentProofInputs: wrongReceiverEncryptionFormatInputs,
            proofBytesHex,
            statement,
        });
        expect(wrongReceiverEncryptionFormatResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            wrongReceiverEncryptionFormatResult.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'proof statement format for receiver-encryption-component must be structured-module-lwe-linear-proof-v1',
                ),
            ),
        ).toBe(true);

        const wrongSuppliedProofStatementInputs = componentProofInputs.map(
            (componentProofInput, componentIndex) =>
                componentIndex === 3
                    ? {
                          ...componentProofInput,
                          proofStatement: createComponentProofStatementFixture({
                              componentId: componentProofInput.componentId,
                              componentProofStatementHash: hash(
                                  'wrong-supplied-component-proof-statement-canonical-hash',
                              ),
                              componentStatementHash:
                                  componentProofInput.statementHash,
                              proofStatementFormat:
                                  componentProofInput.proofStatementFormat,
                          }),
                      }
                    : componentProofInput,
        );
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                componentProofInputs: wrongSuppliedProofStatementInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });

        const duplicateComponentInputs = [
            componentProofInputs[0],
            ...componentProofInputs.slice(0, -1),
        ];
        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                componentProofBundle,
                componentProofInputs: duplicateComponentInputs,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('checks supplied ballot proof bytes against the proof record before the backend gate', () => {
        const statement = createStatement();
        const proofBytesHex = '001122aabbcc';
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2,
        });
        const wrongProofBytes = '001122aabbcd';
        const shortProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2 + 1,
        });

        expect(
            verifyBallotProof({
                statement,
                ballotProof: proofRecord,
                proofBytesHex,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({
                statement,
                ballotProof: proofRecord,
                proofBytesHex: wrongProofBytes,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                statement,
                ballotProof: shortProofRecord,
                proofBytesHex,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyBallotProof({
                statement,
                ballotProof: proofRecord,
                proofBytesHex: 'AA',
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('requires approved dynamic roster profile evidence for non-benchmark receiver counts', () => {
        const { statement } = createStructurallyBoundObjects({
            participantCount: 16,
        });
        const proofBytesHex = '001122aabbcc';
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementHash: hash('relation-statement'),
            proofRoot: hash('proof-root'),
            proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2,
        });
        const dynamicRosterProfileEvidence = createDynamicRosterProfileEvidence(
            {
                frozenRosterSize: statement.receiverPublicKeys.length,
                optionCount: statement.optionCount,
                thresholdProfileHash: statement.thresholdProfileHash,
            },
        );

        const missingEvidenceResult = verifyBallotProof({
            ballotProof: proofRecord,
            proofBytesHex,
            statement,
        });
        expect(missingEvidenceResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            missingEvidenceResult.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'roster profile parameter certificate',
                ),
            ),
        ).toBe(true);

        const selfAssertedEvidenceResult = verifyBallotProof({
            ballotProof: proofRecord,
            dynamicRosterProfileEvidence,
            proofBytesHex,
            statement,
        });
        expect(selfAssertedEvidenceResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            selfAssertedEvidenceResult.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'approved roster profile parameter certificate',
                ),
            ),
        ).toBe(true);
    });

    it.each(casualMicroRosterSizes)(
        'supports acknowledged non-claim casual micro-roster ballot proof shells for roster size %d',
        (rosterSize) => {
            const { statement } = createStructurallyBoundObjects({
                participantCount: rosterSize,
            });
            const proofBytesHex = '001122aabbcc';
            const proofRecord = createBallotProofRecordShell({
                statement,
                relationStatementHash: hash(
                    `micro-roster-relation-${rosterSize}`,
                ),
                proofRoot: hash(`micro-roster-proof-root-${rosterSize}`),
                proofBytesHash: deriveProofBytesHash({ proofBytesHex }),
                proofSizeBytes: proofBytesHex.length / 2,
            });

            const unacknowledgedResult = verifyBallotProof({
                ballotProof: proofRecord,
                proofBytesHex,
                statement,
            });
            expect(unacknowledgedResult).toMatchObject({
                ok: false,
                unresolvedReason: 'BallotPackageInvalid',
            });
            expect(
                unacknowledgedResult.refusedObjects.some((refusal) =>
                    refusal.message.includes('casual micro-roster'),
                ),
            ).toBe(true);

            expect(
                verifyBallotProof({
                    ballotProof: proofRecord,
                    casualMicroRosterAcknowledged: true,
                    proofBytesHex,
                    statement,
                }),
            ).toMatchObject({
                ok: false,
                unresolvedReason: 'OperationUnavailable',
            });
        },
    );
});
