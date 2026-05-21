// This file is one focused part of the split test suite.
import type { BallotPrivacyRosterProfileEvidence } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createBallotPrivacyProfileSet,
    createBallotProofRecordShell,
    createReceiverEncryptionPublicKeyShell,
    createReceiverKeyProofShell,
    createReceiverPayloadShell,
    createShareCommitmentShell,
    deriveBallotPrivacyRosterProfileEvidenceDigest,
    deriveBallotProofEncodingProfileDigest,
    deriveBallotProofParameterSetDigest,
    deriveBallotProofPublicRandomnessDigest,
    deriveProofBytesDigest,
    verifyBallotProof,
} from '../../../src/ballot-privacy/index';

import {
    createComponentProofBundleFixture,
    createComponentProofStatementFixture,
    createComponentProofVerificationInputsFixture,
    createStatement,
    createStructurallyBoundObjects,
    digest,
    requiredComponentIds,
} from './shared.js';

const createDynamicRosterProfileEvidence = (
    input: Pick<
        BallotPrivacyRosterProfileEvidence,
        'frozenRosterSize' | 'optionCount' | 'thresholdProfileDigest'
    >,
): BallotPrivacyRosterProfileEvidence => {
    const payload = {
        dynamicRosterProfileCertificateDigest: digest(
            'dynamic-roster-profile-certificate',
        ),
        frozenRosterSize: input.frozenRosterSize,
        objectType: 'BallotPrivacyRosterProfileEvidence' as const,
        objectVersion: 1 as const,
        optionCount: input.optionCount,
        profileFamily: 'BalancedDefault' as const,
        proofStatementShape: 'M5EncodedScoreBallotProof-v1' as const,
        receiverCoverageProfile: 'AllFrozenRosterReceivers' as const,
        thresholdProfileDigest: input.thresholdProfileDigest,
    };

    return {
        ...payload,
        rosterProfileEvidenceDigest:
            deriveBallotPrivacyRosterProfileEvidenceDigest(payload),
    };
};

describe('ballot privacy proof object boundary', () => {
    it('derives production-shaped receiver key, payload, and commitment shells without witness material', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverPublicKey = createReceiverEncryptionPublicKeyShell({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            rosterDigest: digest('roster'),
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            receiverEncryptionProfileDigest:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileDigest,
            keyMaterialDigest: digest('receiver-key-material'),
        });
        const receiverKeyProof = createReceiverKeyProofShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestDigest: receiverPublicKey.manifestDigest,
            rosterDigest: receiverPublicKey.rosterDigest,
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            recoveryEpoch: receiverPublicKey.recoveryEpoch,
            receiverPublicKeyDigest: receiverPublicKey.receiverPublicKeyDigest,
            receiverEncryptionProfileDigest:
                receiverPublicKey.receiverEncryptionProfileDigest,
            proofBackend: 'LocalLinearLatticeRelation',
            proofRoot: digest('receiver-key-proof-root'),
        });
        const receiverPayload = createReceiverPayloadShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestDigest: receiverPublicKey.manifestDigest,
            rosterDigest: receiverPublicKey.rosterDigest,
            pollSpecDigest: digest('poll-spec'),
            voterIdentityDigest: digest('voter-1'),
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            receiverPublicKeyDigest: receiverPublicKey.receiverPublicKeyDigest,
            receiverEncryptionProfileDigest:
                receiverPublicKey.receiverEncryptionProfileDigest,
            payloadContextDigest: digest('payload-context'),
            ciphertextBodyDigest: digest('ciphertext-body'),
        });
        const shareCommitment = createShareCommitmentShell({
            ceremonyId: receiverPublicKey.ceremonyId,
            manifestDigest: receiverPublicKey.manifestDigest,
            rosterDigest: receiverPublicKey.rosterDigest,
            receiverIdentity: receiverPublicKey.receiverIdentity,
            receiverRosterPosition: receiverPublicKey.receiverRosterPosition,
            shareCommitmentProfileDigest:
                profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
            shareVectorWidth:
                profileSet.shareCommitmentProfile.shareVectorWidth,
            commitmentBodyDigest: digest('share-commitment-body'),
        });

        expect(receiverPublicKey.receiverPublicKeyDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverKeyProof.receiverKeyProofRoot).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverPayload.receiverPayloadDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(receiverPayload).not.toHaveProperty('receiverShareVector');
        expect(receiverPayload).not.toHaveProperty('shareCommitmentOpening');
        expect(shareCommitment.shareCommitmentDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(shareCommitment).not.toHaveProperty('openingRandomness');
    });

    it('builds a deterministic statement that binds every public transcript input', () => {
        const statement = createStatement();
        const changedStatement = createStatement({
            manifestDigest: digest('changed-manifest'),
        });

        expect(statement.objectType).toBe('BallotProofStatement');
        expect(statement.shareVectorWidth).toBe(220);
        expect(statement.ballotScoreEncodingProfileDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.ballotShareLayoutProfileDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.aggregateInputEncodingProfileDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.encodedShareVectorLayoutDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.encodedAggregateLayoutDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.ballotProofStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(statement.challengeDomainDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(changedStatement.ballotProofStatementDigest).not.toBe(
            statement.ballotProofStatementDigest,
        );
        expect(changedStatement.challengeDomainDigest).toBe(
            statement.challengeDomainDigest,
        );
    });

    it('binds the encoded-score layout digests into the challenge domain and proof record', () => {
        const statement = createStatement();
        const changedLayoutStatement = createStatement({
            encodedShareVectorLayoutDigest: digest(
                'changed-encoded-share-vector-layout',
            ),
        });
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedLayoutProofRecord = createBallotProofRecordShell({
            statement: changedLayoutStatement,
            relationStatementDigest: digest('changed-relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(changedLayoutStatement.challengeDomainDigest).not.toBe(
            statement.challengeDomainDigest,
        );
        expect(changedLayoutStatement.ballotProofStatementDigest).not.toBe(
            statement.ballotProofStatementDigest,
        );
        expect(changedLayoutProofRecord.challengeDigest).not.toBe(
            proofRecord.challengeDigest,
        );
    });

    it('binds proof shell challenge to statement and proof roots', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('changed-proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const changedRelationProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('changed-relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });

        expect(proofRecord.objectType).toBe('BallotProofRecord');
        expect(proofRecord.ballotProofStatementDigest).toBe(
            statement.ballotProofStatementDigest,
        );
        expect(proofRecord.relationStatementDigest).toBe(
            digest('relation-statement'),
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedProofRecord.challengeDigest,
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedRelationProofRecord.challengeDigest,
        );
        expect(proofRecord.ballotProofRecordDigest).not.toBe(
            changedProofRecord.ballotProofRecordDigest,
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
            backendStatementDigest: digest('ballot-backend-statement'),
            linearStatementDigest: digest('ballot-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: deriveBallotProofEncodingProfileDigest({
                proofEncoding,
            }),
            proofParameterSetDigest: deriveBallotProofParameterSetDigest({
                parameterSet,
            }),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: deriveBallotProofPublicRandomnessDigest({
                publicRandomnessHex,
            }),
            relationStatementDigest: digest('relation-statement'),
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });
        const changedRandomnessProofRecord = createBallotProofRecordShell({
            backendStatementDigest: digest('ballot-backend-statement'),
            linearStatementDigest: digest('ballot-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: deriveBallotProofEncodingProfileDigest({
                proofEncoding,
            }),
            proofParameterSetDigest: deriveBallotProofParameterSetDigest({
                parameterSet,
            }),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: deriveBallotProofPublicRandomnessDigest({
                publicRandomnessHex: '11'.repeat(32),
            }),
            relationStatementDigest: digest('relation-statement'),
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });
        const incompleteBackendMetadataProofRecord =
            createBallotProofRecordShell({
                linearStatementDigest: digest('ballot-linear-statement'),
                proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
                proofRoot: digest('ballot-proof-root'),
                proofSizeBytes: proofBytesHex.length / 2,
                relationStatementDigest: digest('relation-statement'),
                statement,
            });

        expect(proofRecord.backendStatementDigest).toBe(
            digest('ballot-backend-statement'),
        );
        expect(proofRecord.proofParameterSetDigest).toBe(
            deriveBallotProofParameterSetDigest({ parameterSet }),
        );
        expect(proofRecord.challengeDigest).not.toBe(
            changedRandomnessProofRecord.challengeDigest,
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
            backendStatementDigest: componentProofBundle.backendStatementDigest,
            componentBundleStatementDigest:
                componentProofBundle.componentBundleStatementDigest,
            componentProofBundleDigest:
                componentProofBundle.componentProofBundleDigest,
            linearStatementDigest: digest('component-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: digest('ballot-proof-encoding'),
            proofParameterSetDigest: digest('ballot-proof-parameters'),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: digest('ballot-proof-randomness'),
            relationStatementDigest:
                componentProofBundle.relationStatementDigest,
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
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
            backendStatementDigest:
                reorderedComponentProofBundle.backendStatementDigest,
            componentBundleStatementDigest:
                reorderedComponentProofBundle.componentBundleStatementDigest,
            componentProofBundleDigest:
                reorderedComponentProofBundle.componentProofBundleDigest,
            linearStatementDigest: digest('component-linear-statement'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest: digest('ballot-proof-encoding'),
            proofParameterSetDigest: digest('ballot-proof-parameters'),
            proofRoot: digest('ballot-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest: digest('ballot-proof-randomness'),
            relationStatementDigest:
                reorderedComponentProofBundle.relationStatementDigest,
            statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
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
                    componentProofBundleDigest: digest(
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
                          componentProofStatementDigest: digest(
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
                delete mutableProofInput.componentProofStatementDigest;

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
                        'must be bound to a component proof statement digest',
                    ),
            ),
        ).toBe(true);

        const componentProofBundleWithoutStatementDigest = {
            ...componentProofBundle,
        };
        delete (
            componentProofBundleWithoutStatementDigest as Record<
                string,
                unknown
            >
        ).ballotProofStatementDigest;
        const missingBundleStatementDigestResult = verifyBallotProof({
            ballotProof: proofRecord,
            componentProofBundle:
                componentProofBundleWithoutStatementDigest as typeof componentProofBundle,
            componentProofInputs,
            proofBytesHex,
            statement,
        });
        expect(missingBundleStatementDigestResult).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            missingBundleStatementDigestResult.refusedObjects.some((refusal) =>
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
                              componentProofStatementDigest: digest(
                                  'wrong-supplied-component-proof-statement-canonical-digest',
                              ),
                              componentStatementDigest:
                                  componentProofInput.statementDigest,
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
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2,
        });
        const wrongProofBytes = '001122aabbcd';
        const shortProofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
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

    it('requires dynamic roster profile evidence for non-benchmark receiver counts', () => {
        const { statement } = createStructurallyBoundObjects({
            participantCount: 16,
        });
        const proofBytesHex = '001122aabbcc';
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofSizeBytes: proofBytesHex.length / 2,
        });
        const dynamicRosterProfileEvidence = createDynamicRosterProfileEvidence(
            {
                frozenRosterSize: statement.receiverPublicKeys.length,
                optionCount: statement.optionCount,
                thresholdProfileDigest: statement.thresholdProfileDigest,
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
                refusal.message.includes('roster profile certificate'),
            ),
        ).toBe(true);

        expect(
            verifyBallotProof({
                ballotProof: proofRecord,
                dynamicRosterProfileEvidence,
                proofBytesHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
    });
});
