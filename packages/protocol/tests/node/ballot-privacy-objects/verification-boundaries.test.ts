// This file is one focused part of the split test suite.
import type { ReceiverPayload } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createBallotProofRecordShell,
    createReceiverKeyProofShell,
    createShareCommitmentShell,
    deriveProofBytesDigest,
    deriveReceiverKeyProofEncodingProfileDigest,
    deriveReceiverKeyProofParameterSetDigest,
    deriveReceiverKeyProofPublicRandomnessDigest,
    describeBallotPrivacyProofBackend,
    verifyBallotProof,
    verifyClaimBearingBallotPackage,
    verifyReceiverKeyProof,
} from '../../../src/ballot-privacy/index';

import type { ClaimBearingPackageVerificationInput } from './shared.js';
import {
    createComponentProofBundleFixture,
    createComponentProofVerificationInputsFixture,
    createStatement,
    createStructurallyBoundObjects,
    digest,
} from './shared.js';

const casualMicroRosterSizes = [3, 4, 5, 6, 7, 8, 9] as const;

describe('ballot privacy proof object boundary', () => {
    it('checks supplied receiver-key proof bytes against proof-byte metadata before the backend gate', () => {
        const proofBytesHex = '001122aabbcc';
        const wrongProofBytesHex = '001122aabbcd';
        const proofEncoding = {
            profileId: 'receiver-key-linear-proof-encoding-v1',
        };
        const proofParameterSet = {
            profileId: 'receiver-key-linear-module-lwe-v1',
        };
        const publicRandomnessHex = '00'.repeat(32);
        const receiverKeyProof = createReceiverKeyProofShell({
            backendStatementDigest: digest('receiver-key-backend-statement'),
            ceremonyId: 'ceremony-1',
            linearStatementDigest: digest('receiver-key-linear-statement'),
            manifestDigest: digest('manifest'),
            proofBackend: 'LocalLinearLatticeRelation',
            proofBytesDigest: deriveProofBytesDigest({ proofBytesHex }),
            proofEncodingProfileDigest:
                deriveReceiverKeyProofEncodingProfileDigest({
                    proofEncoding,
                }),
            proofParameterSetDigest: deriveReceiverKeyProofParameterSetDigest({
                parameterSet: proofParameterSet,
            }),
            proofRoot: digest('receiver-key-proof-root'),
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest:
                deriveReceiverKeyProofPublicRandomnessDigest({
                    publicRandomnessHex,
                }),
            receiverEncryptionProfileDigest: digest(
                'receiver-encryption-profile',
            ),
            receiverIdentity: 'receiver-1',
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const incompleteProofMetadata = createReceiverKeyProofShell({
            ceremonyId: 'ceremony-1',
            linearStatementDigest: digest('receiver-key-linear-statement'),
            manifestDigest: digest('manifest'),
            proofBackend: 'LocalLinearLatticeRelation',
            proofRoot: digest('receiver-key-proof-root'),
            receiverEncryptionProfileDigest: digest(
                'receiver-encryption-profile',
            ),
            receiverIdentity: 'receiver-1',
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });

        expect(
            verifyReceiverKeyProof({
                proofBytesHex,
                receiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyReceiverKeyProof({
                proofBytesHex: wrongProofBytesHex,
                receiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyReceiverKeyProof({
                proofBytesHex: 'AA',
                receiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            verifyReceiverKeyProof({
                receiverKeyProof: incompleteProofMetadata,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('keeps proof verification fail-closed until the lattice backend is integrated', () => {
        const statement = createStatement();
        const proofRecord = createBallotProofRecordShell({
            statement,
            relationStatementDigest: digest('relation-statement'),
            proofRoot: digest('proof-root'),
            proofBytesDigest: digest('proof-bytes'),
            proofSizeBytes: 1_024,
        });
        const receiverKeyProof = createReceiverKeyProofShell({
            ceremonyId: statement.ceremonyId,
            manifestDigest: statement.manifestDigest,
            rosterDigest: statement.rosterDigest,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            receiverPublicKeyDigest: digest('receiver-public-key-1'),
            receiverEncryptionProfileDigest:
                statement.receiverEncryptionProfileDigest,
            proofBackend: 'LocalLinearLatticeRelation' as const,
            proofRoot: digest('receiver-key-proof'),
        });
        const structurallyBoundObjects = createStructurallyBoundObjects();
        const structurallyBoundProofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('bound-proof-bytes'),
            relationStatementDigest: digest('bound-relation-statement'),
            proofRoot: digest('bound-proof-root'),
            proofSizeBytes: 1_024,
            statement: structurallyBoundObjects.statement,
        });

        expect(
            verifyBallotProof({ statement, ballotProof: proofRecord }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            backendStatus: {
                portableRustWasmPortRequired: true,
            },
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyBallotProof({ statement, ballotProof: proofRecord })
                .backendStatus?.blockedReason,
        ).toContain(
            'pure TypeScript protocol shell does not verify ballot privacy proof bytes',
        );
        expect(verifyReceiverKeyProof({ receiverKeyProof })).toMatchObject({
            ok: false,
            backendAvailable: false,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(
            verifyClaimBearingBallotPackage({
                ballotPackage: {
                    objectType: 'ClaimBearingBallotPackage',
                    objectVersion: 1,
                    ballotPackageDigest:
                        structurallyBoundObjects.statement.ballotPackageDigest,
                    ballotProofStatement: structurallyBoundObjects.statement,
                    receiverKeyProofRootEvidence:
                        structurallyBoundObjects.receiverKeyProofRootEvidence,
                    ballotProof: structurallyBoundProofRecord,
                    receiverPayloads: structurallyBoundObjects.receiverPayloads,
                    shareCommitments: structurallyBoundObjects.shareCommitments,
                },
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            unresolvedReason: 'OperationUnavailable',
        });
    });

    it('keeps claim-bearing packages fail-closed after component proof preflight', () => {
        const structurallyBoundObjects = createStructurallyBoundObjects();
        const componentProofBundle = createComponentProofBundleFixture(
            structurallyBoundObjects.statement,
        );
        const componentProofInputs =
            createComponentProofVerificationInputsFixture(componentProofBundle);
        const proofBytesHex = '001122aabbcc';
        const ballotProof = createBallotProofRecordShell({
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
            statement: structurallyBoundObjects.statement,
            statementMatrixDigest: digest('ballot-statement-matrix'),
            targetVectorDigest: digest('ballot-target-vector'),
        });

        expect(
            verifyClaimBearingBallotPackage({
                ballotPackage: {
                    objectType: 'ClaimBearingBallotPackage',
                    objectVersion: 1,
                    ballotPackageDigest:
                        structurallyBoundObjects.statement.ballotPackageDigest,
                    ballotProofStatement: structurallyBoundObjects.statement,
                    receiverKeyProofRootEvidence:
                        structurallyBoundObjects.receiverKeyProofRootEvidence,
                    ballotProof,
                    proofBytesHex,
                    componentProofBundle,
                    componentProofInputs,
                    receiverPayloads: structurallyBoundObjects.receiverPayloads,
                    shareCommitments: structurallyBoundObjects.shareCommitments,
                },
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
    });

    it.each(casualMicroRosterSizes)(
        'rejects roster size %d casual micro-rosters for claim-bearing ballot package acceptance',
        (rosterSize) => {
            const structurallyBoundObjects = createStructurallyBoundObjects({
                participantCount: rosterSize,
            });
            const proofRecord = createBallotProofRecordShell({
                proofBytesDigest: digest(
                    `micro-roster-bound-proof-bytes-${rosterSize}`,
                ),
                relationStatementDigest: digest(
                    `micro-roster-bound-relation-statement-${rosterSize}`,
                ),
                proofRoot: digest(
                    `micro-roster-bound-proof-root-${rosterSize}`,
                ),
                proofSizeBytes: 1_024,
                statement: structurallyBoundObjects.statement,
            });

            const result = verifyClaimBearingBallotPackage({
                ballotPackage: {
                    objectType: 'ClaimBearingBallotPackage',
                    objectVersion: 1,
                    ballotPackageDigest:
                        structurallyBoundObjects.statement.ballotPackageDigest,
                    ballotProofStatement: structurallyBoundObjects.statement,
                    receiverKeyProofRootEvidence:
                        structurallyBoundObjects.receiverKeyProofRootEvidence,
                    ballotProof: proofRecord,
                    receiverPayloads: structurallyBoundObjects.receiverPayloads,
                    shareCommitments: structurallyBoundObjects.shareCommitments,
                },
                casualMicroRosterAcknowledged: true,
            });

            expect(result).toMatchObject({
                ok: false,
                unresolvedReason: 'BallotPackageInvalid',
            });
            expect(
                result.refusedObjects.some((refusal) =>
                    refusal.message.includes('at least 10 frozen participants'),
                ),
            ).toBe(true);
        },
    );

    it('uses package-neutral dynamic roster evidence wording for standalone ballot proofs', () => {
        const structurallyBoundObjects = createStructurallyBoundObjects({
            participantCount: 11,
        });
        const proofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('dynamic-proof-bytes'),
            relationStatementDigest: digest('dynamic-relation-statement'),
            proofRoot: digest('dynamic-proof-root'),
            proofSizeBytes: 1_024,
            statement: structurallyBoundObjects.statement,
        });

        const result = verifyBallotProof({
            ballotProof: proofRecord,
            statement: structurallyBoundObjects.statement,
        });

        expect(result).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            result.refusedObjects.some(
                (refusal) =>
                    refusal.message ===
                    'Dynamic ballot privacy verification requires roster profile certificate or workbook evidence for the frozen receiver count.',
            ),
        ).toBe(true);
    });

    it('rejects malformed claim-bearing package shells before the backend gate', () => {
        const structurallyBoundObjects = createStructurallyBoundObjects();
        const firstReceiverPayload =
            structurallyBoundObjects.receiverPayloads[0];
        const firstReceiverPayloadReference =
            structurallyBoundObjects.statement.receiverPayloads[0];
        const firstShareCommitment =
            structurallyBoundObjects.shareCommitments[0];
        if (
            firstReceiverPayload === undefined ||
            firstReceiverPayloadReference === undefined ||
            firstShareCommitment === undefined
        ) {
            throw new Error('receiver fixture should contain a first receiver');
        }
        const proofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('bound-proof-bytes'),
            relationStatementDigest: digest('bound-relation-statement'),
            proofRoot: digest('bound-proof-root'),
            proofSizeBytes: 1_024,
            statement: structurallyBoundObjects.statement,
        });
        const changedChallengeProofRecord = {
            ...proofRecord,
            challengeDigest: digest('changed-challenge'),
        };
        const validStructuralPackage = {
            objectType: 'ClaimBearingBallotPackage',
            objectVersion: 1,
            ballotPackageDigest:
                structurallyBoundObjects.statement.ballotPackageDigest,
            ballotProofStatement: structurallyBoundObjects.statement,
            receiverKeyProofRootEvidence:
                structurallyBoundObjects.receiverKeyProofRootEvidence,
            ballotProof: proofRecord,
            receiverPayloads: structurallyBoundObjects.receiverPayloads,
            shareCommitments: structurallyBoundObjects.shareCommitments,
        } as const satisfies ClaimBearingPackageVerificationInput;
        const packageWithoutReceiverKeyProofRootEvidence: Record<
            string,
            unknown
        > = {
            ...validStructuralPackage,
        };
        delete packageWithoutReceiverKeyProofRootEvidence.receiverKeyProofRootEvidence;
        const packageWithWrongPackageDigest = verifyClaimBearingBallotPackage({
            ballotPackage: {
                ...validStructuralPackage,
                ballotPackageDigest: digest('wrong-package'),
            },
        });
        const packageWithMissingReceiverKeyProofRootEvidence =
            verifyClaimBearingBallotPackage({
                ballotPackage:
                    packageWithoutReceiverKeyProofRootEvidence as unknown as ClaimBearingPackageVerificationInput,
            });
        const packageWithChangedChallenge = verifyClaimBearingBallotPackage({
            ballotPackage: {
                ...validStructuralPackage,
                ballotProof: changedChallengeProofRecord,
            },
        });
        const packageWithLeakedWitness = verifyClaimBearingBallotPackage({
            ballotPackage: {
                ...validStructuralPackage,
                receiverPayloads: [
                    {
                        ...firstReceiverPayload,
                        receiverShareVector: [1, 2, 3],
                    } as unknown as ReceiverPayload,
                    ...structurallyBoundObjects.receiverPayloads.slice(1),
                ],
                shareCommitments: structurallyBoundObjects.shareCommitments,
            },
        });
        const zeroCommitmentPolynomialVector = Array.from({ length: 4 }, () =>
            Array.from({ length: 256 }, () => '0'),
        );
        const malformedCommitmentVector = createShareCommitmentShell({
            ceremonyId: firstShareCommitment.ceremonyId,
            commitmentBodyDigest: digest('wrong-commitment-body'),
            commitmentPolynomialVector: zeroCommitmentPolynomialVector,
            manifestDigest: firstShareCommitment.manifestDigest,
            receiverIdentity: firstShareCommitment.receiverIdentity,
            receiverRosterPosition: firstShareCommitment.receiverRosterPosition,
            rosterDigest: firstShareCommitment.rosterDigest,
            shareCommitmentProfileDigest:
                firstShareCommitment.shareCommitmentProfileDigest,
            shareVectorWidth: firstShareCommitment.shareVectorWidth,
        });
        const packageWithMalformedCommitmentVector =
            verifyClaimBearingBallotPackage({
                ballotPackage: {
                    ...validStructuralPackage,
                    receiverPayloads: structurallyBoundObjects.receiverPayloads,
                    shareCommitments: [
                        malformedCommitmentVector,
                        ...structurallyBoundObjects.shareCommitments.slice(1),
                    ],
                },
            });
        const duplicateReceiverStatement = createStatement({
            receiverPayloads: [
                firstReceiverPayloadReference,
                firstReceiverPayloadReference,
            ],
        });
        const duplicateReceiverProofRecord = createBallotProofRecordShell({
            proofBytesDigest: digest('duplicate-proof-bytes'),
            relationStatementDigest: digest('duplicate-relation-statement'),
            proofRoot: digest('duplicate-proof-root'),
            proofSizeBytes: 1_024,
            statement: duplicateReceiverStatement,
        });

        expect(packageWithWrongPackageDigest).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            packageWithWrongPackageDigest.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'Claim-bearing ballot package shell digest',
                ),
            ),
        ).toBe(true);
        expect(packageWithMissingReceiverKeyProofRootEvidence).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            packageWithMissingReceiverKeyProofRootEvidence.refusedObjects.some(
                (refusal) =>
                    refusal.message.includes(
                        'Receiver-key proof root evidence has an invalid canonical shape',
                    ),
            ),
        ).toBe(true);
        expect(packageWithChangedChallenge).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(packageWithLeakedWitness).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(packageWithMalformedCommitmentVector).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            packageWithMalformedCommitmentVector.refusedObjects.some(
                (refusal) =>
                    refusal.message.includes(
                        'Share commitment polynomial vector is malformed or not bound',
                    ),
            ),
        ).toBe(true);
        expect(
            verifyBallotProof({
                ballotProof: duplicateReceiverProofRecord,
                statement: duplicateReceiverStatement,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('describes the pure TypeScript proof backend boundary', () => {
        const backendStatus = describeBallotPrivacyProofBackend();

        expect(backendStatus.backendAvailable).toBe(false);
        expect(backendStatus.portableRustWasmPortRequired).toBe(true);
        expect(backendStatus.requiredComponents).toEqual([]);
        expect(backendStatus.blockedReason).toContain(
            'pure TypeScript protocol shell does not verify ballot privacy proof bytes',
        );
    });
});
