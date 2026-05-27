import { beforeAll, describe, expect, it } from 'vitest';

import {
    buildBallotProofRecordGenerationRequest,
    type BallotProofRecordGenerationProofContracts,
} from '../../src/ballot-privacy/ballot-proof-linear-statement';
import { compileBallotPrivacyRelation } from '../../src/ballot-privacy/index';
import { deriveThresholdProfile } from '../../src/lifecycle/thresholds';

import {
    type BallotProofRecordGenerationFixture,
    cloneJsonValue,
    createBallotProofRecordGenerationFixture,
    createMicroRosterBallotProofRecordGenerationFixture,
} from './ballot-privacy-proof-record-generation-fixtures';
import './ballot-privacy-proof-record-generation-input/mandatory-profile.js';
import {
    casualMicroRosterSizes,
    digest,
    receiverEncryptionProofStatement,
    requireRecord,
    shareCommitmentProofStatement,
} from './ballot-privacy-proof-record-generation-input/helpers.js';
describe('ballot proof record generation input', () => {
    let fixture: BallotProofRecordGenerationFixture;

    beforeAll(() => {
        fixture = createBallotProofRecordGenerationFixture();
    }, 120_000);

    it('assembles a full relation-derived generation request from explicit components', () => {
        const request = fixture.request;

        expect(request.componentBundleStatement.bundleCoverage).toBe(
            'full-encoded-score-ballot-relation',
        );
        expect(request.linearStatement).toMatchObject({
            componentBundleStatementDigest:
                request.componentBundleStatement.componentBundleStatementDigest,
            objectType: 'BallotProofLinearProofStatement',
            parameterProfileId:
                'full-encoded-score-ballot-linear-compatibility-v1',
            projectionCoverage: 'full-encoded-score-ballot-relation',
            relationBindingKind: 'component-bundle-and-lowered-relation',
            statementColumns: 1,
            statementRows: 1,
        });
        expect(request.linearStatement.relationBindingDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(
            request.componentProofInputs.map(
                (proofInput) => proofInput.componentId,
            ),
        ).toEqual([
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ]);
        expect(
            request.componentProofInputs.map(
                (proofInput) => proofInput.proofStatementFormat,
            ),
        ).toEqual([
            'dense-polynomial-matrix-linear-proof-v1',
            'sparse-polynomial-matrix-linear-proof-v1',
            'sparse-polynomial-matrix-linear-proof-v1',
            'structured-module-lwe-linear-proof-v1',
            'public-zero-witness-binding-check-v1',
        ]);
        expect(Object.keys(request.componentSecretStates).sort()).toEqual([
            'payload-plaintext-field-component',
            'receiver-encryption-component',
            'score-and-shamir-field-component',
            'share-commitment-component',
        ]);
        const receiverEncryptionStatement =
            receiverEncryptionProofStatement(fixture);

        expect(receiverEncryptionStatement.receiverRows).toHaveLength(3);
        expect(receiverEncryptionStatement.receiverRows[0]).toMatchObject({
            ciphertextChunkCount: 5,
            plaintextBitLength: 1142,
            rowCount: 25,
        });
        expect(receiverEncryptionStatement).toMatchObject({
            statementColumns: 150,
            statementRows: 75,
        });
        expect(
            request.componentSecretStates['receiver-encryption-component']
                ?.sourceWitnessCoefficients,
        ).toHaveLength(receiverEncryptionStatement.statementColumns);
    });

    it.each(casualMicroRosterSizes)(
        'assembles a non-claim casual micro-roster generation harness for roster size %d',
        (rosterSize) => {
            const microRosterFixture =
                createMicroRosterBallotProofRecordGenerationFixture(rosterSize);
            const thresholdProfile = deriveThresholdProfile({
                casualMicroRosterAcknowledged: true,
                rosterSize,
            });
            const compiledRelation = compileBallotPrivacyRelation(
                microRosterFixture.relationInput,
            );
            const receiverEncryptionStatementForRoster =
                receiverEncryptionProofStatement(microRosterFixture);
            const shareCommitmentStatementForRoster =
                shareCommitmentProofStatement(microRosterFixture);

            expect(compiledRelation).toMatchObject({
                ok: true,
                optionCount: 2,
                pvssThreshold: thresholdProfile.pvssThreshold,
                rosterSize,
                shareVectorWidth: 22,
            });
            expect(microRosterFixture.relationInput.receivers).toHaveLength(
                rosterSize,
            );
            expect(
                microRosterFixture.relationInput
                    .encodedCoordinateShamirCoefficients,
            ).toHaveLength(22);
            expect(
                microRosterFixture.relationInput
                    .encodedCoordinateShamirCoefficients[0],
            ).toHaveLength(thresholdProfile.pvssThreshold - 1);
            expect(
                microRosterFixture.statement.receiverPublicKeys,
            ).toHaveLength(rosterSize);
            expect(microRosterFixture.statement.shareVectorWidth).toBe(22);
            expect(
                microRosterFixture.request.casualMicroRosterAcknowledged,
            ).toBe(true);
            expect(
                microRosterFixture.request.unsafeSmallRosterAcknowledged,
            ).toBe(true);
            expect(
                receiverEncryptionStatementForRoster.receiverRows,
            ).toHaveLength(rosterSize);
            expect(shareCommitmentStatementForRoster.statementColumns).toBe(
                rosterSize * (22 + 64),
            );
            expect(
                shareCommitmentStatementForRoster.sourceBackendColumnIndices,
            ).toHaveLength(shareCommitmentStatementForRoster.statementColumns);
            if (rosterSize <= 6) {
                expect(shareCommitmentStatementForRoster).toMatchObject({
                    proofStatementFormat:
                        'sparse-polynomial-matrix-linear-proof-v1',
                    statementRows: rosterSize * 1_024,
                });
                expect(
                    shareCommitmentStatementForRoster.receiverRows,
                ).toBeUndefined();
            } else {
                expect(shareCommitmentStatementForRoster).toMatchObject({
                    proofStatementFormat:
                        'structured-module-sis-share-commitment-v1',
                    statementRows: rosterSize * 16,
                });
                expect(
                    shareCommitmentStatementForRoster.receiverRows,
                ).toHaveLength(rosterSize);
            }
            expect(
                microRosterFixture.request.componentProofInputs.map(
                    (proofInput) => proofInput.componentId,
                ),
            ).toEqual([
                'score-and-shamir-field-component',
                'payload-plaintext-field-component',
                'share-commitment-component',
                'receiver-encryption-component',
                'receiver-key-binding-component',
            ]);
        },
    );

    it('rejects statement and payload context drift before constructing proof inputs', () => {
        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: {
                    ...fixture.publicContext,
                    ballotProofStatementDigest: digest(
                        'wrong-ballot-proof-statement',
                    ),
                },
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/ballot proof statement digest/u);

        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: {
                    ...fixture.publicContext,
                    receiverPayloads:
                        fixture.publicContext.receiverPayloads.map(
                            (receiverPayload) => ({
                                ...receiverPayload,
                                plaintextBitLength:
                                    receiverPayload.plaintextBitLength ===
                                    undefined
                                        ? undefined
                                        : receiverPayload.plaintextBitLength -
                                          1,
                            }),
                        ),
                },
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/full encoded-score receiver payload bit length/u);
    });

    it('rejects missing component witnesses and mismatched proof contracts', () => {
        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: {
                    ...fixture.projectionWitness,
                    receiverEncryptionWitnesses: [],
                },
                publicContext: fixture.publicContext,
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/Receiver encryption witness is missing/u);

        const receiverEncryptionParameterSet = requireRecord(
            fixture.proofContracts.componentProofParameterSets[
                'receiver-encryption-component'
            ],
            'receiver-encryption parameter set',
        );
        const wrongContracts: BallotProofRecordGenerationProofContracts = {
            ...cloneJsonValue(fixture.proofContracts),
            componentProofParameterSets: {
                ...fixture.proofContracts.componentProofParameterSets,
                'receiver-encryption-component': {
                    ...receiverEncryptionParameterSet,
                    profileId: 'wrong-receiver-encryption-profile',
                },
            },
        };

        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: wrongContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: fixture.publicContext,
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/receiver-encryption-component parameter set/u);
    });
});
