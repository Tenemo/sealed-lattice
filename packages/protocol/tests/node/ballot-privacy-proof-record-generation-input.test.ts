import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import { beforeAll, describe, expect, it } from 'vitest';

import {
    buildBallotProofRecordGenerationRequest,
    type BallotProofRecordGenerationProofContracts,
} from '../../src/ballot-privacy/ballot-proof-linear-statement';
import { compileBallotPrivacyRelation } from '../../src/ballot-privacy/index';
import { lowerBallotPrivacyRelationToBackendStatement } from '../../src/ballot-privacy/relation-backend-lowering';
import { deriveThresholdProfile } from '../../src/lifecycle/thresholds';

import {
    type BallotProofRecordGenerationFixture,
    cloneJsonValue,
    createBallotProofRecordGenerationFixture,
    createMandatoryProfileBallotProofRecordGenerationFixture,
    createMicroRosterBallotProofRecordGenerationFixture,
} from './ballot-privacy-proof-record-generation-fixtures';

const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-proof-record-generation-input-test',
    });
const mandatoryProfileFixtureTimeoutMs = 900_000;
const casualMicroRosterSizes = [3, 4, 5, 6, 7, 8, 9] as const;

const requireRecord = (
    value: unknown,
    label: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} should be an object.`);
    }

    return value as Record<string, unknown>;
};

const receiverEncryptionProofStatement = (
    fixture: BallotProofRecordGenerationFixture,
): {
    readonly receiverRows: readonly {
        readonly ciphertextChunkCount: number;
        readonly plaintextBitLength: number;
        readonly rowCount: number;
    }[];
    readonly sourceBackendColumnIndices: readonly number[];
    readonly statementColumns: number;
    readonly statementRows: number;
} => {
    const receiverEncryptionInput = fixture.request.componentProofInputs.find(
        (proofInput) =>
            proofInput.componentId === 'receiver-encryption-component',
    );
    if (receiverEncryptionInput === undefined) {
        throw new Error('Receiver-encryption input should be present.');
    }

    return receiverEncryptionInput.proofStatement as {
        readonly receiverRows: readonly {
            readonly ciphertextChunkCount: number;
            readonly plaintextBitLength: number;
            readonly rowCount: number;
        }[];
        readonly sourceBackendColumnIndices: readonly number[];
        readonly statementColumns: number;
        readonly statementRows: number;
    };
};

const shareCommitmentProofStatement = (
    fixture: BallotProofRecordGenerationFixture,
): {
    readonly proofStatementFormat: string;
    readonly receiverRows?: readonly {
        readonly commitmentPolynomialVector: readonly (readonly string[])[];
        readonly rowCount: number;
        readonly rowOffsetWithinStatement: number;
    }[];
    readonly shareVectorWidth: number;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly statementColumns: number;
    readonly statementRows: number;
} => {
    const shareCommitmentInput = fixture.request.componentProofInputs.find(
        (proofInput) => proofInput.componentId === 'share-commitment-component',
    );
    if (shareCommitmentInput === undefined) {
        throw new Error('Share-commitment input should be present.');
    }

    return shareCommitmentInput.proofStatement as {
        readonly proofStatementFormat: string;
        readonly receiverRows?: readonly {
            readonly commitmentPolynomialVector: readonly (readonly string[])[];
            readonly rowCount: number;
            readonly rowOffsetWithinStatement: number;
        }[];
        readonly shareVectorWidth: number;
        readonly sourceBackendColumnIndices: readonly number[];
        readonly statementColumns: number;
        readonly statementRows: number;
    };
};

const fieldProofStatement = (
    fixture: BallotProofRecordGenerationFixture,
    componentId:
        | 'score-and-shamir-field-component'
        | 'payload-plaintext-field-component',
): {
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceColumnPackings?: readonly unknown[];
    readonly statementColumns: number;
    readonly statementRows: number;
} => {
    const proofInput = fixture.request.componentProofInputs.find(
        (candidate) => candidate.componentId === componentId,
    );
    if (proofInput === undefined) {
        throw new Error(`${componentId} input should be present.`);
    }

    return proofInput.proofStatement as {
        readonly sourceBackendColumnIndices: readonly number[];
        readonly sourceColumnPackings?: readonly unknown[];
        readonly statementColumns: number;
        readonly statementRows: number;
    };
};

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

describe('mandatory-profile ballot proof record generation input', () => {
    let fixture: BallotProofRecordGenerationFixture;

    beforeAll(() => {
        fixture = createMandatoryProfileBallotProofRecordGenerationFixture();
    }, mandatoryProfileFixtureTimeoutMs);

    const buildMandatoryRequest = (
        input: Partial<
            Pick<
                BallotProofRecordGenerationFixture,
                | 'proofContracts'
                | 'projectionWitness'
                | 'publicContext'
                | 'randomness'
                | 'relationInput'
                | 'statement'
            >
        >,
    ): ReturnType<typeof buildBallotProofRecordGenerationRequest> =>
        buildBallotProofRecordGenerationRequest({
            proofContracts: input.proofContracts ?? fixture.proofContracts,
            projectionWitness:
                input.projectionWitness ?? fixture.projectionWitness,
            publicContext: input.publicContext ?? fixture.publicContext,
            randomness: input.randomness ?? fixture.randomness,
            relationInput: input.relationInput ?? fixture.relationInput,
            statement: input.statement ?? fixture.statement,
        });

    it('assembles the 20-option all-trustee encoded-score proof request', () => {
        const request = fixture.request;
        const scoreStatement = fieldProofStatement(
            fixture,
            'score-and-shamir-field-component',
        );
        const payloadStatement = fieldProofStatement(
            fixture,
            'payload-plaintext-field-component',
        );
        const receiverEncryptionStatement =
            receiverEncryptionProofStatement(fixture);
        const shareCommitmentStatement = shareCommitmentProofStatement(fixture);

        expect(fixture.relationInput).toMatchObject({
            optionCount: 20,
            pvssThreshold: 7,
            rosterSize: 20,
        });
        expect(fixture.statement).toMatchObject({
            optionCount: 20,
            shareVectorWidth: 220,
            topOptionCount: 20,
        });
        expect(fixture.relationInput.receivers).toHaveLength(20);
        expect(fixture.publicContext.receiverPayloads).toHaveLength(20);
        expect(fixture.publicContext.receiverPublicKeys).toHaveLength(20);
        expect(fixture.publicContext.shareCommitments).toHaveLength(20);
        for (const receiver of fixture.relationInput.receivers) {
            expect(receiver.receiverShareVector).toHaveLength(220);
        }
        expect(
            fixture.relationInput.encodedCoordinateShamirCoefficients,
        ).toHaveLength(220);
        for (const coefficientRow of fixture.relationInput
            .encodedCoordinateShamirCoefficients) {
            expect(coefficientRow).toHaveLength(6);
        }

        expect(
            request.componentProofInputs.map(
                (proofInput) => proofInput.proofStatementFormat,
            ),
        ).toEqual([
            'sparse-polynomial-matrix-linear-proof-v1',
            'sparse-polynomial-matrix-linear-proof-v1',
            'structured-module-sis-share-commitment-v1',
            'structured-module-lwe-linear-proof-v1',
            'public-zero-witness-binding-check-v1',
        ]);
        expect(scoreStatement).toMatchObject({
            statementColumns: 404,
            statementRows: 82,
        });
        expect(scoreStatement.sourceBackendColumnIndices).toHaveLength(10_340);
        expect(scoreStatement.sourceColumnPackings).toHaveLength(
            scoreStatement.statementColumns,
        );
        expect(
            request.componentSecretStates['score-and-shamir-field-component']
                ?.sourceWitnessCoefficients,
        ).toHaveLength(scoreStatement.statementColumns);
        expect(payloadStatement).toMatchObject({
            statementColumns: 1800,
            statementRows: 200,
        });
        expect(payloadStatement.sourceBackendColumnIndices).toHaveLength(
            101_520,
        );
        expect(payloadStatement.sourceColumnPackings).toHaveLength(
            payloadStatement.statementColumns,
        );
        expect(
            request.componentSecretStates['payload-plaintext-field-component']
                ?.sourceWitnessCoefficients,
        ).toHaveLength(payloadStatement.statementColumns);
        expect(receiverEncryptionStatement.receiverRows).toHaveLength(20);
        for (const receiverRow of receiverEncryptionStatement.receiverRows) {
            expect(receiverRow).toMatchObject({
                ciphertextChunkCount: 18,
                plaintextBitLength: 4508,
                rowCount: 90,
            });
        }
        expect(receiverEncryptionStatement).toMatchObject({
            statementColumns: 3600,
            statementRows: 1800,
        });
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: fixture.publicContext,
            relationInput: fixture.relationInput,
        });
        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('mandatory profile relation input should lower');
        }
        const backendStatement = loweringResult.statement.backendStatement;
        const receiverEncryptionComponent =
            backendStatement.proofComponents.find(
                (component) =>
                    component.componentId === 'receiver-encryption-component',
            );
        if (receiverEncryptionComponent === undefined) {
            throw new Error('Receiver-encryption component should be present.');
        }
        const firstReceiverEncryptionSourceColumn =
            receiverEncryptionComponent.variableColumnIndices[0];
        const lastReceiverEncryptionSourceColumn =
            receiverEncryptionComponent.variableColumnIndices[
                receiverEncryptionComponent.variableColumnIndices.length - 1
            ];
        if (
            firstReceiverEncryptionSourceColumn === undefined ||
            lastReceiverEncryptionSourceColumn === undefined
        ) {
            throw new Error(
                'Receiver-encryption component should expose source columns.',
            );
        }
        expect(backendStatement.variableColumns).toHaveLength(
            backendStatement.columnCount,
        );
        expect(receiverEncryptionComponent.variableColumnIndices).toHaveLength(
            receiverEncryptionStatement.statementColumns,
        );
        expect(receiverEncryptionStatement.sourceBackendColumnIndices).toEqual(
            receiverEncryptionComponent.variableColumnIndices,
        );
        expect(firstReceiverEncryptionSourceColumn).toBe(
            loweringResult.statement.variables.length,
        );
        expect(lastReceiverEncryptionSourceColumn).toBeLessThan(
            backendStatement.columnCount,
        );
        expect(
            backendStatement.variableColumns[
                firstReceiverEncryptionSourceColumn
            ],
        ).toMatchObject({
            chunkIndex: 0,
            ciphertextVectorIndex: 0,
            columnIndex: firstReceiverEncryptionSourceColumn,
            receiverRosterPosition: 1,
            variableRole: 'ReceiverEncryptionRandomnessPolynomial',
        });
        expect(
            backendStatement.variableColumns[
                lastReceiverEncryptionSourceColumn
            ],
        ).toMatchObject({
            chunkIndex: 17,
            columnIndex: lastReceiverEncryptionSourceColumn,
            receiverRosterPosition: 20,
            variableRole: 'ReceiverPayloadPlaintextPolynomial',
        });
        expect(
            request.componentSecretStates['receiver-encryption-component']
                ?.sourceWitnessCoefficients,
        ).toHaveLength(receiverEncryptionStatement.statementColumns);
        expect(shareCommitmentStatement).toMatchObject({
            proofStatementFormat: 'structured-module-sis-share-commitment-v1',
            shareVectorWidth: 220,
            statementColumns: 5680,
            statementRows: 320,
        });
        const shareCommitmentReceiverRows =
            shareCommitmentStatement.receiverRows ??
            (() => {
                throw new Error(
                    'Structured share-commitment statement should expose receiver rows.',
                );
            })();
        expect(shareCommitmentReceiverRows).toHaveLength(20);
        expect(
            shareCommitmentStatement.sourceBackendColumnIndices,
        ).toHaveLength(shareCommitmentStatement.statementColumns);
        for (const [
            receiverIndex,
            receiverRow,
        ] of shareCommitmentReceiverRows.entries()) {
            expect(receiverRow.rowCount).toBe(16);
            expect(receiverRow.rowOffsetWithinStatement).toBe(
                receiverIndex * 16,
            );
            expect(receiverRow.commitmentPolynomialVector).toHaveLength(4);
            for (const polynomial of receiverRow.commitmentPolynomialVector) {
                expect(polynomial).toHaveLength(256);
            }
        }
    });

    it('rejects mandatory-profile statement, payload, and witness shape drift', () => {
        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: fixture.publicContext,
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: {
                    ...fixture.statement,
                    optionCount: 19,
                },
            }),
        ).toThrow(/option count/u);

        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: {
                    ...fixture.publicContext,
                    receiverPayloads:
                        fixture.publicContext.receiverPayloads.map(
                            (receiverPayload, receiverPayloadIndex) =>
                                receiverPayloadIndex === 0
                                    ? {
                                          ...receiverPayload,
                                          ciphertextChunkCount: 17,
                                          ciphertextChunks:
                                              receiverPayload.ciphertextChunks?.slice(
                                                  0,
                                                  -1,
                                              ),
                                      }
                                    : receiverPayload,
                        ),
                },
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/canonical receiver payload ciphertext chunk count/u);

        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: {
                    ...fixture.projectionWitness,
                    shareCommitmentOpenings:
                        fixture.projectionWitness.shareCommitmentOpenings?.slice(
                            1,
                        ),
                },
                publicContext: fixture.publicContext,
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/Share commitment opening witness is missing/u);

        expect(() =>
            buildMandatoryRequest({
                statement: {
                    ...fixture.statement,
                    shareVectorWidth: 20,
                },
            }),
        ).toThrow(/share vector width/u);
    });

    it('rejects mandatory-profile score, one-hot, and Shamir witness drift', () => {
        expect(() =>
            buildMandatoryRequest({
                relationInput: {
                    ...fixture.relationInput,
                    normalizedScores:
                        fixture.relationInput.normalizedScores.map(
                            (score, optionIndex) =>
                                optionIndex === 0 ? 0 : score,
                        ),
                },
            }),
        ).toThrow(/score is outside the frozen score domain/u);

        expect(() =>
            buildMandatoryRequest({
                relationInput: {
                    ...fixture.relationInput,
                    normalizedScores:
                        fixture.relationInput.normalizedScores.map(
                            (score, optionIndex) =>
                                optionIndex === 1 ? 11 : score,
                        ),
                },
            }),
        ).toThrow(/score is outside the frozen score domain/u);

        expect(() =>
            buildMandatoryRequest({
                relationInput: {
                    ...fixture.relationInput,
                    scoreOneHotWitnesses:
                        fixture.relationInput.scoreOneHotWitnesses.map(
                            (oneHotWitness, optionIndex) =>
                                optionIndex === 0
                                    ? [1, 1, ...oneHotWitness.slice(2)]
                                    : oneHotWitness,
                        ),
                },
            }),
        ).toThrow(/score one-hot witness is not a valid score encoding/u);

        expect(() =>
            buildMandatoryRequest({
                relationInput: {
                    ...fixture.relationInput,
                    encodedCoordinateShamirCoefficients:
                        fixture.relationInput.encodedCoordinateShamirCoefficients.map(
                            (coefficientRow, coordinateIndex) =>
                                coordinateIndex === 0
                                    ? [...coefficientRow, 0]
                                    : coefficientRow,
                        ),
                },
            }),
        ).toThrow(/degree less than the PVSS threshold/u);

        expect(() =>
            buildMandatoryRequest({
                relationInput: {
                    ...fixture.relationInput,
                    receivers: fixture.relationInput.receivers.map(
                        (receiver, receiverIndex) =>
                            receiverIndex === 0
                                ? {
                                      ...receiver,
                                      receiverShareVector:
                                          receiver.receiverShareVector.map(
                                              (
                                                  shareRepresentative,
                                                  coordinateIndex,
                                              ) =>
                                                  coordinateIndex === 0
                                                      ? shareRepresentative + 1
                                                      : shareRepresentative,
                                          ),
                                  }
                                : receiver,
                    ),
                },
            }),
        ).toThrow(/Shamir quotient constraint is not exact/u);
    });

    it('rejects mandatory-profile public context binding drift', () => {
        for (const [fieldName, label] of [
            ['manifestDigest', 'Manifest digest'],
            ['rosterDigest', 'Roster digest'],
            ['actionContextDigest', 'Action context digest'],
            ['rosterExternalAcceptanceDigest', 'Roster acceptance digest'],
            [
                'ballotScoreEncodingProfileDigest',
                'Ballot score encoding profile digest',
            ],
            [
                'ballotShareLayoutProfileDigest',
                'Ballot share layout profile digest',
            ],
            [
                'aggregateInputEncodingProfileDigest',
                'Aggregate input encoding profile digest',
            ],
            [
                'encodedShareVectorLayoutDigest',
                'Encoded share vector layout digest',
            ],
            ['encodedAggregateLayoutDigest', 'Encoded aggregate layout digest'],
            [
                'shareCommitmentMessageBoundCertDigest',
                'Share commitment message-bound certificate digest',
            ],
        ] as const) {
            expect(() =>
                buildMandatoryRequest({
                    publicContext: {
                        ...fixture.publicContext,
                        [fieldName]: digest(`wrong-${fieldName}`),
                    },
                }),
            ).toThrow(new RegExp(label, 'u'));
        }
    });

    it('rejects mandatory-profile receiver payload, key, and commitment drift', () => {
        expect(() =>
            buildMandatoryRequest({
                publicContext: {
                    ...fixture.publicContext,
                    receiverPayloads:
                        fixture.publicContext.receiverPayloads.map(
                            (receiverPayload, receiverPayloadIndex) =>
                                receiverPayloadIndex === 0
                                    ? {
                                          ...receiverPayload,
                                          receiverPayloadDigest: digest(
                                              'wrong-receiver-payload',
                                          ),
                                      }
                                    : receiverPayload,
                        ),
                },
            }),
        ).toThrow(/Receiver payload digest/u);

        expect(() =>
            buildMandatoryRequest({
                publicContext: {
                    ...fixture.publicContext,
                    receiverPublicKeys:
                        fixture.publicContext.receiverPublicKeys.map(
                            (receiverPublicKey, receiverPublicKeyIndex) =>
                                receiverPublicKeyIndex === 0
                                    ? {
                                          ...receiverPublicKey,
                                          receiverPublicKeyDigest: digest(
                                              'wrong-receiver-public-key',
                                          ),
                                      }
                                    : receiverPublicKey,
                        ),
                },
            }),
        ).toThrow(/Receiver public-key digest/u);

        expect(() =>
            buildMandatoryRequest({
                publicContext: {
                    ...fixture.publicContext,
                    shareCommitments:
                        fixture.publicContext.shareCommitments.map(
                            (shareCommitment, shareCommitmentIndex) =>
                                shareCommitmentIndex === 0
                                    ? {
                                          ...shareCommitment,
                                          shareCommitmentDigest: digest(
                                              'wrong-share-commitment',
                                          ),
                                      }
                                    : shareCommitment,
                        ),
                },
            }),
        ).toThrow(/Share commitment digest/u);

        expect(() =>
            buildMandatoryRequest({
                statement: {
                    ...fixture.statement,
                    shareCommitments:
                        fixture.statement.shareCommitments.slice(1),
                },
            }),
        ).toThrow(/Share commitment references must match/u);
    });

    it('rejects mandatory-profile receiver ciphertext and opening-material drift', () => {
        expect(() =>
            buildMandatoryRequest({
                publicContext: {
                    ...fixture.publicContext,
                    receiverPayloads:
                        fixture.publicContext.receiverPayloads.map(
                            (receiverPayload, receiverPayloadIndex) => {
                                if (receiverPayloadIndex !== 0) {
                                    return receiverPayload;
                                }

                                return {
                                    ...receiverPayload,
                                    ciphertextChunks:
                                        receiverPayload.ciphertextChunks?.map(
                                            (
                                                ciphertextChunk,
                                                ciphertextChunkIndex,
                                            ) =>
                                                ciphertextChunkIndex === 0
                                                    ? {
                                                          ...ciphertextChunk,
                                                          secondCiphertextPolynomial:
                                                              ciphertextChunk.secondCiphertextPolynomial.map(
                                                                  (
                                                                      coefficient,
                                                                      coefficientIndex,
                                                                  ) =>
                                                                      coefficientIndex ===
                                                                      0
                                                                          ? coefficient +
                                                                            1
                                                                          : coefficient,
                                                              ),
                                                      }
                                                    : ciphertextChunk,
                                        ),
                                };
                            },
                        ),
                },
            }),
        ).toThrow(/receiver-encryption-component row .* not satisfied/u);

        expect(() =>
            buildMandatoryRequest({
                projectionWitness: {
                    ...fixture.projectionWitness,
                    receiverPayloadPlaintexts:
                        fixture.projectionWitness.receiverPayloadPlaintexts?.map(
                            (receiverPayloadPlaintext, plaintextIndex) =>
                                plaintextIndex === 0
                                    ? {
                                          ...receiverPayloadPlaintext,
                                          openingRandomness:
                                              receiverPayloadPlaintext.openingRandomness.map(
                                                  (
                                                      openingCoordinate,
                                                      openingCoordinateIndex,
                                                  ) =>
                                                      openingCoordinateIndex ===
                                                      0
                                                          ? openingCoordinate +
                                                            1
                                                          : openingCoordinate,
                                              ),
                                      }
                                    : receiverPayloadPlaintext,
                        ),
                },
            }),
        ).toThrow(/payload-plaintext-field-component row .* not satisfied/u);
    });
});
