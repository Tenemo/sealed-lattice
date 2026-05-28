import { beforeAll, describe, expect, it } from 'vitest';

import { buildBallotProofRecordGenerationRequest } from '../../../src/ballot-privacy/ballot-proof-linear-statement';
import { lowerBallotPrivacyRelationToBackendStatement } from '../../../src/ballot-privacy/relation-backend-lowering';
import {
    type BallotProofRecordGenerationFixture,
    createMandatoryProfileBallotProofRecordGenerationFixture,
} from '../ballot-privacy-proof-record-generation-fixtures';

import {
    hash,
    fieldProofStatement,
    mandatoryProfileFixtureTimeoutMs,
    receiverEncryptionProofStatement,
    shareCommitmentProofStatement,
} from './helpers.js';
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
            ['manifestHash', 'Manifest hash'],
            ['rosterHash', 'Roster hash'],
            ['actionContextHash', 'Action context hash'],
            ['rosterExternalAcceptanceHash', 'Roster acceptance hash'],
            [
                'ballotScoreEncodingProfileHash',
                'Ballot score encoding profile hash',
            ],
            [
                'ballotShareLayoutProfileHash',
                'Ballot share layout profile hash',
            ],
            [
                'aggregateInputEncodingProfileHash',
                'Aggregate input encoding profile hash',
            ],
            [
                'encodedShareVectorLayoutHash',
                'Encoded share vector layout hash',
            ],
            ['encodedAggregateLayoutHash', 'Encoded aggregate layout hash'],
            [
                'shareCommitmentMessageBoundCertHash',
                'Share commitment message-bound certificate hash',
            ],
        ] as const) {
            expect(() =>
                buildMandatoryRequest({
                    publicContext: {
                        ...fixture.publicContext,
                        [fieldName]: hash(`wrong-${fieldName}`),
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
                                          receiverPayloadHash: hash(
                                              'wrong-receiver-payload',
                                          ),
                                      }
                                    : receiverPayload,
                        ),
                },
            }),
        ).toThrow(/Receiver payload hash/u);

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
                                          receiverPublicKeyHash: hash(
                                              'wrong-receiver-public-key',
                                          ),
                                      }
                                    : receiverPublicKey,
                        ),
                },
            }),
        ).toThrow(/Receiver public-key hash/u);

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
                                          shareCommitmentHash: hash(
                                              'wrong-share-commitment',
                                          ),
                                      }
                                    : shareCommitment,
                        ),
                },
            }),
        ).toThrow(/Share commitment hash/u);

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
