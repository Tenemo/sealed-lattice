// This file is one targeted part of the split test suite.
import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    hash,
    explicitReceiverEncryptionFixture,
    publicContext,
    shareCommitmentModulus,
    shareCommitmentOpeningForReceiver,
    minimumOptionRelationInput,
    validRelationInput,
} from './shared.js';

import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentProofStatementDescriptors,
    verifyBallotProofComponentExplicitRows,
    type BallotProofComponentProjectionWitness,
} from '#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement';
import { deriveShareCommitmentBodyHash } from '#packages/protocol/src/ballot-privacy/lattice-primitives';
import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '#packages/protocol/src/ballot-privacy/relation-backend-lowering';

describe('ballot privacy relation backend lowering', () => {
    it('builds component proof statement descriptors for sparse and structured proof paths', () => {
        const relationInput = minimumOptionRelationInput();
        const { context } = explicitReceiverEncryptionFixture(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const componentBundle = buildBallotProofComponentBundleStatement({
            ballotProofStatementHash: context.ballotProofStatementHash,
            loweredStatement: loweringResult.statement,
        });
        const descriptors = buildBallotProofComponentProofStatementDescriptors({
            ballotProofStatementHash: context.ballotProofStatementHash,
            componentBundleStatement: componentBundle,
            loweredStatement: loweringResult.statement,
        });

        expect(descriptors.map((descriptor) => descriptor.componentId)).toEqual(
            ballotPrivacyBackendProofComponentOrder,
        );
        expect(descriptors[0]).toMatchObject({
            denseCoefficientCount: '788480',
            proofBackendRequirement: 'dense-proof-bytes-available-lab-only',
            proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
            rowBatchTermCounts: ['306'],
            sourceRingDegree: 64,
        });
        expect(descriptors[1]).toMatchObject({
            proofBackendRequirement: 'sparse-proof-statement-required',
            proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
            rowBatchTermCounts: ['516', '3684'],
            sparseTermCount: '4200',
        });
        expect(descriptors[2]).toMatchObject({
            proofBackendRequirement: 'sparse-proof-statement-required',
            proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
            rowBatchTermCounts: ['264192'],
            sparseTermCount: '264192',
        });
        expect(descriptors[3]).toMatchObject({
            proofBackendRequirement: 'structured-proof-statement-required',
            proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
            rowBatchTermCounts: ['19683426'],
            structuredCiphertextChunkCount: 15,
            structuredReceiverCount: 3,
            structuredWitnessTermCount: '19683426',
        });
        expect(descriptors[4]).toMatchObject({
            denseCoefficientCount: null,
            proofBackendRequirement: 'public-binding-check-only',
            proofStatementFormat: 'public-binding-check-only-v1',
            rowBatchTermCounts: ['0'],
            sourceRingDegree: null,
            variableColumnCount: 0,
        });
        expect(
            descriptors.every((descriptor) =>
                /^[a-f0-9]{128}$/u.test(descriptor.componentProofStatementHash),
            ),
        ).toBe(true);
        expect(JSON.stringify(descriptors)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('binds public share commitment vectors into explicit backend targets', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const firstResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });
        const firstCommitment = context.shareCommitments[0];
        const changedCommitmentPolynomialVector =
            firstCommitment?.commitmentPolynomialVector?.map(
                (commitmentPolynomial, polynomialIndex) =>
                    commitmentPolynomial.map((coefficient, coefficientIndex) =>
                        polynomialIndex === 0 && coefficientIndex === 0
                            ? (
                                  (BigInt(coefficient) + 1n) %
                                  shareCommitmentModulus
                              ).toString()
                            : coefficient,
                    ),
            );
        if (
            firstCommitment === undefined ||
            changedCommitmentPolynomialVector === undefined
        ) {
            throw new Error('Missing share commitment vector for mutation.');
        }
        const changedContext: BallotPrivacyRelationBackendPublicContext = {
            ...context,
            shareCommitments: context.shareCommitments.map((shareCommitment) =>
                shareCommitment.receiverRosterPosition === 1
                    ? {
                          ...shareCommitment,
                          commitmentBodyHash: deriveShareCommitmentBodyHash({
                              commitmentPolynomialVector:
                                  changedCommitmentPolynomialVector,
                              shareCommitmentProfileHash:
                                  context.shareCommitmentProfileHash,
                          }),
                          commitmentPolynomialVector:
                              changedCommitmentPolynomialVector,
                          commitmentPolynomialVectorHash: deriveProtocolHash(
                              'ChallengeDomainHash',
                              {
                                  commitmentPolynomialVector:
                                      changedCommitmentPolynomialVector,
                                  purpose:
                                      'ballot-privacy-test-share-commitment-polynomial-vector',
                              },
                          ),
                      }
                    : shareCommitment,
            ),
        };
        const secondResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: changedContext,
            relationInput,
        });

        expect(firstResult.ok).toBe(true);
        expect(secondResult.ok).toBe(true);
        if (!firstResult.ok || !secondResult.ok) {
            throw new Error('valid relation inputs should lower');
        }
        expect(firstResult.statement.relationStatementHash).not.toBe(
            secondResult.statement.relationStatementHash,
        );
        expect(
            firstResult.statement.backendStatement.rowBatches[2]
                ?.targetVectorHash,
        ).not.toBe(
            secondResult.statement.backendStatement.rowBatches[2]
                ?.targetVectorHash,
        );
    });

    it('does not let a reused public commitment satisfy another receiver opening', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const firstCommitment = context.shareCommitments[0];
        if (firstCommitment?.commitmentPolynomialVector === undefined) {
            throw new Error('Missing first commitment vector.');
        }
        const firstCommitmentPolynomialVector =
            firstCommitment.commitmentPolynomialVector;
        const reusedCommitmentContext: BallotPrivacyRelationBackendPublicContext =
            {
                ...context,
                shareCommitments: context.shareCommitments.map(
                    (shareCommitment) =>
                        shareCommitment.receiverRosterPosition === 2
                            ? {
                                  ...shareCommitment,
                                  commitmentBodyHash:
                                      deriveShareCommitmentBodyHash({
                                          commitmentPolynomialVector:
                                              firstCommitmentPolynomialVector,
                                          shareCommitmentProfileHash:
                                              context.shareCommitmentProfileHash,
                                      }),
                                  commitmentPolynomialVector:
                                      firstCommitmentPolynomialVector,
                                  commitmentPolynomialVectorHash:
                                      deriveProtocolHash(
                                          'ChallengeDomainHash',
                                          {
                                              commitmentPolynomialVector:
                                                  firstCommitmentPolynomialVector,
                                              purpose:
                                                  'ballot-privacy-test-share-commitment-polynomial-vector',
                                          },
                                      ),
                              }
                            : shareCommitment,
                ),
            };
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: reusedCommitmentContext,
            relationInput,
        });

        expect(result.ok).toBe(true);
        if (!result.ok) {
            throw new Error('relation with public commitment mutation lowers');
        }
        const shareCommitmentRowBatch =
            result.statement.backendStatement.rowBatches[2];
        if (shareCommitmentRowBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected share commitment rows to be explicit.');
        }
        const reusedReceiverRow = shareCommitmentRowBatch.rows.find(
            (row) =>
                row.rowName ===
                'receiver_2_share_commitment_vector_0_coefficient_0_equation',
        );
        if (reusedReceiverRow === undefined) {
            throw new Error('Missing reused receiver commitment row.');
        }
        const secondReceiver = relationInput.receivers[1];
        const witnessValues = new Map<string, bigint>();
        secondReceiver?.receiverShareVector.forEach(
            (shareRepresentative, encodedCoordinateIndex) => {
                witnessValues.set(
                    `receiver_2_encoded_coordinate_${encodedCoordinateIndex}_share`,
                    BigInt(shareRepresentative),
                );
            },
        );
        shareCommitmentOpeningForReceiver(2).forEach(
            (openingCoordinate, openingCoordinateIndex) => {
                witnessValues.set(
                    `receiver_2_share_commitment_opening_coordinate_${openingCoordinateIndex}`,
                    BigInt(openingCoordinate),
                );
            },
        );
        const evaluatedValue = reusedReceiverRow.terms.reduce(
            (accumulatedValue, term) =>
                (accumulatedValue +
                    BigInt(term.coefficient) *
                        (witnessValues.get(term.variableName) ?? 0n)) %
                shareCommitmentModulus,
            0n,
        );

        expect(
            (evaluatedValue + shareCommitmentModulus) % shareCommitmentModulus,
        ).not.toBe(BigInt(reusedReceiverRow.target));
    });

    it('lowers receiver encryption and receiver-key bindings into explicit backend rows', () => {
        const relationInput = minimumOptionRelationInput();
        const { context, projectionWitness: explicitProjectionWitness } =
            explicitReceiverEncryptionFixture(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid explicit relation input should lower');
        }

        const shareVectorWidth = relationInput.optionCount * 11;
        expect(loweringResult.statement.linearRows).toHaveLength(
            2 +
                relationInput.optionCount +
                3 * shareVectorWidth +
                3 * (shareVectorWidth + 64) +
                3 * (shareVectorWidth + 64),
        );
        expect(loweringResult.statement.backendStatement).toMatchObject({
            hashExpandedRowCount: 0,
            explicitRowCount:
                70 + 3 * 86 + 3 * 86 + 3 * 1_024 + 3 * 6_400 + 3 * 1_024,
            rowCount: 70 + 3 * 86 + 3 * 86 + 3 * 1_024 + 3 * 6_400 + 3 * 1_024,
        });
        expect(
            loweringResult.statement.backendStatement.rowBatches.map(
                (rowBatch) => rowBatch.batchName,
            ),
        ).toEqual([
            'encoded_score_field_rows',
            'receiver_payload_plaintext_binding_rows',
            'receiver_payload_plaintext_bit_decomposition_rows',
            'share_commitment_equation_rows',
            'receiver_payload_encryption_equation_rows',
            'receiver_key_binding_rows',
        ]);
        expect(
            loweringResult.statement.backendStatement.proofComponents.map(
                (component) => ({
                    componentId: component.componentId,
                    proofLoweringStatus: component.proofLoweringStatus,
                }),
            ),
        ).toEqual([
            {
                componentId: 'score-and-shamir-field-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'payload-plaintext-field-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'share-commitment-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'receiver-encryption-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'receiver-key-binding-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
        ]);

        const componentBundle = buildBallotProofComponentBundleStatement({
            ballotProofStatementHash: context.ballotProofStatementHash,
            loweredStatement: loweringResult.statement,
        });
        expect(componentBundle.bundleCoverage).toBe(
            'full-encoded-score-ballot-relation',
        );
        expect(
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: loweringResult.statement,
                projectionWitness: explicitProjectionWitness,
                relationInput,
            }),
        ).toMatchObject({
            checkedRowBatchNames: ['receiver_payload_encryption_equation_rows'],
            componentId: 'receiver-encryption-component',
            rowCount: 3 * 6_400,
            verificationStatus: 'explicitRowsSatisfied',
        });
        expect(
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-key-binding-component',
                loweredStatement: loweringResult.statement,
                projectionWitness: explicitProjectionWitness,
                relationInput,
            }),
        ).toMatchObject({
            checkedRowBatchNames: ['receiver_key_binding_rows'],
            componentId: 'receiver-key-binding-component',
            rowCount: 3 * 1_024,
            verificationStatus: 'explicitRowsSatisfied',
        });
        const payloadBitDecompositionRowBatch =
            loweringResult.statement.backendStatement.rowBatches.find(
                (rowBatch) =>
                    rowBatch.batchName ===
                    'receiver_payload_plaintext_bit_decomposition_rows',
            );
        expect(payloadBitDecompositionRowBatch).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 3 * 86,
            rowKind: 'ReceiverPayloadPlaintextBitDecompositionRows',
        });
        expect(loweringResult.statement.backendStatement.bounds).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    boundKind: 'Boolean',
                    boundName: 'receiver_payload_plaintext_bits_boolean',
                }),
                expect.objectContaining({
                    absoluteMaximum: '2',
                    boundName:
                        'receiver_encryption_first_noise_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: '2',
                    boundName:
                        'receiver_encryption_second_noise_certified_absolute_bound',
                }),
            ]),
        );
    });

    it('rejects explicit receiver-encryption rows when ciphertext or encrypted opening material changes', () => {
        const relationInput = minimumOptionRelationInput();
        const { context, projectionWitness: explicitProjectionWitness } =
            explicitReceiverEncryptionFixture(relationInput);
        const firstLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: context,
                relationInput,
            });

        expect(firstLoweringResult.ok).toBe(true);
        if (!firstLoweringResult.ok) {
            throw new Error('valid explicit relation input should lower');
        }

        const changedCiphertextContext: BallotPrivacyRelationBackendPublicContext =
            {
                ...context,
                receiverPayloads: context.receiverPayloads.map(
                    (receiverPayload) =>
                        receiverPayload.receiverRosterPosition === 1
                            ? {
                                  ...receiverPayload,
                                  ciphertextChunks:
                                      receiverPayload.ciphertextChunks?.map(
                                          (ciphertextChunk) =>
                                              ciphertextChunk.chunkIndex === 0
                                                  ? {
                                                        ...ciphertextChunk,
                                                        firstCiphertextVector:
                                                            ciphertextChunk.firstCiphertextVector.map(
                                                                (
                                                                    polynomial,
                                                                    vectorIndex,
                                                                ) =>
                                                                    vectorIndex ===
                                                                    0
                                                                        ? polynomial.map(
                                                                              (
                                                                                  coefficient,
                                                                                  coefficientIndex,
                                                                              ) =>
                                                                                  coefficientIndex ===
                                                                                  0
                                                                                      ? (coefficient +
                                                                                            1) %
                                                                                        12_289
                                                                                      : coefficient,
                                                                          )
                                                                        : polynomial,
                                                            ),
                                                    }
                                                  : ciphertextChunk,
                                      ),
                              }
                            : receiverPayload,
                ),
            };
        const changedCiphertextLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: changedCiphertextContext,
                relationInput,
            });

        expect(changedCiphertextLoweringResult.ok).toBe(true);
        if (!changedCiphertextLoweringResult.ok) {
            throw new Error('mutated public ciphertext should still lower');
        }
        expect(() =>
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: changedCiphertextLoweringResult.statement,
                projectionWitness: explicitProjectionWitness,
                relationInput,
            }),
        ).toThrow(/receiver-encryption-component row/u);

        const wrongOpeningProjectionWitness: BallotProofComponentProjectionWitness =
            {
                ...explicitProjectionWitness,
                receiverPayloadPlaintexts:
                    explicitProjectionWitness.receiverPayloadPlaintexts?.map(
                        (plaintext) =>
                            plaintext.receiverRosterPosition === 1
                                ? {
                                      ...plaintext,
                                      openingRandomness:
                                          plaintext.openingRandomness.map(
                                              (
                                                  openingCoordinate,
                                                  openingCoordinateIndex,
                                              ) =>
                                                  openingCoordinateIndex === 0
                                                      ? openingCoordinate + 1
                                                      : openingCoordinate,
                                          ),
                                  }
                                : plaintext,
                    ),
            };
        expect(() =>
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: firstLoweringResult.statement,
                projectionWitness: wrongOpeningProjectionWitness,
                relationInput,
            }),
        ).toThrow(/receiver-encryption-component row/u);

        const wrongRandomnessProjectionWitness: BallotProofComponentProjectionWitness =
            {
                ...explicitProjectionWitness,
                receiverEncryptionWitnesses:
                    explicitProjectionWitness.receiverEncryptionWitnesses?.map(
                        (receiverWitness) =>
                            receiverWitness.receiverRosterPosition === 1
                                ? {
                                      ...receiverWitness,
                                      chunkWitnesses:
                                          receiverWitness.chunkWitnesses.map(
                                              (chunkWitness) =>
                                                  chunkWitness.chunkIndex === 0
                                                      ? {
                                                            ...chunkWitness,
                                                            encryptionRandomnessVector:
                                                                chunkWitness.encryptionRandomnessVector.map(
                                                                    (
                                                                        polynomial,
                                                                        vectorIndex,
                                                                    ) =>
                                                                        vectorIndex ===
                                                                        0
                                                                            ? polynomial.map(
                                                                                  (
                                                                                      coefficient,
                                                                                      coefficientIndex,
                                                                                  ) =>
                                                                                      coefficientIndex ===
                                                                                      0
                                                                                          ? coefficient +
                                                                                            1
                                                                                          : coefficient,
                                                                              )
                                                                            : polynomial,
                                                                ),
                                                        }
                                                      : chunkWitness,
                                          ),
                                  }
                                : receiverWitness,
                    ),
            };
        expect(() =>
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: firstLoweringResult.statement,
                projectionWitness: wrongRandomnessProjectionWitness,
                relationInput,
            }),
        ).toThrow(/receiver-encryption-component row/u);
    });

    it('binds every public context hash into the relation statement hash', () => {
        const firstResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: validRelationInput(),
        });
        const changedContext = {
            ...publicContext(),
            actionContextHash: hash('changed-action-context'),
        };
        const secondResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: changedContext,
            relationInput: validRelationInput(),
        });

        expect(firstResult.ok).toBe(true);
        expect(secondResult.ok).toBe(true);
        if (!firstResult.ok || !secondResult.ok) {
            throw new Error('Expected both relation lowerings to succeed.');
        }
        expect(firstResult.statement.relationStatementHash).not.toBe(
            secondResult.statement.relationStatementHash,
        );
    });

    it('keeps hostile compiler inputs as relation refusals before lowering', () => {
        const wrongShareInput = validRelationInput();
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: {
                ...wrongShareInput,
                receivers: wrongShareInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 2
                        ? {
                              ...receiver,
                              receiverShareVector:
                                  receiver.receiverShareVector.map(
                                      (shareRepresentative, coordinateIndex) =>
                                          coordinateIndex === 0
                                              ? shareRepresentative + 1
                                              : shareRepresentative,
                                  ),
                          }
                        : receiver,
                ),
            },
        });

        expect(result).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPrivacyRelationInvalid',
        });
        if (result.ok) {
            throw new Error('Expected hostile relation input to be refused.');
        }
        expect(
            result.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'Shamir quotient constraint is not exact',
                ),
            ),
        ).toBe(true);
    });
});
