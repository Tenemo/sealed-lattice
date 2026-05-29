// This file is one targeted part of the split test suite.
import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    explicitReceiverEncryptionFixture,
    projectionWitness,
    publicContext,
    receiverEncryptionModuleRank,
    shareCommitmentModulus,
    shareCommitmentOpeningForReceiver,
    minimumOptionRelationInput,
    validRelationInput,
} from './shared.js';

import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentLinearProofProjection,
    buildBallotProofSparseComponentLinearProofStatement,
    buildBallotProofStructuredReceiverEncryptionProofStatement,
} from '#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement';
import { deriveShareCommitmentBodyHash } from '#packages/protocol/src/ballot-privacy/lattice-primitives';
import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '#packages/protocol/src/ballot-privacy/relation-backend-lowering';

describe('ballot privacy relation backend lowering', () => {
    it('projects receiver payload plaintext binding rows into an explicit component statement', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const projection = buildBallotProofComponentLinearProofProjection({
            ballotProofStatementHash: context.ballotProofStatementHash,
            componentId: 'payload-plaintext-field-component',
            loweredStatement: loweringResult.statement,
            parameterProfileId:
                'payload-plaintext-field-linear-proof-parameter-v1',
            projectionWitness: projectionWitness(relationInput),
            relationInput,
            sourceRingDegree: 1,
            witnessL2BoundSquared: '65536',
        });

        expect(projection.sourceRowBatchNames).toEqual([
            'receiver_payload_plaintext_binding_rows',
        ]);
        expect(projection.linearStatement).toMatchObject({
            coefficientModulus: '65537',
            projectionCoverage: 'payload-plaintext-field-rows-only',
            ringDegree: 1,
            statementColumns: 516,
            statementRows: 258,
        });
        expect(projection.privateWitnessVectorCoefficients).toHaveLength(516);
        expect(projection.linearStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );

        const wrongPayloadOpeningWitness = {
            ...projectionWitness(relationInput),
            receiverPayloadPlaintexts: relationInput.receivers.map(
                (receiver) => ({
                    openingRandomness: shareCommitmentOpeningForReceiver(
                        receiver.receiverRosterPosition,
                    ).map((openingCoordinate, openingCoordinateIndex) =>
                        receiver.receiverRosterPosition === 1 &&
                        openingCoordinateIndex === 0
                            ? openingCoordinate + 1
                            : openingCoordinate,
                    ),
                    receiverRosterPosition: receiver.receiverRosterPosition,
                    receiverShareVector: receiver.receiverShareVector,
                }),
            ),
        };
        expect(() =>
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementHash: context.ballotProofStatementHash,
                componentId: 'payload-plaintext-field-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    'payload-plaintext-field-linear-proof-parameter-v1',
                projectionWitness: wrongPayloadOpeningWitness,
                relationInput,
                sourceRingDegree: 1,
                witnessL2BoundSquared: '65536',
            }),
        ).toThrow(/payload-plaintext-field-component row/u);
    });

    it('projects share commitment rows with BigInt-safe decimal coefficients', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const projection = buildBallotProofComponentLinearProofProjection({
            ballotProofStatementHash: context.ballotProofStatementHash,
            componentId: 'share-commitment-component',
            loweredStatement: loweringResult.statement,
            parameterProfileId: 'share-commitment-linear-proof-parameter-v1',
            projectionWitness: projectionWitness(relationInput),
            relationInput,
            sourceRingDegree: 1,
            witnessL2BoundSquared: '1048576',
        });

        expect(projection.sourceRowBatchNames).toEqual([
            'share_commitment_equation_rows',
        ]);
        expect(projection.linearStatement).toMatchObject({
            coefficientModulus: '18446744069414584321',
            projectionCoverage: 'share-commitment-rows-only',
            ringDegree: 1,
            statementColumns: 258,
            statementRows: 3_072,
        });
        expect(
            typeof projection.linearStatement
                .statementMatrixCoefficients[0]?.[0]?.[0],
        ).toBe('string');
        expect(
            typeof projection.linearStatement.targetVectorCoefficients[0]?.[0],
        ).toBe('string');
        expect(projection.linearStatement.statementHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(projection.privateWitnessVectorCoefficients).toHaveLength(258);
        expect(projection.linearStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );

        const wrongCommitmentOpeningWitness = {
            ...projectionWitness(relationInput),
            shareCommitmentOpenings: relationInput.receivers.map(
                (receiver) => ({
                    openingRandomness: shareCommitmentOpeningForReceiver(
                        receiver.receiverRosterPosition,
                    ).map((openingCoordinate, openingCoordinateIndex) =>
                        receiver.receiverRosterPosition === 1 &&
                        openingCoordinateIndex === 0
                            ? openingCoordinate + 1
                            : openingCoordinate,
                    ),
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        };
        expect(() =>
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementHash: context.ballotProofStatementHash,
                componentId: 'share-commitment-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    'share-commitment-linear-proof-parameter-v1',
                projectionWitness: wrongCommitmentOpeningWitness,
                relationInput,
                sourceRingDegree: 1,
                witnessL2BoundSquared: '1048576',
            }),
        ).toThrow(/share-commitment-component row/u);
    });

    it('refuses a share commitment projection when commitment polynomial vectors are hash-expanded', () => {
        const relationInput = validRelationInput();
        const contextWithExplicitCommitments = publicContext(relationInput);
        const contextWithHashExpandedCommitments = {
            ...contextWithExplicitCommitments,
            shareCommitments:
                contextWithExplicitCommitments.shareCommitments.map(
                    (shareCommitment) => ({
                        commitmentBodyHash: shareCommitment.commitmentBodyHash,
                        commitmentPolynomialVectorHash:
                            shareCommitment.commitmentPolynomialVectorHash,
                        receiverIdentity: shareCommitment.receiverIdentity,
                        receiverRosterPosition:
                            shareCommitment.receiverRosterPosition,
                        shareCommitmentHash:
                            shareCommitment.shareCommitmentHash,
                    }),
                ),
        };
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: contextWithHashExpandedCommitments,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        expect(() =>
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementHash:
                    contextWithHashExpandedCommitments.ballotProofStatementHash,
                componentId: 'share-commitment-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    'share-commitment-linear-proof-parameter-v1',
                projectionWitness: projectionWitness(relationInput),
                relationInput,
                sourceRingDegree: 1,
                witnessL2BoundSquared: '1048576',
            }),
        ).toThrow(/not fully lowered to explicit rows/u);
    });

    it('builds compact sparse component statements without dense matrices or witnesses', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const payloadStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementHash: context.ballotProofStatementHash,
                componentId: 'payload-plaintext-field-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId: 'payload-plaintext-field-linear-sparse-v1',
                sourceRingDegree: 64,
                witnessL2BoundSquared: '65536',
            });
        const shareCommitmentStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementHash: context.ballotProofStatementHash,
                componentId: 'share-commitment-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId: 'share-commitment-linear-sparse-v1',
                sourceRingDegree: 256,
                witnessL2BoundSquared: '1048576',
            });
        if (
            payloadStatement.proofStatementFormat !==
                'sparse-polynomial-matrix-linear-proof-v1' ||
            shareCommitmentStatement.proofStatementFormat !==
                'sparse-polynomial-matrix-linear-proof-v1'
        ) {
            throw new Error('Expected sparse component proof statements.');
        }
        const shareCommitmentRowBatch =
            loweringResult.statement.backendStatement.rowBatches.find(
                (rowBatch) =>
                    rowBatch.batchName === 'share_commitment_equation_rows',
            );
        if (shareCommitmentRowBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected explicit share commitment rows.');
        }
        const expectedShareTermCount = shareCommitmentRowBatch.rows.reduce(
            (termCount, row) => termCount + row.terms.length,
            0,
        );

        expect(payloadStatement).toMatchObject({
            coefficientModulus: '65537',
            objectType: 'BallotProofSparseComponentLinearProofStatement',
            proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
            projectionCoverage: 'payload-plaintext-field-rows-only',
            sourceRingDegree: 64,
            sparseStatementTermCount: '516',
            statementColumns: 516,
            statementRows: 258,
            targetVectorEntryCount: '0',
        });
        expect(shareCommitmentStatement).toMatchObject({
            coefficientModulus: '18446744069414584321',
            projectionCoverage: 'share-commitment-rows-only',
            sourceRingDegree: 256,
            sparseStatementTermCount: expectedShareTermCount.toString(),
            statementColumns: 258,
            statementRows: 3_072,
        });
        expect(
            shareCommitmentStatement.targetVectorEntries.length,
        ).toBeGreaterThan(0);
        expect(shareCommitmentStatement.statementHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(shareCommitmentStatement).not.toHaveProperty(
            'statementMatrixCoefficients',
        );
        expect(payloadStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );
        expect(
            JSON.stringify([payloadStatement, shareCommitmentStatement]),
        ).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('builds structured receiver-encryption proof statements with public Module-LWE material', () => {
        const relationInput = minimumOptionRelationInput();
        const { context } = explicitReceiverEncryptionFixture(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error(
                'valid explicit receiver-encryption input should lower',
            );
        }

        const bundleStatement = buildBallotProofComponentBundleStatement({
            ballotProofStatementHash: context.ballotProofStatementHash,
            loweredStatement: loweringResult.statement,
        });
        const receiverEncryptionComponentStatement =
            bundleStatement.componentStatements.find(
                (componentStatement) =>
                    componentStatement.componentId ===
                    'receiver-encryption-component',
            );
        if (receiverEncryptionComponentStatement === undefined) {
            throw new Error(
                'Receiver-encryption component statement is missing.',
            );
        }
        const structuredStatement =
            buildBallotProofStructuredReceiverEncryptionProofStatement({
                ballotProofStatementHash: context.ballotProofStatementHash,
                componentStatement: receiverEncryptionComponentStatement,
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    'receiver-encryption-structured-linear-proof-v1',
                witnessL2BoundSquared: '8192',
            });

        expect(structuredStatement).toMatchObject({
            coefficientModulus: '12289',
            componentId: 'receiver-encryption-component',
            objectType: 'BallotProofStructuredReceiverEncryptionProofStatement',
            proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
            proofSystemRingDegree: 64,
            sourceRingDegree: 256,
            statementColumns: 3 * 5 * 10,
            statementRows: 3 * 5 * 5,
        });
        expect(structuredStatement.receiverRows).toHaveLength(3);
        expect(
            structuredStatement.receiverRows[0]?.ciphertextChunks,
        ).toHaveLength(5);
        expect(
            structuredStatement.receiverRows[0]?.ciphertextChunks[0]
                ?.randomnessPolynomialColumnIndices,
        ).toHaveLength(receiverEncryptionModuleRank);
        expect(
            structuredStatement.receiverRows[0]?.ciphertextChunks[0]
                ?.firstNoisePolynomialColumnIndices,
        ).toHaveLength(receiverEncryptionModuleRank);
        expect(
            structuredStatement.receiverRows[0]?.ciphertextChunks[0]
                ?.plaintextPolynomialColumnIndex,
        ).toEqual(expect.any(Number));
        expect(structuredStatement.statementHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(JSON.stringify(structuredStatement)).not.toMatch(
            /encryptionRandomnessVector|firstNoiseVector|secondNoisePolynomial|receiverShareVector/u,
        );

        const changedContext: BallotPrivacyRelationBackendPublicContext = {
            ...context,
            receiverPayloads: context.receiverPayloads.map((receiverPayload) =>
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
                                                            vectorIndex === 0
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
        const changedLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: changedContext,
                relationInput,
            });
        expect(changedLoweringResult.ok).toBe(true);
        if (!changedLoweringResult.ok) {
            throw new Error('changed receiver-encryption input should lower');
        }
        const changedBundleStatement = buildBallotProofComponentBundleStatement(
            {
                ballotProofStatementHash:
                    changedContext.ballotProofStatementHash,
                loweredStatement: changedLoweringResult.statement,
            },
        );
        const changedComponentStatement =
            changedBundleStatement.componentStatements.find(
                (componentStatement) =>
                    componentStatement.componentId ===
                    'receiver-encryption-component',
            );
        if (changedComponentStatement === undefined) {
            throw new Error(
                'Changed receiver-encryption component statement is missing.',
            );
        }
        const changedStructuredStatement =
            buildBallotProofStructuredReceiverEncryptionProofStatement({
                ballotProofStatementHash:
                    changedContext.ballotProofStatementHash,
                componentStatement: changedComponentStatement,
                loweredStatement: changedLoweringResult.statement,
                parameterProfileId:
                    'receiver-encryption-structured-linear-proof-v1',
                witnessL2BoundSquared: '8192',
            });

        expect(changedStructuredStatement.statementHash).not.toBe(
            structuredStatement.statementHash,
        );
    });

    it('binds sparse share-commitment statement Hashes to public targets', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
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
        const originalLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: context,
                relationInput,
            });
        const changedLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: changedContext,
                relationInput,
            });

        expect(originalLoweringResult.ok).toBe(true);
        expect(changedLoweringResult.ok).toBe(true);
        if (!originalLoweringResult.ok || !changedLoweringResult.ok) {
            throw new Error('valid relation inputs should lower');
        }

        const originalStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementHash: context.ballotProofStatementHash,
                componentId: 'share-commitment-component',
                loweredStatement: originalLoweringResult.statement,
                parameterProfileId: 'share-commitment-linear-sparse-v1',
                sourceRingDegree: 256,
                witnessL2BoundSquared: '1048576',
            });
        const changedStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementHash:
                    changedContext.ballotProofStatementHash,
                componentId: 'share-commitment-component',
                loweredStatement: changedLoweringResult.statement,
                parameterProfileId: 'share-commitment-linear-sparse-v1',
                sourceRingDegree: 256,
                witnessL2BoundSquared: '1048576',
            });

        if (
            originalStatement.proofStatementFormat !==
                'sparse-polynomial-matrix-linear-proof-v1' ||
            changedStatement.proofStatementFormat !==
                'sparse-polynomial-matrix-linear-proof-v1'
        ) {
            throw new Error('Expected sparse share-commitment statements.');
        }

        expect(originalStatement.sparseStatementMatrixHash).toBe(
            changedStatement.sparseStatementMatrixHash,
        );
        expect(originalStatement.targetVectorHash).not.toBe(
            changedStatement.targetVectorHash,
        );
        expect(originalStatement.statementHash).not.toBe(
            changedStatement.statementHash,
        );
    });

    it('builds an ordered component bundle statement for the full ballot relation', () => {
        const context = publicContext();
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput: validRelationInput(),
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const componentBundle = buildBallotProofComponentBundleStatement({
            ballotProofStatementHash: context.ballotProofStatementHash,
            loweredStatement: loweringResult.statement,
        });

        expect(componentBundle).toMatchObject({
            backendStatementHash:
                loweringResult.statement.backendStatement.backendStatementHash,
            ballotProofStatementHash: context.ballotProofStatementHash,
            bundleCoverage: 'component-bundle-incomplete',
            objectType: 'BallotProofComponentBundleStatement',
            objectVersion: 1,
            relationLabel: 'BallotPrivacyPvssRelation',
            relationStatementHash:
                loweringResult.statement.relationStatementHash,
            requiredComponentIds: ballotPrivacyBackendProofComponentOrder,
        });
        expect(componentBundle.componentBundleStatementHash).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(componentBundle.componentStatements).toHaveLength(5);
        expect(
            componentBundle.componentStatements.map(
                (componentStatement) => componentStatement.componentId,
            ),
        ).toEqual(ballotPrivacyBackendProofComponentOrder);
        expect(componentBundle.componentStatements[0]).toMatchObject({
            coefficientModulus: '65537',
            componentId: 'score-and-shamir-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['encoded_score_field_rows'],
            rowCount: 70,
            rowKinds: ['EncodedScoreFieldRows'],
            variableColumnCount: 176,
        });
        expect(componentBundle.componentStatements[1]).toMatchObject({
            coefficientModulus: '65537',
            componentId: 'payload-plaintext-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['receiver_payload_plaintext_binding_rows'],
            rowCount: 258,
            rowKinds: ['ReceiverPayloadPlaintextBindingRows'],
            variableColumnCount: 516,
        });
        expect(componentBundle.componentStatements[2]).toMatchObject({
            coefficientModulus: '18446744069414584321',
            componentId: 'share-commitment-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['share_commitment_equation_rows'],
            rowCount: 3_072,
            rowKinds: ['ShareCommitmentEquationRows'],
            variableColumnCount: 258,
        });
        expect(
            componentBundle.componentStatements
                .slice(3)
                .every(
                    (componentStatement) =>
                        componentStatement.proofLoweringStatus ===
                        'HashExpandedRowsPending',
                ),
        ).toBe(true);
        expect(
            componentBundle.componentStatements.every(
                (componentStatement) =>
                    /^[a-f0-9]{128}$/u.exec(
                        componentStatement.componentStatementHash,
                    ) !== null &&
                    componentStatement.rowBatchMatrixHashes.length ===
                        componentStatement.rowBatchNames.length &&
                    componentStatement.rowBatchTargetVectorHashes.length ===
                        componentStatement.rowBatchNames.length,
            ),
        ).toBe(true);
        expect(JSON.stringify(componentBundle)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });
});
