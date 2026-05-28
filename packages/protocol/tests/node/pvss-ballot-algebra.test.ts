import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { BallotPackageWitness } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { derivePlaintextTopKOracle } from '../../src/plaintext-oracle/index';
import { deriveBallotPolynomialSetHash } from '../../src/pvss-ballot/ballot-polynomials';
import {
    deriveCanonicalBallotSet,
    deriveTestAggregateShares,
    reconstructAggregateTallyFromShares,
    verifyBallotPackageShell,
    verifyTestAggregateShareOpening,
    verifyTestShareCommitmentOpening,
} from '../../src/pvss-ballot/index';
import { deriveReceiverShareVectors } from '../../src/pvss-ballot/receiver-shares';

import {
    ceremonyId,
    manifestPolicyHashes,
} from './election-foundation-fixture-constants';
import {
    aggregateSharesVector,
    ballotAlgebraVector,
    canonicalBallotSetVector,
    createBallotSetInput,
    createBallotWitness,
    electionManifestHash,
    incrementFieldElement,
    mutateBallotPackage,
    pollSpec,
    pollSpecHash,
    reHashAggregateShareForTest,
    resignBallotPackageForTest,
    rosterHash,
    rosterEntries,
    stripAggregateShareCommitmentHashForTest,
    stripBallotPackageSignatureForTest,
    thresholdProfile,
    thresholdProfileHash,
} from './pvss-ballot-algebra/fixtures.js';
describe('internal PVSS ballot algebra', () => {
    it('derives deterministic receiver shares and test commitments for one ballot', () => {
        const witness = createBallotWitness(
            1,
            [10, undefined, 7],
            'vector-single',
        );

        expect(witness.polynomialSet.normalizedBallot.scores).toEqual([
            10, 1, 7, 1,
        ]);
        expect(witness.ballotPackage.ballotPackageHash).toBe(
            ballotAlgebraVector.ballotPackageHash,
        );
        expect(witness.polynomialSet.ballotPolynomialSetHash).toBe(
            ballotAlgebraVector.ballotPolynomialSetHash,
        );
        expect(witness.polynomialSet.normalizedBallot.scores).toEqual(
            ballotAlgebraVector.normalizedScores,
        );
        expect(witness.receiverShareVectors).toHaveLength(20);
        expect(witness.receiverShareVectors[0]).toMatchObject({
            receiverIdentity: 'participant-1',
            receiverRosterPosition: 1,
            optionCount: 4,
            shareVectorWidth: 20,
        });
        expect(witness.receiverShareVectors[0].shareVector.slice(4)).toEqual(
            Array.from({ length: 16 }, () => 0),
        );
        expect(witness.receiverShareVectors[0].shareVector).toEqual(
            ballotAlgebraVector.firstReceiverShareVector,
        );
        expect(
            witness.shareCommitmentWitnesses[0].commitment.shareCommitmentHash,
        ).toBe(ballotAlgebraVector.firstShareCommitmentHash);
        expect(witness.receiverPayloads[0].payloadHash).toBe(
            ballotAlgebraVector.firstReceiverPayloadHash,
        );
        expect(
            witness.shareCommitmentWitnesses.every((commitmentWitness) =>
                verifyTestShareCommitmentOpening(commitmentWitness),
            ),
        ).toBe(true);
        expect(
            verifyBallotPackageShell({
                ballotPackage: witness.ballotPackage,
                ceremonyId,
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                thresholdProfileHash,
                duplicateBallotPolicyHash:
                    manifestPolicyHashes.duplicateBallotPolicyHash,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }),
        ).toEqual([]);
    });

    it('normalizes only unset options to score one and rejects null scores', () => {
        expect(
            createBallotWitness(1, [7], 'missing-score').polynomialSet
                .normalizedBallot.scores,
        ).toEqual([7, 1, 1, 1]);
        expect(() =>
            createBallotWitness(1, [null, 2, 3, 4] as never, 'null-score'),
        ).toThrow('Scores must be integers');
    });

    it('rejects malformed test helper witnesses and hash references', () => {
        const witness = createBallotWitness(1, [1, 2, 3, 4], 'guarded');
        const commitmentWitness = witness.shareCommitmentWitnesses[0];
        const unsignedMalformedPackage = {
            ...witness.ballotPackage,
            receiverShareCommitments:
                witness.ballotPackage.receiverShareCommitments.map(
                    (commitment, commitmentIndex) =>
                        commitmentIndex === 0
                            ? {
                                  ...commitment,
                                  shareCommitmentHash: 'not-a-hash',
                              }
                            : commitment,
                ),
            receiverPayloadHashes:
                witness.ballotPackage.receiverPayloadHashes.map(
                    (payload, payloadIndex) =>
                        payloadIndex === 0
                            ? {
                                  ...payload,
                                  payloadHash: 'not-a-hash',
                              }
                            : payload,
                ),
        };
        const malformedPackage = resignBallotPackageForTest(
            stripBallotPackageSignatureForTest(unsignedMalformedPackage),
        );
        const malformedPolynomialSet = {
            ...witness.polynomialSet,
            optionPolynomials: witness.polynomialSet.optionPolynomials.map(
                (optionPolynomial, optionIndex) =>
                    optionIndex === 0
                        ? {
                              ...optionPolynomial,
                              optionOrdinal: 99,
                          }
                        : optionPolynomial,
            ),
        };
        const malformedPolynomialSetWithHash = {
            ...malformedPolynomialSet,
            ballotPolynomialSetHash: deriveBallotPolynomialSetHash({
                normalizedBallot: malformedPolynomialSet.normalizedBallot,
                optionPolynomials: malformedPolynomialSet.optionPolynomials,
                pvssThreshold: malformedPolynomialSet.pvssThreshold,
            }),
        };

        expect(() => createBallotWitness(1, [1, 2, 3, 4], '')).toThrow(
            'fixture entropy',
        );
        expect(
            verifyTestShareCommitmentOpening({
                ...commitmentWitness,
                commitment: {
                    ...commitmentWitness.commitment,
                    objectType: 'WrongCommitment' as 'TestShareCommitment',
                },
            }),
        ).toBe(false);
        expect(
            verifyTestShareCommitmentOpening({
                ...commitmentWitness,
                commitment: {
                    ...commitmentWitness.commitment,
                    shareCommitmentHash: 'not-a-hash',
                },
            }),
        ).toBe(false);
        expect(
            verifyBallotPackageShell({
                ballotPackage: malformedPackage,
                ceremonyId,
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                thresholdProfileHash,
                duplicateBallotPolicyHash:
                    manifestPolicyHashes.duplicateBallotPolicyHash,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
        expect(() =>
            deriveReceiverShareVectors({
                polynomialSet: {
                    ...witness.polynomialSet,
                    ballotPolynomialSetHash: deriveProtocolHash(
                        'BallotPolynomialSetHash',
                        { stale: true },
                    ),
                },
                rosterEntries,
                thresholdProfile,
            }),
        ).toThrow('canonical ballot polynomial set hash');
        expect(() =>
            deriveReceiverShareVectors({
                polynomialSet: malformedPolynomialSetWithHash,
                rosterEntries,
                thresholdProfile,
            }),
        ).toThrow('canonical option polynomial slots');
    });

    it('selects the first valid ballot before close and records invalid, duplicate, or late candidates', () => {
        const first = createBallotWitness(1, [1, 2, 3, 4], 'first');
        const duplicate = createBallotWitness(1, [9, 8, 7, 6], 'duplicate');
        const invalidLater = createBallotWitness(2, [4, 4, 4, 4], 'invalid');
        const late = createBallotWitness(3, [5, 5, 5, 5], 'late');
        const invalidShell = mutateBallotPackage(invalidLater.ballotPackage, {
            rosterHash: deriveProtocolHash('RosterHash', {
                marker: 'wrong-roster',
            }),
        });
        const ballotSet = deriveCanonicalBallotSet(
            createBallotSetInput(
                [
                    first,
                    duplicate,
                    {
                        ...invalidLater,
                        ballotPackage: invalidShell,
                    },
                ],
                [late],
            ),
        );

        expect(ballotSet.ok).toBe(true);
        expect(
            ballotSet.countedBallots.map(
                (candidate) => candidate.ballotPackage.ballotPackageHash,
            ),
        ).toEqual([first.ballotPackage.ballotPackageHash]);
        const duplicateRejection = ballotSet.rejectedCandidates.find(
            (candidate) =>
                candidate.ballotPackageHash ===
                duplicate.ballotPackage.ballotPackageHash,
        );
        const invalidLaterRejection = ballotSet.rejectedCandidates.find(
            (candidate) =>
                candidate.ballotPackageHash ===
                invalidLater.ballotPackage.ballotPackageHash,
        );
        const lateRejection = ballotSet.rejectedCandidates.find(
            (candidate) =>
                candidate.ballotPackageHash ===
                late.ballotPackage.ballotPackageHash,
        );

        expect(duplicateRejection?.refusalCodes).toContain(
            'DuplicateBallotPackage',
        );
        expect(invalidLaterRejection?.refusalCodes).toContain(
            'BallotPackageInvalid',
        );
        expect(lateRejection?.refusalCodes).toContain('BallotPackageInvalid');
        expect(ballotSet.ballotSetHash).toMatch(/^[a-f0-9]{128}$/u);
    });

    it('deduplicates retransmitted packages in canonical board order', () => {
        const first = createBallotWitness(1, [1, 2, 3, 4], 'first');
        const duplicate = createBallotWitness(1, [9, 8, 7, 6], 'duplicate');
        const ballotSetInput = createBallotSetInput([first, duplicate, first]);
        const shuffledBallotSetInput = {
            ...ballotSetInput,
            candidateBallots: [
                ballotSetInput.candidateBallots[2],
                ballotSetInput.candidateBallots[1],
                ballotSetInput.candidateBallots[0],
            ],
        };
        const boardOrderResult = deriveCanonicalBallotSet(ballotSetInput);
        const shuffledResult = deriveCanonicalBallotSet(shuffledBallotSetInput);

        expect(boardOrderResult.ok).toBe(true);
        expect(shuffledResult.ok).toBe(true);
        expect(
            boardOrderResult.countedBallots.map(
                (candidate) => candidate.ballotPackage.ballotPackageHash,
            ),
        ).toEqual([first.ballotPackage.ballotPackageHash]);
        expect(
            shuffledResult.countedBallots.map(
                (candidate) => candidate.ballotPackage.ballotPackageHash,
            ),
        ).toEqual([first.ballotPackage.ballotPackageHash]);
        expect(shuffledResult.ballotSetHash).toBe(
            boardOrderResult.ballotSetHash,
        );
    });

    it('rejects ballot-set inputs whose close cutoff does not match close inclusion evidence', () => {
        const witness = createBallotWitness(1, [1, 2, 3, 4], 'close-binding');
        const ballotSetInput = createBallotSetInput([witness]);
        const ballotSet = deriveCanonicalBallotSet({
            ...ballotSetInput,
            closeRecordBoardOrder: {
                boardSequence: 3,
                boardPosition: 0,
            },
        });

        expect(ballotSet.ok).toBe(false);
        expect(ballotSet.ballotSetHash).toBeUndefined();
        expect(
            ballotSet.refusedObjects.map((refusal) => refusal.code),
        ).toContain('BallotSetInvalid');
    });

    it('reconstructs aggregate shares to the plaintext oracle tally', () => {
        const witnesses = [
            createBallotWitness(1, [10, 1, 1, 1], 'vector-1'),
            createBallotWitness(2, [2, 9, 2, 2], 'vector-2'),
            createBallotWitness(3, [3, 3, 8, 3], 'vector-3'),
            createBallotWitness(4, [4, 4, 4, 7], 'vector-4'),
        ];
        const ballotSet = deriveCanonicalBallotSet(
            createBallotSetInput(witnesses),
        );
        expect(() =>
            deriveTestAggregateShares({
                ballotSet: {
                    ...ballotSet,
                    countedBallots: ballotSet.countedBallots.slice(1),
                },
                ballotWitnesses: witnesses,
                rosterEntries,
                thresholdProfile,
            }),
        ).toThrow('canonical ballot-set hash');
        const aggregateShareSet = deriveTestAggregateShares({
            ballotSet,
            ballotWitnesses: [...witnesses].reverse(),
            rosterEntries,
            thresholdProfile,
        });
        const selectedAggregateShares = aggregateShareSet.aggregateShares
            .slice(0, thresholdProfile.pvssThreshold)
            .map((witness) => witness.aggregateShare);
        const reconstructedTally = reconstructAggregateTallyFromShares({
            aggregateShares: selectedAggregateShares,
            ballotSetHash: aggregateShareSet.ballotSetHash,
            optionCount: pollSpec.options.length,
            thresholdProfile,
        });
        const plaintextOracle = derivePlaintextTopKOracle({
            ballots: witnesses.map(
                (witness) => witness.polynomialSet.normalizedBallot,
            ),
            maximumRosterSize: thresholdProfile.rosterSize,
            pollSpec,
        });

        expect(ballotSet.countedBallots).toHaveLength(witnesses.length);
        expect(ballotSet.ballotSetHash).toBe(
            canonicalBallotSetVector.ballotSetHash,
        );
        expect(
            ballotSet.countedBallots.map(
                (candidate) => candidate.ballotPackage.ballotPackageHash,
            ),
        ).toEqual(canonicalBallotSetVector.countedBallotPackageHashes);
        expect(ballotSet.rejectedCandidates).toEqual(
            canonicalBallotSetVector.rejectedCandidates,
        );
        expect(aggregateShareSet.ballotSetHash).toBe(
            aggregateSharesVector.ballotSetHash,
        );
        expect(
            aggregateShareSet.aggregateShares[0].aggregateShare
                .aggregateShareCommitmentHash,
        ).toBe(aggregateSharesVector.firstAggregateShareCommitmentHash);
        expect(
            aggregateShareSet.aggregateShares[0].aggregateShare
                .aggregateShareVector,
        ).toEqual(aggregateSharesVector.firstAggregateShareVector);
        expect(
            aggregateShareSet.aggregateShares.every((witness) =>
                verifyTestAggregateShareOpening(witness),
            ),
        ).toBe(true);
        expect(reconstructedTally).toEqual(
            plaintextOracle.tally.tallyFieldElements,
        );
        expect(reconstructedTally).toEqual(
            aggregateSharesVector.reconstructedTally,
        );
        expect(() =>
            reconstructAggregateTallyFromShares({
                aggregateShares: selectedAggregateShares.slice(
                    0,
                    thresholdProfile.pvssThreshold - 1,
                ),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('exactly');
        expect(
            verifyTestAggregateShareOpening({
                ...aggregateShareSet.aggregateShares[0],
                aggregateOpeningVector: [
                    Number.NaN,
                    ...aggregateShareSet.aggregateShares[0].aggregateOpeningVector.slice(
                        1,
                    ),
                ],
            }),
        ).toBe(false);
        expect(() =>
            reconstructAggregateTallyFromShares({
                aggregateShares: selectedAggregateShares.map(
                    (aggregateShare, aggregateShareIndex) => {
                        if (aggregateShareIndex !== 0) {
                            return aggregateShare;
                        }
                        return reHashAggregateShareForTest({
                            ...stripAggregateShareCommitmentHashForTest(
                                aggregateShare,
                            ),
                            trusteeRosterPosition: 999,
                        });
                    },
                ),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('within the frozen roster');
        expect(() =>
            reconstructAggregateTallyFromShares({
                aggregateShares: selectedAggregateShares,
                ballotSetHash: deriveProtocolHash('BallotSetHash', {
                    marker: 'wrong-ballot-set',
                }),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('expected ballot set');
        expect(() =>
            reconstructAggregateTallyFromShares({
                aggregateShares: selectedAggregateShares.map(
                    (aggregateShare, aggregateShareIndex) => {
                        if (aggregateShareIndex !== 0) {
                            return aggregateShare;
                        }
                        return reHashAggregateShareForTest({
                            ...stripAggregateShareCommitmentHashForTest(
                                aggregateShare,
                            ),
                            ballotSetHash: deriveProtocolHash('BallotSetHash', {
                                marker: 'mixed-ballot-set',
                            }),
                        });
                    },
                ),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('same ballot set');
        expect(() =>
            reconstructAggregateTallyFromShares({
                aggregateShares: selectedAggregateShares.map(
                    (aggregateShare, aggregateShareIndex) => {
                        if (aggregateShareIndex !== 0) {
                            return aggregateShare;
                        }
                        return reHashAggregateShareForTest({
                            ...stripAggregateShareCommitmentHashForTest(
                                aggregateShare,
                            ),
                            aggregateShareVector:
                                aggregateShare.aggregateShareVector.map(
                                    (fieldElement, fieldIndex) =>
                                        fieldIndex === pollSpec.options.length
                                            ? incrementFieldElement(
                                                  fieldElement,
                                              )
                                            : fieldElement,
                                ),
                        });
                    },
                ),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('zero-padded');
        expect(() =>
            reconstructAggregateTallyFromShares({
                aggregateShares: selectedAggregateShares.map(
                    (aggregateShare, aggregateShareIndex) =>
                        aggregateShareIndex === 0
                            ? {
                                  ...aggregateShare,
                                  aggregateShareCommitmentHash:
                                      deriveProtocolHash(
                                          'AggregateShareCommitmentHash',
                                          { marker: 'stale' },
                                      ),
                              }
                            : aggregateShare,
                ),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('canonical aggregate share commitment');
    });

    it('rejects aggregate witnesses whose private shares no longer match the counted package', () => {
        const witnesses = [
            createBallotWitness(1, [10, 1, 1, 1], 'vector-1'),
            createBallotWitness(2, [2, 9, 2, 2], 'vector-2'),
            createBallotWitness(3, [3, 3, 8, 3], 'vector-3'),
            createBallotWitness(4, [4, 4, 4, 7], 'vector-4'),
        ];
        const ballotSet = deriveCanonicalBallotSet(
            createBallotSetInput(witnesses),
        );
        const firstWitness = witnesses[0];
        const mutatedShareVector =
            firstWitness.receiverShareVectors[0].shareVector.map(
                (fieldElement, fieldIndex) =>
                    fieldIndex === 0
                        ? incrementFieldElement(fieldElement)
                        : fieldElement,
            );
        const mutatedCommitmentValues =
            firstWitness.shareCommitmentWitnesses[0].commitment.commitmentValues.map(
                (fieldElement, fieldIndex) =>
                    fieldIndex === 0
                        ? incrementFieldElement(fieldElement)
                        : fieldElement,
            );
        const mutatedWitness: BallotPackageWitness = {
            ...firstWitness,
            receiverShareVectors: firstWitness.receiverShareVectors.map(
                (receiverShareVector, receiverIndex) =>
                    receiverIndex === 0
                        ? {
                              ...receiverShareVector,
                              shareVector: mutatedShareVector,
                          }
                        : receiverShareVector,
            ),
            shareCommitmentWitnesses: firstWitness.shareCommitmentWitnesses.map(
                (commitmentWitness, receiverIndex) =>
                    receiverIndex === 0
                        ? {
                              ...commitmentWitness,
                              shareVector: mutatedShareVector,
                              commitment: {
                                  ...commitmentWitness.commitment,
                                  commitmentValues: mutatedCommitmentValues,
                              },
                          }
                        : commitmentWitness,
            ),
        };

        expect(
            verifyTestShareCommitmentOpening(
                mutatedWitness.shareCommitmentWitnesses[0],
            ),
        ).toBe(true);
        expect(() =>
            deriveTestAggregateShares({
                ballotSet,
                ballotWitnesses: [mutatedWitness, ...witnesses.slice(1)],
                rosterEntries,
                thresholdProfile,
            }),
        ).toThrow('Counted ballot witness');
    });

    it('rejects wrong package context, receiver order, and score shape', () => {
        const witness = createBallotWitness(1, [1, 2, 3, 4], 'negative');

        expect(() => createBallotWitness(1, [0, 2, 3, 4], 'bad-score')).toThrow(
            'Scores must be integers',
        );
        expect(
            verifyBallotPackageShell({
                ballotPackage: mutateBallotPackage(witness.ballotPackage, {
                    optionCount: 5,
                }),
                ceremonyId,
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                thresholdProfileHash,
                duplicateBallotPolicyHash:
                    manifestPolicyHashes.duplicateBallotPolicyHash,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
        expect(
            verifyBallotPackageShell({
                ballotPackage: mutateBallotPackage(witness.ballotPackage, {
                    receiverShareCommitments: [
                        ...witness.ballotPackage.receiverShareCommitments,
                    ].reverse(),
                }),
                ceremonyId,
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                thresholdProfileHash,
                duplicateBallotPolicyHash:
                    manifestPolicyHashes.duplicateBallotPolicyHash,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
        expect(
            verifyBallotPackageShell({
                ballotPackage: witness.ballotPackage,
                ceremonyId,
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                thresholdProfileHash,
                duplicateBallotPolicyHash:
                    manifestPolicyHashes.duplicateBallotPolicyHash,
                optionCount: pollSpec.options.length,
                rosterEntries: rosterEntries.map(
                    ({ participantIdentity, rosterPosition }) => ({
                        participantIdentity,
                        rosterPosition,
                    }),
                ),
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
    });
});
