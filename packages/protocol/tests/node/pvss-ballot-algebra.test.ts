import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPackageCandidate,
    BallotPackageShell,
    BallotPackageWitness,
    CanonicalBallotSetInput,
    PollSpec,
    TestAggregateShare,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { derivePollSpecDigest } from '../../src/lifecycle/poll-spec';
import { deriveFrozenRosterProfile } from '../../src/lifecycle/thresholds';
import { derivePlaintextTopKOracle } from '../../src/plaintext-oracle/index';
import { deriveBallotPolynomialSetDigest } from '../../src/pvss-ballot/ballot-polynomials';
import {
    deriveCanonicalBallotSet,
    deriveTestAggregateShares,
    deriveTestBallotPackage,
    reconstructAggregateTallyFromShares,
    verifyBallotPackageShell,
    verifyTestAggregateShareOpening,
    verifyTestShareCommitmentOpening,
} from '../../src/pvss-ballot/index';
import { deriveReceiverShareVectors } from '../../src/pvss-ballot/receiver-shares';

import {
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
} from './election-foundation-board-helpers';
import {
    ceremonyId,
    getParticipantSigningPublicKeyDigest,
    manifestPolicyDigests,
    createSignature,
} from './election-foundation-fixture-constants';

import aggregateSharesVectorJson from '#test-vectors/pvss-ballot/aggregate-shares.json' with { type: 'json' };
import ballotAlgebraVectorJson from '#test-vectors/pvss-ballot/ballot-algebra.json' with { type: 'json' };
import canonicalBallotSetVectorJson from '#test-vectors/pvss-ballot/canonical-ballot-set.json' with { type: 'json' };

const pollSpec = {
    pollId: 'pvss-ballot-poll',
    question: 'Select the priorities',
    options: ['Alpha', 'Beta', 'Gamma', 'Delta'],
    topOptionCount: 2,
    scoreDomain: {
        min: 1,
        max: 10,
        skippedOptionScore: 1,
    },
    duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
    maxRosterSize: 50,
    minRosterSize: 10,
    rosterPolicy: 'OpenLinkPublicRoster',
    smallRosterPolicy: 'ForbidMicroRoster',
    thresholdProfileFamily: 'BalancedDefault',
    tiePolicy: 'HigherScoreThenLowerOptionIndex',
} as const satisfies PollSpec;

const rosterEntries = Array.from({ length: 20 }, (_unused, rosterIndex) => {
    const participantIdentity = `participant-${String(rosterIndex + 1)}`;

    return {
        participantIdentity,
        rosterPosition: rosterIndex + 1,
        signingPublicKeyDigest:
            getParticipantSigningPublicKeyDigest(participantIdentity),
    };
});
const pollSpecDigest = derivePollSpecDigest(pollSpec);
const rosterDigest = deriveProtocolDigest('RosterDigest', { rosterEntries });
const frozenRosterProfile = deriveFrozenRosterProfile({
    pollSpec,
    rosterDigest,
    rosterSize: rosterEntries.length,
});
const thresholdProfile = frozenRosterProfile.thresholdProfile;
const thresholdProfileDigest = frozenRosterProfile.thresholdProfileDigest;
const electionManifestDigest = deriveProtocolDigest('ElectionManifestDigest', {
    ceremonyId,
    pollSpecDigest,
    rosterDigest,
    thresholdProfileDigest,
});
const closeRecordDigest = deriveProtocolDigest('CloseRecordDigest', {
    ceremonyId,
    closeKind: 'VotingClosed',
});
const ballotAlgebraVector = ballotAlgebraVectorJson as {
    readonly ballotPackageDigest: string;
    readonly ballotPolynomialSetDigest: string;
    readonly firstReceiverPayloadDigest: string;
    readonly firstReceiverShareVector: readonly number[];
    readonly firstShareCommitmentDigest: string;
    readonly normalizedScores: readonly number[];
    readonly schemaVersion: 1;
};
const canonicalBallotSetVector = canonicalBallotSetVectorJson as {
    readonly ballotSetDigest: string;
    readonly countedBallotPackageDigests: readonly string[];
    readonly rejectedCandidates: readonly unknown[];
    readonly schemaVersion: 1;
};
const aggregateSharesVector = aggregateSharesVectorJson as {
    readonly ballotSetDigest: string;
    readonly firstAggregateShareCommitmentDigest: string;
    readonly firstAggregateShareVector: readonly number[];
    readonly reconstructedTally: readonly number[];
    readonly schemaVersion: 1;
};

const createBallotWitness = (
    voterRosterPosition: number,
    scores: readonly (number | null | undefined)[],
    fixtureEntropy = `entropy-${String(voterRosterPosition)}`,
): BallotPackageWitness => {
    const voterIdentity = `participant-${String(voterRosterPosition)}`;
    const publicKeyDigest = getParticipantSigningPublicKeyDigest(voterIdentity);

    return deriveTestBallotPackage(
        {
            ceremonyId,
            voterIdentity,
            voterRosterPosition,
            electionManifestDigest,
            rosterDigest,
            pollSpecDigest,
            duplicateBallotPolicyDigest:
                manifestPolicyDigests.duplicateBallotPolicyDigest,
            thresholdProfileDigest,
            pollSpec,
            thresholdProfile,
            rosterEntries,
            scoreBallot: {
                voterIdentity,
                scores,
            },
            fixtureEntropy,
        },
        (ballotPackageDigest) =>
            createSignature(
                'BallotPackage',
                'Voter',
                voterIdentity,
                publicKeyDigest,
                ballotPackageDigest,
                {
                    manifestDigest: electionManifestDigest,
                    boardHeadDigest: null,
                },
            ),
    );
};

const createBallotSetInput = (
    witnesses: readonly BallotPackageWitness[],
    afterCloseWitnesses: readonly BallotPackageWitness[] = [],
): CanonicalBallotSetInput => {
    const genesisHead = createBoardHead(0, null, 'vector-genesis');
    const ballotHeadWithProofs = createBoardHeadWithObjects(
        1,
        genesisHead.headDigest,
        witnesses.map((witness, boardPosition) => ({
            objectType: 'BallotPackage' as const,
            objectDigest: witness.ballotPackage.ballotPackageDigest,
            boardPosition,
        })),
        'vector-ballots',
    );
    const closeHeadWithProofs = createBoardHeadWithObjects(
        2,
        ballotHeadWithProofs.head.headDigest,
        [
            {
                objectType: 'CloseRecord' as const,
                objectDigest: closeRecordDigest,
                boardPosition: 0,
            },
        ],
        'vector-close',
    );
    const closeHead = closeHeadWithProofs.head;
    const lateHeadWithProofs = createBoardHeadWithObjects(
        3,
        closeHead.headDigest,
        afterCloseWitnesses.map((witness, boardPosition) => ({
            objectType: 'BallotPackage' as const,
            objectDigest: witness.ballotPackage.ballotPackageDigest,
            boardPosition,
        })),
        'vector-late',
    );
    const candidateBallots: BallotPackageCandidate[] = [
        ...witnesses.map((witness, witnessIndex) => ({
            ballotPackage: witness.ballotPackage,
            inclusionProof: ballotHeadWithProofs.inclusionProofs[witnessIndex],
        })),
        ...afterCloseWitnesses.map((witness, witnessIndex) => ({
            ballotPackage: witness.ballotPackage,
            inclusionProof: lateHeadWithProofs.inclusionProofs[witnessIndex],
        })),
    ];

    return {
        boardEvidence: createBoardEvidence([
            genesisHead,
            ballotHeadWithProofs.head,
            closeHead,
            lateHeadWithProofs.head,
        ]),
        ceremonyId,
        electionManifestDigest,
        rosterDigest,
        pollSpecDigest,
        thresholdProfileDigest,
        duplicateBallotPolicyDigest:
            manifestPolicyDigests.duplicateBallotPolicyDigest,
        pollSpec,
        thresholdProfile,
        rosterEntries,
        votingClosedBoardHeadDigest: closeHead.headDigest,
        closeRecordDigest,
        closeRecordBoardOrder: {
            boardSequence: 2,
            boardPosition: 0,
        },
        closeRecordInclusionProof: closeHeadWithProofs.inclusionProofs[0],
        candidateBallots,
        includeRejectedCandidateSummariesInDigest: true,
    };
};

const mutateBallotPackage = (
    ballotPackage: BallotPackageShell,
    overrides: Partial<BallotPackageShell>,
): BallotPackageShell => ({
    ...ballotPackage,
    ...overrides,
});

const deriveBallotPackageDigestForTest = (
    ballotPackage: Omit<
        BallotPackageShell,
        'ballotPackageDigest' | 'signature'
    >,
): string =>
    deriveProtocolDigest('BallotPackageDigest', {
        ballotPolynomialSetDigest: ballotPackage.ballotPolynomialSetDigest,
        ceremonyId: ballotPackage.ceremonyId,
        duplicateBallotPolicyDigest: ballotPackage.duplicateBallotPolicyDigest,
        electionManifestDigest: ballotPackage.electionManifestDigest,
        objectType: ballotPackage.objectType,
        objectVersion: ballotPackage.objectVersion,
        optionCount: ballotPackage.optionCount,
        pollSpecDigest: ballotPackage.pollSpecDigest,
        receiverPayloadDigests: ballotPackage.receiverPayloadDigests,
        receiverShareCommitments: ballotPackage.receiverShareCommitments,
        rosterDigest: ballotPackage.rosterDigest,
        shareVectorWidth: ballotPackage.shareVectorWidth,
        thresholdProfileDigest: ballotPackage.thresholdProfileDigest,
        voterIdentity: ballotPackage.voterIdentity,
        voterRosterPosition: ballotPackage.voterRosterPosition,
    });

const stripBallotPackageSignatureForTest = (
    ballotPackage: BallotPackageShell,
): Omit<BallotPackageShell, 'ballotPackageDigest' | 'signature'> => ({
    objectType: ballotPackage.objectType,
    objectVersion: ballotPackage.objectVersion,
    ceremonyId: ballotPackage.ceremonyId,
    electionManifestDigest: ballotPackage.electionManifestDigest,
    rosterDigest: ballotPackage.rosterDigest,
    pollSpecDigest: ballotPackage.pollSpecDigest,
    thresholdProfileDigest: ballotPackage.thresholdProfileDigest,
    duplicateBallotPolicyDigest: ballotPackage.duplicateBallotPolicyDigest,
    voterIdentity: ballotPackage.voterIdentity,
    voterRosterPosition: ballotPackage.voterRosterPosition,
    optionCount: ballotPackage.optionCount,
    shareVectorWidth: ballotPackage.shareVectorWidth,
    ballotPolynomialSetDigest: ballotPackage.ballotPolynomialSetDigest,
    receiverShareCommitments: ballotPackage.receiverShareCommitments,
    receiverPayloadDigests: ballotPackage.receiverPayloadDigests,
});

const resignBallotPackageForTest = (
    ballotPackage: Omit<
        BallotPackageShell,
        'ballotPackageDigest' | 'signature'
    >,
): BallotPackageShell => {
    const ballotPackageDigest = deriveBallotPackageDigestForTest(ballotPackage);

    return {
        ...ballotPackage,
        ballotPackageDigest,
        signature: createSignature(
            'BallotPackage',
            'Voter',
            ballotPackage.voterIdentity,
            getParticipantSigningPublicKeyDigest(ballotPackage.voterIdentity),
            ballotPackageDigest,
            {
                manifestDigest: ballotPackage.electionManifestDigest,
                boardHeadDigest: null,
            },
        ),
    };
};

const deriveAggregateShareCommitmentDigestForTest = (
    aggregateShare: Omit<TestAggregateShare, 'aggregateShareCommitmentDigest'>,
): string =>
    deriveProtocolDigest('AggregateShareCommitmentDigest', {
        aggregateCommitmentValues: aggregateShare.aggregateCommitmentValues,
        aggregateShareVector: aggregateShare.aggregateShareVector,
        ballotSetDigest: aggregateShare.ballotSetDigest,
        objectType: aggregateShare.objectType,
        shareVectorWidth: aggregateShare.shareVectorWidth,
        trusteeIdentity: aggregateShare.trusteeIdentity,
        trusteeRosterPosition: aggregateShare.trusteeRosterPosition,
    });

const rehashAggregateShareForTest = (
    aggregateShare: Omit<TestAggregateShare, 'aggregateShareCommitmentDigest'>,
): TestAggregateShare => ({
    ...aggregateShare,
    aggregateShareCommitmentDigest:
        deriveAggregateShareCommitmentDigestForTest(aggregateShare),
});

const stripAggregateShareCommitmentDigestForTest = (
    aggregateShare: TestAggregateShare,
): Omit<TestAggregateShare, 'aggregateShareCommitmentDigest'> => ({
    objectType: aggregateShare.objectType,
    ballotSetDigest: aggregateShare.ballotSetDigest,
    trusteeIdentity: aggregateShare.trusteeIdentity,
    trusteeRosterPosition: aggregateShare.trusteeRosterPosition,
    shareVectorWidth: aggregateShare.shareVectorWidth,
    aggregateShareVector: aggregateShare.aggregateShareVector,
    aggregateCommitmentValues: aggregateShare.aggregateCommitmentValues,
});

const incrementFieldElement = (fieldElement: number): number =>
    (fieldElement + 1) % 65_537;

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
        expect(witness.ballotPackage.ballotPackageDigest).toBe(
            ballotAlgebraVector.ballotPackageDigest,
        );
        expect(witness.polynomialSet.ballotPolynomialSetDigest).toBe(
            ballotAlgebraVector.ballotPolynomialSetDigest,
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
            witness.shareCommitmentWitnesses[0].commitment
                .shareCommitmentDigest,
        ).toBe(ballotAlgebraVector.firstShareCommitmentDigest);
        expect(witness.receiverPayloads[0].payloadDigest).toBe(
            ballotAlgebraVector.firstReceiverPayloadDigest,
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
                electionManifestDigest,
                rosterDigest,
                pollSpecDigest,
                thresholdProfileDigest,
                duplicateBallotPolicyDigest:
                    manifestPolicyDigests.duplicateBallotPolicyDigest,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }),
        ).toEqual([]);
    });

    it('rejects malformed test helper witnesses and digest references', () => {
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
                                  shareCommitmentDigest: 'not-a-digest',
                              }
                            : commitment,
                ),
            receiverPayloadDigests:
                witness.ballotPackage.receiverPayloadDigests.map(
                    (payload, payloadIndex) =>
                        payloadIndex === 0
                            ? {
                                  ...payload,
                                  payloadDigest: 'not-a-digest',
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
        const malformedPolynomialSetWithDigest = {
            ...malformedPolynomialSet,
            ballotPolynomialSetDigest: deriveBallotPolynomialSetDigest({
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
                    shareCommitmentDigest: 'not-a-digest',
                },
            }),
        ).toBe(false);
        expect(
            verifyBallotPackageShell({
                ballotPackage: malformedPackage,
                ceremonyId,
                electionManifestDigest,
                rosterDigest,
                pollSpecDigest,
                thresholdProfileDigest,
                duplicateBallotPolicyDigest:
                    manifestPolicyDigests.duplicateBallotPolicyDigest,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
        expect(() =>
            deriveReceiverShareVectors({
                polynomialSet: {
                    ...witness.polynomialSet,
                    ballotPolynomialSetDigest: deriveProtocolDigest(
                        'BallotPolynomialSetDigest',
                        { stale: true },
                    ),
                },
                rosterEntries,
                thresholdProfile,
            }),
        ).toThrow('canonical ballot polynomial set digest');
        expect(() =>
            deriveReceiverShareVectors({
                polynomialSet: malformedPolynomialSetWithDigest,
                rosterEntries,
                thresholdProfile,
            }),
        ).toThrow('canonical option polynomial slots');
    });

    it('selects the last valid ballot before close and records invalid or late candidates', () => {
        const first = createBallotWitness(1, [1, 2, 3, 4], 'first');
        const replacement = createBallotWitness(1, [9, 8, 7, 6], 'replacement');
        const invalidLater = createBallotWitness(2, [4, 4, 4, 4], 'invalid');
        const late = createBallotWitness(3, [5, 5, 5, 5], 'late');
        const invalidShell = mutateBallotPackage(invalidLater.ballotPackage, {
            rosterDigest: deriveProtocolDigest('RosterDigest', {
                marker: 'wrong-roster',
            }),
        });
        const ballotSet = deriveCanonicalBallotSet(
            createBallotSetInput(
                [
                    first,
                    replacement,
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
                (candidate) => candidate.ballotPackage.ballotPackageDigest,
            ),
        ).toEqual([replacement.ballotPackage.ballotPackageDigest]);
        const invalidLaterRejection = ballotSet.rejectedCandidates.find(
            (candidate) =>
                candidate.ballotPackageDigest ===
                invalidLater.ballotPackage.ballotPackageDigest,
        );
        const lateRejection = ballotSet.rejectedCandidates.find(
            (candidate) =>
                candidate.ballotPackageDigest ===
                late.ballotPackage.ballotPackageDigest,
        );

        expect(invalidLaterRejection?.refusalCodes).toContain(
            'BallotPackageInvalid',
        );
        expect(lateRejection?.refusalCodes).toContain('BallotPackageInvalid');
        expect(ballotSet.ballotSetDigest).toMatch(/^[a-f0-9]{128}$/u);
    });

    it('deduplicates retransmitted packages in canonical board order', () => {
        const first = createBallotWitness(1, [1, 2, 3, 4], 'first');
        const replacement = createBallotWitness(1, [9, 8, 7, 6], 'replacement');
        const ballotSetInput = createBallotSetInput([
            first,
            replacement,
            first,
        ]);
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
                (candidate) => candidate.ballotPackage.ballotPackageDigest,
            ),
        ).toEqual([replacement.ballotPackage.ballotPackageDigest]);
        expect(
            shuffledResult.countedBallots.map(
                (candidate) => candidate.ballotPackage.ballotPackageDigest,
            ),
        ).toEqual([replacement.ballotPackage.ballotPackageDigest]);
        expect(shuffledResult.ballotSetDigest).toBe(
            boardOrderResult.ballotSetDigest,
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
        expect(ballotSet.ballotSetDigest).toBeUndefined();
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
        ).toThrow('canonical ballot-set digest');
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
            ballotSetDigest: aggregateShareSet.ballotSetDigest,
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
        expect(ballotSet.ballotSetDigest).toBe(
            canonicalBallotSetVector.ballotSetDigest,
        );
        expect(
            ballotSet.countedBallots.map(
                (candidate) => candidate.ballotPackage.ballotPackageDigest,
            ),
        ).toEqual(canonicalBallotSetVector.countedBallotPackageDigests);
        expect(ballotSet.rejectedCandidates).toEqual(
            canonicalBallotSetVector.rejectedCandidates,
        );
        expect(aggregateShareSet.ballotSetDigest).toBe(
            aggregateSharesVector.ballotSetDigest,
        );
        expect(
            aggregateShareSet.aggregateShares[0].aggregateShare
                .aggregateShareCommitmentDigest,
        ).toBe(aggregateSharesVector.firstAggregateShareCommitmentDigest);
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
                        return rehashAggregateShareForTest({
                            ...stripAggregateShareCommitmentDigestForTest(
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
                ballotSetDigest: deriveProtocolDigest('BallotSetDigest', {
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
                        return rehashAggregateShareForTest({
                            ...stripAggregateShareCommitmentDigestForTest(
                                aggregateShare,
                            ),
                            ballotSetDigest: deriveProtocolDigest(
                                'BallotSetDigest',
                                { marker: 'mixed-ballot-set' },
                            ),
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
                        return rehashAggregateShareForTest({
                            ...stripAggregateShareCommitmentDigestForTest(
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
                                  aggregateShareCommitmentDigest:
                                      deriveProtocolDigest(
                                          'AggregateShareCommitmentDigest',
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
                electionManifestDigest,
                rosterDigest,
                pollSpecDigest,
                thresholdProfileDigest,
                duplicateBallotPolicyDigest:
                    manifestPolicyDigests.duplicateBallotPolicyDigest,
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
                electionManifestDigest,
                rosterDigest,
                pollSpecDigest,
                thresholdProfileDigest,
                duplicateBallotPolicyDigest:
                    manifestPolicyDigests.duplicateBallotPolicyDigest,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
        expect(
            verifyBallotPackageShell({
                ballotPackage: witness.ballotPackage,
                ceremonyId,
                electionManifestDigest,
                rosterDigest,
                pollSpecDigest,
                thresholdProfileDigest,
                duplicateBallotPolicyDigest:
                    manifestPolicyDigests.duplicateBallotPolicyDigest,
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
