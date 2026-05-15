import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPackageCandidate,
    BallotPackageShell,
    BallotPackageWitness,
    CanonicalBallotSetInput,
    PollSpec,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import aggregateSharesVectorJson from '../../../../test-vectors/pvss-ballot/aggregate-shares.json' with { type: 'json' };
import ballotAlgebraVectorJson from '../../../../test-vectors/pvss-ballot/ballot-algebra.json' with { type: 'json' };
import canonicalBallotSetVectorJson from '../../../../test-vectors/pvss-ballot/canonical-ballot-set.json' with { type: 'json' };
import { deriveThresholdProfile } from '../../src/lifecycle/thresholds';
import { derivePlaintextTopKOracle } from '../../src/plaintext-oracle/index';
import {
    deriveCanonicalBallotSet,
    deriveTestAggregateShares,
    deriveTestBallotPackage,
    reconstructAggregateTallyFromShares,
    verifyBallotPackageShell,
    verifyTestAggregateShareOpening,
    verifyTestShareCommitmentOpening,
} from '../../src/pvss-ballot/index';

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
    tiePolicy: 'HigherScoreThenLowerOptionIndex',
} as const satisfies PollSpec;

const thresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const rosterEntries = Array.from({ length: 20 }, (_unused, rosterIndex) => {
    const participantIdentity = `participant-${String(rosterIndex + 1)}`;

    return {
        participantIdentity,
        rosterPosition: rosterIndex + 1,
        signingPublicKeyDigest:
            getParticipantSigningPublicKeyDigest(participantIdentity),
    };
});
const pollSpecDigest = deriveProtocolDigest('PollSpecDigest', {
    duplicateBallotPolicy: pollSpec.duplicateBallotPolicy,
    options: pollSpec.options,
    pollId: pollSpec.pollId,
    question: pollSpec.question,
    scoreDomain: pollSpec.scoreDomain,
    tiePolicy: pollSpec.tiePolicy,
    topOptionCount: pollSpec.topOptionCount,
});
const thresholdProfileDigest = deriveProtocolDigest(
    'ThresholdProfileDigest',
    thresholdProfile,
);
const rosterDigest = deriveProtocolDigest('RosterDigest', { rosterEntries });
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
    const closeHead = createBoardHeadWithObjects(
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
    ).head;
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
            trusteeIdentity: 'participant-1',
            trusteeRosterPosition: 1,
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
        const aggregateShareSet = deriveTestAggregateShares({
            ballotSet,
            ballotWitnesses: [...witnesses].reverse(),
            rosterEntries,
            thresholdProfile,
        });
        const reconstructedTally = reconstructAggregateTallyFromShares({
            aggregateShares: aggregateShareSet.aggregateShares
                .slice(0, thresholdProfile.pvssThreshold)
                .map((witness) => witness.aggregateShare),
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
                aggregateShares: aggregateShareSet.aggregateShares
                    .slice(0, thresholdProfile.pvssThreshold - 1)
                    .map((witness) => witness.aggregateShare),
                optionCount: pollSpec.options.length,
                thresholdProfile,
            }),
        ).toThrow('exactly');
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
    });
});
