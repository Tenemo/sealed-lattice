import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPackageCandidate,
    BallotPackageShell,
    BallotPackageWitness,
    CanonicalBallotSetInput,
    PollSpec,
    TestAggregateShare,
} from '@sealed-lattice/types';

import { derivePollSpecDigest } from '../../../src/lifecycle/poll-spec';
import { deriveFrozenRosterProfile } from '../../../src/lifecycle/thresholds';
import { deriveTestBallotPackage } from '../../../src/pvss-ballot/index';
import {
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
} from '../election-foundation-board-helpers';
import {
    ceremonyId,
    createSignature,
    getParticipantSigningPublicKeyDigest,
    manifestPolicyDigests,
} from '../election-foundation-fixture-constants';

import aggregateSharesVectorJson from '#test-vectors/pvss-ballot/aggregate-shares.json' with { type: 'json' };
import ballotAlgebraVectorJson from '#test-vectors/pvss-ballot/ballot-algebra.json' with { type: 'json' };
import canonicalBallotSetVectorJson from '#test-vectors/pvss-ballot/canonical-ballot-set.json' with { type: 'json' };
export const pollSpec = {
    pollId: 'pvss-ballot-poll',
    question: 'Select the priorities',
    options: ['Alpha', 'Beta', 'Gamma', 'Delta'],
    topOptionCount: 2,
    scoreDomain: {
        min: 1,
        max: 10,
        skippedOptionScore: 1,
    },
    duplicateBallotPolicy: 'FirstValidBeforeVotingClosedCounts',
    maxRosterSize: 50,
    minRosterSize: 10,
    rosterPolicy: 'OpenLinkPublicRoster',
    smallRosterPolicy: 'ForbidMicroRoster',
    thresholdProfileFamily: 'BalancedDefault',
    tiePolicy: 'HigherScoreThenLowerOptionIndex',
} as const satisfies PollSpec;

export const rosterEntries = Array.from(
    { length: 20 },
    (_unused, rosterIndex) => {
        const participantIdentity = `participant-${String(rosterIndex + 1)}`;

        return {
            participantIdentity,
            rosterPosition: rosterIndex + 1,
            signingPublicKeyDigest:
                getParticipantSigningPublicKeyDigest(participantIdentity),
        };
    },
);
export const pollSpecDigest = derivePollSpecDigest(pollSpec);
export const rosterDigest = deriveProtocolDigest('RosterDigest', {
    rosterEntries,
});
const frozenRosterProfile = deriveFrozenRosterProfile({
    pollSpec,
    rosterDigest,
    rosterSize: rosterEntries.length,
});
export const thresholdProfile = frozenRosterProfile.thresholdProfile;
export const thresholdProfileDigest =
    frozenRosterProfile.thresholdProfileDigest;
export const electionManifestDigest = deriveProtocolDigest(
    'ElectionManifestDigest',
    {
        ceremonyId,
        pollSpecDigest,
        rosterDigest,
        thresholdProfileDigest,
    },
);
export const closeRecordDigest = deriveProtocolDigest('CloseRecordDigest', {
    ceremonyId,
    closeKind: 'VotingClosed',
});
export const ballotAlgebraVector = ballotAlgebraVectorJson as {
    readonly ballotPackageDigest: string;
    readonly ballotPolynomialSetDigest: string;
    readonly firstReceiverPayloadDigest: string;
    readonly firstReceiverShareVector: readonly number[];
    readonly firstShareCommitmentDigest: string;
    readonly normalizedScores: readonly number[];
    readonly schemaVersion: 1;
};
export const canonicalBallotSetVector = canonicalBallotSetVectorJson as {
    readonly ballotSetDigest: string;
    readonly countedBallotPackageDigests: readonly string[];
    readonly rejectedCandidates: readonly unknown[];
    readonly schemaVersion: 1;
};
export const aggregateSharesVector = aggregateSharesVectorJson as {
    readonly ballotSetDigest: string;
    readonly firstAggregateShareCommitmentDigest: string;
    readonly firstAggregateShareVector: readonly number[];
    readonly reconstructedTally: readonly number[];
    readonly schemaVersion: 1;
};

export const createBallotWitness = (
    voterRosterPosition: number,
    scores: readonly (number | undefined)[],
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

export const createBallotSetInput = (
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

export const mutateBallotPackage = (
    ballotPackage: BallotPackageShell,
    overrides: Partial<BallotPackageShell>,
): BallotPackageShell => ({
    ...ballotPackage,
    ...overrides,
});

export const deriveBallotPackageDigestForTest = (
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

export const stripBallotPackageSignatureForTest = (
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

export const resignBallotPackageForTest = (
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

export const deriveAggregateShareCommitmentDigestForTest = (
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

export const rehashAggregateShareForTest = (
    aggregateShare: Omit<TestAggregateShare, 'aggregateShareCommitmentDigest'>,
): TestAggregateShare => ({
    ...aggregateShare,
    aggregateShareCommitmentDigest:
        deriveAggregateShareCommitmentDigestForTest(aggregateShare),
});

export const stripAggregateShareCommitmentDigestForTest = (
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

export const incrementFieldElement = (fieldElement: number): number =>
    (fieldElement + 1) % 65_537;
