import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotPackageCandidate,
    BallotPackageShell,
    BallotPackageWitness,
    CanonicalBallotSetInput,
    PollSpec,
    TestAggregateShare,
} from '@sealed-lattice/types';

import {
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
} from '../election-foundation-board-helpers';
import {
    ceremonyId,
    createSignature,
    getParticipantSigningPublicKeyHash,
    manifestPolicyHashes,
} from '../election-foundation-fixture-constants';

import { derivePollSpecHash } from '#packages/protocol/src/lifecycle/poll-spec';
import { deriveFrozenRosterProfile } from '#packages/protocol/src/lifecycle/thresholds';
import { deriveTestBallotPackage } from '#packages/protocol/src/pvss-ballot/index';
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
            signingPublicKeyHash:
                getParticipantSigningPublicKeyHash(participantIdentity),
        };
    },
);
export const pollSpecHash = derivePollSpecHash(pollSpec);
export const rosterHash = deriveProtocolHash('RosterHash', {
    rosterEntries,
});
const frozenRosterProfile = deriveFrozenRosterProfile({
    pollSpec,
    rosterHash,
    rosterSize: rosterEntries.length,
});
export const thresholdProfile = frozenRosterProfile.thresholdProfile;
export const thresholdProfileHash = frozenRosterProfile.thresholdProfileHash;
export const electionManifestHash = deriveProtocolHash('ElectionManifestHash', {
    ceremonyId,
    pollSpecHash,
    rosterHash,
    thresholdProfileHash,
});
export const closeRecordHash = deriveProtocolHash('CloseRecordHash', {
    ceremonyId,
    closeKind: 'VotingClosed',
});
export const ballotAlgebraVector = ballotAlgebraVectorJson as {
    readonly ballotPackageHash: string;
    readonly ballotPolynomialSetHash: string;
    readonly firstReceiverPayloadHash: string;
    readonly firstReceiverShareVector: readonly number[];
    readonly firstShareCommitmentHash: string;
    readonly normalizedScores: readonly number[];
    readonly schemaVersion: 1;
};
export const canonicalBallotSetVector = canonicalBallotSetVectorJson as {
    readonly ballotSetHash: string;
    readonly countedBallotPackageHashes: readonly string[];
    readonly rejectedCandidates: readonly unknown[];
    readonly schemaVersion: 1;
};
export const aggregateSharesVector = aggregateSharesVectorJson as {
    readonly ballotSetHash: string;
    readonly firstAggregateShareCommitmentHash: string;
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
    const publicKeyHash = getParticipantSigningPublicKeyHash(voterIdentity);

    return deriveTestBallotPackage(
        {
            ceremonyId,
            voterIdentity,
            voterRosterPosition,
            electionManifestHash,
            rosterHash,
            pollSpecHash,
            duplicateBallotPolicyHash:
                manifestPolicyHashes.duplicateBallotPolicyHash,
            thresholdProfileHash,
            pollSpec,
            thresholdProfile,
            rosterEntries,
            scoreBallot: {
                voterIdentity,
                scores,
            },
            fixtureEntropy,
        },
        (ballotPackageHash) =>
            createSignature(
                'BallotPackage',
                'Voter',
                voterIdentity,
                publicKeyHash,
                ballotPackageHash,
                {
                    manifestHash: electionManifestHash,
                    boardHeadHash: null,
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
        genesisHead.headHash,
        witnesses.map((witness, boardPosition) => ({
            objectType: 'BallotPackage' as const,
            objectHash: witness.ballotPackage.ballotPackageHash,
            boardPosition,
        })),
        'vector-ballots',
    );
    const closeHeadWithProofs = createBoardHeadWithObjects(
        2,
        ballotHeadWithProofs.head.headHash,
        [
            {
                objectType: 'CloseRecord' as const,
                objectHash: closeRecordHash,
                boardPosition: 0,
            },
        ],
        'vector-close',
    );
    const closeHead = closeHeadWithProofs.head;
    const lateHeadWithProofs = createBoardHeadWithObjects(
        3,
        closeHead.headHash,
        afterCloseWitnesses.map((witness, boardPosition) => ({
            objectType: 'BallotPackage' as const,
            objectHash: witness.ballotPackage.ballotPackageHash,
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
        electionManifestHash,
        rosterHash,
        pollSpecHash,
        thresholdProfileHash,
        duplicateBallotPolicyHash:
            manifestPolicyHashes.duplicateBallotPolicyHash,
        pollSpec,
        thresholdProfile,
        rosterEntries,
        votingClosedBoardHeadHash: closeHead.headHash,
        closeRecordHash,
        closeRecordBoardOrder: {
            boardSequence: 2,
            boardPosition: 0,
        },
        closeRecordInclusionProof: closeHeadWithProofs.inclusionProofs[0],
        candidateBallots,
        includeRejectedCandidateSummariesInHash: true,
    };
};

export const mutateBallotPackage = (
    ballotPackage: BallotPackageShell,
    overrides: Partial<BallotPackageShell>,
): BallotPackageShell => ({
    ...ballotPackage,
    ...overrides,
});

export const deriveBallotPackageHashForTest = (
    ballotPackage: Omit<BallotPackageShell, 'ballotPackageHash' | 'signature'>,
): string =>
    deriveProtocolHash('BallotPackageHash', {
        ballotPolynomialSetHash: ballotPackage.ballotPolynomialSetHash,
        ceremonyId: ballotPackage.ceremonyId,
        duplicateBallotPolicyHash: ballotPackage.duplicateBallotPolicyHash,
        electionManifestHash: ballotPackage.electionManifestHash,
        objectType: ballotPackage.objectType,
        objectVersion: ballotPackage.objectVersion,
        optionCount: ballotPackage.optionCount,
        pollSpecHash: ballotPackage.pollSpecHash,
        receiverPayloadHashes: ballotPackage.receiverPayloadHashes,
        receiverShareCommitments: ballotPackage.receiverShareCommitments,
        rosterHash: ballotPackage.rosterHash,
        shareVectorWidth: ballotPackage.shareVectorWidth,
        thresholdProfileHash: ballotPackage.thresholdProfileHash,
        voterIdentity: ballotPackage.voterIdentity,
        voterRosterPosition: ballotPackage.voterRosterPosition,
    });

export const stripBallotPackageSignatureForTest = (
    ballotPackage: BallotPackageShell,
): Omit<BallotPackageShell, 'ballotPackageHash' | 'signature'> => ({
    objectType: ballotPackage.objectType,
    objectVersion: ballotPackage.objectVersion,
    ceremonyId: ballotPackage.ceremonyId,
    electionManifestHash: ballotPackage.electionManifestHash,
    rosterHash: ballotPackage.rosterHash,
    pollSpecHash: ballotPackage.pollSpecHash,
    thresholdProfileHash: ballotPackage.thresholdProfileHash,
    duplicateBallotPolicyHash: ballotPackage.duplicateBallotPolicyHash,
    voterIdentity: ballotPackage.voterIdentity,
    voterRosterPosition: ballotPackage.voterRosterPosition,
    optionCount: ballotPackage.optionCount,
    shareVectorWidth: ballotPackage.shareVectorWidth,
    ballotPolynomialSetHash: ballotPackage.ballotPolynomialSetHash,
    receiverShareCommitments: ballotPackage.receiverShareCommitments,
    receiverPayloadHashes: ballotPackage.receiverPayloadHashes,
});

export const resignBallotPackageForTest = (
    ballotPackage: Omit<BallotPackageShell, 'ballotPackageHash' | 'signature'>,
): BallotPackageShell => {
    const ballotPackageHash = deriveBallotPackageHashForTest(ballotPackage);

    return {
        ...ballotPackage,
        ballotPackageHash,
        signature: createSignature(
            'BallotPackage',
            'Voter',
            ballotPackage.voterIdentity,
            getParticipantSigningPublicKeyHash(ballotPackage.voterIdentity),
            ballotPackageHash,
            {
                manifestHash: ballotPackage.electionManifestHash,
                boardHeadHash: null,
            },
        ),
    };
};

export const deriveAggregateShareCommitmentHashForTest = (
    aggregateShare: Omit<TestAggregateShare, 'aggregateShareCommitmentHash'>,
): string =>
    deriveProtocolHash('AggregateShareCommitmentHash', {
        aggregateCommitmentValues: aggregateShare.aggregateCommitmentValues,
        aggregateShareVector: aggregateShare.aggregateShareVector,
        ballotSetHash: aggregateShare.ballotSetHash,
        objectType: aggregateShare.objectType,
        purpose: 'pvss-test-aggregate-share-commitment-v1',
        shareVectorWidth: aggregateShare.shareVectorWidth,
        trusteeIdentity: aggregateShare.trusteeIdentity,
        trusteeRosterPosition: aggregateShare.trusteeRosterPosition,
    });

export const reHashAggregateShareForTest = (
    aggregateShare: Omit<TestAggregateShare, 'aggregateShareCommitmentHash'>,
): TestAggregateShare => ({
    ...aggregateShare,
    aggregateShareCommitmentHash:
        deriveAggregateShareCommitmentHashForTest(aggregateShare),
});

export const stripAggregateShareCommitmentHashForTest = (
    aggregateShare: TestAggregateShare,
): Omit<TestAggregateShare, 'aggregateShareCommitmentHash'> => ({
    objectType: aggregateShare.objectType,
    ballotSetHash: aggregateShare.ballotSetHash,
    trusteeIdentity: aggregateShare.trusteeIdentity,
    trusteeRosterPosition: aggregateShare.trusteeRosterPosition,
    shareVectorWidth: aggregateShare.shareVectorWidth,
    aggregateShareVector: aggregateShare.aggregateShareVector,
    aggregateCommitmentValues: aggregateShare.aggregateCommitmentValues,
});

export const incrementFieldElement = (fieldElement: number): number =>
    (fieldElement + 1) % 65_537;
