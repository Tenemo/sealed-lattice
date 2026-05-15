import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    PollSpec,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { deriveThresholdProfile } from '../../src/lifecycle/thresholds';
import {
    deriveTestBallotPackage,
    verifyBallotPackageShell,
    verifyTestShareCommitmentOpening,
} from '../../src/pvss-ballot/index';

const ceremonyId = 'browser-pvss-ceremony';
const pollSpec = {
    pollId: 'browser-pvss-poll',
    question: 'Question',
    options: ['A', 'B', 'C'],
    topOptionCount: 1,
    scoreDomain: {
        min: 1,
        max: 10,
        skippedOptionScore: 1,
    },
    duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
    tiePolicy: 'HigherScoreThenLowerOptionIndex',
} as const satisfies PollSpec;
const thresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const rosterEntries = Array.from({ length: 20 }, (_unused, rosterIndex) => ({
    participantIdentity: `participant-${String(rosterIndex + 1)}`,
    rosterPosition: rosterIndex + 1,
}));
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
const duplicateBallotPolicyDigest = deriveProtocolDigest(
    'DuplicateBallotPolicyDigest',
    { policy: 'last-valid-before-close' },
);

const createDummySignature = (
    ballotPackageDigest: string,
): ProtocolSignatureEnvelope => ({
    profile: {
        algorithm: 'ML-DSA-65',
        mode: 'PureMLDSA',
        providerName: 'browser-fixture',
        providerVersion: '1',
        providerBuildHash: deriveProtocolDigest('ProviderBuildDigest', {
            providerName: 'browser-fixture',
        }),
        fips204Version: 'FIPS 204',
        errataStatus: 'none',
        contextString: 'sealed-lattice:v1',
        contextStringByteLength: 17,
    },
    publicKeyDigest: deriveProtocolDigest('PublicKeyDigest', {
        publicKey: 'browser-fixture',
    }),
    publicKeyBytesHex: '',
    signedRoot: {
        objectType: 'BallotPackage',
        objectVersion: 1,
        ceremonyId,
        manifestDigest: electionManifestDigest,
        boardHeadDigest: null,
        objectRoot: ballotPackageDigest,
        chunkMerkleRoot: null,
        byteLength: 0,
        signerRole: 'Voter',
        signerIdentity: 'participant-1',
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextDigest: deriveProtocolDigest('ActionContextDigest', {
            context: 'browser-fixture',
        }),
    },
    signatureBytesHex: '',
    signatureDigest: deriveProtocolDigest('ProtocolSignatureEnvelopeDigest', {
        ballotPackageDigest,
    }),
});

describe('browser PVSS ballot algebra', () => {
    it('derives deterministic package shells without public SDK APIs', () => {
        const witness = deriveTestBallotPackage(
            {
                ceremonyId,
                voterIdentity: 'participant-1',
                voterRosterPosition: 1,
                electionManifestDigest,
                rosterDigest,
                pollSpecDigest,
                duplicateBallotPolicyDigest,
                thresholdProfileDigest,
                pollSpec,
                thresholdProfile,
                rosterEntries,
                scoreBallot: {
                    voterIdentity: 'participant-1',
                    scores: [10, undefined, 3],
                },
                fixtureEntropy: 'browser-fixture',
            },
            createDummySignature,
        );

        expect(witness.ballotPackage.ballotPackageDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(witness.receiverShareVectors).toHaveLength(20);
        expect(witness.receiverShareVectors[0].shareVector.slice(3)).toEqual(
            Array.from({ length: 17 }, () => 0),
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
                duplicateBallotPolicyDigest,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }),
        ).toEqual([]);
    });
});
