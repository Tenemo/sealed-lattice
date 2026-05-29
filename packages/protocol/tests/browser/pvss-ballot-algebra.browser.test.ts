import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    PollSpec,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { derivePollSpecHash } from '#packages/protocol/src/lifecycle/poll-spec';
import { deriveFrozenRosterProfile } from '#packages/protocol/src/lifecycle/thresholds';
import {
    deriveTestBallotPackage,
    verifyBallotPackageShell,
    verifyTestShareCommitmentOpening,
} from '#packages/protocol/src/pvss-ballot/index';

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
    duplicateBallotPolicy: 'FirstValidBeforeVotingClosedCounts',
    maxRosterSize: 50,
    minRosterSize: 10,
    rosterPolicy: 'OpenLinkPublicRoster',
    smallRosterPolicy: 'ForbidMicroRoster',
    thresholdProfileFamily: 'BalancedDefault',
    tiePolicy: 'HigherScoreThenLowerOptionIndex',
} as const satisfies PollSpec;
const rosterEntries = Array.from({ length: 20 }, (_unused, rosterIndex) => ({
    participantIdentity: `participant-${String(rosterIndex + 1)}`,
    rosterPosition: rosterIndex + 1,
}));
const pollSpecHash = derivePollSpecHash(pollSpec);
const rosterHash = deriveProtocolHash('RosterHash', { rosterEntries });
const frozenRosterProfile = deriveFrozenRosterProfile({
    pollSpec,
    rosterHash,
    rosterSize: rosterEntries.length,
});
const thresholdProfile = frozenRosterProfile.thresholdProfile;
const thresholdProfileHash = frozenRosterProfile.thresholdProfileHash;
const electionManifestHash = deriveProtocolHash('ElectionManifestHash', {
    ceremonyId,
    pollSpecHash,
    rosterHash,
    thresholdProfileHash,
});
const duplicateBallotPolicyHash = deriveProtocolHash('ChallengeDomainHash', {
    payload: { policy: 'first-valid-before-close' },
    purpose: 'browser-fixture-duplicate-ballot-policy-v1',
});

const createDummySignature = (
    ballotPackageHash: string,
): ProtocolSignatureEnvelope => ({
    profile: {
        algorithm: 'ML-DSA-65',
        mode: 'PureMLDSA',
        providerName: 'browser-fixture',
        providerVersion: '1',
        providerBuildHash: deriveProtocolHash('ProviderBuildHash', {
            providerName: 'browser-fixture',
        }),
        fips204Version: 'FIPS 204',
        errataStatus: 'none',
        contextString: 'sealed-lattice:v1',
        contextStringByteLength: 17,
    },
    publicKeyHash: deriveProtocolHash('PublicKeyHash', {
        publicKey: 'browser-fixture',
    }),
    publicKeyBytesHex: '',
    signedRoot: {
        objectType: 'BallotPackage',
        objectVersion: 1,
        ceremonyId,
        manifestHash: electionManifestHash,
        boardHeadHash: null,
        objectRoot: ballotPackageHash,
        chunkMerkleRoot: null,
        byteLength: 0,
        signerRole: 'Voter',
        signerIdentity: 'participant-1',
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextHash: deriveProtocolHash('ActionContextHash', {
            context: 'browser-fixture',
        }),
    },
    signatureBytesHex: '',
    signatureHash: deriveProtocolHash('ProtocolSignatureEnvelopeHash', {
        ballotPackageHash,
    }),
});

describe('browser PVSS ballot algebra', () => {
    it('derives deterministic package shells without public SDK APIs', () => {
        const witness = deriveTestBallotPackage(
            {
                ceremonyId,
                voterIdentity: 'participant-1',
                voterRosterPosition: 1,
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                duplicateBallotPolicyHash,
                thresholdProfileHash,
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

        expect(witness.ballotPackage.ballotPackageHash).toMatch(
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
                electionManifestHash,
                rosterHash,
                pollSpecHash,
                thresholdProfileHash,
                duplicateBallotPolicyHash,
                optionCount: pollSpec.options.length,
                rosterEntries,
                thresholdProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
    });
});
