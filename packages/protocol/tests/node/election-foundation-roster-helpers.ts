import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    FrozenRosterProfile,
    PollSpec,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
} from './election-foundation-board-helpers';
import {
    ceremonyId,
    createSignature,
    getParticipantSigningPublicKeyHash,
    manifestOpaqueBindings,
    manifestPolicyHashes,
    organizerPublicKeyHash,
} from './election-foundation-fixture-constants';

import {
    derivePollSpecHash,
    validatePollSpec,
} from '#packages/protocol/src/lifecycle/poll-spec';
import { deriveFrozenRosterProfile } from '#packages/protocol/src/lifecycle/thresholds';
import {
    deriveElectionManifestHash,
    deriveRegistrationEntryHash,
    deriveRosterHash,
    deriveTrusteeSetupEntryHash,
} from '#packages/protocol/src/roster/index';

export const createRosterPollSpec = (): PollSpec => {
    const validation = validatePollSpec({
        duplicateBallotPolicy: 'FirstValidBeforeVotingClosedCounts',
        maxRosterSize: 50,
        minRosterSize: 3,
        options: Array.from(
            { length: 20 },
            (_, optionIndex) => `Option ${String(optionIndex + 1)}`,
        ),
        pollId: 'poll-main',
        question: 'Choose options',
        rosterPolicy: 'OpenLinkPublicRoster',
        scoreDomain: { max: 10, min: 1, skippedOptionScore: 1 },
        smallRosterPolicy: 'AllowMicroRoster',
        thresholdProfileFamily: 'BalancedDefault',
        tiePolicy: 'HigherScoreThenLowerOptionIndex',
        topOptionCount: 10,
    });

    if (!validation.ok) {
        throw new Error('Roster poll spec fixture must be valid.');
    }

    return validation.normalized;
};

const createFrozenRosterProfile = (
    pollSpec: PollSpec,
    registrations: readonly RegistrationEntry[],
): FrozenRosterProfile => {
    const rosterHash = deriveRosterHash(registrations);
    const rosterSize = registrations.length;

    return deriveFrozenRosterProfile({
        dynamicRosterProfileCertificateHash:
            rosterSize >= 10 && rosterSize !== 10
                ? deriveProtocolHash('ThresholdProfileHash', {
                      certificate: 'dynamic-roster-profile',
                      rosterSize,
                  })
                : undefined,
        pollSpec,
        rosterHash,
        rosterSize,
    });
};

export const createRegistrationEntry = (
    participantIdentity: string,
    boardSequence: number,
    boardPosition: number,
): RegistrationEntry => {
    const signingPublicKeyHash =
        getParticipantSigningPublicKeyHash(participantIdentity);
    const payload = {
        objectType: 'RegistrationEntry',
        objectVersion: 1,
        ceremonyId,
        participantIdentity,
        signingPublicKeyHash,
        boardSequence,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<RegistrationEntry, 'registrationEntryHash' | 'signature'>;
    const registrationEntryHash = deriveRegistrationEntryHash(payload);

    return {
        ...payload,
        registrationEntryHash,
        signature: createSignature(
            'RegistrationEntry',
            'Participant',
            participantIdentity,
            signingPublicKeyHash,
            registrationEntryHash,
        ),
    };
};

export const createTrusteeSetupEntry = (
    trusteeIdentity: string,
    boardSequence: number,
    boardPosition: number,
): TrusteeSetupEntry => {
    const signingPublicKeyHash =
        getParticipantSigningPublicKeyHash(trusteeIdentity);
    const payload = {
        objectType: 'TrusteeSetupEntry',
        objectVersion: 1,
        ceremonyId,
        setupProfileId: manifestOpaqueBindings.bgvPassiveSetupProfileId,
        targetDecryptionProfileId:
            manifestOpaqueBindings.targetDecryptionProfileId,
        trusteeIdentity,
        trusteeSetupRoot: deriveProtocolHash('ParticipantBgvSetupRecordHash', {
            trusteeIdentity,
        }),
        bgvProfileHash: manifestOpaqueBindings.bgvProfileHash,
        rustBgvBackendProfileHash:
            manifestOpaqueBindings.rustBgvBackendProfileHash,
        participantSetupRecordHash: deriveProtocolHash(
            'ParticipantBgvSetupRecordHash',
            {
                trusteeIdentity,
            },
        ),
        publicKeyShareRoot: deriveProtocolHash('PublicKeyShareRoot', {
            trusteeIdentity,
        }),
        collectivePublicKeyRoot: manifestOpaqueBindings.collectivePublicKeyRoot,
        trusteeThresholdVerificationKeyHash: deriveProtocolHash(
            'TrusteeThresholdVerificationKeyHash',
            {
                trusteeIdentity,
            },
        ),
        thresholdShareVerificationKeyRoot:
            manifestOpaqueBindings.thresholdShareVerificationKeyRoot,
        evaluationKeyRoot: manifestOpaqueBindings.evaluationKeyRoot,
        rotSetHash: manifestOpaqueBindings.rotSetHash,
        boardSequence,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<TrusteeSetupEntry, 'trusteeSetupEntryHash' | 'signature'>;
    const trusteeSetupEntryHash = deriveTrusteeSetupEntryHash(payload);

    return {
        ...payload,
        trusteeSetupEntryHash,
        signature: createSignature(
            'TrusteeSetupEntry',
            'Trustee',
            trusteeIdentity,
            signingPublicKeyHash,
            trusteeSetupEntryHash,
        ),
    };
};

export const createElectionManifest = (
    registrations: readonly RegistrationEntry[],
    overrides: Partial<ElectionManifest> = {},
): ElectionManifest => {
    const pollSpec = createRosterPollSpec();
    const rosterHash = deriveRosterHash(registrations);
    const thresholdProfileHash =
        registrations.length >= 3
            ? createFrozenRosterProfile(pollSpec, registrations)
                  .thresholdProfileHash
            : deriveProtocolHash('ThresholdProfileHash', {
                  fixture: 'below-minimum-roster',
                  rosterSize: registrations.length,
              });
    const payload = {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        ceremonyId,
        pollSpecHash: derivePollSpecHash(pollSpec),
        rosterHash,
        thresholdProfileHash,
        manifestPolicyHashes,
        manifestOpaqueBindings,
        boardSequence: 3,
        boardPosition: 0,
        ...overrides,
    } satisfies Omit<ElectionManifest, 'electionManifestHash' | 'signature'>;
    const electionManifestHash = deriveElectionManifestHash(payload);

    return {
        ...payload,
        electionManifestHash,
        signature: createSignature(
            'ElectionManifest',
            'Organizer',
            'organizer',
            organizerPublicKeyHash,
            electionManifestHash,
        ),
    };
};

export const createRosterManifestTranscriptInput = (
    registrations: readonly RegistrationEntry[],
    manifestOverrides: Partial<ElectionManifest> = {},
    options: { readonly includeOrganizer?: boolean } = {},
): RosterManifestTranscriptInput => {
    const rosterRegistrations =
        options.includeOrganizer === false ||
        registrations.some((entry) => entry.participantIdentity === 'organizer')
            ? registrations
            : [
                  ...registrations,
                  createRegistrationEntry('organizer', 1, registrations.length),
              ];
    const trusteeSetupEntries = rosterRegistrations.map((entry, index) =>
        createTrusteeSetupEntry(
            entry.participantIdentity,
            1,
            rosterRegistrations.length + index,
        ),
    );
    const setupObjects = [
        ...rosterRegistrations.map((entry) => ({
            objectType: 'RegistrationEntry' as const,
            objectHash: entry.registrationEntryHash,
            boardPosition: entry.boardPosition,
        })),
        ...trusteeSetupEntries.map((entry) => ({
            objectType: 'TrusteeSetupEntry' as const,
            objectHash: entry.trusteeSetupEntryHash,
            boardPosition: entry.boardPosition,
        })),
    ];
    const genesisHead = createBoardHead(0, null);
    const { head: setupHead, inclusionProofs: setupInclusionProofs } =
        createBoardHeadWithObjects(1, genesisHead.headHash, setupObjects);
    const freezeHead = createBoardHead(2, setupHead.headHash);
    const pollSpec = createRosterPollSpec();
    const frozenRosterProfile = createFrozenRosterProfile(
        pollSpec,
        rosterRegistrations,
    );
    const manifest = createElectionManifest(
        rosterRegistrations,
        manifestOverrides,
    );
    const { head: manifestHead, inclusionProofs: manifestInclusionProofs } =
        createBoardHeadWithObjects(3, freezeHead.headHash, [
            {
                objectType: 'ElectionManifest',
                objectHash: manifest.electionManifestHash,
                boardPosition: manifest.boardPosition,
            },
        ]);
    const registrationInclusionProofs = rosterRegistrations.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectHash === entry.registrationEntryHash,
            ) ?? setupInclusionProofs[0],
    );
    const trusteeSetupInclusionProofs = trusteeSetupEntries.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectHash === entry.trusteeSetupEntryHash,
            ) ?? setupInclusionProofs[0],
    );

    return {
        ceremonyId,
        boardEvidence: createBoardEvidence([
            genesisHead,
            setupHead,
            freezeHead,
            manifestHead,
        ]),
        registrationEntries: rosterRegistrations,
        registrationInclusionProofs,
        trusteeSetupEntries,
        trusteeSetupInclusionProofs,
        pollSpec,
        frozenRosterProfile,
        electionManifest: manifest,
        organizerPublicKeyHash,
        organizerIdentity: 'organizer',
        rosterFreezeBoardSequence: 2,
        manifestInclusionProof: manifestInclusionProofs[0],
    };
};
