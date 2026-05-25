import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    FrozenRosterProfile,
    PollSpec,
    ReceiverKeyRegistration,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    derivePollSpecDigest,
    validatePollSpec,
} from '../../src/lifecycle/poll-spec';
import { deriveFrozenRosterProfile } from '../../src/lifecycle/thresholds';
import {
    deriveElectionManifestDigest,
    deriveReceiverKeyRegistrationDigest,
    deriveRegistrationEntryDigest,
    deriveRosterDigest,
    deriveTrusteeSetupEntryDigest,
} from '../../src/roster/index';

import {
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
} from './election-foundation-board-helpers';
import {
    ceremonyId,
    createSignature,
    getParticipantSigningPublicKeyDigest,
    manifestOpaqueBindings,
    manifestPolicyDigests,
    organizerPublicKeyDigest,
} from './election-foundation-fixture-constants';

export const createRosterPollSpec = (): PollSpec => {
    const validation = validatePollSpec({
        duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
        maxRosterSize: 50,
        minRosterSize: 3,
        options: ['Option A', 'Option B', 'Option C'],
        pollId: 'poll-main',
        question: 'Choose options',
        rosterPolicy: 'OpenLinkPublicRoster',
        scoreDomain: { max: 10, min: 1, skippedOptionScore: 1 },
        smallRosterPolicy: 'AllowMicroRoster',
        thresholdProfileFamily: 'BalancedDefault',
        tiePolicy: 'HigherScoreThenLowerOptionIndex',
        topOptionCount: 2,
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
    const rosterDigest = deriveRosterDigest(registrations);
    const rosterSize = registrations.length;

    return deriveFrozenRosterProfile({
        dynamicRosterProfileCertificateDigest:
            rosterSize >= 10 && rosterSize !== 20
                ? deriveProtocolDigest('ThresholdProfileDigest', {
                      certificate: 'dynamic-roster-profile',
                      rosterSize,
                  })
                : undefined,
        pollSpec,
        rosterDigest,
        rosterSize,
    });
};

export const createRegistrationEntry = (
    participantIdentity: string,
    boardSequence: number,
    boardPosition: number,
): RegistrationEntry => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(participantIdentity);
    const payload = {
        objectType: 'RegistrationEntry',
        objectVersion: 1,
        ceremonyId,
        participantIdentity,
        signingPublicKeyDigest,
        boardSequence,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<
        RegistrationEntry,
        'registrationEntryDigest' | 'signature'
    >;
    const registrationEntryDigest = deriveRegistrationEntryDigest(payload);

    return {
        ...payload,
        registrationEntryDigest,
        signature: createSignature(
            'RegistrationEntry',
            'Participant',
            participantIdentity,
            signingPublicKeyDigest,
            registrationEntryDigest,
        ),
    };
};

export const createReceiverKeyRegistration = (
    participantIdentity: string,
    boardSequence: number,
    boardPosition: number,
): ReceiverKeyRegistration => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(participantIdentity);
    const payload = {
        objectType: 'ReceiverKeyRegistration',
        objectVersion: 1,
        ceremonyId,
        participantIdentity,
        receiverKeyRoot: deriveProtocolDigest('EncryptedEnvelopeRoot', {
            participantIdentity,
        }),
        boardSequence,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<
        ReceiverKeyRegistration,
        'receiverKeyRegistrationDigest' | 'signature'
    >;
    const receiverKeyRegistrationDigest =
        deriveReceiverKeyRegistrationDigest(payload);

    return {
        ...payload,
        receiverKeyRegistrationDigest,
        signature: createSignature(
            'ReceiverKeyRegistration',
            'Participant',
            participantIdentity,
            signingPublicKeyDigest,
            receiverKeyRegistrationDigest,
        ),
    };
};

export const createTrusteeSetupEntry = (
    trusteeIdentity: string,
    boardSequence: number,
    boardPosition: number,
): TrusteeSetupEntry => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(trusteeIdentity);
    const payload = {
        objectType: 'TrusteeSetupEntry',
        objectVersion: 1,
        ceremonyId,
        setupProfileId: manifestOpaqueBindings.bgvPassiveSetupProfileId,
        thresholdDecryptionProfileId:
            manifestOpaqueBindings.thresholdDecryptionProfileId,
        trusteeIdentity,
        trusteeSetupRoot: deriveProtocolDigest(
            'ParticipantBgvSetupRecordDigest',
            {
                trusteeIdentity,
            },
        ),
        bgvProfileDigest: manifestOpaqueBindings.bgvProfileDigest,
        rustBgvBackendProfileDigest:
            manifestOpaqueBindings.rustBgvBackendProfileDigest,
        participantSetupRecordDigest: deriveProtocolDigest(
            'ParticipantBgvSetupRecordDigest',
            {
                trusteeIdentity,
            },
        ),
        publicKeyShareRoot: deriveProtocolDigest('PublicKeyShareRoot', {
            trusteeIdentity,
        }),
        collectivePublicKeyRoot: manifestOpaqueBindings.collectivePublicKeyRoot,
        trusteeThresholdVerificationKeyDigest: deriveProtocolDigest(
            'TrusteeThresholdVerificationKeyDigest',
            {
                trusteeIdentity,
            },
        ),
        thresholdShareVerificationKeyRoot:
            manifestOpaqueBindings.thresholdShareVerificationKeyRoot,
        evaluationKeyRoot: manifestOpaqueBindings.evaluationKeyRoot,
        rotSetDigest: manifestOpaqueBindings.rotSetDigest,
        boardSequence,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<
        TrusteeSetupEntry,
        'trusteeSetupEntryDigest' | 'signature'
    >;
    const trusteeSetupEntryDigest = deriveTrusteeSetupEntryDigest(payload);

    return {
        ...payload,
        trusteeSetupEntryDigest,
        signature: createSignature(
            'TrusteeSetupEntry',
            'Trustee',
            trusteeIdentity,
            signingPublicKeyDigest,
            trusteeSetupEntryDigest,
        ),
    };
};

export const createElectionManifest = (
    registrations: readonly RegistrationEntry[],
    overrides: Partial<ElectionManifest> = {},
): ElectionManifest => {
    const pollSpec = createRosterPollSpec();
    const rosterDigest = deriveRosterDigest(registrations);
    const thresholdProfileDigest =
        registrations.length >= 3
            ? createFrozenRosterProfile(pollSpec, registrations)
                  .thresholdProfileDigest
            : deriveProtocolDigest('ThresholdProfileDigest', {
                  fixture: 'below-minimum-roster',
                  rosterSize: registrations.length,
              });
    const payload = {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        ceremonyId,
        pollSpecDigest: derivePollSpecDigest(pollSpec),
        rosterDigest,
        thresholdProfileDigest,
        manifestPolicyDigests,
        manifestOpaqueBindings,
        boardSequence: 3,
        boardPosition: 0,
        ...overrides,
    } satisfies Omit<ElectionManifest, 'electionManifestDigest' | 'signature'>;
    const electionManifestDigest = deriveElectionManifestDigest(payload);

    return {
        ...payload,
        electionManifestDigest,
        signature: createSignature(
            'ElectionManifest',
            'Organizer',
            'organizer',
            organizerPublicKeyDigest,
            electionManifestDigest,
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
    const receiverKeyRegistrations = rosterRegistrations.map((entry, index) =>
        createReceiverKeyRegistration(
            entry.participantIdentity,
            1,
            rosterRegistrations.length + index,
        ),
    );
    const trusteeSetupEntries = rosterRegistrations.map((entry, index) =>
        createTrusteeSetupEntry(
            entry.participantIdentity,
            1,
            rosterRegistrations.length * 2 + index,
        ),
    );
    const setupObjects = [
        ...rosterRegistrations.map((entry) => ({
            objectType: 'RegistrationEntry' as const,
            objectDigest: entry.registrationEntryDigest,
            boardPosition: entry.boardPosition,
        })),
        ...receiverKeyRegistrations.map((entry) => ({
            objectType: 'ReceiverKeyRegistration' as const,
            objectDigest: entry.receiverKeyRegistrationDigest,
            boardPosition: entry.boardPosition,
        })),
        ...trusteeSetupEntries.map((entry) => ({
            objectType: 'TrusteeSetupEntry' as const,
            objectDigest: entry.trusteeSetupEntryDigest,
            boardPosition: entry.boardPosition,
        })),
    ];
    const genesisHead = createBoardHead(0, null);
    const { head: setupHead, inclusionProofs: setupInclusionProofs } =
        createBoardHeadWithObjects(1, genesisHead.headDigest, setupObjects);
    const freezeHead = createBoardHead(2, setupHead.headDigest);
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
        createBoardHeadWithObjects(3, freezeHead.headDigest, [
            {
                objectType: 'ElectionManifest',
                objectDigest: manifest.electionManifestDigest,
                boardPosition: manifest.boardPosition,
            },
        ]);
    const registrationInclusionProofs = rosterRegistrations.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectDigest ===
                    entry.registrationEntryDigest,
            ) ?? setupInclusionProofs[0],
    );
    const receiverKeyRegistrationInclusionProofs = receiverKeyRegistrations.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectDigest ===
                    entry.receiverKeyRegistrationDigest,
            ) ?? setupInclusionProofs[0],
    );
    const trusteeSetupInclusionProofs = trusteeSetupEntries.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectDigest ===
                    entry.trusteeSetupEntryDigest,
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
        receiverKeyRegistrations,
        receiverKeyRegistrationInclusionProofs,
        trusteeSetupEntries,
        trusteeSetupInclusionProofs,
        pollSpec,
        frozenRosterProfile,
        electionManifest: manifest,
        organizerPublicKeyDigest,
        organizerIdentity: 'organizer',
        rosterFreezeBoardSequence: 2,
        manifestInclusionProof: manifestInclusionProofs[0],
    };
};
