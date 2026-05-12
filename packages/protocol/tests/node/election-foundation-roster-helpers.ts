import {
    deriveElectionManifestDigest,
    deriveProtocolDigest,
    deriveReceiverKeyRegistrationDigest,
    deriveRegistrationEntryDigest,
    deriveRosterDigest,
    deriveTrusteeSetupEntryDigest,
} from '../../src/index';
import type {
    ElectionManifest,
    ReceiverKeyRegistration,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    TrusteeSetupEntry,
} from '../../src/index';

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

export const createRegistrationEntry = (
    participantIdentity: string,
    boardSeq: number,
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
        boardSeq,
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
    boardSeq: number,
    boardPosition: number,
): ReceiverKeyRegistration => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(participantIdentity);
    const payload = {
        objectType: 'ReceiverKeyRegistration',
        objectVersion: 1,
        ceremonyId,
        participantIdentity,
        receiverKeyRoot: deriveProtocolDigest('ReceiverKeyRoot', {
            participantIdentity,
        }),
        boardSeq,
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
    boardSeq: number,
    boardPosition: number,
): TrusteeSetupEntry => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(trusteeIdentity);
    const payload = {
        objectType: 'TrusteeSetupEntry',
        objectVersion: 1,
        ceremonyId,
        trusteeIdentity,
        trusteeSetupRoot: deriveProtocolDigest('TrusteeSetupRoot', {
            trusteeIdentity,
        }),
        boardSeq,
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
    const rosterDigest = deriveRosterDigest(registrations);
    const payload = {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        ceremonyId,
        pollSpecDigest: deriveProtocolDigest('PollSpecDigest', {
            poll: 'main',
        }),
        rosterDigest,
        thresholdProfileDigest: deriveProtocolDigest('ThresholdProfileDigest', {
            rosterSize: registrations.length,
        }),
        manifestPolicyDigests,
        manifestOpaqueBindings,
        boardSeq: 3,
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
        electionManifest: manifest,
        organizerPublicKeyDigest,
        organizerIdentity: 'organizer',
        rosterFreezeBoardSeq: 2,
        manifestInclusionProof: manifestInclusionProofs[0],
    };
};
