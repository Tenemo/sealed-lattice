import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    InclusionProof,
    ProtocolDigest,
    ReceiverKeyRegistration,
    RefusalRecord,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    createRefusal,
    isNonNegativeInteger,
} from '../common/verification-helpers.js';

import {
    deriveElectionManifestDigest,
    deriveReceiverKeyRegistrationDigest,
    deriveRegistrationEntryDigest,
    deriveTrusteeSetupEntryDigest,
} from './digests.js';

export const verifyRegistrationEntry = (
    input: RosterManifestTranscriptInput,
    entry: RegistrationEntry,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveRegistrationEntryDigest({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        recoveryEpoch: entry.recoveryEpoch,
        signingPublicKeyDigest: entry.signingPublicKeyDigest,
    });

    if (entry.registrationEntryDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Registration entry digest does not match its canonical payload.',
                entry.registrationEntryDigest,
                'RegistrationEntry',
            ),
        );
    }
    if (
        entry.objectType !== 'RegistrationEntry' ||
        entry.objectVersion !== 1 ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Registration entry object shape is not canonical.',
                entry.registrationEntryDigest,
                'RegistrationEntry',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Registration entry ceremony does not match the transcript.',
                entry.registrationEntryDigest,
                'RegistrationEntry',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Registration entry must appear before the roster freeze board sequence.',
                entry.registrationEntryDigest,
                'RegistrationEntry',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(entry.signature, {
        objectType: 'RegistrationEntry',
        objectVersion: 1,
        signerRole: 'Participant',
        signerIdentity: entry.participantIdentity,
        ceremonyId: input.ceremonyId,
        manifestDigest: null,
        objectRoot: entry.registrationEntryDigest,
        boardHeadDigest: null,
        publicKeyDigest: entry.signingPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyReceiverKeyRegistration = (
    input: RosterManifestTranscriptInput,
    entry: ReceiverKeyRegistration,
    expectedPublicKeyDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveReceiverKeyRegistrationDigest({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        receiverKeyRoot: entry.receiverKeyRoot,
        recoveryEpoch: entry.recoveryEpoch,
    });

    if (entry.receiverKeyRegistrationDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Receiver-key registration digest does not match its canonical payload.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (
        entry.objectType !== 'ReceiverKeyRegistration' ||
        entry.objectVersion !== 1 ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Receiver-key registration object shape is not canonical.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Receiver-key registration ceremony does not match the transcript.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Receiver-key registration must appear before the roster freeze board sequence.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (expectedPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Receiver-key registration identity is not in the frozen roster.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(entry.signature, {
        objectType: 'ReceiverKeyRegistration',
        objectVersion: 1,
        signerRole: 'Participant',
        signerIdentity: entry.participantIdentity,
        ceremonyId: input.ceremonyId,
        manifestDigest: null,
        objectRoot: entry.receiverKeyRegistrationDigest,
        boardHeadDigest: null,
        publicKeyDigest: expectedPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyTrusteeSetupEntry = (
    input: RosterManifestTranscriptInput,
    entry: TrusteeSetupEntry,
    expectedPublicKeyDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTrusteeSetupEntryDigest({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        recoveryEpoch: entry.recoveryEpoch,
        trusteeIdentity: entry.trusteeIdentity,
        trusteeSetupRoot: entry.trusteeSetupRoot,
    });

    if (entry.trusteeSetupEntryDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry digest does not match its canonical payload.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (
        entry.objectType !== 'TrusteeSetupEntry' ||
        entry.objectVersion !== 1 ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry object shape is not canonical.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Trustee setup entry ceremony does not match the transcript.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Trustee setup entry must appear before the roster freeze board sequence.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (expectedPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Trustee setup identity is not in the frozen roster.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(entry.signature, {
        objectType: 'TrusteeSetupEntry',
        objectVersion: 1,
        signerRole: 'Trustee',
        signerIdentity: entry.trusteeIdentity,
        ceremonyId: input.ceremonyId,
        manifestDigest: null,
        objectRoot: entry.trusteeSetupEntryDigest,
        boardHeadDigest: null,
        publicKeyDigest: expectedPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyManifest = (
    input: RosterManifestTranscriptInput,
    rosterDigest: ProtocolDigest | undefined,
    manifest: ElectionManifest = input.electionManifest,
    manifestInclusionProof: InclusionProof = input.manifestInclusionProof,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveElectionManifestDigest({
        boardPosition: manifest.boardPosition,
        boardSequence: manifest.boardSequence,
        ceremonyId: manifest.ceremonyId,
        manifestOpaqueBindings: manifest.manifestOpaqueBindings,
        manifestPolicyDigests: manifest.manifestPolicyDigests,
        objectType: manifest.objectType,
        objectVersion: manifest.objectVersion,
        pollSpecDigest: manifest.pollSpecDigest,
        rosterDigest: manifest.rosterDigest,
        thresholdProfileDigest: manifest.thresholdProfileDigest,
    });

    if (manifest.electionManifestDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest digest does not match its canonical payload.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (
        manifest.objectType !== 'ElectionManifest' ||
        manifest.objectVersion !== 1 ||
        !isNonNegativeInteger(manifest.boardSequence) ||
        !isNonNegativeInteger(manifest.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest object shape is not canonical.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (manifest.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Election manifest ceremony does not match the transcript.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (rosterDigest !== undefined && manifest.rosterDigest !== rosterDigest) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Election manifest roster digest does not match the frozen roster.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (manifest.boardSequence < input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest must not precede the roster freeze board sequence.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (
        manifestInclusionProof.includedObjectType !== 'ElectionManifest' ||
        manifestInclusionProof.includedObjectDigest !==
            manifest.electionManifestDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Manifest inclusion proof does not bind the election manifest digest.',
                manifestInclusionProof.inclusionProofDigest,
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(manifest.signature, {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        signerRole: 'Organizer',
        signerIdentity: input.organizerIdentity,
        ceremonyId: input.ceremonyId,
        manifestDigest: null,
        objectRoot: manifest.electionManifestDigest,
        boardHeadDigest: null,
        publicKeyDigest: input.organizerPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};
