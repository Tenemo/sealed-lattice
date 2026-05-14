import type {
    ElectionManifest,
    ProtocolDigest,
    ReceiverKeyRegistration,
    RegistrationEntry,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import { deriveProtocolDigest } from '../common/digests.js';

export const deriveRegistrationEntryDigest = (
    entry: Omit<RegistrationEntry, 'registrationEntryDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('RegistrationEntryDigest', {
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

export const deriveReceiverKeyRegistrationDigest = (
    entry: Omit<
        ReceiverKeyRegistration,
        'receiverKeyRegistrationDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverKeyRegistrationDigest', {
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

export const deriveTrusteeSetupEntryDigest = (
    entry: Omit<TrusteeSetupEntry, 'trusteeSetupEntryDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('TrusteeSetupEntryDigest', {
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

export const deriveRosterDigest = (
    entries: readonly RegistrationEntry[],
): ProtocolDigest =>
    deriveProtocolDigest(
        'RosterDigest',
        entries
            .map((entry) => ({
                participantIdentity: entry.participantIdentity,
                registrationEntryDigest: entry.registrationEntryDigest,
                signingPublicKeyDigest: entry.signingPublicKeyDigest,
            }))
            .sort((left, right) =>
                left.participantIdentity.localeCompare(
                    right.participantIdentity,
                ),
            ),
    );

export const deriveElectionManifestDigest = (
    manifest: Omit<ElectionManifest, 'electionManifestDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('ElectionManifestDigest', {
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
