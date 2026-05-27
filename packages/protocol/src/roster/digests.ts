import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    ProtocolDigest,
    ReceiverKeyRegistration,
    RegistrationEntry,
    RosterExternalAcceptance,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import { compareCanonicalStrings } from '../common/verification-helpers.js';

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
        bgvProfileDigest: entry.bgvProfileDigest,
        collectivePublicKeyRoot: entry.collectivePublicKeyRoot,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        evaluationKeyRoot: entry.evaluationKeyRoot,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantSetupRecordDigest: entry.participantSetupRecordDigest,
        publicKeyShareRoot: entry.publicKeyShareRoot,
        recoveryEpoch: entry.recoveryEpoch,
        rotSetDigest: entry.rotSetDigest,
        rustBgvBackendProfileDigest: entry.rustBgvBackendProfileDigest,
        setupProfileId: entry.setupProfileId,
        thresholdDecryptionProfileId: entry.thresholdDecryptionProfileId,
        thresholdShareVerificationKeyRoot:
            entry.thresholdShareVerificationKeyRoot,
        trusteeThresholdVerificationKeyDigest:
            entry.trusteeThresholdVerificationKeyDigest,
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
                participantIdentity: entry.participantIdentity.normalize('NFC'),
                registrationEntryDigest: entry.registrationEntryDigest,
                signingPublicKeyDigest: entry.signingPublicKeyDigest,
            }))
            .sort((left, right) =>
                compareCanonicalStrings(
                    left.participantIdentity,
                    right.participantIdentity,
                ),
            ),
    );

export const deriveRosterExternalAcceptanceDigest = (
    acceptance: Omit<
        RosterExternalAcceptance,
        'rosterExternalAcceptanceDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('RosterExternalAcceptanceDigest', {
        acceptedBoardHeadDigest: acceptance.acceptedBoardHeadDigest,
        ceremonyId: acceptance.ceremonyId,
        electionManifestDigest: acceptance.electionManifestDigest,
        objectType: acceptance.objectType,
        objectVersion: acceptance.objectVersion,
        participantIdentity: acceptance.participantIdentity,
        rosterDigest: acceptance.rosterDigest,
        warningTextVersion: acceptance.warningTextVersion,
    });

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
