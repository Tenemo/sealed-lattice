import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    ProtocolHash,
    RegistrationEntry,
    RosterExternalAcceptance,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import { compareCanonicalStrings } from '../common/verification-helpers.js';

export const deriveRegistrationEntryHash = (
    entry: Omit<RegistrationEntry, 'registrationEntryHash' | 'signature'>,
): ProtocolHash =>
    deriveProtocolHash('RegistrationEntryHash', {
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        recoveryEpoch: entry.recoveryEpoch,
        signingPublicKeyHash: entry.signingPublicKeyHash,
    });

export const deriveTrusteeSetupEntryHash = (
    entry: Omit<TrusteeSetupEntry, 'trusteeSetupEntryHash' | 'signature'>,
): ProtocolHash =>
    deriveProtocolHash('TrusteeSetupEntryHash', {
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        bgvParametersHash: entry.bgvParametersHash,
        collectivePublicKeyRoot: entry.collectivePublicKeyRoot,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        evaluationKeyRoot: entry.evaluationKeyRoot,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantSetupRecordHash: entry.participantSetupRecordHash,
        publicKeyShareRoot: entry.publicKeyShareRoot,
        recoveryEpoch: entry.recoveryEpoch,
        rotSetHash: entry.rotSetHash,
        targetDecryptionId: entry.targetDecryptionId,
        thresholdShareVerificationKeyRoot:
            entry.thresholdShareVerificationKeyRoot,
        trusteeThresholdVerificationKeyHash:
            entry.trusteeThresholdVerificationKeyHash,
        trusteeIdentity: entry.trusteeIdentity,
        trusteeSetupRoot: entry.trusteeSetupRoot,
    });

// Order-independent by design: entries are NFC-normalized and sorted by
// identity before hashing, so any party computes the same roster hash
// regardless of the original registration order.
export const deriveRosterHash = (
    entries: readonly RegistrationEntry[],
): ProtocolHash =>
    deriveProtocolHash(
        'RosterHash',
        entries
            .map((entry) => ({
                participantIdentity: entry.participantIdentity.normalize('NFC'),
                registrationEntryHash: entry.registrationEntryHash,
                signingPublicKeyHash: entry.signingPublicKeyHash,
            }))
            .sort((left, right) =>
                compareCanonicalStrings(
                    left.participantIdentity,
                    right.participantIdentity,
                ),
            ),
    );

export const deriveRosterExternalAcceptanceHash = (
    acceptance: Omit<
        RosterExternalAcceptance,
        'rosterExternalAcceptanceHash' | 'signature'
    >,
): ProtocolHash =>
    deriveProtocolHash('RosterExternalAcceptanceHash', {
        acceptedBoardHeadHash: acceptance.acceptedBoardHeadHash,
        ceremonyId: acceptance.ceremonyId,
        electionManifestHash: acceptance.electionManifestHash,
        objectType: acceptance.objectType,
        objectVersion: acceptance.objectVersion,
        participantIdentity: acceptance.participantIdentity,
        rosterHash: acceptance.rosterHash,
        warningTextVersion: acceptance.warningTextVersion,
    });

export const deriveElectionManifestHash = (
    manifest: Omit<ElectionManifest, 'electionManifestHash' | 'signature'>,
): ProtocolHash =>
    deriveProtocolHash('ElectionManifestHash', {
        boardPosition: manifest.boardPosition,
        boardSequence: manifest.boardSequence,
        ceremonyId: manifest.ceremonyId,
        manifestOpaqueBindings: manifest.manifestOpaqueBindings,
        manifestPolicyHashes: manifest.manifestPolicyHashes,
        objectType: manifest.objectType,
        objectVersion: manifest.objectVersion,
        pollSpecHash: manifest.pollSpecHash,
        rosterHash: manifest.rosterHash,
        thresholdParametersHash: manifest.thresholdParametersHash,
    });
