import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    ProtocolHash,
    RegistrationEntry,
    RosterExternalAcceptance,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    compareCanonicalStrings,
    isProtocolHashString,
} from '../common/verification-helpers.js';

export type CollectiveBgvSetupRosterEntryInput = Readonly<{
    readonly rosterPosition: number;
    readonly trusteeIdentity: string;
    readonly signingPublicKeyHash: ProtocolHash;
}>;

export const deriveRegistrationEntryHash = (
    entry: Omit<RegistrationEntry, 'registrationEntryHash' | 'signature'>,
): ProtocolHash =>
    deriveCanonicalObjectHash({
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
    deriveCanonicalObjectHash({
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
    deriveCanonicalObjectHash({
        objectType: 'Roster',
        entries: entries
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
    });

export const deriveCollectiveBgvSetupRosterHash = (
    entries: readonly CollectiveBgvSetupRosterEntryInput[],
): ProtocolHash => {
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'Collective BGV setup roster entries must be an array.',
        );
    }

    const inputEntries: readonly CollectiveBgvSetupRosterEntryInput[] = entries;
    const rosterEntries = inputEntries
        .map((entry) => {
            if (typeof entry !== 'object' || entry === null) {
                throw new TypeError(
                    'Collective BGV setup roster entry must be an object.',
                );
            }
            if (
                !Number.isSafeInteger(entry.rosterPosition) ||
                entry.rosterPosition < 0
            ) {
                throw new TypeError(
                    'rosterPosition must be a non-negative safe integer.',
                );
            }
            if (
                typeof entry.trusteeIdentity !== 'string' ||
                entry.trusteeIdentity.length === 0
            ) {
                throw new TypeError('trusteeIdentity must be non-empty.');
            }
            if (!isProtocolHashString(entry.signingPublicKeyHash)) {
                throw new TypeError(
                    'signingPublicKeyHash must be a protocol hash.',
                );
            }

            return {
                objectType: 'CollectiveBgvSetupRosterEntry',
                rosterPosition: entry.rosterPosition,
                trusteeIdentity: entry.trusteeIdentity,
                signingPublicKeyHash: entry.signingPublicKeyHash,
            };
        })
        .sort((left, right) => left.rosterPosition - right.rosterPosition);
    for (
        let entryIndex = 1;
        entryIndex < rosterEntries.length;
        entryIndex += 1
    ) {
        if (
            rosterEntries[entryIndex]?.rosterPosition ===
            rosterEntries[entryIndex - 1]?.rosterPosition
        ) {
            throw new TypeError(
                'Collective BGV setup roster entries must have distinct roster positions.',
            );
        }
    }

    return deriveCanonicalObjectHash({
        objectType: 'CollectiveBgvSetupRoster',
        rosterEntries,
    });
};

export const deriveRosterExternalAcceptanceHash = (
    acceptance: Omit<
        RosterExternalAcceptance,
        'rosterExternalAcceptanceHash' | 'signature'
    >,
): ProtocolHash =>
    deriveCanonicalObjectHash({
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
    deriveCanonicalObjectHash({
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
