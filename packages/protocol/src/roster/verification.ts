import { canonicalJson } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    ProtocolHash,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
} from '@sealed-lattice/types';

import { verifyBoardConsistency } from '../board/consistency.js';
import { verifyInclusionProof } from '../board/inclusion-proof.js';
import {
    buildBoardHeadMap,
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';
import { derivePollSpecHash } from '../lifecycle/poll-spec.js';
import { deriveFrozenRosterProfile } from '../lifecycle/thresholds.js';

import { deriveRosterHash } from './hashes.js';
import {
    mapInclusionProofsByObjectHash,
    verifyRequiredIncludedObjectPlacement,
} from './inclusion.js';
import {
    verifyManifest,
    verifyRegistrationEntry,
    verifyTrusteeSetupEntry,
} from './object-validation.js';

const findConflictingRawManifest = (
    input: RosterManifestTranscriptInput,
): ElectionManifest | undefined => {
    const acceptedManifest = input.electionManifest;

    return input.suppliedElectionManifests?.find(
        (manifest) =>
            manifest.ceremonyId === acceptedManifest.ceremonyId &&
            manifest.pollSpecHash === acceptedManifest.pollSpecHash &&
            manifest.electionManifestHash !==
                acceptedManifest.electionManifestHash,
    );
};

const normalizeIdentityForComparison = (identity: string): string =>
    identity.normalize('NFC');

const verifyRosterManifestTranscriptUnchecked = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByHash = buildBoardHeadMap(input.boardEvidence.signedBoardHeads);
    const registrationProofsByHash = mapInclusionProofsByObjectHash(
        input.registrationInclusionProofs,
    );
    const trusteeProofsByHash = mapInclusionProofsByObjectHash(
        input.trusteeSetupInclusionProofs,
    );
    const participantIdentities: string[] = [];
    const participantPublicKeys = new Map<string, ProtocolHash>();
    const seenParticipantIdentities = new Set<string>();

    refusedObjects.push(...boardResult.refusedObjects);
    if (input.boardEvidence.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Roster-manifest board evidence ceremony does not match the transcript.',
            ),
        );
    }

    for (const entry of input.registrationEntries) {
        refusedObjects.push(...verifyRegistrationEntry(input, entry));
        refusedObjects.push(
            ...verifyRequiredIncludedObjectPlacement({
                proofByHash: registrationProofsByHash,
                objectHash: entry.registrationEntryHash,
                expectedObjectType: 'RegistrationEntry',
                headsByHash,
                objectBoardSequence: entry.boardSequence,
                objectBoardPosition: entry.boardPosition,
                rosterFreezeBoardSequence: input.rosterFreezeBoardSequence,
            }),
        );

        const normalizedParticipantIdentity = normalizeIdentityForComparison(
            entry.participantIdentity,
        );
        if (seenParticipantIdentities.has(normalizedParticipantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateRegistration',
                    'Roster freeze rejects duplicate participant registrations after Unicode NFC normalization.',
                    entry.registrationEntryHash,
                    'RegistrationEntry',
                ),
            );
            continue;
        }

        seenParticipantIdentities.add(normalizedParticipantIdentity);
        participantPublicKeys.set(
            normalizedParticipantIdentity,
            entry.signingPublicKeyHash,
        );
        participantIdentities.push(normalizedParticipantIdentity);
    }

    const organizerPublicKeyHash = participantPublicKeys.get(
        normalizeIdentityForComparison(input.organizerIdentity),
    );
    if (organizerPublicKeyHash === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterHashMismatch',
                'Organizer identity must be part of the frozen all-trustee roster.',
            ),
        );
    } else if (organizerPublicKeyHash !== input.organizerPublicKeyHash) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Organizer public key must match the organizer roster registration.',
            ),
        );
    }

    const trusteeIdentities = new Set<string>();
    for (const entry of input.trusteeSetupEntries) {
        const normalizedTrusteeIdentity = normalizeIdentityForComparison(
            entry.trusteeIdentity,
        );
        if (trusteeIdentities.has(normalizedTrusteeIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateTrusteeSetupEntry',
                    'Roster freeze rejects duplicate trustee setup entries after Unicode NFC normalization.',
                    entry.trusteeSetupEntryHash,
                    'TrusteeSetupEntry',
                ),
            );
        }
        trusteeIdentities.add(normalizedTrusteeIdentity);
        refusedObjects.push(
            ...verifyTrusteeSetupEntry(
                input,
                entry,
                participantPublicKeys.get(normalizedTrusteeIdentity),
            ),
        );
        refusedObjects.push(
            ...verifyRequiredIncludedObjectPlacement({
                proofByHash: trusteeProofsByHash,
                objectHash: entry.trusteeSetupEntryHash,
                expectedObjectType: 'TrusteeSetupEntry',
                headsByHash,
                objectBoardSequence: entry.boardSequence,
                objectBoardPosition: entry.boardPosition,
                rosterFreezeBoardSequence: input.rosterFreezeBoardSequence,
            }),
        );
    }

    for (const participantIdentity of participantIdentities) {
        if (!trusteeIdentities.has(participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'MissingTrusteeSetupEntry',
                    'Every roster identity must have a trustee setup entry shell.',
                ),
            );
        }
    }

    const rosterHash = deriveRosterHash(input.registrationEntries);
    const pollSpecHash = derivePollSpecHash(input.pollSpec);
    if (input.electionManifest.pollSpecHash !== pollSpecHash) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest poll spec hash must match the transcript poll specification.',
                input.electionManifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    if (input.frozenRosterProfile.pollSpecHash !== pollSpecHash) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Frozen roster profile poll spec hash must match the transcript poll specification.',
                input.frozenRosterProfile.thresholdProfileHash,
                'FrozenRosterProfile',
            ),
        );
    }
    if (
        input.frozenRosterProfile.rosterHash !== rosterHash ||
        input.frozenRosterProfile.rosterSize !== participantIdentities.length
    ) {
        refusedObjects.push(
            createRefusal(
                'RosterHashMismatch',
                'Frozen roster profile must be derived from the accepted frozen roster.',
                input.frozenRosterProfile.thresholdProfileHash,
                'FrozenRosterProfile',
            ),
        );
    }
    try {
        const expectedFrozenRosterProfile = deriveFrozenRosterProfile({
            pollSpec: input.pollSpec,
            rosterHash,
            rosterSize: participantIdentities.length,
            dynamicRosterProfileCertificateHash:
                input.frozenRosterProfile.thresholdProfile
                    .dynamicRosterProfileCertificateHash ?? undefined,
        });
        if (
            expectedFrozenRosterProfile.thresholdProfileHash !==
            input.frozenRosterProfile.thresholdProfileHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'ManifestHashMismatch',
                    'Frozen roster profile threshold profile hash must match the roster-freeze derived profile.',
                    input.frozenRosterProfile.thresholdProfileHash,
                    'FrozenRosterProfile',
                ),
            );
        }
        if (
            canonicalJson(expectedFrozenRosterProfile) !==
            canonicalJson(input.frozenRosterProfile)
        ) {
            refusedObjects.push(
                createRefusal(
                    'ManifestHashMismatch',
                    'Frozen roster profile payload must match the roster-freeze derived profile.',
                    input.frozenRosterProfile.thresholdProfileHash,
                    'FrozenRosterProfile',
                ),
            );
        }
        if (
            expectedFrozenRosterProfile.thresholdProfileHash !==
            input.electionManifest.thresholdProfileHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'ManifestHashMismatch',
                    'Election manifest threshold profile hash must match the roster-freeze derived profile.',
                    input.electionManifest.electionManifestHash,
                    'ElectionManifest',
                ),
            );
        }
    } catch {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Frozen roster profile could not be derived from the poll policy and accepted roster.',
                input.frozenRosterProfile.thresholdProfileHash,
                'FrozenRosterProfile',
            ),
        );
    }
    refusedObjects.push(...verifyManifest(input, rosterHash));
    refusedObjects.push(
        ...verifyRequiredIncludedObjectPlacement({
            proofByHash: new Map([
                [
                    input.manifestInclusionProof.includedObjectHash,
                    input.manifestInclusionProof,
                ],
            ]),
            objectHash: input.electionManifest.electionManifestHash,
            expectedObjectType: 'ElectionManifest',
            headsByHash,
            objectBoardSequence: input.electionManifest.boardSequence,
            objectBoardPosition: input.electionManifest.boardPosition,
        }),
    );
    if (
        input.manifestInclusionProof.boardSequence <
        input.rosterFreezeBoardSequence
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest inclusion must not precede the roster freeze board sequence.',
                input.manifestInclusionProof.inclusionProofHash,
                'ElectionManifest',
            ),
        );
    }

    let conflictingManifest: ElectionManifest | undefined;
    const acceptedConflictingManifestEvidenceHashes: ProtocolHash[] = [];
    for (const evidence of input.conflictingManifestEvidence ?? []) {
        const evidenceRefusals: RefusalRecord[] = [
            ...verifyManifest(
                input,
                undefined,
                evidence.manifest,
                evidence.manifestInclusionProof,
            ),
            ...verifyInclusionProof(
                evidence.manifestInclusionProof,
                headsByHash,
            ),
        ];
        if (
            evidence.manifestInclusionProof.boardSequence !==
                evidence.manifest.boardSequence ||
            evidence.manifestInclusionProof.boardPosition !==
                evidence.manifest.boardPosition
        ) {
            evidenceRefusals.push(
                createRefusal(
                    'InclusionProofInvalid',
                    'Conflicting manifest board position must match its inclusion proof.',
                    evidence.manifestInclusionProof.inclusionProofHash,
                    'ElectionManifest',
                ),
            );
        }
        refusedObjects.push(...evidenceRefusals);
        if (evidenceRefusals.length > 0) {
            continue;
        }
        acceptedConflictingManifestEvidenceHashes.push(
            evidence.manifest.electionManifestHash,
            evidence.manifestInclusionProof.inclusionProofHash,
        );
        if (
            evidence.manifest.ceremonyId ===
                input.electionManifest.ceremonyId &&
            evidence.manifest.pollSpecHash ===
                input.electionManifest.pollSpecHash &&
            evidence.manifest.electionManifestHash !==
                input.electionManifest.electionManifestHash
        ) {
            conflictingManifest ??= evidence.manifest;
        }
    }

    const rawConflictingManifest = findConflictingRawManifest(input);
    if (rawConflictingManifest !== undefined) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Conflicting manifest evidence must include a board inclusion proof.',
                rawConflictingManifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }

    const forkEvidence = boardResult.forkEvidence;
    const statusLabels: readonly ProtocolVerificationStatusLabel[] =
        conflictingManifest === undefined && forkEvidence === undefined
            ? []
            : ['boardForkSuspected', 'boardEvidencePublished', 'forkDetected'];
    if (conflictingManifest !== undefined) {
        refusedObjects.push(
            createRefusal(
                'ConflictingManifest',
                'Supplied board view contains conflicting manifests for the same ceremony and poll spec.',
                conflictingManifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    const transcriptAccepted =
        refusedObjects.length === 0 && forkEvidence === undefined;

    return {
        ok: transcriptAccepted,
        statusLabels,
        acceptedHashes: transcriptAccepted
            ? uniqueStrings([
                  ...boardResult.acceptedHashes,
                  ...input.registrationEntries.map(
                      (entry) => entry.registrationEntryHash,
                  ),
                  ...input.trusteeSetupEntries.map(
                      (entry) => entry.trusteeSetupEntryHash,
                  ),
                  rosterHash,
                  input.electionManifest.electionManifestHash,
                  input.manifestInclusionProof.inclusionProofHash,
                  ...acceptedConflictingManifestEvidenceHashes,
              ])
            : [],
        refusedObjects,
        forkEvidence,
        electionManifestHash: transcriptAccepted
            ? input.electionManifest.electionManifestHash
            : undefined,
        rosterHash: transcriptAccepted ? rosterHash : undefined,
        participantIdentities,
    };
};

export const verifyRosterManifestTranscript = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification => {
    try {
        return verifyRosterManifestTranscriptUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'RosterHashMismatch',
                    'Roster-manifest transcript could not be canonicalized or validated.',
                ),
            ],
            participantIdentities: [],
        };
    }
};
