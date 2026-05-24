import { canonicalJson } from '@sealed-lattice/crypto';
import type {
    ElectionManifest,
    ProtocolDigest,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import {
    buildBoardHeadMap,
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';
import { derivePollSpecDigest } from '../lifecycle/poll-spec.js';
import { deriveFrozenRosterProfile } from '../lifecycle/thresholds.js';

import { deriveRosterDigest } from './digests.js';
import {
    mapInclusionProofsByObjectDigest,
    verifyRequiredIncludedObjectPlacement,
} from './inclusion.js';
import {
    verifyManifest,
    verifyReceiverKeyRegistration,
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
            manifest.pollSpecDigest === acceptedManifest.pollSpecDigest &&
            manifest.electionManifestDigest !==
                acceptedManifest.electionManifestDigest,
    );
};

const verifyRosterManifestTranscriptUnchecked = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );
    const registrationProofsByDigest = mapInclusionProofsByObjectDigest(
        input.registrationInclusionProofs,
    );
    const receiverProofsByDigest = mapInclusionProofsByObjectDigest(
        input.receiverKeyRegistrationInclusionProofs,
    );
    const trusteeProofsByDigest = mapInclusionProofsByObjectDigest(
        input.trusteeSetupInclusionProofs,
    );
    const participantIdentities: string[] = [];
    const participantPublicKeys = new Map<string, ProtocolDigest>();
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
                proofByDigest: registrationProofsByDigest,
                objectDigest: entry.registrationEntryDigest,
                expectedObjectType: 'RegistrationEntry',
                headsByDigest,
                objectBoardSequence: entry.boardSequence,
                objectBoardPosition: entry.boardPosition,
                rosterFreezeBoardSequence: input.rosterFreezeBoardSequence,
            }),
        );

        if (seenParticipantIdentities.has(entry.participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateRegistration',
                    'Roster freeze rejects duplicate participant registrations.',
                    entry.registrationEntryDigest,
                    'RegistrationEntry',
                ),
            );
            continue;
        }

        seenParticipantIdentities.add(entry.participantIdentity);
        participantPublicKeys.set(
            entry.participantIdentity,
            entry.signingPublicKeyDigest,
        );
        participantIdentities.push(entry.participantIdentity);
    }

    const organizerPublicKeyDigest = participantPublicKeys.get(
        input.organizerIdentity,
    );
    if (organizerPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Organizer identity must be part of the frozen all-trustee roster.',
            ),
        );
    } else if (organizerPublicKeyDigest !== input.organizerPublicKeyDigest) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Organizer public key must match the organizer roster registration.',
            ),
        );
    }

    const receiverIdentities = new Set<string>();
    for (const entry of input.receiverKeyRegistrations) {
        if (receiverIdentities.has(entry.participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateReceiverKeyRegistration',
                    'Roster freeze rejects duplicate receiver-key registrations.',
                    entry.receiverKeyRegistrationDigest,
                    'ReceiverKeyRegistration',
                ),
            );
        }
        receiverIdentities.add(entry.participantIdentity);
        refusedObjects.push(
            ...verifyReceiverKeyRegistration(
                input,
                entry,
                participantPublicKeys.get(entry.participantIdentity),
            ),
        );
        refusedObjects.push(
            ...verifyRequiredIncludedObjectPlacement({
                proofByDigest: receiverProofsByDigest,
                objectDigest: entry.receiverKeyRegistrationDigest,
                expectedObjectType: 'ReceiverKeyRegistration',
                headsByDigest,
                objectBoardSequence: entry.boardSequence,
                objectBoardPosition: entry.boardPosition,
                rosterFreezeBoardSequence: input.rosterFreezeBoardSequence,
            }),
        );
    }

    const trusteeIdentities = new Set<string>();
    for (const entry of input.trusteeSetupEntries) {
        if (trusteeIdentities.has(entry.trusteeIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateTrusteeSetupEntry',
                    'Roster freeze rejects duplicate trustee setup entries.',
                    entry.trusteeSetupEntryDigest,
                    'TrusteeSetupEntry',
                ),
            );
        }
        trusteeIdentities.add(entry.trusteeIdentity);
        refusedObjects.push(
            ...verifyTrusteeSetupEntry(
                input,
                entry,
                participantPublicKeys.get(entry.trusteeIdentity),
            ),
        );
        refusedObjects.push(
            ...verifyRequiredIncludedObjectPlacement({
                proofByDigest: trusteeProofsByDigest,
                objectDigest: entry.trusteeSetupEntryDigest,
                expectedObjectType: 'TrusteeSetupEntry',
                headsByDigest,
                objectBoardSequence: entry.boardSequence,
                objectBoardPosition: entry.boardPosition,
                rosterFreezeBoardSequence: input.rosterFreezeBoardSequence,
            }),
        );
    }

    for (const participantIdentity of participantIdentities) {
        if (!receiverIdentities.has(participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'MissingReceiverKeyRegistration',
                    'Every roster identity must have a receiver-key registration shell.',
                ),
            );
        }
        if (!trusteeIdentities.has(participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'MissingTrusteeSetupEntry',
                    'Every roster identity must have a trustee setup entry shell.',
                ),
            );
        }
    }

    const rosterDigest = deriveRosterDigest(input.registrationEntries);
    const pollSpecDigest = derivePollSpecDigest(input.pollSpec);
    if (input.electionManifest.pollSpecDigest !== pollSpecDigest) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest poll spec digest must match the transcript poll specification.',
                input.electionManifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (input.frozenRosterProfile.pollSpecDigest !== pollSpecDigest) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Frozen roster profile poll spec digest must match the transcript poll specification.',
                input.frozenRosterProfile.thresholdProfileDigest,
                'FrozenRosterProfile',
            ),
        );
    }
    if (
        input.frozenRosterProfile.rosterDigest !== rosterDigest ||
        input.frozenRosterProfile.rosterSize !== participantIdentities.length
    ) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Frozen roster profile must be derived from the accepted frozen roster.',
                input.frozenRosterProfile.thresholdProfileDigest,
                'FrozenRosterProfile',
            ),
        );
    }
    try {
        const expectedFrozenRosterProfile = deriveFrozenRosterProfile({
            pollSpec: input.pollSpec,
            rosterDigest,
            rosterSize: participantIdentities.length,
            dynamicRosterProfileCertificateDigest:
                input.frozenRosterProfile.thresholdProfile
                    .dynamicRosterProfileCertificateDigest ?? undefined,
        });
        if (
            expectedFrozenRosterProfile.thresholdProfileDigest !==
            input.frozenRosterProfile.thresholdProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'ManifestDigestMismatch',
                    'Frozen roster profile threshold profile digest must match the roster-freeze derived profile.',
                    input.frozenRosterProfile.thresholdProfileDigest,
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
                    'ManifestDigestMismatch',
                    'Frozen roster profile payload must match the roster-freeze derived profile.',
                    input.frozenRosterProfile.thresholdProfileDigest,
                    'FrozenRosterProfile',
                ),
            );
        }
        if (
            expectedFrozenRosterProfile.thresholdProfileDigest !==
            input.electionManifest.thresholdProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'ManifestDigestMismatch',
                    'Election manifest threshold profile digest must match the roster-freeze derived profile.',
                    input.electionManifest.electionManifestDigest,
                    'ElectionManifest',
                ),
            );
        }
    } catch {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Frozen roster profile could not be derived from the poll policy and accepted roster.',
                input.frozenRosterProfile.thresholdProfileDigest,
                'FrozenRosterProfile',
            ),
        );
    }
    refusedObjects.push(...verifyManifest(input, rosterDigest));
    refusedObjects.push(
        ...verifyRequiredIncludedObjectPlacement({
            proofByDigest: new Map([
                [
                    input.manifestInclusionProof.includedObjectDigest,
                    input.manifestInclusionProof,
                ],
            ]),
            objectDigest: input.electionManifest.electionManifestDigest,
            expectedObjectType: 'ElectionManifest',
            headsByDigest,
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
                'ManifestDigestMismatch',
                'Election manifest inclusion must not precede the roster freeze board sequence.',
                input.manifestInclusionProof.inclusionProofDigest,
                'ElectionManifest',
            ),
        );
    }

    let conflictingManifest: ElectionManifest | undefined;
    const acceptedConflictingManifestEvidenceDigests: ProtocolDigest[] = [];
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
                headsByDigest,
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
                    evidence.manifestInclusionProof.inclusionProofDigest,
                    'ElectionManifest',
                ),
            );
        }
        refusedObjects.push(...evidenceRefusals);
        if (evidenceRefusals.length > 0) {
            continue;
        }
        acceptedConflictingManifestEvidenceDigests.push(
            evidence.manifest.electionManifestDigest,
            evidence.manifestInclusionProof.inclusionProofDigest,
        );
        if (
            evidence.manifest.ceremonyId ===
                input.electionManifest.ceremonyId &&
            evidence.manifest.pollSpecDigest ===
                input.electionManifest.pollSpecDigest &&
            evidence.manifest.electionManifestDigest !==
                input.electionManifest.electionManifestDigest
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
                rawConflictingManifest.electionManifestDigest,
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
                conflictingManifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    const transcriptAccepted =
        refusedObjects.length === 0 && forkEvidence === undefined;

    return {
        ok: transcriptAccepted,
        statusLabels,
        acceptedDigests: transcriptAccepted
            ? uniqueStrings([
                  ...boardResult.acceptedDigests,
                  ...input.registrationEntries.map(
                      (entry) => entry.registrationEntryDigest,
                  ),
                  ...input.receiverKeyRegistrations.map(
                      (entry) => entry.receiverKeyRegistrationDigest,
                  ),
                  ...input.trusteeSetupEntries.map(
                      (entry) => entry.trusteeSetupEntryDigest,
                  ),
                  rosterDigest,
                  input.electionManifest.electionManifestDigest,
                  input.manifestInclusionProof.inclusionProofDigest,
                  ...acceptedConflictingManifestEvidenceDigests,
              ])
            : [],
        refusedObjects,
        forkEvidence,
        electionManifestDigest: transcriptAccepted
            ? input.electionManifest.electionManifestDigest
            : undefined,
        rosterDigest: transcriptAccepted ? rosterDigest : undefined,
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
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'RosterDigestMismatch',
                    'Roster-manifest transcript could not be canonicalized or validated.',
                ),
            ],
            participantIdentities: [],
        };
    }
};
