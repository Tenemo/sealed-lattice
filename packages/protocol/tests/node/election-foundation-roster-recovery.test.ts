import { describe, expect, it } from 'vitest';

import {
    createBoardEvidence,
    createBoardHeadWithObjects,
    createElectionManifest,
    createKeyFixture,
    createRegistrationEntry,
    createRosterManifestTranscriptInput,
    createSignature,
    deriveProtocolHash,
    deriveRosterHash,
    manifestOpaqueBindings,
    verifyRosterManifestTranscript,
} from './election-foundation-test-helpers';

const retiredThresholdDecryptionProfileId =
    'unsupported-target-decryption-profile-v0';
const retiredBallotValidityProofProfileId = 'PQEvalProof-STARK-BGVReplay-v1';

describe('roster and manifest shells', () => {
    it('accepts an honest registration to manifest transcript', () => {
        const registrations = [
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ];
        const input = createRosterManifestTranscriptInput(registrations);

        const result = verifyRosterManifestTranscript(input);

        expect(result.ok).toBe(true);
        expect(result.participantIdentities).toEqual([
            'participant-1',
            'participant-2',
            'participant-3',
            'organizer',
        ]);
        expect(result.rosterHash).toBe(
            deriveRosterHash(input.registrationEntries),
        );
    });

    it('rejects roster identities that collide after Unicode normalization', () => {
        const registrations = [
            createRegistrationEntry('Cafe\u0301', 1, 0),
            createRegistrationEntry('Caf\u00e9', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ];
        const input = createRosterManifestTranscriptInput(registrations);
        const result = verifyRosterManifestTranscript(input);

        expect(result.ok).toBe(false);
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DuplicateRegistration' }),
            ]),
        );
    });

    it('requires object signatures rather than transport authentication for manifests', () => {
        const input = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ]);
        const transportOnlyKey = createKeyFixture('transport-session-only');
        const manifestWithTransportOnlySignature = {
            ...input.electionManifest,
            signature: createSignature(
                'ElectionManifest',
                'Participant',
                'participant-1',
                transportOnlyKey.publicKeyHash,
                input.electionManifest.electionManifestHash,
            ),
        };

        const result = verifyRosterManifestTranscript({
            ...input,
            electionManifest: manifestWithTransportOnlySignature,
        });

        expect(result.ok).toBe(false);
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongSignerRole' }),
            ]),
        );
    });

    it('rejects retired direct-path profile identifiers in claim-bearing manifests', () => {
        const registrations = [
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ];
        const oldThresholdProfileInput = createRosterManifestTranscriptInput(
            registrations,
            {
                manifestOpaqueBindings: {
                    ...manifestOpaqueBindings,
                    targetDecryptionProfileId:
                        retiredThresholdDecryptionProfileId,
                },
            },
        );
        const oldBallotProofProfileInput = createRosterManifestTranscriptInput(
            registrations,
            {
                manifestOpaqueBindings: {
                    ...manifestOpaqueBindings,
                    ballotValidityProofProfileId:
                        retiredBallotValidityProofProfileId,
                },
            },
        );

        for (const input of [
            oldThresholdProfileInput,
            oldBallotProofProfileInput,
        ]) {
            const result = verifyRosterManifestTranscript(input);

            expect(result.ok).toBe(false);
            expect(result.refusedObjects).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: 'ManifestHashMismatch',
                    }),
                ]),
            );
        }
    });

    it('attributes frozen roster profile mismatches to the frozen profile', () => {
        const input = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ]);
        const changedFrozenRosterProfile = {
            ...input.frozenRosterProfile,
            pollSpecHash: deriveProtocolHash('PollSpecHash', {
                poll: 'changed',
            }),
        };

        const result = verifyRosterManifestTranscript({
            ...input,
            frozenRosterProfile: changedFrozenRosterProfile,
        });

        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ManifestHashMismatch',
                    objectHash: changedFrozenRosterProfile.thresholdProfileHash,
                    objectType: 'FrozenRosterProfile',
                }),
            ]),
        );
    });

    it('rejects frozen roster profiles with mismatched embedded threshold payloads', () => {
        const input = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ]);
        const changedFrozenRosterProfile = {
            ...input.frozenRosterProfile,
            thresholdProfile: {
                ...input.frozenRosterProfile.thresholdProfile,
                claimBearing: true,
                releaseQuorum:
                    input.frozenRosterProfile.thresholdProfile.releaseQuorum +
                    1,
            },
        };

        const result = verifyRosterManifestTranscript({
            ...input,
            frozenRosterProfile: changedFrozenRosterProfile,
        });

        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ManifestHashMismatch',
                    message:
                        'Frozen roster profile payload must match the roster-freeze derived profile.',
                    objectHash: changedFrozenRosterProfile.thresholdProfileHash,
                    objectType: 'FrozenRosterProfile',
                }),
            ]),
        );
    });

    it('rejects a manifest organizer that is not part of the all-trustee roster', () => {
        const input = createRosterManifestTranscriptInput(
            [
                createRegistrationEntry('participant-1', 1, 0),
                createRegistrationEntry('participant-2', 1, 1),
                createRegistrationEntry('participant-3', 1, 2),
            ],
            {},
            { includeOrganizer: false },
        );

        const result = verifyRosterManifestTranscript(input);

        expect(result.ok).toBe(false);
        expect(result.acceptedHashes).toEqual([]);
        expect(result.electionManifestHash).toBeUndefined();
        expect(result.rosterHash).toBeUndefined();
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RosterHashMismatch' }),
            ]),
        );
    });

    it('rejects duplicate, late, conflicting, and changed manifest inputs', () => {
        const firstRegistration = createRegistrationEntry(
            'participant-1',
            1,
            0,
        );
        const duplicateRegistration = createRegistrationEntry(
            'participant-1',
            1,
            1,
        );
        const lateRegistration = createRegistrationEntry('participant-2', 5, 0);
        const registrations = [firstRegistration, duplicateRegistration];
        const input = createRosterManifestTranscriptInput([
            firstRegistration,
            duplicateRegistration,
            lateRegistration,
        ]);
        const changedManifest = createElectionManifest(registrations, {
            boardSequence: 4,
            thresholdProfileHash: deriveProtocolHash('ThresholdProfileHash', {
                profile: 'different-threshold-profile',
            }),
        });
        const wrongFixedProfileManifest = createElectionManifest(
            registrations,
            {
                boardSequence: 4,
                manifestOpaqueBindings: {
                    ...manifestOpaqueBindings,
                    evaluatorReplayProfileId:
                        'unsupported-evaluator-replay-profile',
                },
            },
        );
        const manifestWithUnexpectedOpaqueBinding = createElectionManifest(
            registrations,
            {
                boardSequence: 4,
                manifestOpaqueBindings: {
                    ...manifestOpaqueBindings,
                    unexpectedDirectBindingHash: deriveProtocolHash(
                        'ChallengeDomainHash',
                        {
                            payload: { profile: 'unexpected-profile-binding' },
                            purpose: 'fixture-unexpected-direct-binding-v1',
                        },
                    ),
                } as typeof manifestOpaqueBindings,
            },
        );
        const incompleteOpaqueBindings = {
            ...manifestOpaqueBindings,
        } as Record<string, unknown>;
        delete incompleteOpaqueBindings.encryptedBallotLayoutHash;
        const manifestWithIncompleteOpaqueBindings = createElectionManifest(
            registrations,
            {
                boardSequence: 4,
                manifestOpaqueBindings:
                    incompleteOpaqueBindings as typeof manifestOpaqueBindings,
            },
        );
        const changedPollSpecManifest = createElectionManifest(registrations, {
            boardSequence: 4,
            pollSpecHash: deriveProtocolHash('PollSpecHash', {
                poll: 'different',
            }),
        });
        const lastHead =
            input.boardEvidence.signedBoardHeads[
                input.boardEvidence.signedBoardHeads.length - 1
            ];
        if (lastHead === undefined) {
            throw new Error('Expected roster fixture to include board heads.');
        }
        const { head: conflictHead, inclusionProofs: conflictProofs } =
            createBoardHeadWithObjects(4, lastHead.headHash, [
                {
                    objectType: 'ElectionManifest',
                    objectHash: changedManifest.electionManifestHash,
                    boardPosition: changedManifest.boardPosition,
                },
            ]);
        const {
            head: differentPollSpecHead,
            inclusionProofs: differentPollSpecProofs,
        } = createBoardHeadWithObjects(4, lastHead.headHash, [
            {
                objectType: 'ElectionManifest',
                objectHash: changedPollSpecManifest.electionManifestHash,
                boardPosition: changedPollSpecManifest.boardPosition,
            },
        ]);

        expect(
            verifyRosterManifestTranscript({
                ...input,
                electionManifest: createElectionManifest(registrations),
                boardEvidence: createBoardEvidence([
                    ...input.boardEvidence.signedBoardHeads,
                    conflictHead,
                ]),
                conflictingManifestEvidence: [
                    {
                        manifest: changedManifest,
                        manifestInclusionProof: conflictProofs[0],
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DuplicateRegistration' }),
                expect.objectContaining({ code: 'LateRegistration' }),
                expect.objectContaining({ code: 'RosterHashMismatch' }),
                expect.objectContaining({ code: 'ConflictingManifest' }),
            ]),
        );
        expect(
            verifyRosterManifestTranscript({
                ...input,
                boardEvidence: createBoardEvidence([
                    ...input.boardEvidence.signedBoardHeads,
                    differentPollSpecHead,
                ]),
                conflictingManifestEvidence: [
                    {
                        manifest: changedPollSpecManifest,
                        manifestInclusionProof: differentPollSpecProofs[0],
                    },
                ],
            }).refusedObjects,
        ).not.toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'ConflictingManifest' }),
            ]),
        );
        expect(
            verifyRosterManifestTranscript({
                ...input,
                electionManifest: wrongFixedProfileManifest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'ManifestHashMismatch' }),
            ]),
        );
        for (const manifest of [
            manifestWithUnexpectedOpaqueBinding,
            manifestWithIncompleteOpaqueBindings,
        ]) {
            expect(
                verifyRosterManifestTranscript({
                    ...input,
                    electionManifest: manifest,
                }).refusedObjects,
            ).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        code: 'ManifestHashMismatch',
                        message:
                            'Election manifest opaque bindings must use the current direct encrypted ballot schema.',
                    }),
                ]),
            );
        }
        expect(
            verifyRosterManifestTranscript({
                ...input,
                suppliedElectionManifests: [changedManifest],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );
    });

    it('rejects roster objects included after freeze even if their signed payload claims an earlier position', () => {
        const registration = createRegistrationEntry('participant-1', 1, 0);
        const input = createRosterManifestTranscriptInput([
            registration,
            createRegistrationEntry('participant-2', 1, 1),
        ]);
        const lastHead =
            input.boardEvidence.signedBoardHeads[
                input.boardEvidence.signedBoardHeads.length - 1
            ];
        if (lastHead === undefined) {
            throw new Error('Expected roster fixture to include board heads.');
        }
        const { head: lateHead, inclusionProofs } = createBoardHeadWithObjects(
            4,
            lastHead.headHash,
            [
                {
                    objectType: 'RegistrationEntry',
                    objectHash: registration.registrationEntryHash,
                    boardPosition: 0,
                },
            ],
        );

        expect(
            verifyRosterManifestTranscript({
                ...input,
                boardEvidence: createBoardEvidence([
                    ...input.boardEvidence.signedBoardHeads,
                    lateHead,
                ]),
                registrationInclusionProofs: [inclusionProofs[0]],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
                expect.objectContaining({ code: 'LateRegistration' }),
            ]),
        );
    });

    it('rejects signed registration reuse as trustee setup evidence', () => {
        const registration = createRegistrationEntry('participant-1', 1, 0);
        const input = createRosterManifestTranscriptInput([
            registration,
            createRegistrationEntry('participant-2', 1, 1),
        ]);

        expect(
            verifyRosterManifestTranscript({
                ...input,
                trusteeSetupEntries: [
                    {
                        ...input.trusteeSetupEntries[0],
                        signature: registration.signature,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongObjectType' }),
            ]),
        );
    });
});
