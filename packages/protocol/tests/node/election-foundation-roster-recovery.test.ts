import { describe, expect, it } from 'vitest';

import {
    createBoardEvidence,
    createBoardHeadWithObjects,
    createElectionManifest,
    createKeyFixture,
    createRegistrationEntry,
    createRosterManifestTranscriptInput,
    createSignature,
    deriveCollectiveBgvSetupRosterHash,
    deriveCanonicalObjectHash,
    deriveRosterHash,
    manifestOpaqueBindings,
    verifyRosterManifestTranscript,
} from './election-foundation-test-helpers';

describe('roster and manifest shells', () => {
    it('derives the collective setup roster hash from externally accepted roster entries', () => {
        const entries = [
            {
                rosterPosition: 2,
                trusteeIdentity: 'trustee-2',
                signingPublicKeyHash: 'c'.repeat(128),
            },
            {
                rosterPosition: 0,
                trusteeIdentity: 'trustee-0',
                signingPublicKeyHash: 'a'.repeat(128),
            },
            {
                rosterPosition: 1,
                trusteeIdentity: 'trustee-1',
                signingPublicKeyHash: 'b'.repeat(128),
            },
        ] as const;
        const expectedHash = deriveCanonicalObjectHash({
            objectType: 'CollectiveBgvSetupRoster',
            rosterEntries: [
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    objectVersion: 1,
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    objectVersion: 1,
                    rosterPosition: 1,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    objectVersion: 1,
                    rosterPosition: 2,
                    trusteeIdentity: 'trustee-2',
                    signingPublicKeyHash: 'c'.repeat(128),
                },
            ],
        });

        expect(deriveCollectiveBgvSetupRosterHash(entries)).toBe(expectedHash);
        expect(deriveCollectiveBgvSetupRosterHash([...entries].reverse())).toBe(
            expectedHash,
        );
    });

    it('rejects malformed collective setup roster hash inputs', () => {
        expect(() => deriveCollectiveBgvSetupRosterHash(null as never)).toThrow(
            /must be an array/u,
        );
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([null as never]),
        ).toThrow(/must be an object/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: -1,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
            ]),
        ).toThrow(/rosterPosition/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 0,
                    trusteeIdentity: '',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
            ]),
        ).toThrow(/trusteeIdentity/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
            ]),
        ).toThrow(/distinct roster positions/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'not-a-protocol-hash',
                },
            ]),
        ).toThrow(/signingPublicKeyHash/u);
    });

    it('accepts an honest registration to manifest transcript', () => {
        const registrations = [
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ];
        const input = createRosterManifestTranscriptInput(registrations);

        const result = verifyRosterManifestTranscript(input);

        expect(result.isValid).toBe(true);
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

        expect(result.isValid).toBe(false);
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

        expect(result.isValid).toBe(false);
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongSignerRole' }),
            ]),
        );
    });

    it('attributes frozen roster parameters mismatches to the frozen roster parameters', () => {
        const input = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ]);
        const changedFrozenRosterParameters = {
            ...input.frozenRosterParameters,
            pollSpecHash: deriveCanonicalObjectHash({
                objectType: 'PollSpecHash',
                poll: 'changed',
            }),
        };

        const result = verifyRosterManifestTranscript({
            ...input,
            frozenRosterParameters: changedFrozenRosterParameters,
        });

        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ManifestHashMismatch',
                    objectHash:
                        changedFrozenRosterParameters.thresholdParametersHash,
                    objectType: 'FrozenRosterParameters',
                }),
            ]),
        );
    });

    it('rejects frozen roster parameterss with mismatched embedded threshold payloads', () => {
        const input = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ]);
        const changedFrozenRosterParameters = {
            ...input.frozenRosterParameters,
            thresholdParameters: {
                ...input.frozenRosterParameters.thresholdParameters,
                releaseQuorum:
                    input.frozenRosterParameters.thresholdParameters
                        .releaseQuorum + 1,
            },
        };

        const result = verifyRosterManifestTranscript({
            ...input,
            frozenRosterParameters: changedFrozenRosterParameters,
        });

        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ManifestHashMismatch',
                    message:
                        'Frozen roster parameters payload must match the roster-freeze derived parameters.',
                    objectHash:
                        changedFrozenRosterParameters.thresholdParametersHash,
                    objectType: 'FrozenRosterParameters',
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

        expect(result.isValid).toBe(false);
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
            thresholdParametersHash: deriveCanonicalObjectHash({
                objectType: 'ThresholdParametersHash',
                parameters: 'different-threshold-parameters',
            }),
        });
        const wrongFixedParametersManifest = createElectionManifest(
            registrations,
            {
                boardSequence: 4,
                manifestOpaqueBindings: {
                    ...manifestOpaqueBindings,
                    bgvParametersHash: deriveCanonicalObjectHash({
                        objectType: 'BGVParametersHash',
                        parameters: 'unsupported-fixed-parameters',
                    }),
                },
            },
        );
        const incompleteOpaqueBindings = {
            ...manifestOpaqueBindings,
        } as Record<string, unknown>;
        delete incompleteOpaqueBindings.bgvParametersHash;
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
            pollSpecHash: deriveCanonicalObjectHash({
                objectType: 'PollSpecHash',
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
                electionManifest: wrongFixedParametersManifest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'ManifestHashMismatch' }),
            ]),
        );
        expect(
            verifyRosterManifestTranscript({
                ...input,
                electionManifest: manifestWithIncompleteOpaqueBindings,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ManifestHashMismatch',
                    message:
                        'Election manifest opaque bindings must include canonical setup and target bindings.',
                }),
            ]),
        );
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
