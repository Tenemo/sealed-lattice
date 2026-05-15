import { describe, expect, it } from 'vitest';

import {
    type ActionContext,
    type FirstValidOrderingInput,
    type RecoveryEpochMapEntry,
    type RecoveryEpochUpdate,
    type ValidatedFirstValidObject,
    ceremonyId,
    contextDigest,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createElectionManifest,
    createKeyFixture,
    createRegistrationEntry,
    createRosterManifestTranscriptInput,
    createSignature,
    deriveActionContextDigest,
    deriveProtocolDigest,
    deriveRecoveryEpochUpdateDigest,
    deriveRosterDigest,
    deriveValidatedFirstValidOrder,
    isActionCurrentForRecoveryEpoch,
    manifestOpaqueBindings,
    manifestPolicyDigests,
    recoveryRootKeyFixture,
    verifyRecoveryEpochUpdate,
    verifyRosterManifestTranscript,
} from './election-foundation-test-helpers';

describe('roster, manifest, first-valid, and recovery shells', () => {
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
        expect(result.rosterDigest).toBe(
            deriveRosterDigest(input.registrationEntries),
        );
    });

    it('rejects a manifest organizer that is not part of the all-trustee roster', () => {
        const input = createRosterManifestTranscriptInput(
            [createRegistrationEntry('participant-1', 1, 0)],
            {},
            { includeOrganizer: false },
        );

        const result = verifyRosterManifestTranscript(input);

        expect(result.ok).toBe(false);
        expect(result.acceptedDigests).toEqual([]);
        expect(result.electionManifestDigest).toBeUndefined();
        expect(result.rosterDigest).toBeUndefined();
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RosterDigestMismatch' }),
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
            manifestOpaqueBindings: {
                ...manifestOpaqueBindings,
                mobileProfileId: 'different-mobile-profile',
            },
        });
        const wrongFixedProfileManifest = createElectionManifest(
            registrations,
            {
                boardSequence: 4,
                manifestOpaqueBindings: {
                    ...manifestOpaqueBindings,
                    evaluationProofProfileId:
                        'unsupported-evaluation-proof-profile',
                },
            },
        );
        const changedPollSpecManifest = createElectionManifest(registrations, {
            boardSequence: 4,
            pollSpecDigest: deriveProtocolDigest('PollSpecDigest', {
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
            createBoardHeadWithObjects(4, lastHead.headDigest, [
                {
                    objectType: 'ElectionManifest',
                    objectDigest: changedManifest.electionManifestDigest,
                    boardPosition: changedManifest.boardPosition,
                },
            ]);
        const {
            head: differentPollSpecHead,
            inclusionProofs: differentPollSpecProofs,
        } = createBoardHeadWithObjects(4, lastHead.headDigest, [
            {
                objectType: 'ElectionManifest',
                objectDigest: changedPollSpecManifest.electionManifestDigest,
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
                expect.objectContaining({ code: 'RosterDigestMismatch' }),
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
                expect.objectContaining({ code: 'ManifestDigestMismatch' }),
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
        const input = createRosterManifestTranscriptInput([registration]);
        const lastHead =
            input.boardEvidence.signedBoardHeads[
                input.boardEvidence.signedBoardHeads.length - 1
            ];
        if (lastHead === undefined) {
            throw new Error('Expected roster fixture to include board heads.');
        }
        const { head: lateHead, inclusionProofs } = createBoardHeadWithObjects(
            4,
            lastHead.headDigest,
            [
                {
                    objectType: 'RegistrationEntry',
                    objectDigest: registration.registrationEntryDigest,
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
        const input = createRosterManifestTranscriptInput([registration]);

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

    it('orders validated first-valid candidates and deduplicates retransmission', () => {
        const recoveryEpochState: RecoveryEpochMapEntry = {
            signerIdentity: 'participant-1',
            currentRecoveryEpoch: 0,
            currentDeviceEpoch: 0,
        };
        const objects: ValidatedFirstValidObject[] = [
            {
                objectDigest: 'object-b',
                objectType: 'TargetFinalityRecord',
                boardSequence: 2,
                boardPosition: 1,
                signerIdentity: 'participant-2',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: false,
            },
            {
                objectDigest: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSequence: 1,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: false,
            },
            {
                objectDigest: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSequence: 3,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: true,
            },
        ];
        const input: FirstValidOrderingInput = {
            objects,
            requiredContextDigest: contextDigest,
            selectionPolicyDigest: manifestPolicyDigests.firstValidPolicyDigest,
            expectedSelectionPolicyDigest:
                manifestPolicyDigests.firstValidPolicyDigest,
            currentRecoveryEpochMap: {
                'participant-1': recoveryEpochState,
                'participant-2': {
                    signerIdentity: 'participant-2',
                    currentRecoveryEpoch: 0,
                    currentDeviceEpoch: 0,
                },
            },
        };

        expect(deriveValidatedFirstValidOrder(input)).toMatchObject({
            ok: true,
            orderedObjects: [
                expect.objectContaining({ objectDigest: 'object-a' }),
                expect.objectContaining({ objectDigest: 'object-b' }),
            ],
        });

        const badInput: FirstValidOrderingInput = {
            ...input,
            selectionPolicyDigest: deriveProtocolDigest(
                'FirstValidPolicyDigest',
                { policy: 'wrong' },
            ),
            objects: [
                {
                    ...objects[0],
                    contextDigest: deriveProtocolDigest('ActionContextDigest', {
                        context: 'wrong',
                    }),
                },
                objects[1],
                {
                    ...objects[1],
                    objectDigest: 'object-stale',
                    recoveryEpoch: 9,
                    actionSequence: 1,
                },
                {
                    ...objects[1],
                    objectDigest: 'object-c',
                },
            ],
        };

        expect(deriveValidatedFirstValidOrder(badInput).refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'FirstValidPolicyMismatch' }),
                expect.objectContaining({ code: 'FirstValidContextMismatch' }),
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
                expect.objectContaining({
                    code: 'ConflictingFirstValidObject',
                }),
            ]),
        );
    });

    it('rejects same-identity first-valid conflicts across action sequences', () => {
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextDigest: contextDigest,
                selectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                expectedSelectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                objects: [
                    {
                        objectDigest: 'object-a',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                    {
                        objectDigest: 'object-b',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 1,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 1,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ConflictingFirstValidObject',
                }),
            ]),
        );
    });

    it('rejects malformed first-valid candidate shape before ordering', () => {
        const baseCandidate: ValidatedFirstValidObject = {
            objectDigest: 'object-a',
            objectType: 'TargetFinalityRecord',
            boardSequence: 1,
            boardPosition: 0,
            signerIdentity: 'participant-1',
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 0,
            contextDigest,
            isByteIdenticalRetransmission: false,
        };
        const result = deriveValidatedFirstValidOrder({
            requiredContextDigest: contextDigest,
            selectionPolicyDigest: manifestPolicyDigests.firstValidPolicyDigest,
            expectedSelectionPolicyDigest:
                manifestPolicyDigests.firstValidPolicyDigest,
            currentRecoveryEpochMap: {
                'participant-1': {
                    signerIdentity: 'participant-1',
                    currentRecoveryEpoch: 0,
                    currentDeviceEpoch: 0,
                },
            },
            objects: [
                {
                    ...baseCandidate,
                    objectDigest: 'negative-position',
                    boardPosition: -1,
                },
                {
                    ...baseCandidate,
                    objectDigest: 'unsafe-action-sequence',
                    actionSequence: Number.MAX_SAFE_INTEGER + 1,
                },
                {
                    ...baseCandidate,
                    objectDigest: '',
                },
                {
                    ...baseCandidate,
                    objectDigest: 'malformed-retransmission-flag',
                    isByteIdenticalRetransmission: 'yes' as unknown as boolean,
                },
            ],
        });

        expect(result.ok).toBe(false);
        expect(result.orderedObjects).toEqual([]);
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'FirstValidPolicyMismatch',
                    message:
                        'First-valid object sequence and epoch fields must be non-negative safe integers.',
                }),
                expect.objectContaining({
                    code: 'FirstValidPolicyMismatch',
                    message:
                        'First-valid object string fields must be non-empty canonical strings.',
                }),
                expect.objectContaining({
                    code: 'FirstValidPolicyMismatch',
                    message:
                        'First-valid object retransmission flag must be boolean.',
                }),
            ]),
        );
    });

    it('rejects mixed stale recovery and current device epochs before the old-action cutoff', () => {
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextDigest: contextDigest,
                selectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                expectedSelectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 1,
                        currentDeviceEpoch: 1,
                        oldActionCutoffBoardSequence: 10,
                    },
                },
                objects: [
                    {
                        objectDigest: 'object-mixed-epoch',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 9,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 1,
                        actionSequence: 0,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
            ]),
        );
    });

    it('verifies recovery updates and refuses stale action contexts', () => {
        const currentEntry: RecoveryEpochMapEntry = {
            signerIdentity: 'participant-1',
            currentRecoveryEpoch: 0,
            currentDeviceEpoch: 0,
        };
        const recoveryGenesisHead = createBoardHead(0, null);
        const recoveryHead1 = createBoardHead(
            1,
            recoveryGenesisHead.headDigest,
        );
        const recoveryHead2 = createBoardHead(2, recoveryHead1.headDigest);
        const recoveryHead3 = createBoardHead(3, recoveryHead2.headDigest);
        const recoveryContextHead = createBoardHead(
            4,
            recoveryHead3.headDigest,
        );
        const newSigningKeyFixture = createKeyFixture(
            'participant:participant-1:new-signing',
        );
        const payload = {
            objectType: 'RecoveryEpochUpdate',
            objectVersion: 1,
            ceremonyId,
            signerIdentity: 'participant-1',
            recoveryRootPublicKeyDigest: recoveryRootKeyFixture.publicKeyDigest,
            recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
            previousRecoveryEpoch: 0,
            newRecoveryEpoch: 1,
            previousDeviceEpoch: 0,
            newDeviceEpoch: 1,
            oldActionCutoffBoardSequence: 5,
            boardHeadDigest: recoveryContextHead.headDigest,
            newSigningPublicKeyDigest: newSigningKeyFixture.publicKeyDigest,
            restoredFrozenReceiverStateCommitment: deriveProtocolDigest(
                'EncryptedEnvelopeRoot',
                { receiverState: 'restored' },
            ),
            newTrusteeSetupCommitment: deriveProtocolDigest(
                'CollectivePublicKeyRoot',
                { trusteeSetup: 'new' },
            ),
        } satisfies Omit<
            RecoveryEpochUpdate,
            'recoveryEpochUpdateDigest' | 'signature'
        >;
        const recoveryEpochUpdateDigest =
            deriveRecoveryEpochUpdateDigest(payload);
        const update: RecoveryEpochUpdate = {
            ...payload,
            recoveryEpochUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                recoveryEpochUpdateDigest,
                { boardHeadDigest: payload.boardHeadDigest },
            ),
        };
        const { head: recoveryUpdateHead, inclusionProofs } =
            createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
                {
                    objectType: 'RecoveryEpochUpdate',
                    objectDigest: recoveryEpochUpdateDigest,
                    boardPosition: 0,
                },
            ]);
        const recoveryUpdateInclusionProof = inclusionProofs[0];
        const verification = verifyRecoveryEpochUpdate({
            update,
            currentEntry,
            expectedRecoveryRootPublicKeyDigest:
                recoveryRootKeyFixture.publicKeyDigest,
            expectedRecoveryPolicyDigest:
                manifestPolicyDigests.recoveryPolicyDigest,
            boardEvidence: createBoardEvidence([
                recoveryGenesisHead,
                recoveryHead1,
                recoveryHead2,
                recoveryHead3,
                recoveryContextHead,
                recoveryUpdateHead,
            ]),
            updateInclusionProof: recoveryUpdateInclusionProof,
        });

        expect(verification.ok).toBe(true);
        expect(verification.updatedEntry).toMatchObject({
            currentRecoveryEpoch: 1,
            currentDeviceEpoch: 1,
        });
        const conflictingPayload = {
            ...payload,
            newSigningPublicKeyDigest: createKeyFixture(
                'participant:participant-1:different-new-signing',
            ).publicKeyDigest,
        };
        const conflictingRecoveryEpochUpdateDigest =
            deriveRecoveryEpochUpdateDigest(conflictingPayload);
        const conflictingUpdate: RecoveryEpochUpdate = {
            ...conflictingPayload,
            recoveryEpochUpdateDigest: conflictingRecoveryEpochUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                conflictingRecoveryEpochUpdateDigest,
                { boardHeadDigest: payload.boardHeadDigest },
            ),
        };

        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    recoveryUpdateHead,
                ]),
                updateInclusionProof: recoveryUpdateInclusionProof,
                conflictingUpdates: [conflictingUpdate],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateConflict' }),
            ]),
        );
        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest: createKeyFixture(
                    'recovery-root:wrong',
                ).publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    recoveryUpdateHead,
                ]),
                updateInclusionProof: recoveryUpdateInclusionProof,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        const wrongRecoveryPolicyPayload = {
            ...payload,
            recoveryPolicyDigest: deriveProtocolDigest('RecoveryPolicyDigest', {
                policy: 'wrong-recovery-policy',
            }),
        };
        const wrongRecoveryPolicyUpdateDigest = deriveRecoveryEpochUpdateDigest(
            wrongRecoveryPolicyPayload,
        );
        const wrongRecoveryPolicyUpdate: RecoveryEpochUpdate = {
            ...wrongRecoveryPolicyPayload,
            recoveryEpochUpdateDigest: wrongRecoveryPolicyUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                wrongRecoveryPolicyUpdateDigest,
                { boardHeadDigest: payload.boardHeadDigest },
            ),
        };
        const {
            head: wrongPolicyUpdateHead,
            inclusionProofs: wrongPolicyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: wrongRecoveryPolicyUpdateDigest,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongRecoveryPolicyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    wrongPolicyUpdateHead,
                ]),
                updateInclusionProof: wrongPolicyProofs[0],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateInvalid' }),
            ]),
        );
        const wrongCeremonyPayload = {
            ...payload,
            ceremonyId: 'ceremony-other',
        };
        const wrongCeremonyRecoveryUpdateDigest =
            deriveRecoveryEpochUpdateDigest(wrongCeremonyPayload);
        const wrongCeremonyUpdate: RecoveryEpochUpdate = {
            ...wrongCeremonyPayload,
            recoveryEpochUpdateDigest: wrongCeremonyRecoveryUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                wrongCeremonyRecoveryUpdateDigest,
                {
                    boardHeadDigest: payload.boardHeadDigest,
                    ceremonyId: 'ceremony-other',
                },
            ),
        };
        const {
            head: wrongCeremonyUpdateHead,
            inclusionProofs: wrongCeremonyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: wrongCeremonyRecoveryUpdateDigest,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongCeremonyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    wrongCeremonyUpdateHead,
                ]),
                updateInclusionProof: wrongCeremonyProofs[0],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongCeremony' }),
            ]),
        );

        const staleActionPayload = {
            ceremonyId,
            electionManifestDigest: deriveProtocolDigest(
                'ElectionManifestDigest',
                { manifest: 'main' },
            ),
            signerIdentity: 'participant-1',
            boardHeadDigest: payload.boardHeadDigest,
            boardSequence: 6,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 1,
            recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
            acceptedRecoveryEpochUpdateDigest: recoveryEpochUpdateDigest,
            rosterExternalAcceptanceDigest: deriveProtocolDigest(
                'RosterExternalAcceptanceDigest',
                { participant: 'participant-1', roster: 'main' },
            ),
            contextDigest,
        };
        const staleActionContext: ActionContext = {
            ...staleActionPayload,
            actionContextDigest: deriveActionContextDigest(staleActionPayload),
        };

        expect(
            isActionCurrentForRecoveryEpoch({
                actionContext: staleActionContext,
                recoveryEpochState: verification.updatedEntry ?? currentEntry,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
            ]),
        );

        expect(
            isActionCurrentForRecoveryEpoch({
                actionContext: staleActionContext,
                recoveryEpochState: currentEntry,
                expectedRosterExternalAcceptanceDigest: deriveProtocolDigest(
                    'RosterExternalAcceptanceDigest',
                    { participant: 'participant-1', roster: 'different' },
                ),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'RosterExternalAcceptanceInvalid',
                }),
            ]),
        );
    });
});
