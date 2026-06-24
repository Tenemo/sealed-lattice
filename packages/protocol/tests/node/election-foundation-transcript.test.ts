import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    FoundationTranscriptInput,
    ProtocolRefusalCode,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createBoardEvidence,
    createBoardHeadWithObjects,
    createRegistrationEntry,
    createWitnessCheckpoint,
    deriveTargetFinalityRecordHash,
    manifestOpaqueBindings,
} from './election-foundation-test-helpers';

import { verifyFoundationTranscript } from '#packages/protocol/src/foundation/index';
import {
    createFoundationTranscriptFixture,
    foundationOptionCount,
    foundationParticipantCount,
    foundationTopOptionCount,
} from '#tests/support/foundation-transcript-fixture';

const protocolHashFixture = (label: string): string =>
    deriveProtocolHash('ChallengeDomainHash', {
        label,
        purpose: 'foundation-mutation',
    });

const expectRefusalCode = (
    input: FoundationTranscriptInput,
    code: ProtocolRefusalCode,
): void => {
    const verification = verifyFoundationTranscript(input);

    expect(verification.ok).toBe(false);
    expect(verification.acceptedHashes).toEqual([]);
    expect(verification.refusedObjects).toEqual(
        expect.arrayContaining([expect.objectContaining({ code })]),
    );
};

const createInput = (): FoundationTranscriptInput =>
    structuredClone(createFoundationTranscriptFixture().input);

const createManifestOpaqueBindingInput = (
    overrides: Partial<typeof manifestOpaqueBindings>,
): FoundationTranscriptInput => {
    const input = createInput();

    return {
        ...input,
        rosterManifestTranscript: {
            ...input.rosterManifestTranscript,
            electionManifest: {
                ...input.rosterManifestTranscript.electionManifest,
                manifestOpaqueBindings: {
                    ...input.rosterManifestTranscript.electionManifest
                        .manifestOpaqueBindings,
                    ...overrides,
                },
            },
        },
    };
};

describe('integrated election foundation transcript', () => {
    it('accepts the deterministic direct-route foundation fixture only as foundation evidence', () => {
        const fixture = createFoundationTranscriptFixture();
        const verification = verifyFoundationTranscript(fixture.input);

        expect(
            fixture.input.rosterManifestTranscript.registrationEntries,
        ).toHaveLength(foundationParticipantCount);
        expect(
            fixture.input.rosterManifestTranscript.pollSpec.options,
        ).toHaveLength(foundationOptionCount);
        expect(
            fixture.input.rosterManifestTranscript.pollSpec.topOptionCount,
        ).toBe(foundationTopOptionCount);
        expect(
            fixture.input.rosterManifestTranscript.frozenRosterProfile
                .thresholdProfile,
        ).toMatchObject({
            rosterSize: foundationParticipantCount,
        });
        expect(verification.ok).toBe(true);
        expect(verification.refusedObjects).toEqual([]);
        expect(verification.electionManifestHash).toBe(
            fixture.expectedHashes.electionManifestHash,
        );
        expect(verification.rosterHash).toBe(fixture.expectedHashes.rosterHash);
        expect(verification.rosterExternalAcceptanceHash).toBe(
            fixture.expectedHashes.rosterExternalAcceptanceHash,
        );
        expect(verification.firstValidOrderHash).toBe(
            fixture.expectedHashes.firstValidOrderHash,
        );
        expect(verification.targetProposalHash).toBe(
            fixture.expectedHashes.targetProposalHash,
        );
        expect(verification.targetFinalityCheckpointHash).toBe(
            fixture.expectedHashes.targetFinalityCheckpointHash,
        );
        expect(verification.targetFinalityRecordHash).toBe(
            fixture.expectedHashes.targetFinalityRecordHash,
        );
        expect(verification.componentResults).toMatchObject({
            firstValidOrdering: { ok: true },
            rosterExternalAcceptance: { ok: true },
            rosterManifest: { ok: true },
            targetFinality: { ok: true },
        });
        expect(
            verification.componentResults.firstValidOrdering.orderedObjects,
        ).toHaveLength(2);
        expect(fixture.input.firstValidOrdering.objects).toHaveLength(3);
        expect(verification.validWitnessIdentities).toHaveLength(5);
        expect(verification.nextRequiredEvidence).toEqual(
            expect.arrayContaining([
                'direct ballot proof verification',
                'supported-phone mobile runtime evidence',
            ]),
        );
    });

    it('rejects integrated foundation mutations with structured refusals', () => {
        let boardForkInput = createInput();
        const targetHeads =
            boardForkInput.targetFinality.boardEvidence.signedBoardHeads;
        const targetHead = targetHeads[targetHeads.length - 1];
        if (targetHead === undefined) {
            throw new Error('Expected target head in foundation fixture.');
        }
        const { head: conflictingTargetHead } = createBoardHeadWithObjects(
            targetHead.boardSequence,
            targetHead.previousHeadHash,
            [
                {
                    boardPosition: 0,
                    objectHash: protocolHashFixture(
                        'conflicting-evaluator-replay-record',
                    ),
                    objectType: 'EvaluatorReplayRecord',
                },
            ],
            'conflicting-foundation-target',
        );
        boardForkInput = {
            ...boardForkInput,
            targetFinality: {
                ...boardForkInput.targetFinality,
                boardEvidence: createBoardEvidence([
                    ...targetHeads,
                    conflictingTargetHead,
                ]),
            },
        };
        const hiddenPrefixBaseInput = createInput();
        const hiddenPrefixInput = {
            ...hiddenPrefixBaseInput,
            targetFinality: {
                ...hiddenPrefixBaseInput.targetFinality,
                boardEvidence: createBoardEvidence(
                    hiddenPrefixBaseInput.targetFinality.boardEvidence.signedBoardHeads.slice(
                        1,
                    ),
                ),
            },
        };

        const missingRosterAcceptanceInput = {
            ...createInput(),
            rosterExternalAcceptance: undefined,
        } as unknown as FoundationTranscriptInput;
        const wrongAcceptanceKeyBaseInput = createInput();
        const wrongAcceptanceKeyInput = {
            ...wrongAcceptanceKeyBaseInput,
            rosterExternalAcceptance: {
                ...wrongAcceptanceKeyBaseInput.rosterExternalAcceptance,
                expectedParticipantPublicKeyHash: protocolHashFixture(
                    'wrong-acceptance-key',
                ),
            },
        };
        const wrongRosterHashBaseInput = createInput();
        const wrongRosterHashInput = {
            ...wrongRosterHashBaseInput,
            rosterExternalAcceptance: {
                ...wrongRosterHashBaseInput.rosterExternalAcceptance,
                acceptance: {
                    ...wrongRosterHashBaseInput.rosterExternalAcceptance
                        .acceptance,
                    rosterHash: protocolHashFixture(
                        'wrong-roster-hash-in-acceptance',
                    ),
                },
            },
        };
        const duplicateRegistrationBaseInput = createInput();
        const duplicateRegistrationEntry = {
            ...duplicateRegistrationBaseInput.rosterManifestTranscript
                .registrationEntries[0],
            boardPosition:
                duplicateRegistrationBaseInput.rosterManifestTranscript
                    .registrationEntries.length + 20,
            registrationEntryHash: protocolHashFixture(
                'duplicate-registration-entry',
            ),
        };
        const duplicateRegistrationInput = {
            ...duplicateRegistrationBaseInput,
            rosterManifestTranscript: {
                ...duplicateRegistrationBaseInput.rosterManifestTranscript,
                registrationEntries: [
                    ...duplicateRegistrationBaseInput.rosterManifestTranscript
                        .registrationEntries,
                    duplicateRegistrationEntry,
                ],
            },
        };
        const lateRegistrationBaseInput = createInput();
        const lateRegistration = createRegistrationEntry(
            'late-participant',
            5,
            0,
        );
        const rosterHeads =
            lateRegistrationBaseInput.rosterManifestTranscript.boardEvidence
                .signedBoardHeads;
        const acceptedManifestHead = rosterHeads[rosterHeads.length - 1];
        if (acceptedManifestHead === undefined) {
            throw new Error('Expected accepted manifest head.');
        }
        const {
            head: lateRegistrationHead,
            inclusionProofs: lateRegistrationProofs,
        } = createBoardHeadWithObjects(
            5,
            acceptedManifestHead.headHash,
            [
                {
                    boardPosition: 0,
                    objectHash: lateRegistration.registrationEntryHash,
                    objectType: 'RegistrationEntry',
                },
            ],
            'late-registration',
        );
        const lateRegistrationInput = {
            ...lateRegistrationBaseInput,
            rosterManifestTranscript: {
                ...lateRegistrationBaseInput.rosterManifestTranscript,
                boardEvidence: createBoardEvidence([
                    ...rosterHeads,
                    lateRegistrationHead,
                ]),
                registrationEntries: [
                    ...lateRegistrationBaseInput.rosterManifestTranscript
                        .registrationEntries,
                    lateRegistration,
                ],
                registrationInclusionProofs: [
                    ...lateRegistrationBaseInput.rosterManifestTranscript
                        .registrationInclusionProofs,
                    lateRegistrationProofs[0],
                ],
            },
        };
        const firstValidPolicyBaseInput = createInput();
        const firstValidPolicyInput = {
            ...firstValidPolicyBaseInput,
            firstValidOrdering: {
                ...firstValidPolicyBaseInput.firstValidOrdering,
                selectionPolicyHash: protocolHashFixture(
                    'wrong-first-valid-policy',
                ),
            },
        };
        const wrongFirstValidContextBaseInput = createInput();
        const wrongFirstValidContextInput = {
            ...wrongFirstValidContextBaseInput,
            firstValidOrdering: {
                ...wrongFirstValidContextBaseInput.firstValidOrdering,
                objects: [
                    {
                        ...wrongFirstValidContextBaseInput.firstValidOrdering
                            .objects[0],
                        contextHash: protocolHashFixture(
                            'wrong-first-valid-context',
                        ),
                    },
                    ...wrongFirstValidContextBaseInput.firstValidOrdering.objects.slice(
                        1,
                    ),
                ],
            },
        };
        const conflictingFirstValidBaseInput = createInput();
        const conflictingFirstValidInput = {
            ...conflictingFirstValidBaseInput,
            firstValidOrdering: {
                ...conflictingFirstValidBaseInput.firstValidOrdering,
                objects: [
                    ...conflictingFirstValidBaseInput.firstValidOrdering
                        .objects,
                    {
                        ...conflictingFirstValidBaseInput.firstValidOrdering
                            .objects[1],
                        boardPosition: 3,
                        objectHash: protocolHashFixture(
                            'conflicting-first-valid-object',
                        ),
                    },
                ],
            },
        };
        const staleRecoveryBaseInput = createInput();
        const staleRecoveryInput = {
            ...staleRecoveryBaseInput,
            firstValidOrdering: {
                ...staleRecoveryBaseInput.firstValidOrdering,
                currentRecoveryEpochMap: {
                    ...staleRecoveryBaseInput.firstValidOrdering
                        .currentRecoveryEpochMap,
                    'participant-1': {
                        currentDeviceEpoch: 1,
                        currentRecoveryEpoch: 1,
                        signerIdentity: 'participant-1',
                    },
                },
            },
        };
        const wrongDeviceEpochBaseInput = createInput();
        const wrongDeviceEpochInput = {
            ...wrongDeviceEpochBaseInput,
            firstValidOrdering: {
                ...wrongDeviceEpochBaseInput.firstValidOrdering,
                currentRecoveryEpochMap: {
                    ...wrongDeviceEpochBaseInput.firstValidOrdering
                        .currentRecoveryEpochMap,
                    'participant-2': {
                        currentDeviceEpoch: 1,
                        currentRecoveryEpoch: 0,
                        signerIdentity: 'participant-2',
                    },
                },
            },
        };
        const wrongTopCountBaseInput = createInput();
        const wrongTopCountInput = {
            ...wrongTopCountBaseInput,
            targetFinality: {
                ...wrongTopCountBaseInput.targetFinality,
                record: {
                    ...wrongTopCountBaseInput.targetFinality.record,
                    targetFinalityCheckpoint: {
                        ...wrongTopCountBaseInput.targetFinality.record
                            .targetFinalityCheckpoint,
                        topOptionCount: foundationTopOptionCount - 1,
                    },
                },
            },
        };
        const wrongTargetLayoutBaseInput = createInput();
        const wrongTargetLayoutInput = {
            ...wrongTargetLayoutBaseInput,
            targetFinality: {
                ...wrongTargetLayoutBaseInput.targetFinality,
                record: {
                    ...wrongTargetLayoutBaseInput.targetFinality.record,
                    targetFinalityCheckpoint: {
                        ...wrongTargetLayoutBaseInput.targetFinality.record
                            .targetFinalityCheckpoint,
                        targetLayoutHash: protocolHashFixture(
                            'wrong-target-layout',
                        ),
                    },
                },
            },
        };
        const weakWitnessBaseInput = createInput();
        const weakWitnessInput = {
            ...weakWitnessBaseInput,
            targetFinality: {
                ...weakWitnessBaseInput.targetFinality,
                record: {
                    ...weakWitnessBaseInput.targetFinality.record,
                    witnessCheckpoints:
                        weakWitnessBaseInput.targetFinality.record.witnessCheckpoints.slice(
                            0,
                            4,
                        ),
                },
            },
        };
        const unknownWitnessBaseInput = createInput();
        const unknownWitnessRecord = {
            ...unknownWitnessBaseInput.targetFinality.record,
            witnessCheckpoints: [
                ...unknownWitnessBaseInput.targetFinality.record.witnessCheckpoints.slice(
                    0,
                    4,
                ),
                createWitnessCheckpoint(
                    'unknown-witness',
                    unknownWitnessBaseInput.targetFinality.record
                        .targetFinalityCheckpoint.finalizedBoardHeadHash,
                    unknownWitnessBaseInput.targetFinality.record
                        .targetProposalHash,
                    unknownWitnessBaseInput.targetFinality.record
                        .targetFinalityCheckpoint.targetFinalityCheckpointHash,
                    unknownWitnessBaseInput.targetFinality.record
                        .targetFinalityCheckpoint.electionManifestHash,
                ),
            ],
        };
        const unknownWitnessInput = {
            ...unknownWitnessBaseInput,
            targetFinality: {
                ...unknownWitnessBaseInput.targetFinality,
                record: unknownWitnessRecord,
            },
        };
        const duplicateWitnessBaseInput = createInput();
        const duplicateWitnessRecord = {
            ...duplicateWitnessBaseInput.targetFinality.record,
            witnessCheckpoints: [
                duplicateWitnessBaseInput.targetFinality.record
                    .witnessCheckpoints[0],
                duplicateWitnessBaseInput.targetFinality.record
                    .witnessCheckpoints[0],
                ...duplicateWitnessBaseInput.targetFinality.record.witnessCheckpoints.slice(
                    1,
                ),
            ],
        };
        const duplicateWitnessInput = {
            ...duplicateWitnessBaseInput,
            targetFinality: {
                ...duplicateWitnessBaseInput.targetFinality,
                record: {
                    ...duplicateWitnessRecord,
                    targetFinalityRecordHash: deriveTargetFinalityRecordHash({
                        ceremonyId: duplicateWitnessRecord.ceremonyId,
                        inclusionProof: duplicateWitnessRecord.inclusionProof,
                        objectType: duplicateWitnessRecord.objectType,
                        objectVersion: duplicateWitnessRecord.objectVersion,
                        targetFinalityCheckpoint:
                            duplicateWitnessRecord.targetFinalityCheckpoint,
                        targetFinalityPolicyHash:
                            duplicateWitnessRecord.targetFinalityPolicyHash,
                        targetFinalityScope:
                            duplicateWitnessRecord.targetFinalityScope,
                        targetProposalHash:
                            duplicateWitnessRecord.targetProposalHash,
                        witnessCheckpoints:
                            duplicateWitnessRecord.witnessCheckpoints,
                        witnessPolicyHash:
                            duplicateWitnessRecord.witnessPolicyHash,
                    }),
                },
            },
        };
        const wrongWitnessProposalBaseInput = createInput();
        const wrongWitnessProposalRecord = {
            ...wrongWitnessProposalBaseInput.targetFinality.record,
            witnessCheckpoints: [
                ...wrongWitnessProposalBaseInput.targetFinality.record.witnessCheckpoints.slice(
                    0,
                    4,
                ),
                createWitnessCheckpoint(
                    wrongWitnessProposalBaseInput.targetFinality.record
                        .witnessCheckpoints[4].witnessIdentity,
                    wrongWitnessProposalBaseInput.targetFinality.record
                        .targetFinalityCheckpoint.finalizedBoardHeadHash,
                    protocolHashFixture('wrong-witness-target-proposal'),
                    wrongWitnessProposalBaseInput.targetFinality.record
                        .targetFinalityCheckpoint.targetFinalityCheckpointHash,
                    wrongWitnessProposalBaseInput.targetFinality.record
                        .targetFinalityCheckpoint.electionManifestHash,
                ),
            ],
        };
        const wrongWitnessProposalInput = {
            ...wrongWitnessProposalBaseInput,
            targetFinality: {
                ...wrongWitnessProposalBaseInput.targetFinality,
                record: wrongWitnessProposalRecord,
            },
        };
        const wrongBoardPolicyBaseInput = createInput();
        const wrongBoardPolicyInput = {
            ...wrongBoardPolicyBaseInput,
            targetFinality: {
                ...wrongBoardPolicyBaseInput.targetFinality,
                record: {
                    ...wrongBoardPolicyBaseInput.targetFinality.record,
                    targetFinalityCheckpoint: {
                        ...wrongBoardPolicyBaseInput.targetFinality.record
                            .targetFinalityCheckpoint,
                        boardPolicyHash: protocolHashFixture(
                            'wrong-target-finality-board-policy',
                        ),
                    },
                },
            },
        };
        const proposalNotIncludedBaseInput = createInput();
        const proposalNotIncludedInput = {
            ...proposalNotIncludedBaseInput,
            targetFinality: {
                ...proposalNotIncludedBaseInput.targetFinality,
                record: {
                    ...proposalNotIncludedBaseInput.targetFinality.record,
                    inclusionProof: {
                        ...proposalNotIncludedBaseInput.targetFinality.record
                            .inclusionProof,
                        includedObjectHash: protocolHashFixture(
                            'wrong-included-evaluator-replay-record',
                        ),
                    },
                },
            },
        };
        const wrongObjectTypeBaseInput = createInput();
        const wrongObjectTypeInput = {
            ...wrongObjectTypeBaseInput,
            firstValidOrdering: {
                ...wrongObjectTypeBaseInput.firstValidOrdering,
                objects: [
                    {
                        ...wrongObjectTypeBaseInput.firstValidOrdering
                            .objects[0],
                        objectType: 'TargetFinalityRecord' as const,
                    },
                    ...wrongObjectTypeBaseInput.firstValidOrdering.objects.slice(
                        1,
                    ),
                ],
            },
        };
        const manifestBindingInput = createManifestOpaqueBindingInput({
            evaluatorReplayProfileId: 'unsupported-evaluator-replay-profile',
        });
        const ballotProofProfileInput = createManifestOpaqueBindingInput({
            ballotValidityProofProfileId:
                'unsupported-ballot-validity-proof-profile',
        });
        const encryptedBallotLayoutInput = createManifestOpaqueBindingInput({
            encryptedBallotLayoutHash: protocolHashFixture(
                'wrong-encrypted-ballot-layout',
            ),
        });
        const encryptedAggregateProfileInput = createManifestOpaqueBindingInput(
            {
                encryptedBallotAggregateProfileHash: protocolHashFixture(
                    'wrong-encrypted-ballot-aggregate-profile',
                ),
            },
        );
        const directComparisonProfileInput = createManifestOpaqueBindingInput({
            directComparisonProfileId: 'unsupported-direct-comparison-profile',
        });
        const targetDecryptionProfileInput = createManifestOpaqueBindingInput({
            targetDecryptionProfileId: 'unsupported-target-decryption-profile',
        });
        const mobileProfileInput = createManifestOpaqueBindingInput({
            mobileProfileId: 'unsupported-mobile-profile',
        });

        const mutationCases = [
            [boardForkInput, 'BoardForkDetected'],
            [hiddenPrefixInput, 'BoardConsistencyFailure'],
            [missingRosterAcceptanceInput, 'RosterExternalAcceptanceInvalid'],
            [wrongAcceptanceKeyInput, 'RosterExternalAcceptanceInvalid'],
            [wrongRosterHashInput, 'RosterExternalAcceptanceInvalid'],
            [duplicateRegistrationInput, 'DuplicateRegistration'],
            [lateRegistrationInput, 'LateRegistration'],
            [firstValidPolicyInput, 'FirstValidPolicyMismatch'],
            [wrongFirstValidContextInput, 'FirstValidContextMismatch'],
            [conflictingFirstValidInput, 'ConflictingFirstValidObject'],
            [staleRecoveryInput, 'StaleRecoveryEpoch'],
            [wrongDeviceEpochInput, 'StaleRecoveryEpoch'],
            [wrongTopCountInput, 'TargetFinalityPolicyMismatch'],
            [wrongTargetLayoutInput, 'TargetFinalityPolicyMismatch'],
            [weakWitnessInput, 'WitnessQuorumNotReached'],
            [unknownWitnessInput, 'UnknownWitness'],
            [duplicateWitnessInput, 'DuplicateWitness'],
            [wrongWitnessProposalInput, 'TargetFinalityPolicyMismatch'],
            [wrongBoardPolicyInput, 'TargetFinalityPolicyMismatch'],
            [proposalNotIncludedInput, 'EvaluatorReplayRecordNotIncluded'],
            [wrongObjectTypeInput, 'WrongObjectType'],
            [manifestBindingInput, 'ManifestHashMismatch'],
            [ballotProofProfileInput, 'ManifestHashMismatch'],
            [encryptedBallotLayoutInput, 'ManifestHashMismatch'],
            [encryptedAggregateProfileInput, 'ManifestHashMismatch'],
            [directComparisonProfileInput, 'ManifestHashMismatch'],
            [targetDecryptionProfileInput, 'ManifestHashMismatch'],
            [mobileProfileInput, 'ManifestHashMismatch'],
        ] as const satisfies readonly (readonly [
            FoundationTranscriptInput,
            ProtocolRefusalCode,
        ])[];

        for (const [input, code] of mutationCases) {
            expectRefusalCode(input, code);
        }
    });
});
