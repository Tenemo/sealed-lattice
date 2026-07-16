import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import type {
    BrowserActionProofAttemptBinding,
    BrowserActionStorageRootBinding,
} from '@sealed-lattice/types';
import { beforeAll, describe, expect, it } from 'vitest';

import {
    BrowserActionStorageCustodyError,
    type BrowserFoundationCheckpointHandle,
    type CommittedBrowserFoundationInitializationBatch,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    BrowserFoundationAuthorityError,
    openBrowserFoundationAuthority,
} from '#packages/protocol/src/runtime/browser-foundation-authority-combined';
import type {
    BrowserFoundationActionRandomnessHandle,
    BrowserFoundationDurableStateBindingHandle,
    BrowserFoundationInitializationInput,
    BrowserFoundationNormalWitnessRoleHandle,
    BrowserFoundationOperationOwner,
    BrowserRecoveredFoundationInitializationBatch,
    BrowserFoundationStateReservationIntentHandle,
    TransferableBrowserFoundationOperationOwner,
} from '#packages/protocol/src/runtime/browser-foundation-operation-owner';
import type {
    CanonicalBoardRuntime,
    TransferableCanonicalBoardRuntime,
    VerifiedCanonicalBoardSnapshot,
} from '#packages/protocol/src/runtime/canonical-board-runtime';
import {
    copyRuntimeBuildAuthorityBindingDescription,
    type CanonicalBoardContextInput,
    type RuntimeBuildAuthorityBinding,
    UntrustedCanonicalBoardCarrier,
    VerifiedTranscriptObject,
} from '#packages/wasm/src/index';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';
import { activateRuntimeBuildAuthorityBindingFixture } from '#packages/wasm/tests/support/runtime-build-authority-binding-fixture';

const opaque = <Value>(): Value =>
    Object.freeze(Object.create(null) as object) as Value;

const rosterVector = createStateVerifierTestVector();
const orderedRosterParticipantIdentities =
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
        openAuthenticatedMailboxFrozenRoster(rosterVector.canonicalRosterBytes),
    );
const subjectParticipantIdentity = orderedRosterParticipantIdentities[0];
if (subjectParticipantIdentity === undefined) {
    throw new Error('The foundation roster test vector has no participant.');
}
const witnessSubjectParticipantIdentities =
    orderedRosterParticipantIdentities.slice(1);

let runtimeBuildAuthorityBinding: RuntimeBuildAuthorityBinding;
let runtimeBuildManifestHash: Uint8Array = new Uint8Array();
let suiteIdentifier: Uint8Array = new Uint8Array();

type CanonicalBoardTestState = {
    closeAttemptCount?: number;
    closeCount: number;
    closeFailures?: Error[];
};

const createCanonicalBoardRuntime = (
    context: CanonicalBoardContextInput,
    state: CanonicalBoardTestState,
): TransferableCanonicalBoardRuntime => {
    const snapshot = opaque<VerifiedCanonicalBoardSnapshot>();
    const verifiedObject = opaque<VerifiedTranscriptObject>();
    const runtime: CanonicalBoardRuntime = {
        close: () => {
            state.closeAttemptCount = (state.closeAttemptCount ?? 0) + 1;
            const closeFailure = state.closeFailures?.shift();
            if (closeFailure !== undefined) {
                throw closeFailure;
            }
            state.closeCount += 1;
        },
        copyCachedCarrier: () => ({
            isValid: false,
            refusalReason: 'missingPrerequisite',
        }),
        copyCanonicalCarrierSet: () => ({ isValid: true, value: [] }),
        copyContextInput: () => ({
            ...context,
            canonicalActionDefinitionBytes:
                context.canonicalActionDefinitionBytes.slice(),
            canonicalBoardPolicyBytes:
                context.canonicalBoardPolicyBytes.slice(),
            canonicalManifestBytes: context.canonicalManifestBytes.slice(),
            canonicalRosterBytes: context.canonicalRosterBytes.slice(),
            canonicalSuiteRecordBytes:
                context.canonicalSuiteRecordBytes.slice(),
            expectedActionContextHash:
                context.expectedActionContextHash.slice(),
            expectedCeremonyContextHash:
                context.expectedCeremonyContextHash.slice(),
            expectedSuiteIdentifier: context.expectedSuiteIdentifier.slice(),
        }),
        findObject: () => ({
            isValid: false,
            refusalReason: 'missingPrerequisite',
        }),
        ingestUnordered: (
            carriers: readonly UntrustedCanonicalBoardCarrier[],
        ) =>
            carriers.length === 0
                ? { isValid: false, refusalReason: 'missingPrerequisite' }
                : { isValid: true, value: snapshot },
        objects: (candidateSnapshot) =>
            candidateSnapshot === snapshot
                ? { isValid: true, value: [verifiedObject] }
                : { isValid: false, refusalReason: 'wrongContext' },
        state: () => 'active',
    };
    return Object.freeze({
        ...runtime,
        claimExclusiveOwner: () => runtime,
    });
};

const copyInitializationInput = (
    input: BrowserFoundationInitializationInput,
): BrowserFoundationInitializationInput => ({
    actionRandomnessRecordContext: {
        recordVersion: input.actionRandomnessRecordContext.recordVersion,
    },
    canonicalRosterBytes: input.canonicalRosterBytes.slice(),
    orderedWitnessBindings: input.orderedWitnessBindings.map((binding) => ({
        subjectParticipantIdentity: binding.subjectParticipantIdentity.slice(),
        witnessParticipantIdentity: binding.witnessParticipantIdentity.slice(),
    })),
    runtimeBuildManifestHash: input.runtimeBuildManifestHash.slice(),
});

type OperationOwnerTestState = {
    activateFreshCount: number;
    activateRecoveredCount: number;
    closeAttemptCount: number;
    closeCount: number;
    commitCount: number;
    committedInput?: BrowserFoundationInitializationInput;
    lifecycleEvents: string[];
    openRecoveredCount: number;
    retireCount: number;
    witnessVoteCount: number;
};

type DeviceWrappingRetirementTestStorage = {
    retirementTombstonePresent: boolean;
};

const createOperationOwner = (
    input: Readonly<{
        closeFailures?: readonly Error[];
        crossWireActivatedWitnesses?: boolean;
        failClaim?: boolean;
        freshCommitFailure?: Error;
        freshCommitFailureAfterRetirementAttempt?: Error;
        recoveredOpenFailure?: Error;
        recoveredOpenFailureAfterRetirementAttempt?: Error;
        retirementCompareAndSwapFailures?: readonly Error[];
        retirementStorage?: DeviceWrappingRetirementTestStorage;
        witnessVoteFailure?: Error;
    }> = {},
): Readonly<{
    owner: TransferableBrowserFoundationOperationOwner;
    state: OperationOwnerTestState;
}> => {
    const state: OperationOwnerTestState = {
        activateFreshCount: 0,
        activateRecoveredCount: 0,
        closeAttemptCount: 0,
        closeCount: 0,
        commitCount: 0,
        lifecycleEvents: [],
        openRecoveredCount: 0,
        retireCount: 0,
        witnessVoteCount: 0,
    };
    const closeFailures = [...(input.closeFailures ?? [])];
    const retirementCompareAndSwapFailures = [
        ...(input.retirementCompareAndSwapFailures ?? []),
    ];
    const normalHandles = witnessSubjectParticipantIdentities.map(() =>
        opaque<BrowserFoundationNormalWitnessRoleHandle>(),
    );
    const normalSubjects = new Map(
        normalHandles.map((handle, handleIndex) => [
            handle,
            witnessSubjectParticipantIdentities[handleIndex],
        ]),
    );
    const committedBatch =
        opaque<CommittedBrowserFoundationInitializationBatch>();
    const recoveredBatch =
        opaque<BrowserRecoveredFoundationInitializationBatch>();
    const actionRandomnessHandle =
        opaque<BrowserFoundationActionRandomnessHandle>();
    const durableStateBindingHandle =
        opaque<BrowserFoundationDurableStateBindingHandle>();
    const stateReservationIntentHandle =
        opaque<BrowserFoundationStateReservationIntentHandle>();
    const binding: BrowserActionStorageRootBinding = {
        actionContextHash: rosterVector.actionContextHash.slice(),
        ceremonyContextHash: rosterVector.ceremonyContextHash.slice(),
        participantId: subjectParticipantIdentity.slice(),
        suiteId: suiteIdentifier.slice(),
    };
    let closed = false;
    let reservationOrdinal = 0;
    const attemptDurableRetirement = (): Promise<void> => {
        state.retireCount += 1;
        state.lifecycleEvents.push('retire');
        const injectedFailure = retirementCompareAndSwapFailures.shift();
        if (injectedFailure !== undefined) {
            return Promise.reject(injectedFailure);
        }
        if (input.retirementStorage !== undefined) {
            input.retirementStorage.retirementTombstonePresent = true;
        }
        return Promise.resolve();
    };
    const activatedHandles = () =>
        input.crossWireActivatedWitnesses === true
            ? [...normalHandles].reverse()
            : normalHandles;
    const operationOwner: BrowserFoundationOperationOwner = {
        activateFreshFoundationInitialization: () => {
            state.activateFreshCount += 1;
            return Promise.resolve({
                actionRandomnessHandle,
                orderedWitnessRoleHandles: activatedHandles(),
            });
        },
        activateRecoveredFoundationInitialization: () => {
            state.activateRecoveredCount += 1;
            return Promise.resolve({
                actionRandomnessHandle,
                orderedWitnessRoleHandles: activatedHandles(),
            });
        },
        beginCheckpoint: () =>
            Promise.resolve(opaque<BrowserFoundationCheckpointHandle>()),
        cacheWitnessExactOutput: () => Promise.resolve(),
        cacheWitnessSignedVoteCarrier: (_role, cacheInput) =>
            Promise.resolve(cacheInput.canonicalSignedVoteCarrier.slice()),
        close: () => {
            state.closeAttemptCount += 1;
            state.lifecycleEvents.push('close');
            const closeFailure = closeFailures.shift();
            if (closeFailure !== undefined) {
                return Promise.reject(closeFailure);
            }
            if (!closed) {
                closed = true;
                state.closeCount += 1;
            }
            return Promise.resolve();
        },
        closeFoundationActionRandomness: () => Promise.resolve(),
        closeWitnessDurableStateBinding: () => Promise.resolve(),
        commitFreshFoundationInitialization: (initializationInput) => {
            state.commitCount += 1;
            state.committedInput = copyInitializationInput(initializationInput);
            if (input.retirementStorage?.retirementTombstonePresent === true) {
                return Promise.reject(
                    new BrowserActionStorageCustodyError(
                        'Unavailable',
                        'The participant has a durable retirement tombstone.',
                    ),
                );
            }
            if (input.freshCommitFailure !== undefined) {
                return Promise.reject(input.freshCommitFailure);
            }
            if (input.freshCommitFailureAfterRetirementAttempt !== undefined) {
                const commitFailure =
                    input.freshCommitFailureAfterRetirementAttempt;
                return attemptDurableRetirement().then(
                    () =>
                        Promise.reject(
                            new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Fresh foundation construction failed after durable retirement.',
                                commitFailure,
                            ),
                        ),
                    (retirementFailure: unknown) =>
                        Promise.reject(
                            new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Fresh foundation construction and its first durable-retirement attempt failed.',
                                [commitFailure, retirementFailure],
                            ),
                        ),
                );
            }
            return Promise.resolve({ committedBatch });
        },
        compareAndLockWitnessIntent: () => Promise.resolve(),
        certifyFoundationActionRandomnessReservation: () => {
            reservationOrdinal += 1;
            return Promise.resolve({
                isValid: true,
                value: {
                    canonicalStateCertificate: Uint8Array.of(0x75),
                    stateReservationIdentifier: `state-reservation-${String(reservationOrdinal)}`,
                },
            });
        },
        copyBinding: () => ({
            actionContextHash: binding.actionContextHash.slice(),
            ceremonyContextHash: binding.ceremonyContextHash.slice(),
            participantId: binding.participantId.slice(),
            suiteId: binding.suiteId.slice(),
        }),
        copyCheckpointDescription: () =>
            Promise.resolve({
                checkpointLineageIdentifier: new Uint8Array(32).fill(1),
            }),
        copyWitnessSubjectParticipantIdentity: (handle) =>
            Promise.resolve(
                normalSubjects.get(handle)?.slice() ?? new Uint8Array(64),
            ),
        deriveFoundationTargetReleaseAttempt: () =>
            Promise.resolve<BrowserActionProofAttemptBinding>({
                applicationSlotHash: new Uint8Array(64).fill(0x61),
                attemptIdentifier: new Uint8Array(32).fill(0x62),
            }),
        openActionStateVerifierSession: () =>
            Promise.resolve({ isValid: true, value: 'state-verifier' }),
        openRecoveredFoundationInitialization: () => {
            state.openRecoveredCount += 1;
            if (
                input.recoveredOpenFailureAfterRetirementAttempt !== undefined
            ) {
                const openFailure =
                    input.recoveredOpenFailureAfterRetirementAttempt;
                return attemptDurableRetirement().then(
                    () =>
                        Promise.reject(
                            new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Recovered foundation construction failed after durable retirement.',
                                openFailure,
                            ),
                        ),
                    (retirementFailure: unknown) =>
                        Promise.reject(
                            new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'Recovered foundation construction and its first durable-retirement attempt failed.',
                                [openFailure, retirementFailure],
                            ),
                        ),
                );
            }
            if (input.recoveredOpenFailure !== undefined) {
                return Promise.reject(input.recoveredOpenFailure);
            }
            return Promise.resolve({ recoveredBatch });
        },
        openWitnessDurableStateBinding: () =>
            Promise.resolve(durableStateBindingHandle),
        produceFoundationActionRandomnessReservationIntent: () =>
            Promise.resolve({
                isValid: true,
                value: {
                    canonicalReservationIntentCarrier: Uint8Array.of(0x73),
                    intentHandle: stateReservationIntentHandle,
                },
            }),
        publishCheckpoint: () => Promise.resolve(Uint8Array.of(1)),
        readWitnessExactOutput: () => Promise.resolve(Uint8Array.of(2)),
        readWitnessSignedVoteCarrier: () => Promise.resolve(Uint8Array.of(3)),
        releaseActionStateObject: () => Promise.resolve(),
        releaseFoundationStateReservationIntent: () => Promise.resolve(),
        retire: attemptDurableRetirement,
        restoreCheckpointState: () => Promise.resolve(),
        resumeCheckpoint: () =>
            Promise.resolve(opaque<BrowserFoundationCheckpointHandle>()),
        verifyActionStateReservation: () => {
            reservationOrdinal += 1;
            return Promise.resolve({
                isValid: true,
                value: `state-reservation-${String(reservationOrdinal)}`,
            });
        },
        verifyFoundationActionRandomnessReservation: () => {
            reservationOrdinal += 1;
            return Promise.resolve({
                isValid: true,
                value: `state-reservation-${String(reservationOrdinal)}`,
            });
        },
        voteForFoundationActionRandomnessReservationIntent: () => {
            state.witnessVoteCount += 1;
            if (input.witnessVoteFailure !== undefined) {
                return Promise.reject(input.witnessVoteFailure);
            }
            return Promise.resolve({
                isValid: true,
                value: Uint8Array.of(0x74),
            });
        },
    };
    return Object.freeze({
        owner: Object.freeze({
            ...operationOwner,
            claimExclusiveOwner: () => {
                if (input.failClaim === true) {
                    throw new Error('Injected operation-owner claim failure.');
                }
                return operationOwner;
            },
        }),
        state,
    });
};

const openTestAuthority = (
    initializationMode: 'fresh' | 'recovered',
    operationOwner: TransferableBrowserFoundationOperationOwner,
    boardState: CanonicalBoardTestState,
) =>
    openBrowserFoundationAuthority({
        canonicalBoardRuntime: createCanonicalBoardRuntime(
            {
                actionIdentifier: 'action',
                canonicalActionDefinitionBytes: Uint8Array.of(0xa1),
                canonicalBoardPolicyBytes: Uint8Array.of(0xb1),
                canonicalManifestBytes: Uint8Array.of(0xc1),
                canonicalRosterBytes: rosterVector.canonicalRosterBytes,
                canonicalSuiteRecordBytes: Uint8Array.of(0xd1),
                ceremonyIdentifier: 'ceremony',
                expectedActionContextHash: rosterVector.actionContextHash,
                expectedCeremonyContextHash: rosterVector.ceremonyContextHash,
                expectedSuiteIdentifier: suiteIdentifier,
            },
            boardState,
        ),
        initializationMode,
        operationOwner,
        runtimeBuildAuthorityBinding,
    });

const createAuthorityHarness = async (
    initializationMode: 'fresh' | 'recovered',
    ownerInput: Parameters<typeof createOperationOwner>[0] = {},
) => {
    const boardState: CanonicalBoardTestState = { closeCount: 0 };
    const operation = createOperationOwner(ownerInput);
    const authority = await openTestAuthority(
        initializationMode,
        operation.owner,
        boardState,
    );
    return Object.freeze({ authority, boardState, operation });
};

describe('combined browser foundation authority', () => {
    beforeAll(async () => {
        const fixture = await activateRuntimeBuildAuthorityBindingFixture();
        runtimeBuildAuthorityBinding =
            fixture.activation.runtimeBuildAuthorityBinding;
        const description = copyRuntimeBuildAuthorityBindingDescription(
            runtimeBuildAuthorityBinding,
        );
        runtimeBuildManifestHash = description.runtimeBuildManifestHash;
        suiteIdentifier = description.suiteIdentifier;
    });

    it('derives the exact fixed-roster witness set and activates fresh local state', async () => {
        const harness = await createAuthorityHarness('fresh');
        await expect(harness.authority.witnessRoles()).rejects.toMatchObject({
            code: 'InvalidState',
        });

        await expect(harness.authority.startup()).resolves.toBe('active');
        await expect(harness.authority.startup()).resolves.toBe('active');
        expect(harness.operation.state.commitCount).toBe(1);
        expect(harness.operation.state.activateFreshCount).toBe(1);
        expect(harness.operation.state.activateRecoveredCount).toBe(0);
        expect(harness.operation.state.committedInput).toEqual({
            actionRandomnessRecordContext: { recordVersion: 0n },
            canonicalRosterBytes: rosterVector.canonicalRosterBytes,
            orderedWitnessBindings: witnessSubjectParticipantIdentities.map(
                (identity) => ({
                    subjectParticipantIdentity: identity,
                    witnessParticipantIdentity: subjectParticipantIdentity,
                }),
            ),
            runtimeBuildManifestHash,
        });

        const witnessRoles = await harness.authority.witnessRoles();
        expect(witnessRoles).toHaveLength(9);
        await expect(
            Promise.all(
                witnessRoles.map((role) =>
                    harness.authority.copyWitnessRoleDescription(role),
                ),
            ),
        ).resolves.toEqual(
            witnessSubjectParticipantIdentities.map((identity) => ({
                subjectParticipantIdentity: identity,
            })),
        );

        const capability = harness.authority.activeCapability();
        const vote =
            await harness.authority.voteForActionRandomnessReservationIntent(
                capability,
                witnessRoles[0],
                Uint8Array.of(0x73),
            );
        expect(vote).toEqual({ isValid: true, value: Uint8Array.of(0x74) });
        expect(harness.operation.state.witnessVoteCount).toBe(1);

        await harness.authority.close();
        expect(harness.operation.state.closeCount).toBe(1);
        expect(harness.boardState.closeCount).toBe(1);
    });

    it('opens recovered state without creating fresh local material', async () => {
        const harness = await createAuthorityHarness('recovered');
        expect(harness.operation.state.commitCount).toBe(0);
        expect(harness.operation.state.openRecoveredCount).toBe(1);

        await expect(harness.authority.startup()).resolves.toBe('active');
        expect(harness.operation.state.activateFreshCount).toBe(0);
        expect(harness.operation.state.activateRecoveredCount).toBe(1);
        await harness.authority.close();
    });

    it('fails closed when recovered local records do not authenticate', async () => {
        const boardState: CanonicalBoardTestState = { closeCount: 0 };
        const operation = createOperationOwner({
            recoveredOpenFailure: new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'Injected recovered-record authentication failure.',
            ),
        });
        await expect(
            openBrowserFoundationAuthority({
                canonicalBoardRuntime: createCanonicalBoardRuntime(
                    {
                        actionIdentifier: 'action',
                        canonicalActionDefinitionBytes: Uint8Array.of(0xa1),
                        canonicalBoardPolicyBytes: Uint8Array.of(0xb1),
                        canonicalManifestBytes: Uint8Array.of(0xc1),
                        canonicalRosterBytes: rosterVector.canonicalRosterBytes,
                        canonicalSuiteRecordBytes: Uint8Array.of(0xd1),
                        ceremonyIdentifier: 'ceremony',
                        expectedActionContextHash:
                            rosterVector.actionContextHash,
                        expectedCeremonyContextHash:
                            rosterVector.ceremonyContextHash,
                        expectedSuiteIdentifier: suiteIdentifier,
                    },
                    boardState,
                ),
                initializationMode: 'recovered',
                operationOwner: operation.owner,
                runtimeBuildAuthorityBinding,
            }),
        ).rejects.toMatchObject({ code: 'RecordAuthenticationFailed' });
        expect(operation.state.retireCount).toBe(1);
        expect(operation.state.closeCount).toBe(1);
        expect(operation.state.lifecycleEvents).toEqual(['retire', 'close']);
        expect(boardState.closeCount).toBe(1);
    });

    it.each([
        new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Injected invalid input.',
        ),
        new BrowserActionStorageCustodyError(
            'InvalidState',
            'Injected invalid state.',
        ),
        new BrowserActionStorageCustodyError(
            'CommitmentMismatch',
            'Injected commitment mismatch.',
        ),
        Object.assign(new Error('Injected semantic conflict.'), {
            code: 'Conflict',
        }),
        Object.assign(new Error('Injected missing record.'), {
            code: 'MissingRecord',
        }),
    ])(
        'keeps healthy local authority active after nonterminal witness failure %#',
        async (witnessVoteFailure) => {
            const harness = await createAuthorityHarness('fresh', {
                witnessVoteFailure,
            });
            await harness.authority.startup();
            const capability = harness.authority.activeCapability();
            const witnessRole = (await harness.authority.witnessRoles())[0];

            await expect(
                harness.authority.voteForActionRandomnessReservationIntent(
                    capability,
                    witnessRole,
                    Uint8Array.of(0x73),
                ),
            ).rejects.toBe(witnessVoteFailure);
            expect(harness.authority.state()).toBe('active');
            expect(harness.authority.retirementReason()).toBeUndefined();
            expect(harness.operation.state.retireCount).toBe(0);
            expect(harness.operation.state.closeCount).toBe(0);
            expect(harness.boardState.closeCount).toBe(0);

            await harness.authority.close();
            expect(harness.operation.state.retireCount).toBe(0);
            expect(harness.operation.state.lifecycleEvents).toEqual(['close']);
        },
    );

    it.each([
        Object.assign(new Error('Injected authentication failure.'), {
            code: 'AuthenticationFailed',
        }),
        new BrowserActionStorageCustodyError(
            'RecordAuthenticationFailed',
            'Injected record authentication failure.',
        ),
        new BrowserActionStorageCustodyError(
            'StorageFailure',
            'Injected storage failure.',
        ),
        new BrowserActionStorageCustodyError(
            'Unavailable',
            'Injected unavailable storage.',
        ),
        new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'Injected worker failure.',
        ),
    ])(
        'retires local custody exactly once before close after permanent witness failure %#',
        async (witnessVoteFailure) => {
            const harness = await createAuthorityHarness('fresh', {
                witnessVoteFailure,
            });
            await harness.authority.startup();
            const capability = harness.authority.activeCapability();
            const witnessRole = (await harness.authority.witnessRoles())[0];

            await expect(
                harness.authority.voteForActionRandomnessReservationIntent(
                    capability,
                    witnessRole,
                    Uint8Array.of(0x73),
                ),
            ).rejects.toBe(witnessVoteFailure);
            expect(harness.authority.state()).toBe('retired');
            expect(harness.authority.retirementReason()).toBe(
                'witnessStateUnavailable',
            );
            expect(harness.operation.state.retireCount).toBe(1);
            expect(harness.operation.state.closeCount).toBe(1);
            expect(harness.operation.state.lifecycleEvents).toEqual([
                'retire',
                'close',
            ]);
            expect(harness.boardState.closeCount).toBe(1);

            await harness.authority.close();
            expect(harness.operation.state.retireCount).toBe(1);
            expect(harness.operation.state.closeCount).toBe(1);
        },
    );

    it('keeps durable retirement retryable after its compare-and-swap fails', async () => {
        const retirementStorage: DeviceWrappingRetirementTestStorage = {
            retirementTombstonePresent: false,
        };
        const harness = await createAuthorityHarness('fresh', {
            retirementCompareAndSwapFailures: [
                new BrowserActionStorageCustodyError(
                    'StorageFailure',
                    'Injected retirement compare-and-swap failure.',
                ),
            ],
            retirementStorage,
            witnessVoteFailure: new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Injected permanent witness storage failure.',
            ),
        });
        await harness.authority.startup();
        const capability = harness.authority.activeCapability();
        const witnessRole = (await harness.authority.witnessRoles())[0];

        await expect(
            harness.authority.voteForActionRandomnessReservationIntent(
                capability,
                witnessRole,
                Uint8Array.of(0x73),
            ),
        ).rejects.toMatchObject({ code: 'CleanupFailed' });
        expect(retirementStorage.retirementTombstonePresent).toBe(false);
        expect(harness.authority.state()).toBe('retired');
        expect(harness.operation.state.lifecycleEvents).toEqual(['retire']);
        expect(harness.operation.state.closeCount).toBe(0);
        expect(harness.boardState.closeCount).toBe(0);

        await expect(harness.authority.close()).resolves.toBeUndefined();
        expect(retirementStorage.retirementTombstonePresent).toBe(true);
        expect(harness.operation.state.retireCount).toBe(2);
        expect(harness.operation.state.closeCount).toBe(1);
        expect(harness.operation.state.lifecycleEvents).toEqual([
            'retire',
            'retire',
            'close',
        ]);
        expect(harness.boardState.closeCount).toBe(1);

        await expect(
            createAuthorityHarness('fresh', { retirementStorage }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
    });

    it.each(['fresh', 'recovered'] as const)(
        'completes fail-once durable retirement before failed %s construction releases ownership',
        async (initializationMode) => {
            const retirementStorage: DeviceWrappingRetirementTestStorage = {
                retirementTombstonePresent: false,
            };
            const boardState: CanonicalBoardTestState = { closeCount: 0 };
            const constructionFailure = new BrowserActionStorageCustodyError(
                'StorageFailure',
                `Injected ${initializationMode} foundation authentication failure.`,
            );
            const operation = createOperationOwner({
                ...(initializationMode === 'fresh'
                    ? {
                          freshCommitFailureAfterRetirementAttempt:
                              constructionFailure,
                      }
                    : {
                          recoveredOpenFailureAfterRetirementAttempt:
                              constructionFailure,
                      }),
                retirementCompareAndSwapFailures: [
                    new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'Injected first retirement compare-and-swap failure.',
                    ),
                ],
                retirementStorage,
            });

            await expect(
                openTestAuthority(
                    initializationMode,
                    operation.owner,
                    boardState,
                ),
            ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
            expect(retirementStorage.retirementTombstonePresent).toBe(true);
            expect(operation.state.retireCount).toBe(2);
            expect(operation.state.closeCount).toBe(1);
            expect(operation.state.lifecycleEvents).toEqual([
                'retire',
                'retire',
                'close',
            ]);
            expect(boardState.closeCount).toBe(1);

            await expect(
                createAuthorityHarness('fresh', { retirementStorage }),
            ).rejects.toMatchObject({ code: 'Unavailable' });
        },
    );

    it.each(['fresh', 'recovered'] as const)(
        'retains failed %s construction ownership through repeated terminal cleanup failures',
        async (initializationMode) => {
            const retirementStorage: DeviceWrappingRetirementTestStorage = {
                retirementTombstonePresent: false,
            };
            const boardState: CanonicalBoardTestState = {
                closeAttemptCount: 0,
                closeCount: 0,
                closeFailures: [
                    new Error('Injected first canonical-board close failure.'),
                    new Error('Injected second canonical-board close failure.'),
                ],
            };
            const constructionFailure = new BrowserActionStorageCustodyError(
                'StorageFailure',
                `Injected ${initializationMode} foundation construction failure.`,
            );
            const operation = createOperationOwner({
                closeFailures: [
                    new Error('Injected first operation-owner close failure.'),
                    new Error('Injected second operation-owner close failure.'),
                ],
                ...(initializationMode === 'fresh'
                    ? { freshCommitFailure: constructionFailure }
                    : { recoveredOpenFailure: constructionFailure }),
                retirementCompareAndSwapFailures: [
                    new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'Injected first retirement compare-and-swap failure.',
                    ),
                    new BrowserActionStorageCustodyError(
                        'StorageFailure',
                        'Injected second retirement compare-and-swap failure.',
                    ),
                ],
                retirementStorage,
            });

            await expect(
                openTestAuthority(
                    initializationMode,
                    operation.owner,
                    boardState,
                ),
            ).rejects.toBe(constructionFailure);
            expect(retirementStorage.retirementTombstonePresent).toBe(true);
            expect(operation.state.retireCount).toBe(3);
            expect(operation.state.closeAttemptCount).toBe(3);
            expect(operation.state.closeCount).toBe(1);
            expect(operation.state.lifecycleEvents).toEqual([
                'retire',
                'retire',
                'retire',
                'close',
                'close',
                'close',
            ]);
            expect(boardState.closeAttemptCount).toBe(3);
            expect(boardState.closeCount).toBe(1);

            await expect(
                createAuthorityHarness('fresh', { retirementStorage }),
            ).rejects.toMatchObject({ code: 'Unavailable' });
        },
    );

    it('rejects cross-wired activated witness roles', async () => {
        const harness = await createAuthorityHarness('fresh', {
            crossWireActivatedWitnesses: true,
        });
        await expect(harness.authority.startup()).rejects.toBeInstanceOf(
            BrowserFoundationAuthorityError,
        );
        expect(harness.authority.state()).toBe('retired');
        expect(harness.operation.state.closeCount).toBe(1);
        expect(harness.boardState.closeCount).toBe(1);
    });

    it('closes an already claimed board when operation-owner transfer fails', async () => {
        const boardState: CanonicalBoardTestState = { closeCount: 0 };
        const operation = createOperationOwner({ failClaim: true });
        await expect(
            openBrowserFoundationAuthority({
                canonicalBoardRuntime: createCanonicalBoardRuntime(
                    {
                        actionIdentifier: 'action',
                        canonicalActionDefinitionBytes: Uint8Array.of(0xa1),
                        canonicalBoardPolicyBytes: Uint8Array.of(0xb1),
                        canonicalManifestBytes: Uint8Array.of(0xc1),
                        canonicalRosterBytes: rosterVector.canonicalRosterBytes,
                        canonicalSuiteRecordBytes: Uint8Array.of(0xd1),
                        ceremonyIdentifier: 'ceremony',
                        expectedActionContextHash:
                            rosterVector.actionContextHash,
                        expectedCeremonyContextHash:
                            rosterVector.ceremonyContextHash,
                        expectedSuiteIdentifier: suiteIdentifier,
                    },
                    boardState,
                ),
                initializationMode: 'fresh',
                operationOwner: operation.owner,
                runtimeBuildAuthorityBinding,
            }),
        ).rejects.toThrow('Injected operation-owner claim failure.');
        expect(boardState.closeCount).toBe(1);
        expect(operation.state.closeCount).toBe(0);
    });
});
