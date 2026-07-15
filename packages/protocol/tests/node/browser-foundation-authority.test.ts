import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import {
    BrowserActionStorageCustodyError,
    stateCapabilityKinds,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserActionStorageRootBinding,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserPersistentProofAttemptInput,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type UntrustedExpectedStorageRootCommitment,
    type VerificationResult,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    BrowserFoundationAuthorityError,
    openBrowserFoundationAuthority,
} from '#packages/protocol/src/index';
import type {
    AuthenticatedCheckpointStore,
    CheckpointBoundary,
    CheckpointOperationIdentity,
    ExpectedCheckpointBoundary,
    ResumedCheckpoint,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import {
    AuthenticatedRuntimeRecordError,
    type RuntimeStorageAuthorityContext,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import type {
    BrowserActionStorageCustody,
    BrowserDeviceWrappingSnapshot,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import type {
    BrowserFoundationActiveCapability,
    BrowserFoundationAuthority,
    BrowserFoundationProofAttempt,
    BrowserFoundationWitnessRoleInput,
} from '#packages/protocol/src/runtime/browser-foundation-authority';
import type {
    CanonicalBoardRuntime,
    VerifiedCanonicalBoardSnapshot,
} from '#packages/protocol/src/runtime/canonical-board-runtime';
import type { DurableStateWitnessService } from '#packages/protocol/src/runtime/durable-state-witness-service';
import type {
    NamespaceFreshnessActiveCapability,
    NamespaceFreshnessContext,
    NamespaceFreshnessSubjectRuntime,
    NamespaceFreshnessSubjectState,
    NamespaceFreshnessWitnessService,
} from '#packages/protocol/src/runtime/namespace-freshness-runtime';
import type {
    ProofApplicationLedger,
    ProofApplicationLedgerSnapshot,
    ProofApplicationReservation,
    ProofApplicationReservationCapability,
} from '#packages/protocol/src/runtime/proof-application-ledger';
import type {
    ProofApplicationReservationBinding,
    CanonicalBoardVerifierConfiguration,
    UntrustedCanonicalBoardCarrier,
    VerifiedStateDurableBinding,
    VerifiedTranscriptObject,
} from '#packages/wasm/src/index';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';

const hash = (value: number): Uint8Array => new Uint8Array(64).fill(value);
const bytesKey = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const opaque = <Value>(): Value =>
    Object.freeze(Object.create(null) as object) as Value;

const rosterVector = createStateVerifierTestVector();
const orderedRosterParticipantIdentities =
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
        openAuthenticatedMailboxFrozenRoster(rosterVector.canonicalRosterBytes),
    );
const runtimeBuildManifestHash = hash(0x44);

const runtimeAuthorityContext = (
    ownerParticipantIdentity: Uint8Array,
): RuntimeStorageAuthorityContext => ({
    actionContextHash: rosterVector.actionContextHash.slice(),
    ceremonyContextHash: rosterVector.ceremonyContextHash.slice(),
    ownerParticipantIdentity: ownerParticipantIdentity.slice(),
    runtimeBuildManifestHash: runtimeBuildManifestHash.slice(),
    suiteIdentifier: rosterVector.suiteIdentifier.slice(),
});

class FakeNamespaceFreshnessRuntime implements NamespaceFreshnessSubjectRuntime {
    public nextMutationState: NamespaceFreshnessSubjectState = 'active';
    public nextStartupState: NamespaceFreshnessSubjectState = 'active';
    #activeCapability: NamespaceFreshnessActiveCapability | undefined;
    #state: NamespaceFreshnessSubjectState = 'unavailable';

    public constructor(readonly context: NamespaceFreshnessContext) {}

    public copyContext(): NamespaceFreshnessContext {
        return {
            actionContextHash: this.context.actionContextHash.slice(),
            ceremonyContextHash: this.context.ceremonyContextHash.slice(),
            storageInstanceIdentity:
                this.context.storageInstanceIdentity.slice(),
            subjectParticipantIdentity:
                this.context.subjectParticipantIdentity.slice(),
            suiteIdentifier: this.context.suiteIdentifier.slice(),
        };
    }

    public activeCapability(): NamespaceFreshnessActiveCapability {
        if (this.#state !== 'active' || this.#activeCapability === undefined) {
            throw new Error('No active namespace capability.');
        }
        return this.#activeCapability;
    }

    public async certifyMutation(
        durableMutation: () => Promise<void>,
    ): Promise<NamespaceFreshnessSubjectState> {
        if (this.#state !== 'active') {
            throw new Error('The namespace is unavailable.');
        }
        this.#state = 'unavailable';
        this.#activeCapability = undefined;
        await durableMutation();
        this.#state = this.nextMutationState;
        if (this.#state === 'active') {
            this.#activeCapability =
                opaque<NamespaceFreshnessActiveCapability>();
        }
        return this.#state;
    }

    public retirementReason(): undefined {
        return undefined;
    }

    public startup(): Promise<NamespaceFreshnessSubjectState> {
        this.#state = this.nextStartupState;
        this.#activeCapability =
            this.#state === 'active'
                ? opaque<NamespaceFreshnessActiveCapability>()
                : undefined;
        return Promise.resolve(this.#state);
    }

    public state(): NamespaceFreshnessSubjectState {
        return this.#state;
    }
}

class FakeBrowserActionStorageCustody implements BrowserActionStorageCustody {
    public cleanupFailure: Error | undefined;
    public closed = false;
    public closedRandomnessIdentifiers: string[] = [];
    public closedStateSessionIdentifiers: string[] = [];
    public releasedReservationIdentifiers: string[] = [];
    public openLocalRecordFailure: Error | undefined;
    public openSealedActionRandomnessFailure: Error | undefined;
    #nextRandomnessIdentifier = 0;
    #nextReservationIdentifier = 0;
    readonly #randomnessSecretByIdentifier = new Map<string, number>();
    readonly #reservationSecretByIdentifier = new Map<string, number>();

    public constructor(readonly binding: BrowserActionStorageRootBinding) {}

    public copyBinding(): BrowserActionStorageRootBinding {
        return {
            actionContextHash: this.binding.actionContextHash.slice(),
            ceremonyContextHash: this.binding.ceremonyContextHash.slice(),
            participantId: this.binding.participantId.slice(),
            suiteId: this.binding.suiteId.slice(),
        };
    }

    public initialize(): Promise<BrowserDeviceWrappingSnapshot> {
        return Promise.resolve({
            mutationIdentifier: new Uint8Array(32),
            storageRootCommitment: hash(0x41),
        });
    }

    public currentSnapshot(): Promise<BrowserDeviceWrappingSnapshot> {
        return this.initialize();
    }

    public openIntoOwnedWorker(_input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<void> {
        return Promise.resolve();
    }

    public deriveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        return Promise.resolve(
            hash(input.recordType === 'actionRandomness' ? 0x31 : 0x32),
        );
    }

    public sealLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        return Promise.resolve(Uint8Array.from(input.plaintext).reverse());
    }

    public openLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        if (this.openLocalRecordFailure !== undefined) {
            return Promise.reject(this.openLocalRecordFailure);
        }
        return Promise.resolve(Uint8Array.from(input.envelope).reverse());
    }

    public hashLocalRecordEnvelope(envelope: Uint8Array): Promise<Uint8Array> {
        return Promise.resolve(hash(envelope[0] ?? 0));
    }

    public openActionStateVerifierSession(
        _input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        return Promise.resolve({
            isValid: true,
            value: 'state-session',
        });
    }

    public verifyActionStateReservation(
        _input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        this.#nextReservationIdentifier += 1;
        const identifier = `state-reservation-${String(this.#nextReservationIdentifier)}`;
        this.#reservationSecretByIdentifier.set(identifier, 0xa1);
        return Promise.resolve({
            isValid: true,
            value: identifier,
        });
    }

    public verifyActionRandomnessReservation(
        _input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        this.#nextReservationIdentifier += 1;
        const identifier = `randomness-reservation-${String(this.#nextReservationIdentifier)}`;
        this.#reservationSecretByIdentifier.set(identifier, 0xa2);
        return Promise.resolve({
            isValid: true,
            value: identifier,
        });
    }

    public releaseActionStateObject(identifier: string): Promise<void> {
        this.releasedReservationIdentifiers.push(identifier);
        this.#reservationSecretByIdentifier.delete(identifier);
        return Promise.resolve();
    }

    public closeActionStateVerifierSession(identifier: string): Promise<void> {
        this.closedStateSessionIdentifiers.push(identifier);
        return Promise.resolve();
    }

    public createAndSealActionRandomness(
        _input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserSealedActionRandomnessSession> {
        this.#nextRandomnessIdentifier += 1;
        const identifier = `randomness-${String(this.#nextRandomnessIdentifier)}`;
        this.#randomnessSecretByIdentifier.set(identifier, 0x91);
        return Promise.resolve({
            actionRandomnessCommitment: hash(0x51),
            actionRandomnessSessionIdentifier: identifier,
            canonicalEnvelope: Uint8Array.of(1, 2, 3),
        });
    }

    public openSealedActionRandomness(
        input: BrowserActionRandomnessRecordContext & {
            actionRandomnessCommitment: Uint8Array;
            canonicalEnvelope: Uint8Array;
        },
    ): Promise<BrowserOpenedActionRandomnessSession> {
        if (this.openSealedActionRandomnessFailure !== undefined) {
            return Promise.reject(this.openSealedActionRandomnessFailure);
        }
        if (
            input.canonicalEnvelope.byteLength !== 3 ||
            input.canonicalEnvelope[0] !== 1 ||
            input.canonicalEnvelope[1] !== 2 ||
            input.canonicalEnvelope[2] !== 3
        ) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'RecordAuthenticationFailed',
                    'The stored action-randomness envelope is corrupt.',
                ),
            );
        }
        this.#nextRandomnessIdentifier += 1;
        const identifier = `randomness-${String(this.#nextRandomnessIdentifier)}`;
        this.#randomnessSecretByIdentifier.set(identifier, 0x91);
        return Promise.resolve({
            actionRandomnessCommitment:
                input.actionRandomnessCommitment.slice(),
            actionRandomnessSessionIdentifier: identifier,
        });
    }

    public closeActionRandomness(identifier: string): Promise<void> {
        this.closedRandomnessIdentifiers.push(identifier);
        this.#randomnessSecretByIdentifier.delete(identifier);
        return Promise.resolve();
    }

    public derivePersistentProofAttempt(
        input: BrowserPersistentProofAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        const randomnessSecret = this.#randomnessSecretByIdentifier.get(
            input.actionRandomnessSessionIdentifier,
        );
        const reservationSecret = this.#reservationSecretByIdentifier.get(
            input.stateReservationIdentifier,
        );
        if (randomnessSecret === undefined || reservationSecret === undefined) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The proof attempt did not receive live owned-worker handles.',
                ),
            );
        }
        const attemptIdentifier = hash(input.rosterPosition);
        attemptIdentifier[1] = input.schedulePosition ?? 0;
        attemptIdentifier[2] = input.statementSchemaIdentifier & 0xff;
        attemptIdentifier[3] = randomnessSecret;
        attemptIdentifier[4] = reservationSecret;
        return Promise.resolve({
            applicationSlotHash: input.applicationStatementHash.slice(),
            attemptIdentifier,
        });
    }

    public deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        const randomnessSecret = this.#randomnessSecretByIdentifier.get(
            input.actionRandomnessSessionIdentifier,
        );
        const reservationSecret = this.#reservationSecretByIdentifier.get(
            input.stateReservationIdentifier,
        );
        if (randomnessSecret === undefined || reservationSecret === undefined) {
            return Promise.reject(
                new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The target-release attempt did not receive live owned-worker handles.',
                ),
            );
        }
        const attemptIdentifier = hash(input.rosterPosition);
        attemptIdentifier[1] = randomnessSecret;
        attemptIdentifier[2] = reservationSecret;
        return Promise.resolve({
            applicationSlotHash: hash(0x62),
            attemptIdentifier,
        });
    }

    public delete(
        _expectedSnapshot: BrowserDeviceWrappingSnapshot,
    ): Promise<void> {
        return Promise.resolve();
    }

    public close(): Promise<void> {
        this.closed = true;
        return this.cleanupFailure === undefined
            ? Promise.resolve()
            : Promise.reject(this.cleanupFailure);
    }
}

class FakeCheckpointStore implements AuthenticatedCheckpointStore {
    public interruptNextPublication = false;
    public publicationFailure: Error | undefined;
    public resumeFailure: Error | undefined;
    #nextIdentifier = 1;
    readonly #stateByLineage = new Map<string, readonly Uint8Array[]>();

    public constructor(
        readonly authorityContext: RuntimeStorageAuthorityContext,
    ) {}

    public copyAuthorityContext(): RuntimeStorageAuthorityContext {
        return {
            actionContextHash: this.authorityContext.actionContextHash.slice(),
            ceremonyContextHash:
                this.authorityContext.ceremonyContextHash.slice(),
            ownerParticipantIdentity:
                this.authorityContext.ownerParticipantIdentity.slice(),
            runtimeBuildManifestHash:
                this.authorityContext.runtimeBuildManifestHash.slice(),
            suiteIdentifier: this.authorityContext.suiteIdentifier.slice(),
        };
    }

    public beginOperation(
        streamAttemptIdentifiers: readonly Uint8Array[],
    ): Promise<CheckpointOperationIdentity> {
        const identifier = new Uint8Array(32).fill(this.#nextIdentifier);
        this.#nextIdentifier += 1;
        return Promise.resolve(
            Object.freeze({
                checkpointLineageIdentifier: identifier,
                streamAttemptIdentifiers: streamAttemptIdentifiers.map(
                    (identifier) => identifier.slice(),
                ),
            }) as unknown as CheckpointOperationIdentity,
        );
    }

    public evict(checkpointLineageIdentifier: Uint8Array): Promise<void> {
        this.#stateByLineage.delete(bytesKey(checkpointLineageIdentifier));
        return Promise.resolve();
    }

    public async publish(input: {
        boundary: CheckpointBoundary;
        identity: CheckpointOperationIdentity;
        stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
    }): Promise<Uint8Array> {
        if (this.publicationFailure !== undefined) {
            throw this.publicationFailure;
        }
        const chunks: Uint8Array[] = [];
        for await (const chunk of input.stateChunks) {
            chunks.push(chunk.slice());
            if (this.interruptNextPublication) {
                this.interruptNextPublication = false;
                throw new Error('Publication interrupted.');
            }
        }
        this.#stateByLineage.set(
            bytesKey(input.identity.checkpointLineageIdentifier),
            Object.freeze(chunks),
        );
        return Uint8Array.of(input.boundary.safeBoundaryOrdinal, chunks.length);
    }

    public repair(_checkpointLineageIdentifier: Uint8Array): Promise<void> {
        return Promise.resolve();
    }

    public async resume(input: {
        checkpointLineageIdentifier: Uint8Array;
        expectedBoundary: ExpectedCheckpointBoundary;
    }): Promise<ResumedCheckpoint> {
        if (this.resumeFailure !== undefined) {
            throw this.resumeFailure;
        }
        const chunks = this.#stateByLineage.get(
            bytesKey(input.checkpointLineageIdentifier),
        );
        if (chunks === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'MissingRecord',
                'The checkpoint is missing.',
            );
        }
        const identity = await this.beginOperation(
            input.expectedBoundary.orderedRandomCursors.map(
                (cursor) => cursor.streamAttemptIdentifier,
            ),
        );
        const resumedIdentity = Object.freeze({
            ...identity,
            checkpointLineageIdentifier:
                input.checkpointLineageIdentifier.slice(),
        }) as CheckpointOperationIdentity;
        return Object.freeze({
            canonicalManifestBytes: Uint8Array.of(
                input.expectedBoundary.safeBoundaryOrdinal,
                chunks.length,
            ),
            operationIdentity: resumedIdentity,
            restoreState: async (consumeChunk) => {
                for (let index = 0; index < chunks.length; index += 1) {
                    await consumeChunk(index, chunks[index].slice());
                }
            },
            stateStreamDescriptorBytes: Uint8Array.of(chunks.length),
        });
    }
}

class FakeProofApplicationLedger implements ProofApplicationLedger {
    readonly #reservations = new WeakMap<object, ProofApplicationReservation>();
    readonly #snapshot: {
        proofByteCount: bigint;
        proofObjectCount: number;
        proofQueryCount: bigint;
        proofVerificationCount: number;
        signatureVerificationCount: number;
    } = {
        proofByteCount: 0n,
        proofObjectCount: 0,
        proofQueryCount: 0n,
        proofVerificationCount: 0,
        signatureVerificationCount: 0,
    };

    public constructor(
        readonly authorityContext: RuntimeStorageAuthorityContext,
    ) {}

    public copyAuthorityContext(): RuntimeStorageAuthorityContext {
        return {
            actionContextHash: this.authorityContext.actionContextHash.slice(),
            ceremonyContextHash:
                this.authorityContext.ceremonyContextHash.slice(),
            ownerParticipantIdentity:
                this.authorityContext.ownerParticipantIdentity.slice(),
            runtimeBuildManifestHash:
                this.authorityContext.runtimeBuildManifestHash.slice(),
            suiteIdentifier: this.authorityContext.suiteIdentifier.slice(),
        };
    }

    public reserve(
        _reservationBinding: ProofApplicationReservationBinding,
    ): Promise<ProofApplicationReservationCapability> {
        this.#snapshot.proofByteCount += 5n;
        this.#snapshot.proofObjectCount += 1;
        const capability = opaque<ProofApplicationReservationCapability>();
        this.#reservations.set(capability, this.#reservation(false));
        return Promise.resolve(capability);
    }

    public copyReservation(
        reservation: ProofApplicationReservationCapability,
    ): ProofApplicationReservation {
        const value = this.#reservations.get(reservation);
        if (value === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Unknown proof reservation.',
            );
        }
        return Object.freeze({
            ...value,
            applicationSlotHash: value.applicationSlotHash.slice(),
        });
    }

    public beginVerification(input: {
        proofQueryCount: bigint;
        reservation: ProofApplicationReservationCapability;
        signatureVerificationCount: number;
    }): Promise<ProofApplicationReservation> {
        this.copyReservation(input.reservation);
        this.#snapshot.proofQueryCount += input.proofQueryCount;
        this.#snapshot.proofVerificationCount += 1;
        this.#snapshot.signatureVerificationCount +=
            input.signatureVerificationCount;
        const started = this.#reservation(true);
        this.#reservations.set(input.reservation, started);
        return Promise.resolve(started);
    }

    public releaseBeforeVerification(
        reservation: ProofApplicationReservationCapability,
    ): Promise<boolean> {
        this.copyReservation(reservation);
        if (this.#snapshot.proofObjectCount === 0) {
            return Promise.resolve(false);
        }
        this.#snapshot.proofByteCount -= 5n;
        this.#snapshot.proofObjectCount -= 1;
        this.#reservations.delete(reservation);
        return Promise.resolve(true);
    }

    public snapshot(): Promise<ProofApplicationLedgerSnapshot> {
        return Promise.resolve(Object.freeze({ ...this.#snapshot }));
    }

    #reservation(verificationStarted: boolean): ProofApplicationReservation {
        return Object.freeze({
            applicationSlotHash: hash(0x71),
            applicationStatementSchemaIdentifier: 0x2110,
            proofByteLength: 5n,
            verificationStarted,
        });
    }
}

type FakeWitnessRoleState = {
    conflictNextIntent: boolean;
    freshnessState: 'active' | 'retired';
    exactOutput?: Uint8Array;
    signedVoteCarrier?: Uint8Array;
};

const createWitnessRole = (
    subjectParticipantIdentity: Uint8Array,
    serviceSubjectParticipantIdentity = subjectParticipantIdentity,
): Readonly<{
    input: BrowserFoundationWitnessRoleInput;
    state: FakeWitnessRoleState;
}> => {
    const state: FakeWitnessRoleState = {
        conflictNextIntent: false,
        freshnessState: 'active',
    };
    const namespaceFreshnessService: NamespaceFreshnessWitnessService = {
        copyBinding: () => ({
            context: {
                actionContextHash: rosterVector.actionContextHash.slice(),
                ceremonyContextHash: rosterVector.ceremonyContextHash.slice(),
                storageInstanceIdentity: hash(0x70),
                subjectParticipantIdentity:
                    serviceSubjectParticipantIdentity.slice(),
                suiteIdentifier: rosterVector.suiteIdentifier.slice(),
            },
            witnessParticipantIdentity:
                orderedRosterParticipantIdentities[0].slice(),
        }),
        state: () => state.freshnessState,
        vote: (canonicalCheckpoint) =>
            state.freshnessState === 'retired'
                ? Promise.resolve({
                      isValid: false,
                      refusalReason: 'consumedState',
                  })
                : Promise.resolve({
                      isValid: true,
                      value: Uint8Array.of(
                          subjectParticipantIdentity[0] ?? 0,
                          canonicalCheckpoint[0] ?? 0,
                      ),
                  }),
    };
    const durableStateService: DurableStateWitnessService = {
        compareAndLockIntent: () => {
            if (state.conflictNextIntent) {
                state.conflictNextIntent = false;
                return Promise.reject(
                    new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'The witness already locked another intent.',
                    ),
                );
            }
            return Promise.resolve();
        },
        copyAuthorityContext: () =>
            runtimeAuthorityContext(orderedRosterParticipantIdentities[0]),
        cacheSignedVoteCarrier: (input) => {
            state.signedVoteCarrier = input.canonicalSignedVoteCarrier.slice();
            return Promise.resolve(state.signedVoteCarrier.slice());
        },
        readSignedVoteCarrier: () =>
            state.signedVoteCarrier === undefined
                ? Promise.reject(
                      new AuthenticatedRuntimeRecordError(
                          'MissingRecord',
                          'The signed carrier is missing.',
                      ),
                  )
                : Promise.resolve(state.signedVoteCarrier.slice()),
        cacheExactOutput: (input) => {
            state.exactOutput = input.exactOutputBytes.slice();
            return Promise.resolve();
        },
        readExactOutput: () =>
            state.exactOutput === undefined
                ? Promise.reject(
                      new AuthenticatedRuntimeRecordError(
                          'MissingRecord',
                          'The exact output is missing.',
                      ),
                  )
                : Promise.resolve(state.exactOutput.slice()),
    };
    return {
        input: {
            durableStateService,
            namespaceFreshnessService,
            subjectParticipantIdentity: subjectParticipantIdentity.slice(),
        },
        state,
    };
};

const createCanonicalBoardRuntime = (
    configuration: CanonicalBoardVerifierConfiguration,
): CanonicalBoardRuntime => {
    const snapshot = opaque<VerifiedCanonicalBoardSnapshot>();
    const verifiedObject = opaque<VerifiedTranscriptObject>();
    let closed = false;
    return {
        close: () => {
            closed = true;
        },
        copyConfiguration: () => ({
            actionContextHash: configuration.actionContextHash.slice(),
            canonicalRosterBytes: configuration.canonicalRosterBytes.slice(),
            ceremonyContextHash: configuration.ceremonyContextHash.slice(),
            maximumBallotAttemptsPerParticipant:
                configuration.maximumBallotAttemptsPerParticipant,
            maximumRetainedCanonicalCarrierByteLength:
                configuration.maximumRetainedCanonicalCarrierByteLength,
            maximumRetainedTranscriptObjects:
                configuration.maximumRetainedTranscriptObjects,
            maximumUnorderedCarriersPerBatch:
                configuration.maximumUnorderedCarriersPerBatch,
            suiteIdentifier: configuration.suiteIdentifier.slice(),
        }),
        copyCachedCarrier: () => ({
            isValid: false,
            refusalReason: 'missingPrerequisite',
        }),
        findObject: () => ({
            isValid: false,
            refusalReason: 'missingPrerequisite',
        }),
        ingestUnordered: (
            carriers: readonly UntrustedCanonicalBoardCarrier[],
        ) =>
            closed || carriers.length === 0
                ? { isValid: false, refusalReason: 'consumedState' }
                : { isValid: true, value: snapshot },
        objects: (candidateSnapshot) =>
            candidateSnapshot === snapshot && !closed
                ? { isValid: true, value: Object.freeze([verifiedObject]) }
                : { isValid: false, refusalReason: 'wrongContext' },
        state: () => (closed ? 'closed' : 'active'),
    };
};

type AuthorityHarness = Readonly<{
    authority: BrowserFoundationAuthority;
    checkpointStore: FakeCheckpointStore;
    custody: FakeBrowserActionStorageCustody;
    namespaceRuntime: FakeNamespaceFreshnessRuntime;
    witnessRoles: readonly ReturnType<typeof createWitnessRole>[];
}>;

type AuthorityConstructionOverrides = Readonly<{
    canonicalBoardConfiguration?: CanonicalBoardVerifierConfiguration;
    checkpointAuthorityContext?: RuntimeStorageAuthorityContext;
    custodyBinding?: BrowserActionStorageRootBinding;
    namespaceContext?: NamespaceFreshnessContext;
    proofAuthorityContext?: RuntimeStorageAuthorityContext;
    witnessServiceSubjectIdentities?: readonly Uint8Array[];
    witnessIdentities?: readonly Uint8Array[];
}>;

const createAuthorityHarness = (
    sharedCheckpointStore?: FakeCheckpointStore,
    overrides: AuthorityConstructionOverrides = {},
): AuthorityHarness => {
    const subjectParticipantIdentity = orderedRosterParticipantIdentities[0];
    const authorityContext = runtimeAuthorityContext(
        subjectParticipantIdentity,
    );
    const custody = new FakeBrowserActionStorageCustody(
        overrides.custodyBinding ?? {
            actionContextHash: rosterVector.actionContextHash,
            ceremonyContextHash: rosterVector.ceremonyContextHash,
            participantId: subjectParticipantIdentity,
            suiteId: rosterVector.suiteIdentifier,
        },
    );
    const checkpointStore =
        sharedCheckpointStore ??
        new FakeCheckpointStore(
            overrides.checkpointAuthorityContext ?? authorityContext,
        );
    const namespaceRuntime = new FakeNamespaceFreshnessRuntime(
        overrides.namespaceContext ?? {
            actionContextHash: rosterVector.actionContextHash,
            ceremonyContextHash: rosterVector.ceremonyContextHash,
            storageInstanceIdentity: hash(0x45),
            subjectParticipantIdentity,
            suiteIdentifier: rosterVector.suiteIdentifier,
        },
    );
    const witnessIdentities =
        overrides.witnessIdentities ??
        orderedRosterParticipantIdentities.slice(1);
    const serviceSubjectIdentities =
        overrides.witnessServiceSubjectIdentities ?? witnessIdentities;
    const witnessRoles = Object.freeze(
        witnessIdentities.map((identity, roleIndex) =>
            createWitnessRole(
                identity,
                serviceSubjectIdentities[roleIndex] ?? identity,
            ),
        ),
    );
    const canonicalBoardConfiguration: CanonicalBoardVerifierConfiguration =
        overrides.canonicalBoardConfiguration ?? {
            actionContextHash: rosterVector.actionContextHash,
            canonicalRosterBytes: rosterVector.canonicalRosterBytes,
            ceremonyContextHash: rosterVector.ceremonyContextHash,
            maximumBallotAttemptsPerParticipant: 8,
            maximumRetainedCanonicalCarrierByteLength: 1_048_576,
            maximumRetainedTranscriptObjects: 128,
            maximumUnorderedCarriersPerBatch: 32,
            suiteIdentifier: rosterVector.suiteIdentifier,
        };
    const proofApplicationLedger = new FakeProofApplicationLedger(
        overrides.proofAuthorityContext ?? authorityContext,
    );
    return {
        authority: openBrowserFoundationAuthority({
            canonicalBoardRuntime: createCanonicalBoardRuntime(
                canonicalBoardConfiguration,
            ),
            checkpointStore,
            custody,
            namespaceFreshnessRuntime: namespaceRuntime,
            orderedWitnessRoles: witnessRoles.map((role) => role.input),
            proofApplicationLedger,
        }),
        checkpointStore,
        custody,
        namespaceRuntime,
        witnessRoles,
    };
};

const activate = async (
    harness: AuthorityHarness,
): Promise<BrowserFoundationActiveCapability> => {
    expect(await harness.authority.startup()).toBe('active');
    return harness.authority.activeCapability();
};

const stateReservationInput = () => ({
    canonicalReservationIntentCarrier: Uint8Array.of(1),
    canonicalStateCertificate: Uint8Array.of(2),
    capabilityKind: stateCapabilityKinds.setupActionRandomnessRoot,
    expectedAuthorizationHash: hash(0x21),
    subjectParticipantIdentity: hash(0x41),
});

const checkpointBoundary = (): CheckpointBoundary => ({
    operationKind: 3,
    orderedRandomCursors: Object.freeze([]),
    orderedSourceDigests: Object.freeze([hash(0x61)]),
    safeBoundaryOrdinal: 2,
    stateStreamDescriptorBytes: Uint8Array.of(4, 5),
    stateStreamDomain: 'sealed-lattice/test/foundation-state/v1',
});

const expectedCheckpointBoundary = (): ExpectedCheckpointBoundary => {
    const { stateStreamDescriptorBytes: _descriptor, ...boundary } =
        checkpointBoundary();
    return boundary;
};

describe('browser foundation authority', () => {
    it('rejects cross-wired board, roster, custody, freshness, ledger, and checkpoint bindings', () => {
        const subjectParticipantIdentity =
            orderedRosterParticipantIdentities[0];
        const baseAuthorityContext = runtimeAuthorityContext(
            subjectParticipantIdentity,
        );
        const baseBoardConfiguration: CanonicalBoardVerifierConfiguration = {
            actionContextHash: rosterVector.actionContextHash,
            canonicalRosterBytes: rosterVector.canonicalRosterBytes,
            ceremonyContextHash: rosterVector.ceremonyContextHash,
            maximumBallotAttemptsPerParticipant: 8,
            maximumRetainedCanonicalCarrierByteLength: 1_048_576,
            maximumRetainedTranscriptObjects: 128,
            maximumUnorderedCarriersPerBatch: 32,
            suiteIdentifier: rosterVector.suiteIdentifier,
        };
        const mismatches: readonly AuthorityConstructionOverrides[] = [
            {
                canonicalBoardConfiguration: {
                    ...baseBoardConfiguration,
                    actionContextHash: hash(0xa1),
                },
            },
            {
                canonicalBoardConfiguration: {
                    ...baseBoardConfiguration,
                    canonicalRosterBytes:
                        rosterVector.canonicalRosterBytes.slice(0, -1),
                },
            },
            {
                custodyBinding: {
                    actionContextHash: rosterVector.actionContextHash,
                    ceremonyContextHash: rosterVector.ceremonyContextHash,
                    participantId: subjectParticipantIdentity,
                    suiteId: hash(0xa2),
                },
            },
            {
                namespaceContext: {
                    actionContextHash: rosterVector.actionContextHash,
                    ceremonyContextHash: rosterVector.ceremonyContextHash,
                    storageInstanceIdentity: hash(0x45),
                    subjectParticipantIdentity: hash(0xa3),
                    suiteIdentifier: rosterVector.suiteIdentifier,
                },
            },
            {
                proofAuthorityContext: {
                    ...baseAuthorityContext,
                    actionContextHash: hash(0xa4),
                },
            },
            {
                checkpointAuthorityContext: {
                    ...baseAuthorityContext,
                    runtimeBuildManifestHash: hash(0xa5),
                },
            },
        ];

        for (const mismatch of mismatches) {
            expect(() =>
                createAuthorityHarness(undefined, mismatch),
            ).toThrowError(
                expect.objectContaining({ code: 'InvalidConfiguration' }),
            );
        }
    });

    it('requires witness roles to be exactly the other canonical roster identities in roster order', () => {
        const subjectParticipantIdentity =
            orderedRosterParticipantIdentities[0];
        const expectedWitnessIdentities =
            orderedRosterParticipantIdentities.slice(1);
        const reorderedWitnessIdentities = [...expectedWitnessIdentities];
        [reorderedWitnessIdentities[0], reorderedWitnessIdentities[1]] = [
            reorderedWitnessIdentities[1],
            reorderedWitnessIdentities[0],
        ];
        const duplicateWitnessIdentities = [...expectedWitnessIdentities];
        duplicateWitnessIdentities[1] = duplicateWitnessIdentities[0];
        const selfWitnessIdentities = [...expectedWitnessIdentities];
        selfWitnessIdentities[0] = subjectParticipantIdentity;
        const substitutedWitnessIdentities = [...expectedWitnessIdentities];
        substitutedWitnessIdentities[0] = hash(0xb1);
        const invalidWitnessIdentityLists = [
            expectedWitnessIdentities.slice(0, -1),
            reorderedWitnessIdentities,
            duplicateWitnessIdentities,
            selfWitnessIdentities,
            substitutedWitnessIdentities,
        ] as const;

        for (const witnessIdentities of invalidWitnessIdentityLists) {
            expect(() =>
                createAuthorityHarness(undefined, { witnessIdentities }),
            ).toThrowError(
                expect.objectContaining({ code: 'InvalidConfiguration' }),
            );
        }
    });

    it('rejects a canonical witness label backed by a service for another roster subject', () => {
        const witnessServiceSubjectIdentities =
            orderedRosterParticipantIdentities.slice(1);
        [
            witnessServiceSubjectIdentities[0],
            witnessServiceSubjectIdentities[1],
        ] = [
            witnessServiceSubjectIdentities[1],
            witnessServiceSubjectIdentities[0],
        ];

        expect(() =>
            createAuthorityHarness(undefined, {
                witnessServiceSubjectIdentities,
            }),
        ).toThrowError(
            expect.objectContaining({ code: 'InvalidConfiguration' }),
        );
    });

    it('composes canonical ingestion, custody, state reservation, proof resources, checkpointing, and fixed-roster witnessing', async () => {
        const harness = createAuthorityHarness();
        const capability = await activate(harness);
        const board = await harness.authority.ingestCanonicalBoard(capability, [
            { canonicalCarrier: Uint8Array.of(4, 5, 6) },
        ]);
        expect(board.isValid).toBe(true);
        if (!board.isValid) {
            throw new Error(board.refusalReason);
        }
        expect(
            await harness.authority.listCanonicalBoardObjects(
                capability,
                board.value,
            ),
        ).toMatchObject({ isValid: true });

        const localPlaintext = Uint8Array.of(3, 7, 9, 11);
        const localRecordInput = {
            actionRandomnessCommitment: hash(0x51),
            identifierInput: {
                applicationSlotHash: hash(0x52),
                recordType: 'proofAttempt' as const,
            },
            plaintext: localPlaintext,
            recordVersion: 1n,
        };
        const localEnvelope = await harness.authority.sealLocalRecord(
            capability,
            localRecordInput,
        );
        expect(localEnvelope).toEqual(Uint8Array.of(11, 9, 7, 3));
        expect(
            await harness.authority.openLocalRecord(capability, {
                ...localRecordInput,
                envelope: localEnvelope,
            }),
        ).toEqual(localPlaintext);

        const actionRandomness = await harness.authority.createActionRandomness(
            capability,
            {
                recordVersion: 0n,
            },
        );
        const stateReservation = await harness.authority.verifyStateReservation(
            capability,
            stateReservationInput(),
        );
        expect(stateReservation.isValid).toBe(true);
        if (!stateReservation.isValid) {
            throw new Error(stateReservation.refusalReason);
        }
        const proofAttempt =
            await harness.authority.derivePersistentProofAttempt(
                capability,
                actionRandomness,
                stateReservation.value,
                {
                    applicationStatementHash: hash(0x81),
                    rosterPosition: 4,
                    schedulePosition: 7,
                    statementSchemaIdentifier: 0x2110,
                },
            );
        expect(proofAttempt.applicationSlotHash).toEqual(hash(0x81));
        expect(proofAttempt.attemptIdentifier.slice(0, 3)).toEqual(
            Uint8Array.of(4, 7, 0x10),
        );

        const reservationBinding = opaque<ProofApplicationReservationBinding>();
        const proofReservation =
            await harness.authority.reserveProofApplication(
                capability,
                reservationBinding,
            );
        await harness.authority.beginProofVerification(capability, {
            proofQueryCount: 6n,
            reservation: proofReservation,
            signatureVerificationCount: 2,
        });
        expect(
            await harness.authority.proofApplicationSnapshot(capability),
        ).toEqual({
            proofByteCount: 5n,
            proofObjectCount: 1,
            proofQueryCount: 6n,
            proofVerificationCount: 1,
            signatureVerificationCount: 2,
        });

        const checkpoint = await harness.authority.beginCheckpoint(
            capability,
            0,
        );
        expect(
            await harness.authority.publishCheckpoint(capability, checkpoint, {
                boundary: checkpointBoundary(),
                stateChunks: [Uint8Array.of(10), Uint8Array.of(20, 30)],
            }),
        ).toEqual(Uint8Array.of(2, 2));

        const witnessRoles = await harness.authority.witnessRoles(capability);
        expect(witnessRoles).toHaveLength(9);
        expect(
            await harness.authority.voteForNamespaceCheckpoint(
                capability,
                witnessRoles[3],
                Uint8Array.of(0x55),
            ),
        ).toEqual({
            isValid: true,
            value: Uint8Array.of(
                harness.witnessRoles[3].input.subjectParticipantIdentity[0],
                0x55,
            ),
        });
    });

    it('copies retained bytes and derives byte-identical attempts after authenticated same-browser continuation', async () => {
        const harness = createAuthorityHarness();
        const capability = await activate(harness);
        const created = await harness.authority.createActionRandomness(
            capability,
            { recordVersion: 0n },
        );
        const description =
            await harness.authority.copyActionRandomnessDescription(
                capability,
                created,
            );
        const reservation = await harness.authority.verifyStateReservation(
            capability,
            stateReservationInput(),
        );
        if (!reservation.isValid) {
            throw new Error(reservation.refusalReason);
        }
        const attemptInput = {
            applicationStatementHash: hash(0x72),
            rosterPosition: 2,
            schedulePosition: 9,
            statementSchemaIdentifier: 0x1212,
        };
        const firstAttempt =
            await harness.authority.derivePersistentProofAttempt(
                capability,
                created,
                reservation.value,
                attemptInput,
            );
        description.canonicalEnvelope[0] = 0xff;
        description.actionRandomnessCommitment[0] = 0xff;
        const copiedAgain =
            await harness.authority.copyActionRandomnessDescription(
                capability,
                created,
            );
        expect(copiedAgain.canonicalEnvelope).toEqual(Uint8Array.of(1, 2, 3));
        expect(copiedAgain.actionRandomnessCommitment).toEqual(hash(0x51));

        await harness.authority.closeActionRandomness(capability, created);
        const resumed = await harness.authority.resumeActionRandomness(
            capability,
            { ...copiedAgain, recordVersion: 0n },
        );
        const secondAttempt =
            await harness.authority.derivePersistentProofAttempt(
                capability,
                resumed,
                reservation.value,
                attemptInput,
            );
        expect(secondAttempt).toEqual(firstAttempt);
    });

    it('rejects active, randomness, reservation, checkpoint, and witness capabilities from another operation', async () => {
        const first = createAuthorityHarness();
        const second = createAuthorityHarness();
        const firstCapability = await activate(first);
        const secondCapability = await activate(second);
        const firstRandomness = await first.authority.createActionRandomness(
            firstCapability,
            {
                recordVersion: 0n,
            },
        );
        const firstReservation = await first.authority.verifyStateReservation(
            firstCapability,
            stateReservationInput(),
        );
        if (!firstReservation.isValid) {
            throw new Error(firstReservation.refusalReason);
        }
        const firstCheckpoint = await first.authority.beginCheckpoint(
            firstCapability,
            0,
        );
        const firstWitness = (
            await first.authority.witnessRoles(firstCapability)
        )[0];

        await expect(
            second.authority.proofApplicationSnapshot(firstCapability),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            second.authority.copyActionRandomnessDescription(
                secondCapability,
                firstRandomness,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            second.authority.releaseStateReservation(
                secondCapability,
                firstReservation.value,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            second.authority.copyCheckpointDescription(
                secondCapability,
                firstCheckpoint,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            second.authority.copyWitnessRoleDescription(
                secondCapability,
                firstWitness,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(second.authority.state()).toBe('active');
    });

    it('makes the operation unavailable during mutation and invalidates the predecessor capability after certification', async () => {
        const harness = createAuthorityHarness();
        const predecessorCapability = await activate(harness);
        let observedState: string | undefined;
        expect(
            await harness.authority.certifyMutation(
                predecessorCapability,
                () => {
                    observedState = harness.authority.state();
                    expect(() =>
                        harness.authority.activeCapability(),
                    ).toThrowError(
                        expect.objectContaining({ code: 'InvalidState' }),
                    );
                    return Promise.resolve();
                },
            ),
        ).toBe('active');
        expect(observedState).toBe('unavailable');
        const successorCapability = harness.authority.activeCapability();
        expect(successorCapability).not.toBe(predecessorCapability);
        await expect(
            harness.authority.proofApplicationSnapshot(predecessorCapability),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            harness.authority.proofApplicationSnapshot(successorCapability),
        ).resolves.toMatchObject({ proofObjectCount: 0 });
    });

    it('recovers an interrupted checkpoint publication and restores exact immutable chunks', async () => {
        const harness = createAuthorityHarness();
        const capability = await activate(harness);
        const checkpoint = await harness.authority.beginCheckpoint(
            capability,
            0,
        );
        const originalChunks = [
            Uint8Array.of(1, 3, 5),
            Uint8Array.of(2, 4, 6, 8),
        ];
        harness.checkpointStore.interruptNextPublication = true;
        await expect(
            harness.authority.publishCheckpoint(capability, checkpoint, {
                boundary: checkpointBoundary(),
                stateChunks: originalChunks,
            }),
        ).rejects.toThrow('Publication interrupted.');
        expect(harness.authority.state()).toBe('active');

        await harness.authority.publishCheckpoint(capability, checkpoint, {
            boundary: checkpointBoundary(),
            stateChunks: originalChunks,
        });
        const checkpointDescription =
            await harness.authority.copyCheckpointDescription(
                capability,
                checkpoint,
            );
        originalChunks[0][0] = 0xff;
        originalChunks[1].fill(0xee);
        const resumed = await harness.authority.resumeCheckpoint(capability, {
            checkpointLineageIdentifier:
                checkpointDescription.checkpointLineageIdentifier,
            expectedBoundary: expectedCheckpointBoundary(),
        });
        const restoredChunks: Uint8Array[] = [];
        await harness.authority.restoreCheckpointState(
            capability,
            resumed,
            (chunkIndex, chunkBytes) => {
                restoredChunks[chunkIndex] = chunkBytes;
            },
        );
        expect(restoredChunks).toEqual([
            Uint8Array.of(1, 3, 5),
            Uint8Array.of(2, 4, 6, 8),
        ]);
    });

    it('retires permanently when checkpoint rollback, local-record corruption, or witness-state loss is observed', async () => {
        const checkpointHarness = createAuthorityHarness();
        const checkpointCapability = await activate(checkpointHarness);
        checkpointHarness.checkpointStore.resumeFailure =
            new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'The stored checkpoint was rolled back.',
            );
        await expect(
            checkpointHarness.authority.resumeCheckpoint(checkpointCapability, {
                checkpointLineageIdentifier: new Uint8Array(32),
                expectedBoundary: expectedCheckpointBoundary(),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(checkpointHarness.authority.state()).toBe('retired');
        expect(checkpointHarness.authority.retirementReason()).toBe(
            'localStateAuthenticationFailed',
        );
        await expect(
            checkpointHarness.authority.startup(),
        ).rejects.toBeInstanceOf(BrowserFoundationAuthorityError);

        const recordHarness = createAuthorityHarness();
        const recordCapability = await activate(recordHarness);
        recordHarness.custody.openLocalRecordFailure =
            new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'The record tag is invalid.',
            );
        await expect(
            recordHarness.authority.openLocalRecord(recordCapability, {
                actionRandomnessCommitment: hash(0x51),
                envelope: Uint8Array.of(1),
                identifierInput: {
                    applicationSlotHash: hash(0x71),
                    recordType: 'proofAttempt',
                },
                recordVersion: 1n,
            }),
        ).rejects.toMatchObject({ code: 'RecordAuthenticationFailed' });
        expect(recordHarness.authority.state()).toBe('retired');

        const witnessHarness = createAuthorityHarness();
        const witnessCapability = await activate(witnessHarness);
        const witnessRole = (
            await witnessHarness.authority.witnessRoles(witnessCapability)
        )[0];
        witnessHarness.witnessRoles[0].state.freshnessState = 'retired';
        await expect(
            witnessHarness.authority.voteForNamespaceCheckpoint(
                witnessCapability,
                witnessRole,
                Uint8Array.of(1),
            ),
        ).resolves.toMatchObject({
            isValid: false,
            refusalReason: 'consumedState',
        });
        expect(witnessHarness.authority.state()).toBe('retired');
        expect(witnessHarness.authority.retirementReason()).toBe(
            'witnessStateUnavailable',
        );
    });

    it('preserves a fixed witness lock across a conflicting intent without treating the conflict as local loss', async () => {
        const harness = createAuthorityHarness();
        const capability = await activate(harness);
        const witnessRole = (
            await harness.authority.witnessRoles(capability)
        )[0];
        harness.witnessRoles[0].state.conflictNextIntent = true;
        const verifiedIntentBinding = opaque<VerifiedStateDurableBinding>();
        await expect(
            harness.authority.compareAndLockWitnessIntent(
                capability,
                witnessRole,
                { verifiedIntentBinding },
            ),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(harness.authority.state()).toBe('active');
        await expect(
            harness.authority.compareAndLockWitnessIntent(
                capability,
                witnessRole,
                { verifiedIntentBinding },
            ),
        ).resolves.toBeUndefined();
    });

    it('remains retired and reports cleanup failure when secret revocation cannot finish', async () => {
        const harness = createAuthorityHarness();
        const capability = await activate(harness);
        const randomness = await harness.authority.createActionRandomness(
            capability,
            { recordVersion: 0n },
        );
        const reservation = await harness.authority.verifyStateReservation(
            capability,
            stateReservationInput(),
        );
        if (!reservation.isValid) {
            throw new Error(reservation.refusalReason);
        }
        expect(randomness).toBeDefined();
        harness.custody.cleanupFailure = new Error(
            'Owned worker termination failed.',
        );
        await expect(harness.authority.close()).rejects.toMatchObject({
            code: 'CleanupFailed',
            name: 'BrowserFoundationAuthorityError',
        });
        expect(harness.authority.state()).toBe('retired');
        expect(harness.authority.retirementReason()).toBe('closed');
        expect(harness.custody.closedRandomnessIdentifiers).toEqual([
            'randomness-1',
        ]);
        expect(harness.custody.releasedReservationIdentifiers).toEqual([
            'state-reservation-1',
        ]);
        expect(harness.custody.closedStateSessionIdentifiers).toEqual([
            'state-session',
        ]);
        expect(() => harness.authority.activeCapability()).toThrowError(
            expect.objectContaining({ code: 'Retired' }),
        );
    });
});
