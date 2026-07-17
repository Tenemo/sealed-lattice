import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { foundationProfile, stateCapabilityKinds } from '@sealed-lattice/types';
import {
    afterEach,
    beforeAll,
    beforeEach,
    describe,
    expect,
    expectTypeOf,
    it,
} from 'vitest';

import { createCanonicalCarrierSigningKeyPairFixtures } from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    commonProofApplicationHandoffLogicalRecordKey,
    commonProofApplicationHandoffMarkerRecordByteLength,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import {
    openDurableStateWitnessService,
    persistCommonProofApplicationAuthorization,
    type DurableStateWitnessService,
    type DurableStateWitnessServiceLimits,
    type TransferableDurableStateWitnessService,
} from '#packages/protocol/src/runtime/durable-state-witness-service';
import {
    generateRuntimeStorageEncryptionKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    openStateVerifierSession,
    type StateVerifierSession,
    type VerifiedStateDurableBinding,
    type VerifiedStateReservation,
} from '#packages/wasm/src/state-verifier-runtime';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    emptyHomogeneousListItem,
    foundationHash512,
    hashItem,
    presentOptionalItem,
    unsigned16Item,
    unsigned64Item,
    variableBytesItem,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import {
    createStateVerifierTestVector,
    type StateVerifierTestVector,
} from '#packages/wasm/tests/state-verifier-test-vectors';
import { canonicalStreamChunkBuffers as chunkBuffers } from '#tests/support/canonical-stream-chunk-buffers';

const serviceLimits = {
    maximumExactOutputByteLength:
        foundationProfile.streamChunkByteLength + 1_024,
    maximumRecordSealingCount: 256,
    maximumSignedVoteCarrierByteLength: 8 * 1_024,
    transactionLifetimeMilliseconds: 5_000,
} as const;

const objectSignatureContext = new TextEncoder().encode(
    'sealed-lattice/object-signature/v1',
);
const stateOutputIntentObjectType = 0x0052;
const stateWitnessVoteObjectType = 0x0053;

const byteArraysEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((byte, byteIndex) => byte === right[byteIndex]);

const requireValid = <Value>(result: {
    isValid: boolean;
    refusalReason?: string;
    value?: Value;
}): Value => {
    if (!result.isValid) {
        throw new Error(result.refusalReason ?? 'verification failed');
    }
    return result.value as Value;
};

const descriptorFor = (
    kernel: TranscriptCoreKernel,
    streamDomain: CanonicalStreamDomain,
    bytes: Uint8Array,
): Uint8Array => {
    const writer = openCanonicalStreamWorkerRuntime({ kernel }).openWriter({
        streamDomain,
        totalByteLength: bytes.byteLength,
    });
    for (const [chunkIndex, chunk] of chunkBuffers(bytes).entries()) {
        writer.absorbChunk(chunkIndex, chunk);
    }
    return writer.finish();
};

const createSignedCarrier = (
    vector: StateVerifierTestVector,
    input: {
        objectType: number;
        payloadBytes: Uint8Array;
        producerParticipantIdentity: Uint8Array;
        producerRosterPosition: number;
        producerSequence: bigint;
        signatureHedge?: Uint8Array;
        signaturePurpose: string;
    },
): Readonly<{ canonicalCarrier: Uint8Array; objectHash: Uint8Array }> => {
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    try {
        const canonicalEnvelope = canonicalTuple(
            0x0100,
            asciiItem('sealed-lattice'),
            unsigned16Item(1),
            hashItem(vector.suiteIdentifier),
            unsigned16Item(input.objectType),
            hashItem(vector.ceremonyContextHash),
            hashItem(vector.actionContextHash),
            presentOptionalItem(0x07, input.producerParticipantIdentity),
            unsigned64Item(input.producerSequence),
            emptyHomogeneousListItem(0x06),
            variableBytesItem(input.payloadBytes),
        );
        const objectHash = foundationHash512(
            'sealed-lattice/foundation/object/v1',
            variableBytesItem(canonicalEnvelope),
        );
        const signatureMessage = foundationHash512(
            'sealed-lattice/foundation/signature-message/v1',
            hashItem(objectHash),
            hashItem(vector.rosterHash),
            asciiItem(input.signaturePurpose),
        );
        const signature = ml_dsa65.sign(
            signatureMessage,
            signingKeyPairs[input.producerRosterPosition].secretKey,
            {
                context: objectSignatureContext,
                extraEntropy: input.signatureHedge ?? false,
            },
        );
        return {
            canonicalCarrier: canonicalTuple(
                0x0101,
                variableBytesItem(canonicalEnvelope),
                canonicalItem(0x01, signature),
            ),
            objectHash,
        };
    } finally {
        for (const { secretKey } of signingKeyPairs) {
            secretKey.fill(0);
        }
    }
};

const createConflictingOutputIntent = (
    vector: StateVerifierTestVector,
): Readonly<{ canonicalCarrier: Uint8Array; exactOutputBytes: Uint8Array }> => {
    const exactOutputBytes = vector.exactOutputBytes.slice();
    exactOutputBytes[exactOutputBytes.byteLength - 1] ^= 1;
    const exactOutputHash = foundationHash512(
        'sealed-lattice/state/exact-output/v1',
        unsigned16Item(stateCapabilityKinds.targetRelease),
        unsigned64Item(BigInt(exactOutputBytes.byteLength)),
        variableBytesItem(exactOutputBytes),
    );
    return {
        canonicalCarrier: createSignedCarrier(vector, {
            objectType: stateOutputIntentObjectType,
            payloadBytes: canonicalTuple(
                0x1611,
                hashItem(vector.reservation.objectHash),
                hashItem(exactOutputHash),
            ),
            producerParticipantIdentity: vector.subjectParticipantIdentity,
            producerRosterPosition: 0,
            producerSequence: 0n,
            signaturePurpose: 'state-output-intent',
        }).canonicalCarrier,
        exactOutputBytes,
    };
};

const createHedgedReservationVoteCarriers = (
    vector: StateVerifierTestVector,
): readonly [Uint8Array, Uint8Array] => {
    const payloadBytes = canonicalTuple(
        0x1612,
        hashItem(vector.reservation.objectHash),
    );
    const carrierForHedgeByte = (hedgeByte: number): Uint8Array =>
        createSignedCarrier(vector, {
            objectType: stateWitnessVoteObjectType,
            payloadBytes,
            producerParticipantIdentity: vector.witnessParticipantIdentity,
            producerRosterPosition: 1,
            producerSequence: 1n,
            signatureHedge: new Uint8Array(32).fill(hedgeByte),
            signaturePurpose: 'state-witness-vote',
        }).canonicalCarrier;
    return [carrierForHedgeByte(0x35), carrierForHedgeByte(0xa7)];
};

const openSession = (
    kernel: TranscriptCoreKernel,
    vector: StateVerifierTestVector,
): StateVerifierSession =>
    requireValid(
        openStateVerifierSession({
            configuration: {
                actionContextHash: vector.actionContextHash,
                canonicalRosterBytes: vector.canonicalRosterBytes,
                ceremonyContextHash: vector.ceremonyContextHash,
                suiteIdentifier: vector.suiteIdentifier,
            },
            kernel,
        }),
    );

const verifyReservation = (input: {
    session: StateVerifierSession;
    vector: StateVerifierTestVector;
}): VerifiedStateReservation =>
    requireValid(
        input.session.verifyReservation({
            canonicalReservationIntentCarrier:
                input.vector.reservation.canonicalIntentCarrier,
            canonicalStateCertificate:
                input.vector.reservation.canonicalStateCertificate,
            capabilityKind: stateCapabilityKinds.targetRelease,
            expectedAuthorizationHash: input.vector.authorizationHash,
            subjectParticipantIdentity: input.vector.subjectParticipantIdentity,
        }),
    );

const verifyReservationIntentBinding = (input: {
    canonicalReservationIntentCarrier?: Uint8Array;
    expectedAuthorizationHash?: Uint8Array;
    session: StateVerifierSession;
    vector: StateVerifierTestVector;
}): VerifiedStateDurableBinding => {
    const verifiedReservationIntent = requireValid(
        input.session.verifyReservationIntent({
            canonicalReservationIntentCarrier:
                input.canonicalReservationIntentCarrier ??
                input.vector.reservation.canonicalIntentCarrier,
            capabilityKind: stateCapabilityKinds.targetRelease,
            expectedAuthorizationHash:
                input.expectedAuthorizationHash ??
                input.vector.authorizationHash,
            subjectParticipantIdentity: input.vector.subjectParticipantIdentity,
        }),
    );
    return requireValid(
        input.session.durableBindingFor(verifiedReservationIntent),
    );
};

const verifyOutputBinding = (input: {
    canonicalOutputIntentCarrier?: Uint8Array;
    exactOutputBytes?: Uint8Array;
    kernel: TranscriptCoreKernel;
    session: StateVerifierSession;
    vector: StateVerifierTestVector;
}): VerifiedStateDurableBinding => {
    const reservation = verifyReservation(input);
    const exactOutputBytes =
        input.exactOutputBytes ?? input.vector.exactOutputBytes;
    const output = requireValid(
        input.session.openOutputIntentVerification({
            canonicalOutputIntentCarrier:
                input.canonicalOutputIntentCarrier ??
                input.vector.output.canonicalIntentCarrier,
            exactOutputDescriptorBytes: descriptorFor(
                input.kernel,
                canonicalStreamDomains.stateTargetReleaseExactOutput,
                exactOutputBytes,
            ),
            verifiedReservation: reservation,
        }),
    );
    for (const [chunkIndex, chunk] of chunkBuffers(
        exactOutputBytes,
    ).entries()) {
        requireValid(output.absorbChunk(chunkIndex, chunk));
    }
    const verifiedOutputIntent = requireValid(output.finish());
    return requireValid(input.session.durableBindingFor(verifiedOutputIntent));
};

describe('durable state witness service', () => {
    let kernel: TranscriptCoreKernel;
    let vector: StateVerifierTestVector;
    let encryptionKey: CryptoKey;
    let session: StateVerifierSession;
    let verifiedConflictingReservationBinding: VerifiedStateDurableBinding;
    let verifiedOutputBinding: VerifiedStateDurableBinding;
    let verifiedReservationBinding: VerifiedStateDurableBinding;

    beforeAll(async () => {
        vector = createStateVerifierTestVector();
        kernel = await loadFreshTranscriptCoreKernel();
    });

    beforeEach(async () => {
        encryptionKey = await generateRuntimeStorageEncryptionKey();
        session = openSession(kernel, vector);
        verifiedReservationBinding = verifyReservationIntentBinding({
            session,
            vector,
        });
        const conflictingAuthorizationHash = vector.authorizationHash.slice();
        conflictingAuthorizationHash[0] ^= 0xff;
        verifiedConflictingReservationBinding = verifyReservationIntentBinding({
            canonicalReservationIntentCarrier:
                vector.conflictingReservation.canonicalIntentCarrier,
            expectedAuthorizationHash: conflictingAuthorizationHash,
            session,
            vector,
        });
        verifiedOutputBinding = verifyOutputBinding({
            kernel,
            session,
            vector,
        });
    });

    afterEach(() => {
        session.cancel();
    });

    const openService = async (input?: {
        limits?: DurableStateWitnessServiceLimits;
    }): Promise<{
        adapter: Awaited<ReturnType<typeof openRuntimeTestStore>>['adapter'];
        service: TransferableDurableStateWitnessService;
        store: Awaited<ReturnType<typeof openRuntimeTestStore>>['store'];
    }> => {
        const { adapter, store } = await openRuntimeTestStore();
        return {
            adapter,
            service: openDurableStateWitnessService({
                authorityContext: runtimeAuthorityContext({
                    actionContextHash: vector.actionContextHash,
                    ceremonyContextHash: vector.ceremonyContextHash,
                    suiteIdentifier: vector.suiteIdentifier,
                }),
                encryptionKey,
                limits: input?.limits ?? serviceLimits,
                store,
            }),
            store,
        };
    };

    it('exposes the durable witness and exact-output operations with explicit missing records', async () => {
        expectTypeOf<keyof DurableStateWitnessService>().toEqualTypeOf<
            | 'cacheExactOutput'
            | 'cacheSignedVoteCarrier'
            | 'close'
            | 'compareAndLockIntent'
            | 'copyAuthorityContext'
            | 'readExactOutput'
            | 'readSignedVoteCarrier'
        >();
        const { service } = await openService();

        await expect(
            service.readSignedVoteCarrier({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
        await expect(
            service.readExactOutput({ verifiedOutputBinding }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
    });

    it('persists one fixed common-proof authorization frame and rereads the exact authenticated bytes', async () => {
        const { adapter, service } = await openService();
        const authorizationFrame = Uint8Array.from(
            { length: 746 },
            (_, byteIndex) => (byteIndex * 149 + 31) & 0xff,
        );
        const proofApplicationSlotHash = new Uint8Array(64).fill(0x6d);
        const initialMutationCount = adapter.atomicMutationCount;
        const publicationDispositions: string[] = [];

        const authenticatedFrame =
            await persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    publicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            });

        expect([...authenticatedFrame]).toEqual([...authorizationFrame]);
        expect(publicationDispositions).toEqual(['published-or-indeterminate']);
        expect(adapter.atomicMutationCount).toBe(initialMutationCount + 1);

        const duplicatePublicationDispositions: string[] = [];
        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    duplicatePublicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(duplicatePublicationDispositions).toEqual([]);
        expect(adapter.atomicMutationCount).toBe(initialMutationCount + 1);
    });

    it('atomically replaces the authenticated handoff marker with a durable application that survives service restart', async () => {
        const { service, store } = await openService();
        const markerRecordBytes = Uint8Array.from(
            { length: commonProofApplicationHandoffMarkerRecordByteLength },
            (_unused, byteIndex) => (byteIndex * 43 + 19) & 0xff,
        );
        const markerTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 10_000,
        });
        try {
            const markerLease = await markerTransaction.issueWriteLease({
                declaredByteLength: markerRecordBytes.byteLength,
                expectedCurrentValue: null,
                logicalRecordKey: commonProofApplicationHandoffLogicalRecordKey,
            });
            await markerLease.write(markerRecordBytes);
            await markerLease.seal(({ bytes }) => {
                expect(bytes).toEqual(markerRecordBytes);
            });
            await markerTransaction.commit();
        } catch (error) {
            await markerTransaction.closeAfterFailure();
            throw error;
        }

        const authorizationFrame = new Uint8Array(746).fill(0x83);
        const proofApplicationSlotHash = new Uint8Array(64).fill(0x47);
        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                handoff: {
                    canonicalMarkerRecordBytes: markerRecordBytes,
                    logicalRecordKey:
                        commonProofApplicationHandoffLogicalRecordKey,
                },
                onPublicationDisposition: () => undefined,
                proofApplicationSlotHash,
            }),
        ).resolves.toEqual(authorizationFrame);
        await expect(
            store.readAuthenticated({
                authenticate: () => undefined,
                logicalRecordKey: commonProofApplicationHandoffLogicalRecordKey,
            }),
        ).resolves.toBeUndefined();
        await service.close();

        const reopenedService = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: vector.actionContextHash,
                ceremonyContextHash: vector.ceremonyContextHash,
                suiteIdentifier: vector.suiteIdentifier,
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });
        await expect(
            persistCommonProofApplicationAuthorization(reopenedService, {
                authorizationFrame,
                onPublicationDisposition: () => undefined,
                proofApplicationSlotHash,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await reopenedService.close();
    });

    it('refuses every noncanonical common-proof authorization-frame length before storage mutation', async () => {
        for (const authorizationFrameByteLength of [0, 1, 745, 747, 65_536]) {
            const { adapter, service } = await openService();
            const initialMutationCount = adapter.atomicMutationCount;
            const publicationDispositions: string[] = [];

            await expect(
                persistCommonProofApplicationAuthorization(service, {
                    authorizationFrame: new Uint8Array(
                        authorizationFrameByteLength,
                    ),
                    onPublicationDisposition: (disposition) => {
                        publicationDispositions.push(disposition);
                    },
                    proofApplicationSlotHash: new Uint8Array(64).fill(0x35),
                }),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            expect(publicationDispositions).toEqual([]);
            expect(adapter.atomicMutationCount).toBe(initialMutationCount);
        }
    });

    it('reports a published-or-indeterminate disposition before committed readback failure', async () => {
        const { adapter, service } = await openService();
        const authorizationFrame = new Uint8Array(746).fill(0x8e);
        const proofApplicationSlotHash = new Uint8Array(64).fill(0x4c);
        const publicationDispositions: string[] = [];
        adapter.afterAtomicMutation = (mutation) => {
            const committedIndex = mutation.writes.find((write) =>
                write.key.includes('/indices/'),
            );
            if (committedIndex === undefined) {
                return;
            }
            adapter.rawDelete(committedIndex.key);
            adapter.afterAtomicMutation = undefined;
        };

        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    publicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(publicationDispositions).toEqual(['published-or-indeterminate']);
        expect(adapter.atomicMutationCount).toBeGreaterThan(0);
    });

    it('reports definite nonpublication after adapter rejection and permits an exact retry', async () => {
        const { adapter, service } = await openService();
        const authorizationFrame = new Uint8Array(746).fill(0x72);
        const proofApplicationSlotHash = new Uint8Array(64).fill(0x39);
        const firstPublicationDispositions: string[] = [];
        adapter.failAtomicMutationAfter(1);

        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    firstPublicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(firstPublicationDispositions).toEqual([
            'definitely-not-published',
        ]);

        const retryPublicationDispositions: string[] = [];
        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    retryPublicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).resolves.toEqual(authorizationFrame);
        expect(retryPublicationDispositions).toEqual([
            'published-or-indeterminate',
        ]);
    });

    it('reports definite nonpublication after staging failure and permits an exact retry', async () => {
        const { adapter, service } = await openService();
        const authorizationFrame = new Uint8Array(746).fill(0x91);
        const proofApplicationSlotHash = new Uint8Array(64).fill(0x58);
        const firstPublicationDispositions: string[] = [];
        adapter.failNextWriteCount = 1;

        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    firstPublicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(firstPublicationDispositions).toEqual([
            'definitely-not-published',
        ]);

        const retryPublicationDispositions: string[] = [];
        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    retryPublicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).resolves.toEqual(authorizationFrame);
        expect(retryPublicationDispositions).toEqual([
            'published-or-indeterminate',
        ]);
    });

    it('reports definite nonpublication after transient pretransaction read failure', async () => {
        const { adapter, service } = await openService();
        const authorizationFrame = new Uint8Array(746).fill(0xa4);
        const proofApplicationSlotHash = new Uint8Array(64).fill(0x27);
        const firstPublicationDispositions: string[] = [];
        adapter.failNextReadCount = 1;

        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: (disposition) => {
                    firstPublicationDispositions.push(disposition);
                },
                proofApplicationSlotHash,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(firstPublicationDispositions).toEqual([
            'definitely-not-published',
        ]);

        await expect(
            persistCommonProofApplicationAuthorization(service, {
                authorizationFrame,
                onPublicationDisposition: () => undefined,
                proofApplicationSlotHash,
            }),
        ).resolves.toEqual(authorizationFrame);
    });

    it('transfers exclusive ownership and blocks every operation after close', async () => {
        const { service: retainedService } = await openService();
        const ownedService = retainedService.claimExclusiveOwner();

        expect(() => retainedService.copyAuthorityContext()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
        expect(() => retainedService.claimExclusiveOwner()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );

        const firstClose = ownedService.close();
        expect(ownedService.close()).toBe(firstClose);
        await firstClose;
        expect(() =>
            ownedService.compareAndLockIntent({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));
        expect(() => ownedService.copyAuthorityContext()).toThrowError(
            expect.objectContaining({ code: 'InvalidState' }),
        );
    });

    it('locks reservations and outputs idempotently while refusing every conflicting slot use', async () => {
        const conflictingOutput = createConflictingOutputIntent(vector);
        const verifiedConflictingOutputBinding = verifyOutputBinding({
            canonicalOutputIntentCarrier: conflictingOutput.canonicalCarrier,
            exactOutputBytes: conflictingOutput.exactOutputBytes,
            kernel,
            session,
            vector,
        });
        const { service } = await openService();

        await expect(
            service.compareAndLockIntent({
                verifiedIntentBinding: verifiedOutputBinding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });

        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedReservationBinding,
        });
        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedReservationBinding,
        });
        await expect(
            service.compareAndLockIntent({
                verifiedIntentBinding: verifiedConflictingReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });

        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedOutputBinding,
        });
        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedOutputBinding,
        });
        await expect(
            service.compareAndLockIntent({
                verifiedIntentBinding: verifiedConflictingOutputBinding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('resolves concurrent identical locks and allows only one conflicting reservation', async () => {
        const { service } = await openService();

        await expect(
            Promise.all([
                service.compareAndLockIntent({
                    verifiedIntentBinding: verifiedReservationBinding,
                }),
                service.compareAndLockIntent({
                    verifiedIntentBinding: verifiedReservationBinding,
                }),
            ]),
        ).resolves.toEqual([undefined, undefined]);

        const { service: conflictingService } = await openService();
        const conflictingResults = await Promise.allSettled([
            conflictingService.compareAndLockIntent({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
            conflictingService.compareAndLockIntent({
                verifiedIntentBinding: verifiedConflictingReservationBinding,
            }),
        ]);
        expect(
            conflictingResults.filter(
                (result) => result.status === 'fulfilled',
            ),
        ).toHaveLength(1);
        const rejected = conflictingResults.find(
            (result) => result.status === 'rejected',
        );
        expect(rejected).toMatchObject({
            reason: { code: 'Conflict' },
            status: 'rejected',
        });
    });

    it('uses separate durable transactions and returns the first complete hedged carrier', async () => {
        const [firstCarrier, secondCarrier] =
            createHedgedReservationVoteCarriers(vector);
        expect(firstCarrier).not.toEqual(secondCarrier);
        const { adapter, service, store } = await openService();

        await expect(
            service.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: firstCarrier,
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });

        adapter.failAtomicMutationAfter(1);
        await expect(
            service.compareAndLockIntent({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await expect(
            service.readSignedVoteCarrier({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });

        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedReservationBinding,
        });
        const reopenedService = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: vector.actionContextHash,
                ceremonyContextHash: vector.ceremonyContextHash,
                suiteIdentifier: vector.suiteIdentifier,
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });

        adapter.failAtomicMutationAfter(1);
        await expect(
            reopenedService.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: firstCarrier,
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await expect(
            service.readSignedVoteCarrier({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });

        const racedCarriers = await Promise.all([
            service.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: firstCarrier,
                verifiedIntentBinding: verifiedReservationBinding,
            }),
            reopenedService.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: secondCarrier,
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ]);
        expect(racedCarriers[0]).toEqual(racedCarriers[1]);
        expect(
            [firstCarrier, secondCarrier].some((carrier) =>
                byteArraysEqual(carrier, racedCarriers[0]),
            ),
        ).toBe(true);
        const alternateCarrier = byteArraysEqual(racedCarriers[0], firstCarrier)
            ? secondCarrier
            : firstCarrier;
        await expect(
            service.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: alternateCarrier,
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).resolves.toEqual(racedCarriers[0]);
        await expect(
            reopenedService.readSignedVoteCarrier({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).resolves.toEqual(racedCarriers[0]);
    });

    it('bounds signed carriers before storage and detects authenticated carrier corruption', async () => {
        const [carrier] = createHedgedReservationVoteCarriers(vector);
        const { service: boundedService } = await openService({
            limits: {
                ...serviceLimits,
                maximumSignedVoteCarrierByteLength: carrier.byteLength - 1,
            },
        });
        await expect(
            boundedService.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: carrier,
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const { adapter, service } = await openService();
        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedReservationBinding,
        });
        await service.cacheSignedVoteCarrier({
            canonicalSignedVoteCarrier: carrier,
            verifiedIntentBinding: verifiedReservationBinding,
        });
        const carrierObjectKey = adapter
            .keys()
            .filter((key) => key.includes('/objects/'))
            .map((key) => ({
                byteLength: adapter.rawRead(key)?.byteLength ?? 0,
                key,
            }))
            .sort((left, right) => right.byteLength - left.byteLength)[0]?.key;
        if (carrierObjectKey === undefined) {
            throw new Error('signed-vote carrier object is missing');
        }
        const corruptCarrierRecord = adapter.rawRead(carrierObjectKey);
        if (corruptCarrierRecord === undefined) {
            throw new Error('signed-vote carrier bytes are missing');
        }
        corruptCarrierRecord[corruptCarrierRecord.byteLength - 1] ^= 1;
        adapter.rawWrite(carrierObjectKey, corruptCarrierRecord);
        await expect(
            service.readSignedVoteCarrier({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('authenticates the lock record before replay or transition', async () => {
        const { adapter, service } = await openService();
        await service.compareAndLockIntent({
            verifiedIntentBinding: verifiedReservationBinding,
        });
        const lockObjectKey = adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        if (lockObjectKey === undefined) {
            throw new Error('intent-lock object is missing');
        }
        const corruptLockRecord = adapter.rawRead(lockObjectKey);
        if (corruptLockRecord === undefined) {
            throw new Error('intent-lock bytes are missing');
        }
        corruptLockRecord[Math.floor(corruptLockRecord.byteLength / 2)] ^= 1;
        adapter.rawWrite(lockObjectKey, corruptLockRecord);

        await expect(
            service.compareAndLockIntent({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('seals, replays, authenticates, and bounds exact output', async () => {
        const { adapter, service } = await openService();
        const changedOutput = vector.exactOutputBytes.slice();
        changedOutput[changedOutput.byteLength - 1] ^= 1;

        await expect(
            service.cacheExactOutput({
                exactOutputBytes: changedOutput,
                verifiedOutputBinding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });

        adapter.failAtomicMutationAfter(1);
        await expect(
            service.cacheExactOutput({
                exactOutputBytes: vector.exactOutputBytes,
                verifiedOutputBinding,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });

        await service.cacheExactOutput({
            exactOutputBytes: vector.exactOutputBytes,
            verifiedOutputBinding,
        });
        await service.cacheExactOutput({
            exactOutputBytes: vector.exactOutputBytes,
            verifiedOutputBinding,
        });
        await expect(
            service.readExactOutput({ verifiedOutputBinding }),
        ).resolves.toEqual(vector.exactOutputBytes);

        const exactOutputObjectKey = adapter
            .keys()
            .filter((key) => key.includes('/objects/'))
            .map((key) => ({
                byteLength: adapter.rawRead(key)?.byteLength ?? 0,
                key,
            }))
            .sort((left, right) => right.byteLength - left.byteLength)[0]?.key;
        if (exactOutputObjectKey === undefined) {
            throw new Error('exact-output cache object is missing');
        }
        adapter.rawDelete(exactOutputObjectKey);
        await expect(
            service.readExactOutput({ verifiedOutputBinding }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('refuses forged bindings and bindings from another authority context', async () => {
        const { store } = await openRuntimeTestStore();
        const forgedBinding = Object.freeze(
            Object.create(null),
        ) as VerifiedStateDurableBinding;
        const wrongContextService = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: new Uint8Array(64).fill(0x99),
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });

        await expect(
            wrongContextService.compareAndLockIntent({
                verifiedIntentBinding: verifiedReservationBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            wrongContextService.cacheSignedVoteCarrier({
                canonicalSignedVoteCarrier: vector.reservationVoteCarriers[0],
                verifiedIntentBinding: forgedBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            wrongContextService.readSignedVoteCarrier({
                verifiedIntentBinding: forgedBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            wrongContextService.cacheExactOutput({
                exactOutputBytes: vector.exactOutputBytes,
                verifiedOutputBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            wrongContextService.readExactOutput({
                verifiedOutputBinding: forgedBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });
});
