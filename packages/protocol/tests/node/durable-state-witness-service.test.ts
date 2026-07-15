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

import {
    openDurableStateWitnessService,
    type DurableStateWitnessService,
    type DurableStateWitnessServiceLimits,
} from '#packages/protocol/src/index';
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
} from '#packages/wasm/src/state-verifier-runtime';
import {
    createStateVerifierTestVector,
    type StateVerifierTestVector,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const serviceLimits = {
    maximumExactOutputByteLength:
        foundationProfile.streamChunkByteLength + 1_024,
    maximumRecordSealingCount: 256,
    transactionLifetimeMilliseconds: 5_000,
} as const;

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

const chunkBuffers = (bytes: Uint8Array): readonly ArrayBuffer[] => {
    const chunks: ArrayBuffer[] = [];
    for (
        let offset = 0;
        offset < bytes.byteLength;
        offset += foundationProfile.streamChunkByteLength
    ) {
        chunks.push(
            bytes.slice(
                offset,
                offset + foundationProfile.streamChunkByteLength,
            ).buffer,
        );
    }
    return chunks;
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
                maximumRecoveryTransitionsPerStateKey: 2,
                suiteIdentifier: vector.suiteIdentifier,
            },
            kernel,
        }),
    );

const verifyOutputBinding = (input: {
    kernel: TranscriptCoreKernel;
    session: StateVerifierSession;
    vector: StateVerifierTestVector;
}): VerifiedStateDurableBinding => {
    const reservation = requireValid(
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
    const output = requireValid(
        input.session.openOutputIntentVerification({
            canonicalOutputIntentCarrier:
                input.vector.output.canonicalIntentCarrier,
            exactOutputDescriptorBytes: descriptorFor(
                input.kernel,
                canonicalStreamDomains.stateTargetReleaseExactOutput,
                input.vector.exactOutputBytes,
            ),
            verifiedReservation: reservation,
        }),
    );
    for (const [chunkIndex, chunk] of chunkBuffers(
        input.vector.exactOutputBytes,
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
    let verifiedOutputBinding: VerifiedStateDurableBinding;

    beforeAll(async () => {
        vector = createStateVerifierTestVector();
        kernel = await loadFreshTranscriptCoreKernel();
    });

    beforeEach(async () => {
        encryptionKey = await generateRuntimeStorageEncryptionKey();
        session = openSession(kernel, vector);
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
        service: DurableStateWitnessService;
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

    it('exposes only exact-output operations and reports a missing record', async () => {
        expectTypeOf<keyof DurableStateWitnessService>().toEqualTypeOf<
            'cacheExactOutput' | 'readExactOutput'
        >();
        const { service } = await openService();
        expect(Object.keys(service).sort()).toEqual([
            'cacheExactOutput',
            'readExactOutput',
        ]);

        await expect(
            service.readExactOutput({ verifiedOutputBinding }),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
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
        const wrongContextService = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: new Uint8Array(64).fill(0x99),
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });

        await expect(
            wrongContextService.cacheExactOutput({
                exactOutputBytes: vector.exactOutputBytes,
                verifiedOutputBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            wrongContextService.readExactOutput({
                verifiedOutputBinding: Object.freeze(
                    Object.create(null),
                ) as VerifiedStateDurableBinding,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });
});
