import { foundationProfile } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it } from 'vitest';

import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from '#packages/wasm/src/bgv-canonical-stream-runtime';
import {
    canonicalStreamDomains,
    CanonicalStreamCancellationError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

const makeChunk = (byteLength: number, seed: number): ArrayBuffer => {
    const bytes = new Uint8Array(new ArrayBuffer(byteLength));
    for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
        bytes[byteIndex] = (seed + byteIndex * 131) & 0xff;
    }
    return bytes.buffer;
};

const descriptorFor = (
    kernel: TranscriptCoreKernel,
    streamDomain: CanonicalStreamDomain,
    chunks: readonly ArrayBuffer[],
): Uint8Array => {
    const runtime = openCanonicalStreamWorkerRuntime({ kernel });
    const totalByteLength = chunks.reduce(
        (byteLength, chunk) => byteLength + chunk.byteLength,
        0,
    );
    const writer = runtime.openWriter({ streamDomain, totalByteLength });
    expect(writer.chunkCount).toBe(chunks.length);
    chunks.forEach((chunk, chunkIndex) => {
        writer.absorbChunk(chunkIndex, chunk);
    });
    return writer.finish();
};

const pullChunks =
    (chunks: readonly ArrayBuffer[]) =>
    (input: {
        readonly chunkIndex: number;
        readonly expectedByteLength: number;
    }): Promise<ArrayBuffer | undefined> => {
        const chunk = chunks[input.chunkIndex];
        if (chunk === undefined) {
            return Promise.resolve(undefined);
        }
        expect(chunk.byteLength).toBe(input.expectedByteLength);
        return Promise.resolve(chunk.slice(0));
    };

const authenticateMaterial = async (
    kernel: TranscriptCoreKernel,
    runtime: ReturnType<typeof openBgvCanonicalStreamRuntime>,
    input: {
        readonly chunks: readonly ArrayBuffer[];
        readonly family: Parameters<typeof runtime.readMaterial>[0]['family'];
        readonly materialRoot: string;
        readonly streamDomain: CanonicalStreamDomain;
    },
): Promise<void> =>
    runtime.readMaterial({
        descriptorBytes: descriptorFor(
            kernel,
            input.streamDomain,
            input.chunks,
        ),
        family: input.family,
        materialRoot: input.materialRoot,
        pullChunk: pullChunks(input.chunks),
    });

describe('BGV canonical stream runtime with the real WASM kernel', () => {
    let kernel: TranscriptCoreKernel;

    beforeEach(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('rejects an accepted-setup session owned by another kernel', async () => {
        const otherKernel = await loadFreshTranscriptCoreKernel();
        const otherKernelSession = otherKernel.beginAcceptedSetupSession();

        expect(() =>
            openBgvCanonicalStreamRuntime({
                acceptedSetupSession: otherKernelSession,
                kernel,
            }),
        ).toThrowError(CanonicalStreamInternalError);
        expect(
            otherKernelSession.verifyCollectiveBgvSetup({ setupPackage: {} }),
        ).toEqual({
            isValid: false,
            refusalReason: 'outsideSupportedProfile',
        });

        const matchingSession = kernel.beginAcceptedSetupSession();
        expect(() =>
            openBgvCanonicalStreamRuntime({
                acceptedSetupSession: matchingSession,
                kernel,
            }),
        ).not.toThrow();
        matchingSession.cancel();
    });

    it('retains setup proof bytes only after canonical terminal authentication', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [makeChunk(73, 11)];
        const materialRoot = '11'.repeat(64);

        await authenticateMaterial(kernel, runtime, {
            chunks,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot,
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
        });

        await expect(
            authenticateMaterial(kernel, runtime, {
                chunks,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot,
                streamDomain: canonicalStreamDomains.publicKeyShareProof,
            }),
        ).rejects.toThrowError(CanonicalStreamRefusalError);
    });

    it('refuses domain substitution, reordering, replay, and truncation and then permits a clean retry', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [
            makeChunk(foundationProfile.streamChunkByteLength, 17),
            makeChunk(41, 29),
        ];

        const wrongDomainDescriptor = descriptorFor(
            kernel,
            canonicalStreamDomains.evaluatorKeyStore,
            chunks,
        );
        const wrongDomain = runtime.openVerifier({
            descriptorBytes: wrongDomainDescriptor,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot: '21'.repeat(64),
        });
        expect(() => wrongDomain.absorbChunk(0, chunks[0])).toThrowError(
            CanonicalStreamRefusalError,
        );
        expect(wrongDomain.state()).toBe('failed');

        const descriptor = descriptorFor(
            kernel,
            canonicalStreamDomains.publicKeyShareProof,
            chunks,
        );
        const reordered = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot: '22'.repeat(64),
        });
        expect(() => reordered.absorbChunk(1, chunks[1])).toThrowError(
            CanonicalStreamRefusalError,
        );
        expect(reordered.state()).toBe('failed');

        const replayed = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot: '23'.repeat(64),
        });
        replayed.absorbChunk(0, chunks[0]);
        expect(() => replayed.absorbChunk(0, chunks[0])).toThrowError(
            CanonicalStreamRefusalError,
        );
        expect(replayed.state()).toBe('failed');

        const truncated = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot: '24'.repeat(64),
        });
        truncated.absorbChunk(0, chunks[0]);
        expect(() => truncated.finish()).toThrowError(
            CanonicalStreamRefusalError,
        );
        expect(truncated.state()).toBe('failed');

        await expect(
            authenticateMaterial(kernel, runtime, {
                chunks,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '25'.repeat(64),
                streamDomain: canonicalStreamDomains.publicKeyShareProof,
            }),
        ).resolves.toBeUndefined();
    });

    it('binds exact retransmission and keeps cancellation idempotent', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const original = makeChunk(89, 37);
        const descriptor = descriptorFor(
            kernel,
            canonicalStreamDomains.sameSecretProof,
            [original],
        );
        const mutated = original.slice(0);
        new Uint8Array(mutated)[0] ^= 1;

        const substituted = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.sameSecretBridge,
            materialRoot: '31'.repeat(64),
        });
        expect(() => substituted.absorbChunk(0, mutated)).toThrowError(
            CanonicalStreamRefusalError,
        );

        const cancelled = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.sameSecretBridge,
            materialRoot: '32'.repeat(64),
        });
        cancelled.cancel();
        expect(() => cancelled.cancel()).not.toThrow();
        expect(cancelled.state()).toBe('cancelled');

        await expect(
            authenticateMaterial(kernel, runtime, {
                chunks: [original],
                family: bgvCanonicalStreamFamilies.sameSecretBridge,
                materialRoot: '33'.repeat(64),
                streamDomain: canonicalStreamDomains.sameSecretProof,
            }),
        ).resolves.toBeUndefined();
    });

    it('refuses oversized component material before pulling or emitting bytes', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        let pullCount = 0;
        let emissionCount = 0;

        await expect(
            runtime.writeSourceMaterial({
                emitChunk: () => {
                    emissionCount += 1;
                    return Promise.resolve();
                },
                family: bgvCanonicalStreamFamilies.relinearizationComponent,
                materialRoot: '34'.repeat(64),
                pullChunk: () => {
                    pullCount += 1;
                    return Promise.resolve(undefined);
                },
                totalByteLength:
                    foundationProfile.maximumCanonicalStreamByteLength + 1,
            }),
        ).rejects.toThrowError(CanonicalStreamResourceError);
        expect(pullCount).toBe(0);
        expect(emissionCount).toBe(0);
    });

    it('refuses retained material that cannot fit the remaining WASM safety bound before pulling bytes', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const descriptorBytes = canonicalStreamDescriptorFixture(
            foundationProfile.maximumWasmMemoryByteLength,
        );
        let pullCount = 0;

        await expect(
            runtime.readMaterial({
                descriptorBytes,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '35'.repeat(64),
                pullChunk: () => {
                    pullCount += 1;
                    return Promise.resolve(undefined);
                },
            }),
        ).rejects.toThrowError(CanonicalStreamResourceError);
        expect(pullCount).toBe(0);

        await expect(
            authenticateMaterial(kernel, runtime, {
                chunks: [makeChunk(41, 35)],
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '36'.repeat(64),
                streamDomain: canonicalStreamDomains.publicKeyShareProof,
            }),
        ).resolves.toBeUndefined();
    });

    it('fails closed on overlapping ownership without exposing capabilities', async () => {
        const firstRuntime = openBgvCanonicalStreamRuntime({ kernel });
        const secondRuntime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [makeChunk(47, 41)];
        const descriptor = descriptorFor(
            kernel,
            canonicalStreamDomains.publicKeyShareProof,
            chunks,
        );
        const first = firstRuntime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot: '41'.repeat(64),
        });

        let overlappingOwnershipFailure: unknown;
        try {
            secondRuntime.openVerifier({
                descriptorBytes: descriptor,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '42'.repeat(64),
            });
        } catch (error) {
            overlappingOwnershipFailure = error;
        }
        expect(overlappingOwnershipFailure).toBeInstanceOf(
            CanonicalStreamRefusalError,
        );
        expect(overlappingOwnershipFailure).toMatchObject({
            refusalReason: 'consumedState',
        });
        expect(() => first.absorbChunk(0, chunks[0])).not.toThrow();
        expect(() => first.finish()).not.toThrow();
        expect(first.state()).toBe('completed');

        await expect(
            authenticateMaterial(kernel, firstRuntime, {
                chunks,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '43'.repeat(64),
                streamDomain: canonicalStreamDomains.publicKeyShareProof,
            }),
        ).resolves.toBeUndefined();
    });

    it('releases each pulled chunk before requesting the next chunk', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [
            makeChunk(foundationProfile.streamChunkByteLength, 51),
            makeChunk(37, 52),
        ];
        let liveChunk: ArrayBuffer | undefined;
        let liveChunkCount = 0;
        let maximumLiveChunkCount = 0;

        await runtime.readMaterial({
            descriptorBytes: descriptorFor(
                kernel,
                canonicalStreamDomains.publicKeyShareProof,
                chunks,
            ),
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot: '51'.repeat(64),
            pullChunk: (request) => {
                if (liveChunk !== undefined) {
                    if (
                        !new Uint8Array(liveChunk).every((byte) => byte === 0)
                    ) {
                        throw new Error(
                            'The runtime retained a prior canonical chunk.',
                        );
                    }
                    liveChunk = undefined;
                    liveChunkCount -= 1;
                }
                const sourceChunk = chunks[request.chunkIndex];
                if (sourceChunk === undefined) {
                    return Promise.resolve(undefined);
                }
                expect(sourceChunk.byteLength).toBe(request.expectedByteLength);
                liveChunk = sourceChunk.slice(0);
                liveChunkCount += 1;
                maximumLiveChunkCount = Math.max(
                    maximumLiveChunkCount,
                    liveChunkCount,
                );
                return Promise.resolve(liveChunk);
            },
        });

        expect(maximumLiveChunkCount).toBe(1);
        expect(liveChunkCount).toBe(0);
    });

    it('cancels an aborted pull transaction and permits a clean retry', async () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [makeChunk(43, 61)];
        const descriptorBytes = descriptorFor(
            kernel,
            canonicalStreamDomains.publicKeyShareProof,
            chunks,
        );
        const abortController = new AbortController();
        let cancelledChunk: ArrayBuffer | undefined;

        await expect(
            runtime.readMaterial({
                abortSignal: abortController.signal,
                descriptorBytes,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '61'.repeat(64),
                pullChunk: () => {
                    cancelledChunk = chunks[0].slice(0);
                    abortController.abort();
                    return Promise.resolve(cancelledChunk);
                },
            }),
        ).rejects.toThrowError(CanonicalStreamCancellationError);
        if (cancelledChunk === undefined) {
            throw new Error('The cancelled pull did not return its chunk.');
        }
        expect(new Uint8Array(cancelledChunk).every((byte) => byte === 0)).toBe(
            true,
        );

        await expect(
            runtime.readMaterial({
                descriptorBytes,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '61'.repeat(64),
                pullChunk: pullChunks(chunks),
            }),
        ).resolves.toBeUndefined();
    });
});
