import { foundationProfile } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it } from 'vitest';

import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from '#packages/wasm/src/bgv-canonical-stream-runtime';
import {
    canonicalStreamDomains,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

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

describe('BGV canonical stream runtime with the real WASM kernel', () => {
    let kernel: TranscriptCoreKernel;

    beforeEach(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('stages setup proof bytes only after canonical terminal authentication', () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [makeChunk(73, 11)];
        const materialRoot = '11'.repeat(64);

        const descriptor = runtime.stage({
            chunks,
            family: bgvCanonicalStreamFamilies.publicKeyShare,
            materialRoot,
        });

        expect(descriptor.byteLength).toBeGreaterThan(0);
        expect(() =>
            runtime.stage({
                chunks,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot,
            }),
        ).toThrowError(CanonicalStreamRefusalError);
    });

    it('refuses domain substitution, reordering, replay, and truncation and then permits a clean retry', () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const chunks = [
            makeChunk(foundationProfile.streamChunkByteLength, 17),
            makeChunk(41, 29),
        ];

        const wrongDomainDescriptor = descriptorFor(
            kernel,
            canonicalStreamDomains.checkpointState,
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

        expect(() =>
            runtime.stage({
                chunks,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '25'.repeat(64),
            }),
        ).not.toThrow();
    });

    it('binds exact retransmission and keeps cancellation idempotent', () => {
        const runtime = openBgvCanonicalStreamRuntime({ kernel });
        const original = makeChunk(89, 37);
        const descriptor = descriptorFor(
            kernel,
            canonicalStreamDomains.evaluatorKeyStore,
            [original],
        );
        const mutated = original.slice(0);
        new Uint8Array(mutated)[0] ^= 1;

        const substituted = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.relinearizationComponent,
            materialRoot: '31'.repeat(64),
        });
        expect(() => substituted.absorbChunk(0, mutated)).toThrowError(
            CanonicalStreamRefusalError,
        );

        const cancelled = runtime.openVerifier({
            descriptorBytes: descriptor,
            family: bgvCanonicalStreamFamilies.relinearizationComponent,
            materialRoot: '32'.repeat(64),
        });
        cancelled.cancel();
        expect(() => cancelled.cancel()).not.toThrow();
        expect(cancelled.state()).toBe('cancelled');

        expect(() =>
            runtime.stage({
                chunks: [original],
                family: bgvCanonicalStreamFamilies.relinearizationComponent,
                materialRoot: '33'.repeat(64),
            }),
        ).not.toThrow();
    });

    it('fails closed on overlapping ownership without exposing capabilities', () => {
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

        expect(() =>
            secondRuntime.openVerifier({
                descriptorBytes: descriptor,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '42'.repeat(64),
            }),
        ).toThrowError(CanonicalStreamResourceError);
        expect(() => first.absorbChunk(0, chunks[0])).toThrow();
        expect(first.state()).toBe('failed');

        expect(() =>
            firstRuntime.stage({
                chunks,
                family: bgvCanonicalStreamFamilies.publicKeyShare,
                materialRoot: '43'.repeat(64),
            }),
        ).not.toThrow();
    });
});
