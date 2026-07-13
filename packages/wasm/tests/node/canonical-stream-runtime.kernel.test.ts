import { foundationProfile } from '@sealed-lattice/types';
import { beforeAll, describe, expect, it } from 'vitest';

import {
    canonicalStreamDomains,
    CanonicalStreamCancellationError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
    type CanonicalStreamWorkerRuntime,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const maximumCanonicalStreamByteLength = 2_147_483_648;

const createBytes = (
    byteLength: number,
    seed = 19,
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(new ArrayBuffer(byteLength));
    for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
        bytes[byteIndex] = (seed + byteIndex * 131) & 0xff;
    }
    return bytes;
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

const writeDescriptor = (
    runtime: CanonicalStreamWorkerRuntime,
    streamDomain: CanonicalStreamDomain,
    bytes: Uint8Array,
): Uint8Array => {
    const lease = runtime.openWriter({
        streamDomain,
        totalByteLength: bytes.byteLength,
    });
    for (const [chunkIndex, chunk] of chunkBuffers(bytes).entries()) {
        lease.absorbChunk(chunkIndex, chunk);
    }
    return lease.finish();
};

describe('Canonical stream real-WASM runtime', () => {
    let kernel: TranscriptCoreKernel;

    beforeAll(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('preserves the exact closed canonical stream domain registry', () => {
        expect(canonicalStreamDomains).toEqual({
            privateMailboxCiphertext: 1,
            dealerVssShareLinkageProof: 2,
            recipientAggregateThresholdShareProof: 3,
            sameSecretProof: 4,
            publicKeyShareProof: 5,
            collectivePublicKeyAggregateProof: 6,
            relinearizationRoundOneProof: 7,
            relinearizationRoundOneAggregateProof: 8,
            relinearizationRoundTwoProof: 9,
            galoisShareProof: 10,
            evaluatorKeyAggregateProof: 11,
            collectivePublicKey: 12,
            evaluatorKeyStore: 13,
            ballotCiphertext: 14,
            ballotValidityProof: 15,
            aggregateCiphertext: 16,
            replayTargetIdentifierCiphertext: 17,
            replayTargetOrderCiphertext: 18,
            targetIdentifierPartialDecryption: 19,
            targetOrderPartialDecryption: 20,
            maliciousTargetShareProof: 21,
            checkpointState: 22,
            stateBallotCandidateListExactOutput: 23,
            stateFinalitySignatureExactOutput: 24,
            stateTargetReleaseExactOutput: 25,
            publicKeyShareMaterial: 26,
            publicEvaluationKeyMaterial: 27,
        });
    });

    it('round-trips exact chunk boundaries in every verifier-owned domain', () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        const domains = Object.values(canonicalStreamDomains);
        expect(new Set(domains).size).toBe(domains.length);

        for (const [domainIndex, streamDomain] of domains.entries()) {
            const byteLength =
                domainIndex % 3 === 0
                    ? 1
                    : domainIndex % 3 === 1
                      ? foundationProfile.streamChunkByteLength
                      : foundationProfile.streamChunkByteLength + 17;
            const bytes = createBytes(byteLength, domainIndex + 1);
            const descriptor = writeDescriptor(runtime, streamDomain, bytes);
            const verifier = runtime.openVerifier({
                descriptorBytes: descriptor,
                streamDomain,
            });
            for (const [chunkIndex, chunk] of chunkBuffers(bytes).entries()) {
                verifier.absorbChunk(chunkIndex, chunk);
            }
            verifier.finish();
        }

        const counters = runtime.counterSnapshot();
        expect(counters.activeSessionCount).toBe(0);
        expect(counters.completedSessionCount).toBe(domains.length * 2);
        expect(counters.maximumObservedCopiedPayloadByteLength).toBe(
            foundationProfile.streamChunkByteLength,
        );
        expect(counters.maximumObservedResidentPayloadChunkCount).toBe(2);
        expect(counters.javascriptToWasmPayloadCopyCount).toBe(
            counters.absorbedPayloadChunkCount,
        );
        expect(counters.wasmToJavascriptPayloadCopyCount).toBe(0);
        expect(
            counters.maximumObservedWasmMemoryByteLength,
        ).toBeLessThanOrEqual(foundationProfile.maximumWasmMemoryByteLength);
    });

    it('refuses numeric codes without an implemented stream domain', () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        const supportedCodes = new Set<number>(
            Object.values(canonicalStreamDomains),
        );
        const largestSupportedCode = Math.max(...supportedCodes);

        for (
            let unsupportedCode = 0;
            unsupportedCode <= largestSupportedCode + 1;
            unsupportedCode += 1
        ) {
            if (supportedCodes.has(unsupportedCode)) {
                continue;
            }
            expect(() =>
                runtime.openWriter({
                    streamDomain: unsupportedCode as CanonicalStreamDomain,
                    totalByteLength: 1,
                }),
            ).toThrowError(
                expect.objectContaining({
                    refusalReason: 'malformedEncoding',
                }),
            );
        }
    });

    it('poisons reordered, duplicate, short, overlong, and trailing sessions', () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        const bytes = createBytes(
            foundationProfile.streamChunkByteLength + 17,
            41,
        );
        const [firstChunk, finalChunk] = chunkBuffers(bytes);

        const reordered = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: bytes.byteLength,
        });
        expect(() => reordered.absorbChunk(1, finalChunk)).toThrowError(
            CanonicalStreamRefusalError,
        );
        expect(reordered.state()).toBe('failed');

        const duplicate = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: bytes.byteLength,
        });
        duplicate.absorbChunk(0, firstChunk.slice(0));
        expect(() =>
            duplicate.absorbChunk(0, firstChunk.slice(0)),
        ).toThrowError(CanonicalStreamRefusalError);

        const short = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: bytes.byteLength,
        });
        expect(() =>
            short.absorbChunk(
                0,
                firstChunk.slice(0, firstChunk.byteLength - 1),
            ),
        ).toThrowError(CanonicalStreamRefusalError);

        const oversized = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: bytes.byteLength,
        });
        expect(() =>
            oversized.absorbChunk(
                0,
                new ArrayBuffer(foundationProfile.streamChunkByteLength + 1),
            ),
        ).toThrowError(CanonicalStreamResourceError);

        const trailingBytes = createBytes(17, 73);
        const trailingDescriptor = writeDescriptor(
            runtime,
            canonicalStreamDomains.evaluatorKeyStore,
            trailingBytes,
        );
        const trailing = runtime.openVerifier({
            descriptorBytes: trailingDescriptor,
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
        });
        trailing.absorbChunk(0, trailingBytes.buffer.slice(0));
        expect(() => trailing.absorbChunk(1, new ArrayBuffer(1))).toThrowError(
            CanonicalStreamRefusalError,
        );
        expect(runtime.counterSnapshot().activeSessionCount).toBe(0);
    });

    it('refuses substituted, truncated, wrong-domain, and wrong-terminal streams', () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        const bytes = createBytes(
            foundationProfile.streamChunkByteLength + 17,
            89,
        );
        const descriptor = writeDescriptor(
            runtime,
            canonicalStreamDomains.publicKeyShareProof,
            bytes,
        );
        const chunks = chunkBuffers(bytes);

        const substituted = runtime.openVerifier({
            descriptorBytes: descriptor,
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
        });
        const changed = chunks[0].slice(0);
        new Uint8Array(changed)[0] ^= 1;
        expect(() => substituted.absorbChunk(0, changed)).toThrowError(
            expect.objectContaining({ refusalReason: 'wrongHashOrRoot' }),
        );

        const truncated = runtime.openVerifier({
            descriptorBytes: descriptor,
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
        });
        truncated.absorbChunk(0, chunks[0].slice(0));
        expect(() => truncated.finish()).toThrowError(
            expect.objectContaining({ refusalReason: 'wrongTypeOrLength' }),
        );

        const wrongDomain = runtime.openVerifier({
            descriptorBytes: descriptor,
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
        });
        expect(() =>
            wrongDomain.absorbChunk(0, chunks[0].slice(0)),
        ).toThrowError(
            expect.objectContaining({ refusalReason: 'wrongHashOrRoot' }),
        );

        const wrongTerminalDescriptor = descriptor.slice();
        wrongTerminalDescriptor[wrongTerminalDescriptor.byteLength - 1] ^= 1;
        const wrongTerminal = runtime.openVerifier({
            descriptorBytes: wrongTerminalDescriptor,
            streamDomain: canonicalStreamDomains.publicKeyShareProof,
        });
        for (const [chunkIndex, chunk] of chunks.entries()) {
            wrongTerminal.absorbChunk(chunkIndex, chunk.slice(0));
        }
        expect(() => wrongTerminal.finish()).toThrowError(
            expect.objectContaining({ refusalReason: 'wrongHashOrRoot' }),
        );
    });

    it('pulls without prefetch, exposes only authenticated bytes, and cleans cancellation', async () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        const bytes = createBytes(
            foundationProfile.streamChunkByteLength + 97,
            113,
        );
        const writeChunks = chunkBuffers(bytes);
        const writePulls: number[] = [];
        let inFlightPullCount = 0;
        let maximumInFlightPullCount = 0;
        const descriptor = await runtime.write({
            emitChunk: ({ bytes: emittedBytes, chunkIndex }) => {
                expect(new Uint8Array(emittedBytes)).toEqual(
                    new Uint8Array(writeChunks[chunkIndex]),
                );
                return Promise.resolve();
            },
            pullChunk: async ({ chunkIndex, expectedByteLength }) => {
                inFlightPullCount += 1;
                maximumInFlightPullCount = Math.max(
                    maximumInFlightPullCount,
                    inFlightPullCount,
                );
                writePulls.push(chunkIndex);
                await Promise.resolve();
                inFlightPullCount -= 1;
                if (chunkIndex === writeChunks.length) {
                    return undefined;
                }
                expect(writeChunks[chunkIndex].byteLength).toBe(
                    expectedByteLength,
                );
                return writeChunks[chunkIndex].slice(0);
            },
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: bytes.byteLength,
        });
        expect(writePulls).toEqual([0, 1, 2]);
        expect(maximumInFlightPullCount).toBe(1);

        const readChunks = chunkBuffers(bytes);
        const consumedIndices: number[] = [];
        await runtime.read({
            consumeVerifiedChunk: ({ bytes: verifiedBytes, chunkIndex }) => {
                consumedIndices.push(chunkIndex);
                expect(new Uint8Array(verifiedBytes)).toEqual(
                    new Uint8Array(readChunks[chunkIndex]),
                );
                return Promise.resolve();
            },
            descriptorBytes: descriptor,
            pullChunk: ({ chunkIndex }) =>
                Promise.resolve(
                    chunkIndex === readChunks.length
                        ? undefined
                        : readChunks[chunkIndex].slice(0),
                ),
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
        });
        expect(consumedIndices).toEqual([0, 1]);

        const abortController = new AbortController();
        await expect(
            runtime.write({
                abortSignal: abortController.signal,
                emitChunk: () => {
                    abortController.abort();
                    return Promise.resolve();
                },
                pullChunk: ({ chunkIndex }) =>
                    Promise.resolve(
                        chunkIndex < writeChunks.length
                            ? writeChunks[chunkIndex].slice(0)
                            : undefined,
                    ),
                streamDomain: canonicalStreamDomains.evaluatorKeyStore,
                totalByteLength: bytes.byteLength,
            }),
        ).rejects.toBeInstanceOf(CanonicalStreamCancellationError);
        expect(runtime.counterSnapshot().activeSessionCount).toBe(0);
    });

    it('enforces one session, exact object caps, and fallible worker entropy', () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        const first = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: 1,
        });
        expect(() =>
            runtime.openWriter({
                streamDomain: canonicalStreamDomains.evaluatorKeyStore,
                totalByteLength: 1,
            }),
        ).toThrowError(CanonicalStreamResourceError);
        expect(first.state()).toBe('active');
        expect(runtime.counterSnapshot().activeSessionCount).toBe(1);
        first.absorbChunk(0, new Uint8Array([1]).buffer);
        expect(first.finish()).toBeInstanceOf(Uint8Array);
        expect(first.state()).toBe('completed');
        expect(runtime.counterSnapshot().activeSessionCount).toBe(0);

        const exactMaximum = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: maximumCanonicalStreamByteLength,
        });
        expect(exactMaximum.chunkCount).toBe(
            maximumCanonicalStreamByteLength / 1_048_576,
        );
        exactMaximum.cancel();
        expect(() =>
            runtime.openWriter({
                streamDomain: canonicalStreamDomains.evaluatorKeyStore,
                totalByteLength: maximumCanonicalStreamByteLength + 1,
            }),
        ).toThrowError(CanonicalStreamResourceError);

        const entropyFailure = new Error('entropy unavailable');
        const failingRuntime = openCanonicalStreamWorkerRuntime({
            fillRandomValues: () => {
                throw entropyFailure;
            },
            kernel,
        });
        expect(() =>
            failingRuntime.openWriter({
                streamDomain: canonicalStreamDomains.evaluatorKeyStore,
                totalByteLength: 1,
            }),
        ).toThrowError(
            expect.objectContaining({
                failureCause: entropyFailure,
                name: 'CanonicalStreamInternalError',
            }),
        );
        expect(failingRuntime.counterSnapshot().startedSessionCount).toBe(0);

        const zeroEntropyRuntime = openCanonicalStreamWorkerRuntime({
            fillRandomValues: (destination) => destination.fill(0),
            kernel,
        });
        expect(() =>
            zeroEntropyRuntime.openWriter({
                streamDomain: canonicalStreamDomains.evaluatorKeyStore,
                totalByteLength: 1,
            }),
        ).toThrowError(CanonicalStreamInternalError);
    });

    it('never panics on a deterministic hostile descriptor corpus and remains reusable', () => {
        const runtime = openCanonicalStreamWorkerRuntime({ kernel });
        let pseudorandomState = 0x9e37_79b9;
        const nextByte = (): number => {
            pseudorandomState ^= pseudorandomState << 13;
            pseudorandomState ^= pseudorandomState >>> 17;
            pseudorandomState ^= pseudorandomState << 5;
            return pseudorandomState & 0xff;
        };

        for (let caseIndex = 0; caseIndex < 256; caseIndex += 1) {
            const descriptor = Uint8Array.from(
                { length: 1 + (caseIndex % 257) },
                nextByte,
            );
            expect(() =>
                runtime.openVerifier({
                    descriptorBytes: descriptor,
                    streamDomain: canonicalStreamDomains.evaluatorKeyStore,
                }),
            ).toThrow();
            expect(runtime.counterSnapshot().activeSessionCount).toBe(0);
        }

        const finalLease = runtime.openWriter({
            streamDomain: canonicalStreamDomains.evaluatorKeyStore,
            totalByteLength: 1,
        });
        finalLease.absorbChunk(0, Uint8Array.of(7).buffer);
        expect(finalLease.finish().byteLength).toBeGreaterThan(0);
    });
});
