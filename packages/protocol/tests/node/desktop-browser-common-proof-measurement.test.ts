import { sha512 } from '@noble/hashes/sha2.js';
import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import type { CommonProofBrowserCustody } from '#packages/protocol/src/runtime/common-proof-browser-custody';
import {
    measureProductionDesktopBrowserCommonProofCase,
    type ProductionDesktopBrowserCommonProofMeasurementCase,
} from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';

const measurementIdentity = Object.freeze({
    actionContextHash: '11'.repeat(64),
    inputCorpusHash: '22'.repeat(64),
    manifestHash: '33'.repeat(64),
    packagedWasmSha256: '44'.repeat(32),
    runtimeBuildManifestHash: '55'.repeat(64),
    suiteIdentifier: '66'.repeat(64),
});

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const createMeasurementCase = (input: {
    malformedEvidenceBuffer?: boolean;
    proofBytes: Uint8Array<ArrayBuffer>;
}) => {
    const events: string[] = [];
    const committedChunks = new Map<number, Uint8Array<ArrayBuffer>>();
    let rawAuthenticatedReadCount = 0;
    let sealed = false;

    const readChunk = (
        chunkIndex: number,
        exactByteLength: number,
    ): Uint8Array<ArrayBuffer> => {
        const chunk = committedChunks.get(chunkIndex);
        if (chunk === undefined || chunk.byteLength !== exactByteLength) {
            throw new Error('The controlled proof store received a bad read.');
        }
        if (!input.malformedEvidenceBuffer) {
            return chunk.slice();
        }
        const paddedBytes = new Uint8Array(exactByteLength + 2);
        paddedBytes.set(chunk, 1);
        return paddedBytes.subarray(1, 1 + exactByteLength);
    };

    const custody: CommonProofBrowserCustody = Object.freeze({
        armApplicationHandoff: () =>
            Promise.resolve({
                canonicalMarkerRecordBytes: Uint8Array.of(1),
                logicalRecordKey: 'controlled-handoff',
            }),
        completeVerifiedOutput: () => {
            events.push('close');
            return Promise.resolve();
        },
        copyCheckpointResumeDescriptor: () => undefined,
        externalMemory: Object.freeze({
            executeTransaction: () => Promise.resolve([]),
        }),
        prefixReplayExternalMemory: Object.freeze({
            executeDeterministicPrefixReplayTransaction: () =>
                Promise.resolve([]),
        }),
        outputStore: Object.freeze({
            commitChunk: (
                chunkIndex: number,
                chunkBytes: Uint8Array<ArrayBuffer>,
            ) => {
                committedChunks.set(chunkIndex, chunkBytes.slice());
                return Promise.resolve();
            },
            readChunk: (chunkIndex: number, exactByteLength: number) =>
                Promise.resolve(readChunk(chunkIndex, exactByteLength)),
        }),
        authenticatedOutput: () => {
            if (!sealed) {
                throw new Error('The controlled proof output is not sealed.');
            }
            return Object.freeze({
                declaredByteLength: input.proofBytes.byteLength,
                readCommittedChunk: (
                    chunkIndex: number,
                    exactByteLength: number,
                ) => {
                    rawAuthenticatedReadCount += 1;
                    events.push(`read-${String(rawAuthenticatedReadCount)}`);
                    return Promise.resolve(
                        readChunk(chunkIndex, exactByteLength),
                    );
                },
            });
        },
        releaseExternalMemory: () => Promise.resolve(),
        retire: () => Promise.resolve(),
        sealCanonicalOutput: () => {
            sealed = true;
        },
        suspendForAuthenticatedResume: () => Promise.resolve(),
    });

    const measurementCase: ProductionDesktopBrowserCommonProofMeasurementCase =
        Object.freeze({
            caseIdentifier: 'controlled-proof-fresh',
            executionKind: 'fresh',
            open: () =>
                Promise.resolve(
                    Object.freeze({
                        close: () => custody.completeVerifiedOutput(),
                        custody,
                        execute: async ({
                            custody: measuredCustody,
                        }: {
                            custody: CommonProofBrowserCustody;
                            yieldControl(): Promise<void>;
                        }) => {
                            const chunkCount = Math.ceil(
                                input.proofBytes.byteLength /
                                    foundationProfile.streamChunkByteLength,
                            );
                            for (
                                let chunkIndex = 0;
                                chunkIndex < chunkCount;
                                chunkIndex += 1
                            ) {
                                const chunkStart =
                                    chunkIndex *
                                    foundationProfile.streamChunkByteLength;
                                const chunk = input.proofBytes.slice(
                                    chunkStart,
                                    Math.min(
                                        chunkStart +
                                            foundationProfile.streamChunkByteLength,
                                        input.proofBytes.byteLength,
                                    ),
                                );
                                await measuredCustody.outputStore.commitChunk(
                                    chunkIndex,
                                    chunk,
                                );
                                chunk.fill(0);
                            }
                            measuredCustody.sealCanonicalOutput();

                            if (!input.malformedEvidenceBuffer) {
                                const verifiedInput =
                                    measuredCustody.authenticatedOutput();
                                for (
                                    let chunkIndex = 0;
                                    chunkIndex < chunkCount;
                                    chunkIndex += 1
                                ) {
                                    const exactByteLength = Math.min(
                                        foundationProfile.streamChunkByteLength,
                                        input.proofBytes.byteLength -
                                            chunkIndex *
                                                foundationProfile.streamChunkByteLength,
                                    );
                                    const verifiedBytes =
                                        await verifiedInput.readCommittedChunk(
                                            chunkIndex,
                                            exactByteLength,
                                        );
                                    verifiedBytes.fill(0);
                                }
                            }
                        },
                        measurementIdentity,
                        wasmMemory: new WebAssembly.Memory({ initial: 1 }),
                    }),
                ),
        });

    return Object.freeze({
        events,
        measurementCase,
        get rawAuthenticatedReadCount(): number {
            return rawAuthenticatedReadCount;
        },
    });
};

describe('Desktop-browser common-proof measurement', () => {
    it('binds the exact identity and hashes every authenticated proof byte outside measured traffic', async () => {
        const proofBytes = new Uint8Array(
            foundationProfile.streamChunkByteLength + 19,
        );
        for (let byteIndex = 0; byteIndex < proofBytes.length; byteIndex += 1) {
            proofBytes[byteIndex] = (byteIndex * 37 + 13) & 0xff;
        }
        const fixture = createMeasurementCase({ proofBytes });

        const measurement =
            await measureProductionDesktopBrowserCommonProofCase(
                [fixture.measurementCase],
                fixture.measurementCase.caseIdentifier,
            );

        expect(measurement.measurementIdentity).toEqual(measurementIdentity);
        expect(measurement.publicOutputHashes.canonicalProofStreamSha512).toBe(
            bytesToHex(sha512(proofBytes)),
        );
        expect(measurement.canonicalOutputTraffic).toMatchObject({
            authenticatedInputReadByteLength: proofBytes.byteLength,
            authenticatedInputReadCount: 2,
            authenticatedInputRequestedByteLength: proofBytes.byteLength,
            committedByteLength: proofBytes.byteLength,
            committedChunkCount: 2,
            sealCount: 1,
        });
        expect(fixture.rawAuthenticatedReadCount).toBe(4);
        expect(fixture.events).toEqual([
            'read-1',
            'read-2',
            'read-3',
            'read-4',
            'close',
        ]);
    });

    it('refuses a shared proof-output view and still closes the production session', async () => {
        const fixture = createMeasurementCase({
            malformedEvidenceBuffer: true,
            proofBytes: Uint8Array.of(1, 2, 3, 4),
        });

        await expect(
            measureProductionDesktopBrowserCommonProofCase(
                [fixture.measurementCase],
                fixture.measurementCase.caseIdentifier,
            ),
        ).rejects.toThrow(
            'returned malformed canonical bytes for evidence hashing',
        );
        expect(fixture.events).toEqual(['read-1', 'close']);
    });
});
