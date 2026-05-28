// This file is one targeted part of the split test suite.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
    createTranscriptCoreKernelLoader,
    type TranscriptCoreKernel,
} from '../../../src/transcript-core-bridge';

import { createMockKernelExports } from './shared.js';

describe('transcript-core kernel in Node', () => {
    it('deallocates command inputs and outputs', async () => {
        const { deallocate, encodedCommandResponseLength, loadMockKernel } =
            createMockKernelExports();
        const kernel = await loadMockKernel();

        expect(
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toBe('abc123');
        expect(deallocate).toHaveBeenCalledWith(
            128,
            encodedCommandResponseLength,
        );
        expect(deallocate).toHaveBeenCalledWith(12, expect.any(Number));
        expect(deallocate).toHaveBeenCalledWith(512, 4);
    });

    it('deallocates aliased command pointers only once', async () => {
        const { deallocate, encodedCommandResponseLength, loadMockKernel } =
            createMockKernelExports({
                commandPointer: 12,
            });
        const kernel = await loadMockKernel();

        expect(
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toBe('abc123');
        expect(deallocate).toHaveBeenCalledTimes(2);
        expect(deallocate).toHaveBeenCalledWith(
            12,
            encodedCommandResponseLength,
        );
        expect(deallocate).toHaveBeenCalledWith(512, 4);
        expect(
            deallocate.mock.calls.filter(([pointer]) => pointer === 12),
        ).toEqual([[12, encodedCommandResponseLength]]);
    });

    it('deallocates aliased round-trip pointers only once', async () => {
        const { deallocate, loadMockKernel } = createMockKernelExports();
        const kernel = await loadMockKernel();

        expect(
            Array.from(kernel.roundTripBytes(Uint8Array.from([2, 4, 6, 8]))),
        ).toEqual([2, 4, 6, 8]);
        expect(deallocate).toHaveBeenCalledTimes(1);
        expect(deallocate).toHaveBeenCalledWith(12, 4);
    });

    it('handles empty round-trip inputs without allocating input bytes', async () => {
        const { deallocate, loadMockKernel } = createMockKernelExports();
        const kernel = await loadMockKernel();

        expect(Array.from(kernel.roundTripBytes(new Uint8Array()))).toEqual([]);
        expect(deallocate).toHaveBeenCalledWith(12, 0);
    });

    it('rejects null pointers for non-empty allocations', async () => {
        const { loadMockKernel } = createMockKernelExports({
            allocationPointer: 0,
        });
        const kernel = await loadMockKernel();

        expect(() => kernel.roundTripBytes(Uint8Array.from([1]))).toThrow(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    });

    it('rejects null command output pointers for non-empty outputs', async () => {
        const { loadMockKernel } = createMockKernelExports({
            commandPointer: 0,
        });
        const kernel = await loadMockKernel();

        expect(() =>
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel returned a null pointer for a non-empty transcript-core command result.',
        );
    });

    it('rejects null command output-length allocations', async () => {
        const { loadMockKernel } = createMockKernelExports({
            outputLengthAllocationPointer: 0,
        });
        const kernel = await loadMockKernel();

        expect(() =>
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel returned a null pointer for the output-length allocation.',
        );
    });

    it('rejects overlapping kernel commands on one instance', async () => {
        const loadedKernelReference: { current?: TranscriptCoreKernel } = {};
        const { loadMockKernel } = createMockKernelExports({
            onCommand: () => {
                loadedKernelReference.current?.hashRaw('00');
            },
        });
        loadedKernelReference.current = await loadMockKernel();

        expect(() =>
            loadedKernelReference.current?.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel cannot run overlapping command operations on one instance.',
        );
    });

    it('rejects a transcript-core kernel with the wrong integrity hash', async () => {
        const { getInstantiateCallCount, loadMockKernel } =
            createMockKernelExports({
                expectedKernelSha256Hex:
                    '0000000000000000000000000000000000000000000000000000000000000000',
            });

        await expect(loadMockKernel()).rejects.toThrow(
            'The transcript-core kernel failed integrity verification',
        );
        expect(getInstantiateCallCount()).toBe(0);
    });

    it('rejects invalid transcript-core kernel integrity hash metadata', async () => {
        const { getInstantiateCallCount, loadMockKernel } =
            createMockKernelExports({
                expectedKernelSha256Hex: 'not-a-sha256-hash',
            });

        await expect(loadMockKernel()).rejects.toThrow(
            'The transcript-core kernel expected integrity hash is invalid',
        );
        expect(getInstantiateCallCount()).toBe(0);
    });

    it('requires either a pinned hash or an explicit unpinned local-loader opt-in', async () => {
        const loadMockKernel = createTranscriptCoreKernelLoader(
            pathToFileURL(path.resolve('mock-sealed-lattice-kernel.wasm')),
        );

        await expect(loadMockKernel()).rejects.toThrow(
            'The transcript-core kernel loader requires expectedKernelSha256Hex unless allowUnpinnedKernel is explicitly enabled.',
        );
    });

    it('allows explicit unpinned local loader use', async () => {
        const { getInstantiateCallCount, loadMockKernel } =
            createMockKernelExports({
                allowUnpinnedKernel: true,
            });

        const kernel = await loadMockKernel();

        expect(kernel.exportedFunctionNames).toContain('memory');
        expect(getInstantiateCallCount()).toBe(1);
    });

    it('rejects invalid command response shapes', async () => {
        const { loadMockKernel } = createMockKernelExports({
            commandResponse: {
                success: true,
            },
        });
        const kernel = await loadMockKernel();

        expect(() =>
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel returned an invalid command response.',
        );
    });

    it('memoizes the loaded kernel promise', async () => {
        const { getInstantiateCallCount, loadMockKernel } =
            createMockKernelExports();
        const [leftKernel, rightKernel] = await Promise.all([
            loadMockKernel(),
            loadMockKernel(),
        ]);

        expect(leftKernel).toBe(rightKernel);
        expect(getInstantiateCallCount()).toBe(1);
    });

    it('retries loading after a failed kernel instantiation', async () => {
        const {
            getInstantiateCallCount,
            loadMockKernel,
            rejectNextInstantiation,
        } = createMockKernelExports();
        rejectNextInstantiation(new Error('first load failed'));

        await expect(loadMockKernel()).rejects.toThrow('first load failed');
        const kernel = await loadMockKernel();

        expect(kernel.exportedFunctionNames).toContain('memory');
        expect(getInstantiateCallCount()).toBe(2);
    });
});
