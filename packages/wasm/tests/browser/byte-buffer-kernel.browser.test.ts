import { describe, expect, it } from 'vitest';

import {
    loadByteBufferKernel,
    roundTripBytesThroughKernel,
} from '@sealed-lattice/wasm';

describe('byte-buffer kernel in browsers', () => {
    it('loads the byte-buffer module and exposes the expected exports', async () => {
        const kernel = await loadByteBufferKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_roundtrip',
            ]),
        );
    });

    it('round-trips empty and non-empty byte buffers', async () => {
        const kernel = await loadByteBufferKernel();

        expect(Array.from(kernel.roundTripBytes(new Uint8Array()))).toEqual([]);
        expect(
            Array.from(
                kernel.roundTripBytes(
                    Uint8Array.from([255, 200, 128, 64, 32, 0]),
                ),
            ),
        ).toEqual([255, 200, 128, 64, 32, 0]);
    });

    it('round-trips bytes through the async helper', async () => {
        await expect(
            roundTripBytesThroughKernel(Uint8Array.from([1, 3, 3, 7])),
        ).resolves.toEqual(Uint8Array.from([1, 3, 3, 7]));
    });
});
