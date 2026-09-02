import { describe, expect, it } from 'vitest';

import {
    ConstructionCommandWriter,
    ConstructionKernelCommandError,
    executeConstructionCommand,
} from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairDecryptionKeyByteLength,
    pairEncryptionKeyByteLength,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const pseudorandomBytes = (length: number, seed: bigint): Uint8Array => {
    let state = seed;
    const mask = (1n << 64n) - 1n;
    return Uint8Array.from({ length }, () => {
        state ^= (state << 13n) & mask;
        state ^= state >> 7n;
        state ^= (state << 17n) & mask;
        state &= mask;
        return Number(state & 0xffn);
    });
};

describe('mailbox ML-KEM scalar WASM runtime', () => {
    it('generates exact ML-KEM-768 key bytes', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const runtime = openPairEncryptionRuntime(kernel);
        const randomness = pseudorandomBytes(
            pairEncryptionKeyGenerationRandomnessByteLength,
            0x5a17n,
        );

        const keyPair = runtime.generateKeyPair(randomness);
        expect(keyPair.encryptionKey).toHaveLength(pairEncryptionKeyByteLength);
        expect(keyPair.decryptionKey).toHaveLength(pairDecryptionKeyByteLength);
        expect(runtime.generateKeyPair(randomness)).toEqual(keyPair);
        expect(() => runtime.generateKeyPair(new Uint8Array(1))).toThrow(
            /64-byte/u,
        );
    });

    it.each([5, 6])(
        'keeps rejected generic mailbox command %s tombstoned',
        async (command) => {
            const kernel = await instantiateConstructionKernelCommandRuntime(
                kernelUrl,
                { allowUnpinnedKernel: true },
            );
            const request = new ConstructionCommandWriter();
            request.writeU8(command);
            expect(() =>
                executeConstructionCommand(kernel, request, () => undefined),
            ).toThrowError(ConstructionKernelCommandError);
        },
    );
});
