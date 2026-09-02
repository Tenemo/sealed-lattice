import { describe, expect, it } from 'vitest';

import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
    pairEncryptionRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import {
    openPrivatePreparationBodyRuntime,
    privatePreparationBodyByteLength,
    privatePreparationPlaintextByteLength,
    type PrivatePreparationContextInput,
} from '../../src/private-preparation-body-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const deterministicBytes = (length: number, seed: number): Uint8Array => {
    let state = BigInt(seed);
    return Uint8Array.from({ length }, () => {
        state ^= state << 13n;
        state ^= state >> 7n;
        state ^= state << 17n;
        state &= (1n << 64n) - 1n;
        return Number(state & 0xffn);
    });
};

const context = (): PrivatePreparationContextInput => ({
    participantCount: 10,
    actionProposalIdentity: new Uint8Array(64).fill(0x11),
    rosterIdentity: new Uint8Array(64).fill(0x22),
    preparationAttempt: 7,
    predecessorIdentity: new Uint8Array(64).fill(0x33),
    senderPosition: 2,
    recipientPosition: 8,
});

describe('private preparation body runtime with the scalar WASM kernel', () => {
    it('emits the exact carrier and opens only the bound context', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const runtime = openPrivatePreparationBodyRuntime(kernel);
        const pair = pairRuntime.generateKeyPair(
            deterministicBytes(
                pairEncryptionKeyGenerationRandomnessByteLength,
                0x91a2,
            ),
        );
        const plaintext = deterministicBytes(
            privatePreparationPlaintextByteLength,
            0x77b1,
        );
        const sealed = runtime.seal(
            context(),
            pair.encryptionKey,
            deterministicBytes(pairEncryptionRandomnessByteLength, 0x8123),
            plaintext,
        );

        expect(sealed.body).toHaveLength(privatePreparationBodyByteLength);
        expect(sealed.identity).toHaveLength(64);
        expect(
            runtime.open(
                context(),
                pair.encryptionKey,
                pair.decryptionKey,
                sealed.body,
            ),
        ).toEqual(plaintext);

        const wrongContext = { ...context(), preparationAttempt: 8 };
        expect(() =>
            runtime.open(
                wrongContext,
                pair.encryptionKey,
                pair.decryptionKey,
                sealed.body,
            ),
        ).toThrow(ConstructionKernelCommandError);
    });

    it('distinguishes carrier identity from authenticated plaintext', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const runtime = openPrivatePreparationBodyRuntime(kernel);
        const pair = pairRuntime.generateKeyPair(
            deterministicBytes(
                pairEncryptionKeyGenerationRandomnessByteLength,
                0x91a2,
            ),
        );
        const plaintext = deterministicBytes(
            privatePreparationPlaintextByteLength,
            0x77b1,
        );
        const sealed = runtime.seal(
            context(),
            pair.encryptionKey,
            deterministicBytes(pairEncryptionRandomnessByteLength, 0x8123),
            plaintext,
        );

        const recordMutation = Uint8Array.from(sealed.body);
        recordMutation[recordMutation.byteLength - 1] ^= 1;
        expect(() =>
            runtime.open(
                context(),
                pair.encryptionKey,
                pair.decryptionKey,
                recordMutation,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const otherPair = pairRuntime.generateKeyPair(
            deterministicBytes(
                pairEncryptionKeyGenerationRandomnessByteLength,
                0x91a3,
            ),
        );
        expect(() =>
            runtime.open(
                context(),
                otherPair.encryptionKey,
                otherPair.decryptionKey,
                sealed.body,
            ),
        ).toThrow(ConstructionKernelCommandError);
    });
});
