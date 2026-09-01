import { describe, expect, it } from 'vitest';

import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPreparationMaterialRuntime,
    preparationAffineCoefficientByteLength,
    preparationContributionOpeningVectorByteLength,
    preparationPlaintextByteLength,
    preparationSubsetCommitmentVectorByteLength,
    type PreparationMaterialContextInput,
} from '../../src/preparation-material-runtime.js';
import { openPreparationParentRuntime } from '../../src/preparation-parent-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const deterministicBytes = (length: number, seed: bigint): Uint8Array => {
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

const context: PreparationMaterialContextInput = {
    participantCount: 10,
    actionProposalIdentity: new Uint8Array(64).fill(0x11),
    actionKeySetRosterIdentity: new Uint8Array(64).fill(0x22),
    preparationAttempt: 7,
    predecessorIdentity: new Uint8Array(64).fill(0x33),
    senderPosition: 2,
};

describe('preparation material scalar WASM runtime', () => {
    it('generates exact pair payloads and verifies every signed opening slot', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const materialRuntime = openPreparationMaterialRuntime(kernel);
        const parentRuntime = openPreparationParentRuntime(kernel);
        const material = materialRuntime.generate(
            context,
            deterministicBytes(
                preparationContributionOpeningVectorByteLength,
                0x5001n,
            ),
            deterministicBytes(preparationAffineCoefficientByteLength, 0x6001n),
        );
        expect(material.subsetCommitments).toHaveLength(
            preparationSubsetCommitmentVectorByteLength,
        );
        expect(material.recipientPlaintexts).toHaveLength(9);
        for (const plaintext of material.recipientPlaintexts) {
            expect(plaintext).toHaveLength(preparationPlaintextByteLength);
        }

        const parent = parentRuntime.encode({
            ...context,
            subsetCommitments: material.subsetCommitments,
            privateBodyIdentities: Array.from({ length: 9 }, (_, index) =>
                new Uint8Array(64).fill(index + 1),
            ),
        });
        for (
            let recipientPosition = 0;
            recipientPosition < 10;
            recipientPosition += 1
        ) {
            if (recipientPosition === context.senderPosition) {
                continue;
            }
            const plaintextIndex =
                recipientPosition < context.senderPosition
                    ? recipientPosition
                    : recipientPosition - 1;
            expect(
                materialRuntime.verifyPlaintext(
                    context,
                    recipientPosition,
                    parent.body,
                    material.recipientPlaintexts[plaintextIndex] ??
                        new Uint8Array(),
                ),
            ).toHaveLength(64);
        }

        const mutated = Uint8Array.from(material.recipientPlaintexts[7] ?? []);
        mutated[20] ^= 1;
        expect(() =>
            materialRuntime.verifyPlaintext(context, 8, parent.body, mutated),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            materialRuntime.verifyPlaintext(
                context,
                7,
                parent.body,
                material.recipientPlaintexts[7] ?? new Uint8Array(),
            ),
        ).toThrow(ConstructionKernelCommandError);
    });
});
