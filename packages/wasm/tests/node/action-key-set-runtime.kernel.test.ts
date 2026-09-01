import { describe, expect, it } from 'vitest';

import {
    actionKeySetBodyByteLength,
    openActionKeySetRuntime,
} from '../../src/action-key-set-runtime.js';
import {
    actionSignatureKeyByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const participantCount = 10;
const actionSignaturePurposeCount = 4;

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

describe('action key set scalar WASM runtime', () => {
    it('emits and verifies the exact completion-profile key roster', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const keySetRuntime = openActionKeySetRuntime(kernel);
        const proposalIdentity = pseudorandomBytes(64, 0x4a31n);
        const bodies: Uint8Array[] = [];
        let expectedPairKey: Uint8Array | undefined;

        for (
            let rosterPosition = 0;
            rosterPosition < participantCount;
            rosterPosition += 1
        ) {
            const signatureVerificationKeys: Uint8Array[] = [];
            for (
                let purpose = 0;
                purpose < actionSignaturePurposeCount;
                purpose += 1
            ) {
                const secretKey = pseudorandomBytes(
                    actionSignatureKeyByteLength,
                    0x1000n + BigInt(rosterPosition * 16 + purpose),
                );
                signatureVerificationKeys.push(
                    signatureRuntime.deriveVerificationKey(secretKey),
                );
                secretKey.fill(0);
            }
            const pairEncryptionKeys: Uint8Array[] = [];
            for (
                let pairKeyIndex = 0;
                pairKeyIndex < participantCount - 1;
                pairKeyIndex += 1
            ) {
                const randomness = pseudorandomBytes(
                    pairEncryptionKeyGenerationRandomnessByteLength,
                    0x9000n + BigInt(rosterPosition * 32 + pairKeyIndex),
                );
                const keyPair = pairRuntime.generateKeyPair(randomness);
                pairEncryptionKeys.push(keyPair.encryptionKey);
                if (rosterPosition === 8 && pairKeyIndex === 2) {
                    expectedPairKey = Uint8Array.from(keyPair.encryptionKey);
                }
                keyPair.decryptionKey.fill(0);
                randomness.fill(0);
            }
            const encoded = keySetRuntime.encode({
                participantCount,
                proposalIdentity,
                rosterPosition,
                nonce: pseudorandomBytes(32, 0xa000n + BigInt(rosterPosition)),
                actionSignatureVerificationKeys: signatureVerificationKeys,
                pairEncryptionKeys,
            });
            expect(encoded.body).toHaveLength(
                actionKeySetBodyByteLength(participantCount),
            );
            expect(
                keySetRuntime.verify(
                    participantCount,
                    proposalIdentity,
                    rosterPosition,
                    encoded.body,
                ),
            ).toEqual(encoded.identity);
            bodies.push(encoded.body);
        }

        expect(actionKeySetBodyByteLength(participantCount)).toBe(66_954);
        expect(bodies.reduce((sum, body) => sum + body.byteLength, 0)).toBe(
            669_540,
        );
        const rosterIdentity = keySetRuntime.verifyCompleteRoster(
            participantCount,
            bodies,
        );
        expect(rosterIdentity).toHaveLength(64);
        expect(expectedPairKey).toBeDefined();
        expect(
            keySetRuntime.resolvePairEncryptionKey(
                participantCount,
                proposalIdentity,
                rosterIdentity,
                2,
                8,
                bodies,
            ),
        ).toEqual(expectedPairKey);

        const wrongProposal = Uint8Array.from(proposalIdentity);
        wrongProposal[0] ^= 1;
        expect(() =>
            keySetRuntime.verify(
                participantCount,
                wrongProposal,
                0,
                bodies[0] ?? new Uint8Array(),
            ),
        ).toThrowError(ConstructionKernelCommandError);

        const reorderedBodies = [...bodies];
        [reorderedBodies[0], reorderedBodies[1]] = [
            reorderedBodies[1] ?? new Uint8Array(),
            reorderedBodies[0] ?? new Uint8Array(),
        ];
        expect(() =>
            keySetRuntime.verifyCompleteRoster(
                participantCount,
                reorderedBodies,
            ),
        ).toThrowError(ConstructionKernelCommandError);
    });

    it('rejects a malformed pair key before emitting a key set', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const keySetRuntime = openActionKeySetRuntime(kernel);
        const invalidPairKeys = Array.from(
            { length: participantCount - 1 },
            () => new Uint8Array(4_608),
        );
        invalidPairKeys[0]?.subarray(0, 3).fill(0xff);
        expect(() =>
            keySetRuntime.encode({
                participantCount,
                proposalIdentity: new Uint8Array(64),
                rosterPosition: 0,
                nonce: new Uint8Array(32),
                actionSignatureVerificationKeys: Array.from(
                    { length: actionSignaturePurposeCount },
                    (_unused, purpose) => {
                        const key = new Uint8Array(
                            actionSignatureKeyByteLength,
                        );
                        key[0] = purpose;
                        return key;
                    },
                ),
                pairEncryptionKeys: invalidPairKeys,
            }),
        ).toThrowError(ConstructionKernelCommandError);
    });
});
