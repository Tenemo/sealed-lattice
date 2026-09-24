import { describe, expect, it } from 'vitest';

import {
    compileRegistrationCustodyCensus,
    registrationRootNonce,
} from '#tests/registration-custody-model.js';

describe('registration private-state encoding', () => {
    it('derives the secret positions and complete bounded retained inventory', () => {
        const value = compileRegistrationCustodyCensus();
        expect(value.indexBytes).toBe(2n);
        expect(value.secretPlaintextBytes).toBe(516n);
        expect(value.capsuleBytes).toBe(532n);
        expect(value.recordCount).toBe(12n);
        expect(value.maximumManifestBytes).toBe(1044n);
        expect(value.maximumRootBytes).toBe(1060n);
        expect(value.maximumRestoreInputBytes).toBeLessThan(1_572_864n);
        expect(value.retainedPayloadBytes).toBeLessThan(16n * 1024n ** 2n);
    });

    it('separates the initial and completed root counters from every plaintext block', () => {
        const inputs = new Set<bigint>([0n]);
        for (const ordinal of [0, 1] as const) {
            const nonce = registrationRootNonce(ordinal);
            let initial = 0n;
            for (const byte of nonce) initial = (initial << 8n) + BigInt(byte);
            initial = (initial << 32n) + 1n;
            const plaintextBlocks = ordinal === 0 ? 1 : 66;
            for (let offset = 0; offset <= plaintextBlocks; offset++) {
                const input = initial + BigInt(offset);
                expect(inputs.has(input)).toBe(false);
                inputs.add(input);
            }
        }
        const value = compileRegistrationCustodyCensus();
        expect(BigInt(inputs.size)).toBe(value.rootDistinctBlockInputs);
        expect(value.capsuleDistinctBlockInputs).toBe(35n);
        expect(value.maximumRootHashDegree).toBe(136n);
        expect(value.maximumCapsuleHashDegree).toBe(111n);
    });
});
