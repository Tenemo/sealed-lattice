import { describe, expect, it } from 'vitest';

import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

describe('signed registration and original-key custody', () => {
    it('accounts for the canonical username and every public or secret record', () => {
        const value = compileRegistrationEnrollmentCensus();
        expect(value.maximumHeaderBytes).toBe(3565n);
        expect(value.proofRoleBytes).toBe(282n);
        expect(value.recipientCapsuleBytes).toBe(532n);
        expect(value.signingCapsuleBytes).toBe(52n);
        expect(value.maximumRecords).toBe(15n);
        expect(value.maximumManifestBytes).toBe(1167n);
        expect(value.maximumRootBytes).toBe(1183n);
        expect(value.maximumRestoreInputBytes).toBeLessThan(1_572_864n);
        expect(value.maximumRetainedPayloadBytes).toBeLessThan(
            16n * 1024n ** 2n,
        );
    });

    it('charges both original secret capsules without reusing their data key', () => {
        const value = compileRegistrationEnrollmentCensus();
        expect(value.manifestPrefixBytes).toBe(72n);
        expect(value.rootAssociatedBytes).toBe(132n);
        expect(value.recipientAssociatedBytes).toBe(482n);
        expect(value.rootDistinctBlockInputs).toBe(77n);
        expect(value.signingDistinctBlockInputs).toBe(5n);
    });

    it('enumerates the root counter inputs independently of the byte census', () => {
        const inputs = new Set<bigint>([0n]);
        for (const [nonceOrdinal, plaintextBlocks] of [
            [0n, 1],
            [1n, 73],
        ] as const) {
            const initial = (nonceOrdinal << 32n) + 1n;
            for (let counter = 0; counter <= plaintextBlocks; counter++) {
                const input = initial + BigInt(counter);
                expect(inputs.has(input)).toBe(false);
                inputs.add(input);
            }
        }
        expect(BigInt(inputs.size)).toBe(
            compileRegistrationEnrollmentCensus().rootDistinctBlockInputs,
        );
    });
});
