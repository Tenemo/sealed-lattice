import { describe, expect, it } from 'vitest';

import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

describe('signed registration and original-key custody', () => {
    it('accounts for the canonical username and every public or secret record', () => {
        const value = compileRegistrationEnrollmentCensus();
        expect(value.maximumHeaderBytes).toBe(3565n);
        expect(value.proofRoleBytes).toBe(282n);
        expect(value.pollDefinitionOverheadBytes).toBe(2135n);
        expect(value.maximumCreatorInputBytes).toBeLessThan(1_048_576n);
        expect(value.maximumJoinInputBytes).toBeLessThan(1_572_864n);
        expect(value.recipientCapsuleBytes).toBe(532n);
        expect(value.signingCapsuleBytes).toBe(52n);
        expect(value.maximumEnrollmentRecords).toBe(17n);
        expect(value.maximumRecords).toBe(19n);
        expect(value.maximumEnrollmentManifestBytes).toBe(1377n);
        expect(value.maximumProposalIntentManifestBytes).toBe(1482n);
        expect(value.maximumManifestBytes).toBe(1555n);
        expect(value.maximumRootBytes).toBe(1571n);
        expect(value.maximumRestoreInputBytes).toBeLessThan(1_572_864n);
        expect(value.maximumRetainedPayloadBytes).toBeLessThan(
            16n * 1024n ** 2n,
        );
    });

    it('charges both original secret capsules without reusing their data key', () => {
        const value = compileRegistrationEnrollmentCensus();
        expect(value.manifestPrefixBytes).toBe(136n);
        expect(value.rootAssociatedBytes).toBe(68n);
        expect(value.recipientAssociatedBytes).toBe(482n);
        expect(value.initialRootDistinctBlockInputs).toBe(95n);
        expect(value.rootDistinctBlockInputs).toBe(100n);
        expect(value.signingDistinctBlockInputs).toBe(5n);
    });

    it('enumerates the root counter inputs independently of the byte census', () => {
        const inputs = new Set<bigint>([0n]);
        for (const [nonceOrdinal, plaintextBlocks] of [
            [0n, 5],
            [1n, 87],
        ] as const) {
            const initial = (nonceOrdinal << 32n) + 1n;
            for (let counter = 0; counter <= plaintextBlocks; counter++) {
                const input = initial + BigInt(counter);
                expect(inputs.has(input)).toBe(false);
                inputs.add(input);
            }
        }
        expect(BigInt(inputs.size)).toBe(
            compileRegistrationEnrollmentCensus()
                .initialRootDistinctBlockInputs,
        );
        for (const [nonceOrdinal, blocks] of [
            [2n, 93],
            [3n, 98],
        ] as const) {
            const rotatedKeyInputs = new Set<bigint>([0n]);
            for (let counter = 0; counter <= blocks; counter++) {
                const input = (nonceOrdinal << 32n) + 1n + BigInt(counter);
                expect(rotatedKeyInputs.has(input)).toBe(false);
                rotatedKeyInputs.add(input);
            }
            expect(BigInt(rotatedKeyInputs.size)).toBeLessThanOrEqual(
                compileRegistrationEnrollmentCensus().rootDistinctBlockInputs,
            );
        }
    });
});
