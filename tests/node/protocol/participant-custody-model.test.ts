import { describe, expect, it } from 'vitest';

import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { compileParticipantCustodyCensus } from '#tests/participant-custody-model.js';

describe('shared participant custody', () => {
    it('retains every contribution polynomial once and omits fixed statement framing', () => {
        const value = compileParticipantCustodyCensus();
        const body = compileContributionBodyCensus();
        expect(value.publicRecords.some((record) => record.object === 0)).toBe(
            false,
        );
        for (const polynomial of body.polynomials) {
            const records = value.publicRecords.filter(
                (record) => record.object === polynomial.expandedIndex + 1,
            );
            expect(
                records.reduce((total, record) => total + record.length, 0n),
            ).toBe(polynomial.bytes);
            expect(
                records.every(
                    (record, index) =>
                        record.offset === BigInt(index) * (1n << 20n),
                ),
            ).toBe(true);
        }
    });

    it('carries the complete existing private checkpoint without exceeding the root or storage bounds', () => {
        const value = compileParticipantCustodyCensus();
        const checkpoint = compileFirstOracleCheckpointCensus();
        expect(BigInt(value.checkpointLengths.length)).toBe(
            checkpoint.recordCount,
        );
        expect(
            value.checkpointLengths.reduce(
                (total, length) => total + length,
                0n,
            ),
        ).toBe(checkpoint.ciphertextBytes);
        expect(value.maximumRootBytes).toBeLessThan(1_572_864n);
        expect(value.maximumRetainedPayloadBytes).toBeLessThan(2_147_483_648n);
    });
});
