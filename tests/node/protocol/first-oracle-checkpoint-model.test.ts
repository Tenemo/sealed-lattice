import { describe, expect, it } from 'vitest';

import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';

describe('complete first-oracle proof checkpoint', () => {
    it('accounts for every required private field without deterministic caches', () => {
        const model = compileFirstOracleCheckpointCensus();
        expect(model.fields.map((field) => field.plaintextBytes)).toEqual([
            365n * 65536n * 2n,
            366n * 1409n * 16n,
            131072n * 48n,
            262144n * 128n,
            262144n * 201n,
        ]);
        let bytes = 0n;
        let records = 0n;
        for (const field of model.fields) {
            let remaining = field.units;
            while (remaining > 0n) {
                const units =
                    remaining < field.unitsPerRecord
                        ? remaining
                        : field.unitsPerRecord;
                const plaintext = units * field.unitBytes;
                expect(plaintext).toBeLessThanOrEqual(16384n);
                expect(plaintext % field.unitBytes).toBe(0n);
                bytes += plaintext + 16n;
                remaining -= units;
                records++;
            }
        }
        expect(bytes).toBe(model.ciphertextBytes);
        expect(records).toBe(model.recordCount);
        expect(model.dataKeyBytes).toBe(32n * records);
        expect(model.recordHashBytes).toBe(64n * records);
        expect(model.maximumHeaderBytes).toBeLessThan(16384n);
        expect(model.maximumHeaderBytes).toBe(
            4n + 4n + 2n + 1024n + 64n + 64n + 145n + 2n + 10n * 64n,
        );
        expect(model.publicRecordCount).toBe(1n + 24n * 7n + 20n * 2n + 1n);
        expect(model.publicPlaintextBytes).toBe(
            145n + 24n * 65536n * 109n + 20n * 65536n * 21n + 4096n * 6n,
        );
        expect(model.maximumRootPlaintextBytes).toBeLessThan(1_048_576n);
        expect(model.maximumRetainedPayloadBytes).toBeLessThan(402_653_184n);
        expect(
            model.ciphertextBytes + model.dataKeyBytes + model.recordHashBytes,
        ).toBeLessThan(268_435_456n);
    });
});
