import { describe, expect, it } from 'vitest';

import {
    chargeKernelJsonSnapshotValues,
    createKernelJsonSnapshotState,
    snapshotKernelJsonValue,
} from '#packages/sdk/src/kernel-json-snapshot.js';

const snapshot = (value: unknown): unknown =>
    snapshotKernelJsonValue(value, 'input', createKernelJsonSnapshotState());

describe('kernel JSON snapshot', () => {
    it('owns a deep JSON copy before asynchronous kernel work begins', () => {
        const input = {
            nested: { value: 'original' },
            values: [1, { enabled: true }],
            ignored: undefined,
        };

        const ownedSnapshot = snapshot(input);
        input.nested.value = 'mutated';
        input.values[1] = { enabled: false };

        expect(ownedSnapshot).toEqual({
            nested: { value: 'original' },
            values: [1, { enabled: true }],
        });
    });

    it('rejects executable and non-JSON containers without invoking accessors', () => {
        let accessorReadCount = 0;
        const accessorBackedValue: Record<string, unknown> = {};
        Object.defineProperty(accessorBackedValue, 'value', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'executed';
            },
        });
        const cyclicValue: Record<string, unknown> = {};
        cyclicValue.self = cyclicValue;

        for (const rejectedValue of [
            accessorBackedValue,
            cyclicValue,
            Object.assign(Object.create({ inherited: true }), { safe: true }),
            new Uint8Array([1, 2, 3]),
            { toJSON: () => ({ replaced: true }) },
        ]) {
            expect(() => snapshot(rejectedValue)).toThrow(TypeError);
        }
        expect(accessorReadCount).toBe(0);
    });

    it('enforces nesting and aggregate value limits without large fixtures', () => {
        let nestedValue: Record<string, unknown> = { leaf: true };
        for (let depth = 0; depth < 65; depth += 1) {
            nestedValue = { child: nestedValue };
        }

        expect(() => snapshot(nestedValue)).toThrow(RangeError);

        const state = createKernelJsonSnapshotState();
        chargeKernelJsonSnapshotValues(state, 1_000_000);
        expect(() => chargeKernelJsonSnapshotValues(state, 1)).toThrow(
            RangeError,
        );
    });
});
