import { describe, expect, it, vi } from 'vitest';

import {
    chargeKernelJsonSnapshotValues,
    createKernelJsonSnapshotState,
    snapshotKernelJsonValue,
} from '#packages/sdk/src/kernel-json-snapshot';

describe('Kernel JSON snapshots', () => {
    it('copies nested values without retaining caller mutations', () => {
        const source = { entries: [{ value: 'before' }] };
        const snapshot = snapshotKernelJsonValue(
            source,
            'setupPackage',
            createKernelJsonSnapshotState(),
        );

        source.entries[0].value = 'after';

        expect(snapshot).toEqual({ entries: [{ value: 'before' }] });
    });

    it('charges the complete object graph against one shared budget', () => {
        const state = createKernelJsonSnapshotState();
        chargeKernelJsonSnapshotValues(state, 999_999);

        expect(() =>
            snapshotKernelJsonValue({ value: 1 }, 'setupPackage', state),
        ).toThrow('exceeds the accepted value count');
    });

    it('rejects accessors and cycles before cloning them', () => {
        const getter = vi.fn(() => 'secret');
        const accessorValue = Object.defineProperty({}, 'value', {
            enumerable: true,
            get: getter,
        });
        expect(() =>
            snapshotKernelJsonValue(
                accessorValue,
                'setupPackage',
                createKernelJsonSnapshotState(),
            ),
        ).toThrow('setupPackage.value cannot be an accessor property');
        expect(getter).not.toHaveBeenCalled();

        const cyclicValue: { self?: unknown } = {};
        cyclicValue.self = cyclicValue;
        expect(() =>
            snapshotKernelJsonValue(
                cyclicValue,
                'setupPackage',
                createKernelJsonSnapshotState(),
            ),
        ).toThrow('setupPackage.self cannot contain a cycle');
    });
});
