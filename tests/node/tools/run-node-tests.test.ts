import { describe, expect, it } from 'vitest';

import { parseRequestedNodeTestLanes } from '#tools/ci/run-node-tests';

describe('Node test runner arguments', () => {
    it('runs every Node lane by default', () => {
        expect(parseRequestedNodeTestLanes([])).toEqual([
            'fast',
            'protocol',
            'kernel-fast',
            'kernel-heavy',
        ]);
    });

    it('accepts a single bare lane', () => {
        expect(parseRequestedNodeTestLanes(['kernel-fast'])).toEqual([
            'kernel-fast',
        ]);
    });

    it('expands the kernel aggregate lane', () => {
        expect(parseRequestedNodeTestLanes(['kernel'])).toEqual([
            'kernel-fast',
            'kernel-heavy',
        ]);
    });

    it('accepts comma-separated and space-separated lane lists', () => {
        expect(
            parseRequestedNodeTestLanes(['fast,protocol', 'kernel-fast']),
        ).toEqual(['fast', 'protocol', 'kernel-fast']);
    });

    it('rejects empty and unsupported lane names', () => {
        expect(() => parseRequestedNodeTestLanes([''])).toThrow(
            'At least one Node test lane is required.',
        );
        expect(() => parseRequestedNodeTestLanes(['unsupported'])).toThrow(
            'Unsupported Node test lane: unsupported',
        );
        expect(() => parseRequestedNodeTestLanes(['--unsupported'])).toThrow(
            'Unsupported Node test lane: --unsupported',
        );
    });
});
