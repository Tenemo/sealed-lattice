import { describe, expect, it } from 'vitest';

import packageManifest from '../../package.json';

import * as rootModule from '#root';

const expectedExportKeys = ['.'] as const;

describe('public package surface', () => {
    it('publishes the expected exports', () => {
        expect(Object.keys(packageManifest.exports).sort()).toEqual(
            [...expectedExportKeys].sort(),
        );
    });

    it('keeps the root package intentionally tiny', () => {
        expect(Object.keys(rootModule).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
    });
});
