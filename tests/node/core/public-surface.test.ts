import { describe, expect, it } from 'vitest';

import * as publicApi from '#root';

describe('public package surface', () => {
    it('keeps the root export intentionally narrow', () => {
        expect(Object.keys(publicApi).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
    });
});
