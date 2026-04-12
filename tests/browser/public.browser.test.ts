import { describe, expect, it } from 'vitest';

import { expandCoreVectorInput } from '../../test-vectors/core';
import coreVectors from '../../test-vectors/core.json';

import * as publicApi from '#root';
import { sha256Hex } from '#root';

type CoreVector = {
    expected: string;
    id: string;
    input: Parameters<typeof expandCoreVectorInput>[0];
};

describe('browser public surface', () => {
    it('keeps the root browser export surface intentionally narrow', () => {
        expect(Object.keys(publicApi).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
        expect(publicApi.sha256Hex).toBe(sha256Hex);
    });

    it.each(coreVectors.vectors as readonly CoreVector[])(
        'matches the generated vector for $id',
        async (vector) => {
            await expect(
                sha256Hex(expandCoreVectorInput(vector.input)),
            ).resolves.toBe(vector.expected);
        },
    );
});
