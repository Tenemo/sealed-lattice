import { describe, expect, it } from 'vitest';

import { sha256Hex } from '#root';
import { expandCoreVectorInput } from '#test-vectors/core';
import coreVectors from '#test-vectors/core.json';

type CoreVector = {
    expected: string;
    id: string;
    input: Parameters<typeof expandCoreVectorInput>[0];
};

describe('sha256Hex in the browser runtime', () => {
    it.each(coreVectors.vectors as readonly CoreVector[])(
        'matches the generated vector for $id',
        async (vector) => {
            await expect(
                sha256Hex(expandCoreVectorInput(vector.input)),
            ).resolves.toBe(vector.expected);
        },
    );
});
