import { describe, expect, it } from 'vitest';

import coreVectors from '../../test-vectors/core.json';

import { sha256Hex } from '#root';

type CoreVector = {
    expected: string;
    id: string;
    input: {
        kind: 'hex' | 'repeat-text' | 'text';
        value: string;
        count?: number;
    };
};

const expandCoreVectorInput = (
    input: CoreVector['input'],
): string | Uint8Array => {
    switch (input.kind) {
        case 'text':
            return input.value;
        case 'hex':
            return Uint8Array.from(
                input.value
                    .match(/.{1,2}/g)
                    ?.map((chunk) => Number.parseInt(chunk, 16)) ?? [],
            );
        case 'repeat-text':
            return input.value.repeat(input.count ?? 0);
    }
};

describe('browser public API', () => {
    it.each(coreVectors.vectors as readonly CoreVector[])(
        'matches the generated vector for $id',
        async (vector) => {
            await expect(
                sha256Hex(expandCoreVectorInput(vector.input)),
            ).resolves.toBe(vector.expected);
        },
    );
});
