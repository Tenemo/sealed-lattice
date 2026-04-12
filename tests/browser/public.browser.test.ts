import { describe, expect, it } from 'vitest';

import coreVectors from '../../test-vectors/core.json';

import * as publicApi from '#root';
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

describe('browser public surface', () => {
    it('keeps the root browser export surface intentionally narrow', () => {
        expect(Object.keys(publicApi).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
        expect(publicApi.sha256Hex).toBe(sha256Hex);
        expect(publicApi).not.toHaveProperty('getWebCrypto');
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
