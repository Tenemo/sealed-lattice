import { describe, expect, it } from 'vitest';

import coreVectors from '../../test-vectors/core.json';

import { sha256Hex } from '#root';

type TextVectorInput = {
    kind: 'text';
    value: string;
};

type HexVectorInput = {
    kind: 'hex';
    value: string;
};

type RepeatTextVectorInput = {
    count: number;
    kind: 'repeat-text';
    value: string;
};

type CoreVector = {
    expected: string;
    id: string;
    input: TextVectorInput | HexVectorInput | RepeatTextVectorInput;
};

const expandInput = (input: CoreVector['input']): string | Uint8Array => {
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
            return input.value.repeat(input.count);
    }
};

describe('sha256Hex in the browser runtime', () => {
    it.each(coreVectors.vectors as readonly CoreVector[])(
        'matches the generated vector for $id',
        async (vector) => {
            await expect(sha256Hex(expandInput(vector.input))).resolves.toBe(
                vector.expected,
            );
        },
    );
});
