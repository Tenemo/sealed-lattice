import { afterEach, describe, expect, it, vi } from 'vitest';

import coreVectors from '../../../test-vectors/core.json';

import { UnsupportedRuntimeError, sha256Hex as sha256HexFromCore } from '#core';
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

describe('sha256Hex', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it.each(coreVectors.vectors as readonly CoreVector[])(
        'matches the generated vector for $id',
        async (vector) => {
            const input = expandInput(vector.input);

            await expect(sha256Hex(input)).resolves.toBe(vector.expected);
            await expect(sha256HexFromCore(input)).resolves.toBe(
                vector.expected,
            );
        },
    );

    it('returns lowercase hexadecimal output', async () => {
        const digest = await sha256Hex('ABC');

        expect(digest).toMatch(/^[0-9a-f]{64}$/u);
        expect(digest).toBe(digest.toLowerCase());
    });

    it('throws a typed runtime error when subtle.digest is unavailable', async () => {
        vi.stubGlobal('crypto', undefined);

        await expect(sha256Hex('test')).rejects.toBeInstanceOf(
            UnsupportedRuntimeError,
        );
    });
});
