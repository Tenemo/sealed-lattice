import { afterEach, describe, expect, it, vi } from 'vitest';

import coreVectors from '../../../test-vectors/core.json';

import * as rootPackageExports from '#root';
import { UnsupportedRuntimeError, sha256Hex } from '#root';

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

describe('node public API', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('keeps the root export intentionally narrow', () => {
        expect(Object.keys(rootPackageExports).sort()).toEqual([
            'UnsupportedRuntimeError',
            'sha256Hex',
        ]);
        expect(rootPackageExports).not.toHaveProperty('bytesToHex');
        expect(rootPackageExports).not.toHaveProperty('getWebCrypto');
        expect(rootPackageExports).not.toHaveProperty('normalizeInputToBytes');
    });

    it.each(coreVectors.vectors as readonly CoreVector[])(
        'matches the generated vector for $id',
        async (vector) => {
            await expect(
                sha256Hex(expandCoreVectorInput(vector.input)),
            ).resolves.toBe(vector.expected);
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

    it('throws a typed runtime error when subtle.digest is not callable', async () => {
        vi.stubGlobal('crypto', {
            subtle: {
                digest: 'not-a-function',
            },
        });

        await expect(sha256Hex('test')).rejects.toBeInstanceOf(
            UnsupportedRuntimeError,
        );
    });
});
