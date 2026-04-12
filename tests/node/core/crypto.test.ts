import { afterEach, describe, expect, it, vi } from 'vitest';

import { expandCoreVectorInput } from '../../../test-vectors/core';
import coreVectors from '../../../test-vectors/core.json';

import { UnsupportedRuntimeError, sha256Hex } from '#root';

type CoreVector = {
    expected: string;
    id: string;
    input: Parameters<typeof expandCoreVectorInput>[0];
};

describe('core crypto helpers', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
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
});
