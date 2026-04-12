import { afterEach, describe, expect, it, vi } from 'vitest';

import coreVectors from '../../../test-vectors/core.json';

import {
    bytesToHex,
    getWebCrypto,
    normalizeInputToBytes,
    sha256Hex,
} from '#core';
import { UnsupportedRuntimeError } from '#root';

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

    it('clones byte input before hashing helpers consume it', () => {
        const original = new Uint8Array([0x00, 0x01, 0x02, 0xff]);
        const normalized = normalizeInputToBytes(original);

        original[0] = 0xaa;

        expect(normalized).toEqual(new Uint8Array([0x00, 0x01, 0x02, 0xff]));
        expect(normalized).not.toBe(original);
    });

    it('encodes bytes as lowercase hex with leading zeroes preserved', () => {
        expect(bytesToHex(new Uint8Array([0x00, 0x0f, 0xa0, 0xff]))).toBe(
            '000fa0ff',
        );
    });

    it('returns the supported crypto implementation when digest is available', () => {
        const digest = vi.fn();
        const cryptoApi = {
            subtle: {
                digest,
            },
        } as unknown as Crypto;

        vi.stubGlobal('crypto', cryptoApi);

        expect(getWebCrypto()).toBe(cryptoApi);
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
