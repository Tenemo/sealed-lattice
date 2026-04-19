import { describe, expect, it } from 'vitest';

describe('crypto package shell', () => {
    it('keeps the package shell intentionally empty', async () => {
        const cryptoPackage = await import('@sealed-lattice/crypto');

        expect(Object.keys(cryptoPackage)).toEqual([]);
    });
});
