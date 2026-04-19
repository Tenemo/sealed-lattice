import { describe, expect, it } from 'vitest';

describe('protocol package shell', () => {
    it('keeps the package shell intentionally empty', async () => {
        const protocolPackage = await import('@sealed-lattice/protocol');

        expect(Object.keys(protocolPackage)).toEqual([]);
    });
});
