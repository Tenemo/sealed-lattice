import { describe, expect, it } from 'vitest';

describe('testkit package shell', () => {
    it('keeps the package shell intentionally empty', async () => {
        const testkitPackage = await import('@sealed-lattice/testkit');

        expect(Object.keys(testkitPackage)).toEqual([]);
    });
});
