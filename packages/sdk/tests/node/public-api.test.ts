import { describe, expect, it } from 'vitest';

describe('sealed-lattice public facade', () => {
    it('imports successfully and exposes no runtime exports', async () => {
        const publicFacade = await import('sealed-lattice');

        expect(Object.keys(publicFacade)).toEqual([]);
    });
});
