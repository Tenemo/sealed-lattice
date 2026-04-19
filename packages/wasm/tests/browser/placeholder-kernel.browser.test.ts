import { describe, expect, it } from 'vitest';

import {
    loadPlaceholderKernel,
    loadPlaceholderValue,
} from '../../src/index.js';

describe('placeholder kernel in browsers', () => {
    it('loads the placeholder module and exposes the expected export', async () => {
        const kernel = await loadPlaceholderKernel();

        expect(kernel.exportedFunctionNames).toContain(
            'sealed_lattice_placeholder_value',
        );
        expect(kernel.getPlaceholderValue()).toBe(7);
    });

    it('returns the placeholder value through the convenience helper', async () => {
        await expect(loadPlaceholderValue()).resolves.toBe(7);
    });
});
