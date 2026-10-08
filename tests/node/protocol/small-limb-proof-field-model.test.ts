import { describe, expect, it } from 'vitest';

import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

describe('small-limb proof field', () => {
    it('certifies the base field and the degree-three extension separately', () => {
        const field = compileSmallLimbProofFieldCensus();
        expect(field.modulus).toBe((1n << 128n) - 133n * (1n << 64n) + 1n);
        expect(field.modulusBitLength).toBe(128n);
        expect(field.packedFieldElementByteLength).toBe(16n);
        expect(field.packedExtensionElementByteLength).toBe(48n);
        expect(field.oddFactor % 2n).toBe(1n);
        expect(field.oddFactor).toBeLessThan(field.wordRadix);
        expect(field.transformOrder).toBe(1n << 20n);
    });
});
