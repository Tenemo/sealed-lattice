import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';

describe('ballot body framing', () => {
    it('transmits both ciphertext pairs and reconstructs fixed common and certified key inputs', () => {
        const layout = compileBallotBodyCensus();
        expect(layout.polynomials.map((value) => value.expandedIndex)).toEqual([
            2, 3, 6, 7,
        ]);
        expect(layout.contextBytes).toBe(136n);
        expect(layout.proofRoleBytes).toBe(8n + 30n + 4n + 30n + 192n + 2n);
        expect(layout.headerBytes).toBe(148n);
        expect(layout.ciphertextBytes).toBe(
            2n * 65536n * 109n + 2n * 4096n * 6n,
        );
        expect(layout.reconstructedInputBytes).toBe(layout.ciphertextBytes);
        expect(layout.maximumSignedBodyBytes).toBe(
            layout.headerBytes +
                layout.ciphertextBytes +
                layout.maximumProofBytes +
                3309n,
        );
        expect(layout.maximumBodyBytes).toBeLessThan(1n << 32n);
        expect(layout.maximumBodyBytes).toBeGreaterThan(8_388_608n);
    });
});
