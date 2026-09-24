import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotWordProofLayout } from '#tests/full-word-proof-layout-model.js';

// Each canonical coefficient is a sign byte plus enough magnitude bytes for
// its modulus: 109 bytes in the 65536-coefficient FHE family and 6 bytes in
// the 4096-coefficient auxiliary family. The transmitted ciphertexts and the
// reconstructed common and key inputs each hold two polynomials per family.
const polynomialPairPerFamilyBytes = 2n * 65536n * 109n + 2n * 4096n * 6n;

describe('ballot body framing', () => {
    it('transmits both ciphertext pairs and reconstructs fixed common and certified key inputs', () => {
        const layout = compileBallotBodyCensus();
        expect(layout.polynomials.map((value) => value.expandedIndex)).toEqual([
            2, 3, 6, 7,
        ]);
        expect(
            layout.reconstructedPolynomials.map((value) => value.expandedIndex),
        ).toEqual([0, 1, 4, 5]);
        expect(layout.contextBytes).toBe(136n);
        expect(layout.proofRoleBytes).toBe(8n + 30n + 4n + 30n + 192n + 2n);
        expect(layout.headerBytes).toBe(148n);
        expect(layout.envelopeBytes).toBe(214n);
        expect(layout.ciphertextBytes).toBe(polynomialPairPerFamilyBytes);
        expect(layout.reconstructedInputBytes).toBe(
            polynomialPairPerFamilyBytes,
        );
        // ML-DSA-65 signature size, FIPS 204 Table 2.
        expect(layout.signatureBytes).toBe(3309n);
        // The proof maximum comes from the separately tested proof layout
        // model.
        const maximumProofBytes =
            compileBallotWordProofLayout().maximumMultiproofBytes;
        expect(layout.maximumProofBytes).toBe(maximumProofBytes);
        expect(layout.maximumBodyBytes).toBe(
            148n + polynomialPairPerFamilyBytes + maximumProofBytes,
        );
        expect(layout.maximumSignedBodyBytes).toBe(
            148n +
                polynomialPairPerFamilyBytes +
                maximumProofBytes +
                214n +
                3309n,
        );
        expect(layout.maximumBodyBytes).toBeLessThan(1n << 32n);
        expect(layout.maximumBodyBytes).toBeGreaterThan(8_388_608n);
    });
});
