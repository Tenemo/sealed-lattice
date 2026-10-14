import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

// Each canonical coefficient is a sign byte plus enough magnitude bytes for
// its modulus: 109 bytes in the 65536-coefficient FHE family and 6 bytes in
// the 4096-coefficient auxiliary family. The transmitted ciphertexts and the
// reconstructed common and key inputs each hold two polynomials per family.
const polynomialPairPerFamilyBytes = 2n * 65536n * 109n + 2n * 4096n * 6n;

describe('ballot body framing', () => {
    it('transmits both ciphertext pairs and reconstructs fixed common and certified key inputs', () => {
        const layout = compileBallotBodyCensus(completionProfile());
        expect(layout.polynomials.map((value) => value.expandedIndex)).toEqual([
            2, 3, 6, 7,
        ]);
        expect(
            layout.reconstructedPolynomials.map((value) => value.expandedIndex),
        ).toEqual([0, 1, 4, 5]);
        expect(layout.setupKeyPolynomials).toEqual([
            { expandedIndex: 1, bytes: 65536n * 109n },
        ]);
        expect(layout.setupKeyInputBytes).toBe(65536n * 109n);
        expect(layout.locallyDerivedInputBytes).toBe(
            65536n * 109n + 2n * 4096n * 6n,
        );
        expect(
            layout.setupKeyInputBytes + layout.locallyDerivedInputBytes,
        ).toBe(layout.reconstructedInputBytes);
        expect(layout.contextBytes).toBe(136n);
        expect(layout.proofRoleBytes).toBe(
            8n + 30n + 4n + 30n + 4n + 128n + 128n + 2n,
        );
        // The proof length and the context, then the proof header from the
        // separately tested proof layout model.
        const proofLayout = compileBallotWordProofLayout(completionProfile());
        expect(layout.headerBytes).toBe(144n + proofLayout.headerBytes);
        expect(layout.envelopeBytes).toBe(210n);
        expect(layout.ciphertextBytes).toBe(polynomialPairPerFamilyBytes);
        expect(layout.reconstructedInputBytes).toBe(
            polynomialPairPerFamilyBytes,
        );
        // ML-DSA-65 signature size, FIPS 204 Table 2.
        expect(layout.signatureBytes).toBe(3309n);
        // The rest of the proof follows the ciphertexts, so a body holds
        // the header and ciphertexts and then the proof after its header.
        const maximumProofBytes = proofLayout.maximumMultiproofBytes;
        expect(layout.maximumProofBytes).toBe(maximumProofBytes);
        expect(layout.minimumBodyBytes).toBe(
            144n + proofLayout.headerBytes + polynomialPairPerFamilyBytes,
        );
        expect(layout.maximumBodyBytes).toBe(
            144n + polynomialPairPerFamilyBytes + maximumProofBytes,
        );
        expect(layout.maximumSignedBodyBytes).toBe(
            144n +
                polynomialPairPerFamilyBytes +
                maximumProofBytes +
                210n +
                3309n,
        );
        expect(layout.maximumBodyBytes).toBeLessThan(1n << 32n);
        expect(layout.maximumBodyBytes).toBeGreaterThan(8_388_608n);
    });
});
