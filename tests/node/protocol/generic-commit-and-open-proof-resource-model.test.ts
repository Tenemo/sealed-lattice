import { describe, expect, it } from 'vitest';

import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { compileGenericCommitAndOpenProofResourceCensus } from '#tests/generic-commit-and-open-proof-resource-model.js';
import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

const participantCount = BigInt(candidateBgvParameterInputs.participantCount);
const polynomialModulusDegree =
    candidateBgvParameterInputs.polynomialModulusDegree;

// The smallest t with (3/2)^t >= 2^securityBitLength, that is
// 3^t >= 2^(t + securityBitLength), searched with exact integers.
const smallestRepetitionCount = (securityBitLength: bigint): bigint => {
    let repetitionCount = 0n;
    while (
        3n ** repetitionCount <
        2n ** (repetitionCount + securityBitLength)
    ) {
        repetitionCount += 1n;
    }
    return repetitionCount;
};

// CDGORRSZ17 Section 7.3: one ZKB++ repetition has soundness error 2/3, and
// Grover search halves the exponent, so 128-bit post-quantum security needs
// (3/2)^(t/2) >= 2^128, that is (3/2)^t >= 2^256.
const classicalRepetitionCount = smallestRepetitionCount(128n);
const postQuantumRepetitionCount = smallestRepetitionCount(2n * 128n);

// CDGORRSZ17 Section 5 gives the optimized ZKB++/Unruh proof size
// t[c + 3 kappa + log2(3) + l(m + 2b)], so each of the b binary
// multiplication gates costs 2 t l bits, with l = 1 for a binary circuit.
const binaryWireBitLength = 1n;
const proofBitsPerBinaryMultiplicationGate =
    2n * postQuantumRepetitionCount * binaryWireBitLength;

// KLSW24 Section 4.1 IndKeyGen samples two secrets s and r, one error vector
// each for b, d, and v, and one error vector per automorphism key. Every error
// vector holds one ring element per gadget digit, and the gadget has one digit
// per residue-number-system limb of the pinned ciphertext modulus. The ranking
// graph rotates slots, so the floor charges at least one automorphism key.
const gadgetLength = BigInt(
    candidateBgvParameterInputs.ciphertextModulusPrimeFactors.length,
);
const automorphismKeyCount = 1n;
const boundedRingElementCountPerSetupContribution =
    2n + (3n + automorphismKeyCount) * gadgetLength;
const boundedCoefficientCountPerSetupContribution =
    boundedRingElementCountPerSetupContribution * polynomialModulusDegree;
// The model charges one binary multiplication per bounded coefficient.
const minimumProofSizePerSetupContributionBitLength =
    boundedCoefficientCountPerSetupContribution *
    proofBitsPerBinaryMultiplicationGate;
const minimumProofCorpusBitLength =
    participantCount * minimumProofSizePerSetupContributionBitLength;

// The complete public protocol corpus has a planning target of 2^31 bytes,
// and a result more than fifty percent above a target returns to
// architecture review.
const setupTransferVarianceCeilingByteLength = (3n * 2n ** 31n) / 2n;

describe('generic commit-and-open proof resource model', () => {
    const census = compileGenericCommitAndOpenProofResourceCensus();

    it('derives the post-quantum repetition count from the ZKB++ soundness error', () => {
        // CDGORRSZ17 Section 7.3 quotes 219 classical and 438 post-quantum
        // repetitions for 128-bit security.
        expect(classicalRepetitionCount).toBe(219n);
        expect(postQuantumRepetitionCount).toBe(438n);
        expect(census.quantumSecurityParallelRepetitionCount).toBe(
            postQuantumRepetitionCount,
        );
        expect(census.proofBitsPerBinaryMultiplicationGate).toBe(
            proofBitsPerBinaryMultiplicationGate,
        );
    });

    it('counts the KLSW24 bounded witness of one setup contribution', () => {
        expect(census.boundedRingElementCountPerSetupContribution).toBe(
            boundedRingElementCountPerSetupContribution,
        );
        expect(census.boundedCoefficientCountPerSetupContribution).toBe(
            boundedCoefficientCountPerSetupContribution,
        );
    });

    it('sizes the byte-aligned proof floor per contribution and for all participants', () => {
        expect(minimumProofSizePerSetupContributionBitLength % 8n).toBe(0n);
        expect(census.minimumProofSizePerSetupContributionByteLength).toBe(
            minimumProofSizePerSetupContributionBitLength / 8n,
        );
        expect(census.minimumProofCorpusByteLength).toBe(
            minimumProofCorpusBitLength / 8n,
        );
    });

    it('exceeds the setup-transfer variance ceiling once the setup corpus is added', () => {
        const thresholdKeyResources =
            compileThresholdKeyAggregationResourceLowerBound();
        // The threshold model maintains the same ceiling independently.
        expect(
            thresholdKeyResources.setupTransferVarianceCeilingByteLength,
        ).toBe(setupTransferVarianceCeilingByteLength);
        // The setup corpus comes from the separately tested threshold model.
        const combinedSetupAndProofSubtotalByteLength =
            thresholdKeyResources.minimumPublicEncryptedSharingSetupCorpusByteLength +
            minimumProofCorpusBitLength / 8n;
        expect(census.combinedSetupAndProofSubtotalByteLength).toBe(
            combinedSetupAndProofSubtotalByteLength,
        );
        // The proof corpus alone fits under the ceiling, and adding the setup
        // corpus breaches it.
        expect(minimumProofCorpusBitLength / 8n).toBeLessThan(
            setupTransferVarianceCeilingByteLength,
        );
        expect(combinedSetupAndProofSubtotalByteLength).toBeGreaterThan(
            setupTransferVarianceCeilingByteLength,
        );
        expect(census.exceedsSetupTransferVarianceCeiling).toBe(true);
    });
});
