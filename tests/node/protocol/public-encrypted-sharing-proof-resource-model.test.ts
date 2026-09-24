import { describe, expect, it } from 'vitest';

import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';
import {
    compilePublicEncryptedSharingProofResourceCensus,
    minimumLigeroQueryCount,
} from '#tests/public-encrypted-sharing-proof-resource-model.js';
import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

// The number of binary digits of a nonnegative integer, found by comparison
// with powers of two.
const binaryDigitCount = (value: bigint): bigint => {
    let digitCount = 0n;
    while (1n << digitCount <= value) digitCount += 1n;
    return digitCount;
};

// t queries reach soundness exponent lambda exactly when 2^(lambda + t) <= 3^t,
// that is lambda <= floor(log2(3^t)) - t. The table grows 3^t and its binary
// digit count together instead of taking logarithms.
const reachedSoundnessBitLengths = (maximumQueryCount: bigint): bigint[] => {
    const reached: bigint[] = [];
    let powerOfThree = 1n;
    let powerOfThreeDigitCount = 1n;
    for (
        let queryCount = 0n;
        queryCount <= maximumQueryCount;
        queryCount += 1n
    ) {
        reached.push(powerOfThreeDigitCount - 1n - queryCount);
        powerOfThree *= 3n;
        while (1n << powerOfThreeDigitCount <= powerOfThree) {
            powerOfThreeDigitCount += 1n;
        }
    }
    return reached;
};

const queryCountFromTable = (
    reached: readonly bigint[],
    soundnessBitLength: bigint,
): bigint => BigInt(reached.findIndex((value) => value >= soundnessBitLength));

type LigeroParameters = Readonly<{
    codeDimension: bigint;
    messageBlockLength: bigint;
    proofBitLength: bigint;
    witnessRowCount: bigint;
}>;

// The screen's AHIV22 Section 5.3 communication for a message block of l
// coordinates: the code dimension k is the smallest power of two above l + t,
// the code has length 3k, the witness fills floor(C / l) + 1 rows, and each
// query opens a Merkle path of ceil(log2(3k)) random-oracle outputs. Unlike a
// scan over every block length, this search visits one block per code
// dimension and row count.
const searchLigeroParametersByRowClass = (
    constraintCount: bigint,
    queryCount: bigint,
    repetitionCount: bigint,
    fieldBitLength: bigint,
    randomOracleOutputBitLength: bigint,
): LigeroParameters => {
    let best: LigeroParameters | undefined;
    for (let codeDimension = 2n; ; codeDimension *= 2n) {
        // Exactly the blocks with k/2 <= l + t < k use this code dimension.
        const lastBlockLength = codeDimension - 1n - queryCount;
        const firstBlockLength =
            codeDimension / 2n - queryCount > 1n
                ? codeDimension / 2n - queryCount
                : 1n;
        if (lastBlockLength < firstBlockLength) continue;
        // The code-dimension term grows with k and l, and every other term is
        // nonnegative, so no later block can undercut the best proof.
        if (
            best !== undefined &&
            fieldBitLength *
                repetitionCount *
                (4n * codeDimension + firstBlockLength - 2n) >=
                best.proofBitLength
        ) {
            return best;
        }
        const merklePathLength = binaryDigitCount(3n * codeDimension - 1n);
        // Blocks with the same row count differ only in the growing l term,
        // so the first block of each row class is its only candidate.
        let blockLength = firstBlockLength;
        while (blockLength <= lastBlockLength) {
            const witnessRowCount = constraintCount / blockLength + 1n;
            const proofBitLength =
                fieldBitLength *
                    (repetitionCount * (4n * codeDimension + blockLength - 2n) +
                        queryCount *
                            (4n * witnessRowCount + 3n * repetitionCount)) +
                queryCount * merklePathLength * randomOracleOutputBitLength;
            if (best === undefined || proofBitLength < best.proofBitLength) {
                best = {
                    codeDimension,
                    messageBlockLength: blockLength,
                    proofBitLength,
                    witnessRowCount,
                };
            }
            blockLength =
                witnessRowCount === 1n
                    ? lastBlockLength + 1n
                    : constraintCount / (witnessRowCount - 1n) + 1n;
        }
    }
};

describe('public encrypted sharing proof resource model', () => {
    it('matches the exact Ligero query count for every soundness exponent through 640 bits', () => {
        const reached = reachedSoundnessBitLengths(1_200n);
        const soundnessBitLengths = Array.from(
            { length: 641 },
            (_unused, index) => BigInt(index),
        );
        expect(
            soundnessBitLengths.map((soundnessBitLength) =>
                minimumLigeroQueryCount(soundnessBitLength),
            ),
        ).toEqual(
            soundnessBitLengths.map((soundnessBitLength) =>
                queryCountFromTable(reached, soundnessBitLength),
            ),
        );
    });

    it('counts exact Ligero queries where (2/3)^t comes closest to a power of two', () => {
        // Each continued-fraction convergent p/q of log2(3) puts 3^q closer to
        // 2^p than any smaller power of three gets to a power of two, so
        // (2/3)^q lands just beside 2^-(p - q). The convergents alternate
        // sides: where 3^q < 2^p, q queries fall just short. No exponent
        // through 23,398 separates ceil(lambda / log2(3/2)) in doubles from
        // the exact count, so these closest approaches are the boundary cases.
        const convergents = [
            [19n, 12n],
            [65n, 41n],
            [84n, 53n],
            [485n, 306n],
            [1_054n, 665n],
            [24_727n, 15_601n],
            [50_508n, 31_867n],
        ] as const;
        for (const [powerOfTwoExponent, powerOfThreeExponent] of convergents) {
            const soundnessBitLength =
                powerOfTwoExponent - powerOfThreeExponent;
            const queryCount = minimumLigeroQueryCount(soundnessBitLength);
            expect(queryCount).toBe(
                3n ** powerOfThreeExponent >= 1n << powerOfTwoExponent
                    ? powerOfThreeExponent
                    : powerOfThreeExponent + 1n,
            );
            // (2/3)^t <= 2^-lambda holds at t and fails at t - 1.
            expect(1n << (soundnessBitLength + queryCount)).toBeLessThanOrEqual(
                3n ** queryCount,
            );
            expect(
                1n << (soundnessBitLength + queryCount - 1n),
            ).toBeGreaterThan(3n ** (queryCount - 1n));
        }
    });

    it('refuses a negative soundness exponent', () => {
        expect(() => minimumLigeroQueryCount(-1n)).toThrow(RangeError);
    });

    it('derives every screen output from pinned operands and an independent Ligero search', () => {
        const sharing = compileBoundedIntegerSharingPrivacyCensus();
        const fieldModulus = compileCandidateSetupProofFieldCensus().modulus;
        const proofBudgetByteLength =
            compileThresholdKeyAggregationResourceLowerBound()
                .availablePublicEncryptedSharingProofPerContributorByteLength;
        const ringDegree = candidateBgvParameterInputs.polynomialModulusDegree;
        const participantCount = BigInt(
            candidateBgvParameterInputs.participantCount,
        );
        // Release needs max(f + 1, 2) shares for f = floor((n - 1) / 3), so
        // the sharing polynomial has one fewer nonconstant coefficient.
        const releaseThreshold = (participantCount - 1n) / 3n + 1n;
        const sharingPolynomialDegree =
            (releaseThreshold > 2n ? releaseThreshold : 2n) - 1n;
        // The RNS gadget has one digit per ciphertext prime.
        const gadgetLength = BigInt(
            candidateBgvParameterInputs.ciphertextModulusPrimeFactors.length,
        );

        // CMS19 Theorem 8.6 bounds the compiled soundness error by
        // O(t^2 epsilon + t^3 / 2^lambda) for t quantum oracle queries. At
        // t = 2^64, both terms meet the 80-bit target plus a 16-bit component
        // margin at these exponents.
        const componentTargetBitLength = 80n + 16n;
        const oracleQueryBitLength = 64n;
        const interactiveSoundnessBitLength =
            componentTargetBitLength + 2n * oracleQueryBitLength;
        const randomOracleOutputBitLength =
            componentTargetBitLength + 3n * oracleQueryBitLength;
        const queryCount = queryCountFromTable(
            reachedSoundnessBitLengths(500n),
            interactiveSoundnessBitLength,
        );
        const fieldBitLength = binaryDigitCount(fieldModulus);
        // The field alone has at least 2^lambda elements, so the minimum of one
        // repetition already meets the soundness exponent.
        expect(fieldModulus).toBeGreaterThanOrEqual(
            1n << interactiveSoundnessBitLength,
        );
        const repetitionCount = 1n;

        // KLSW24 Section 4.1 IndKeyGen with one automorphism samples the
        // secrets s and r and the gadget vectors e0, e1, e2, and e'_1, and
        // publishes the gadget vectors b, d, v, and h_1. Share encryption
        // samples a secret and an error for its key, then coins and two errors
        // for each two-component recipient ciphertext.
        const keySecrets = ['s', 'r'];
        const keyErrorVectors = ['e0', 'e1', 'e2', 'e1 prime'];
        const publicKeyVectors = ['b', 'd', 'v', 'h1'];
        const shareKeyWitnesses = ['secret', 'error'];
        const shareCiphertextWitnesses = [
            'coins',
            'first error',
            'second error',
        ];
        const shareCiphertextComponents = ['first', 'second'];
        const ternaryRingElementCount =
            BigInt(keySecrets.length) +
            BigInt(keyErrorVectors.length) * gadgetLength +
            BigInt(shareKeyWitnesses.length) +
            participantCount * BigInt(shareCiphertextWitnesses.length);
        // A centered sharing coefficient a in [-R, R] is shifted to a + R in
        // [0, 2R], a set of 2R + 1 values.
        let decompositionBitLength = 0n;
        while (
            1n << decompositionBitLength <
            2n * sharing.coefficientSamplingBound + 1n
        ) {
            decompositionBitLength += 1n;
        }
        const binaryRingElementCount =
            sharingPolynomialDegree * decompositionBitLength;
        // Linear rows: every public-key coordinate, the share-encryption key,
        // one sharing evaluation per recipient, both components of every
        // recipient ciphertext, and one bit recomposition per coefficient.
        const linearRingEquationCount =
            BigInt(publicKeyVectors.length) * gadgetLength +
            1n +
            participantCount +
            participantCount * BigInt(shareCiphertextComponents.length) +
            sharingPolynomialDegree;
        // Per ring coordinate: two multiplications for each ternary element,
        // one booleanity check for each bit, one endpoint product for each
        // decomposed coefficient, and one row for each linear equation.
        const constraintCountPerCoordinate =
            2n * ternaryRingElementCount +
            binaryRingElementCount +
            sharingPolynomialDegree +
            linearRingEquationCount;
        const constraintCount = ringDegree * constraintCountPerCoordinate;

        const ligero = searchLigeroParametersByRowClass(
            constraintCount,
            queryCount,
            repetitionCount,
            fieldBitLength,
            randomOracleOutputBitLength,
        );
        const proofByteLength = (ligero.proofBitLength + 7n) / 8n;
        const codeLength = 3n * ligero.codeDimension;
        const fieldElementByteLength = (fieldBitLength + 7n) / 8n;
        const boundedCoefficientCount =
            (ternaryRingElementCount + binaryRingElementCount) * ringDegree;
        // Serialized ring coefficients are bit-packed: the public key modulo
        // the ciphertext modulus, and the share-encryption key and ciphertexts
        // modulo the share-encryption modulus.
        const ciphertextModulusBitLength = binaryDigitCount(
            candidateBgvParameterInputs.ciphertextModulusPrimeFactors.reduce(
                (product, prime) => product * prime,
                1n,
            ),
        );
        const shareEncryptionModulusBitLength = binaryDigitCount(
            sharing.shareEncryptionModulus,
        );
        const publicInputBitLength =
            ringDegree *
            (BigInt(publicKeyVectors.length) *
                gadgetLength *
                ciphertextModulusBitLength +
                (1n +
                    participantCount *
                        BigInt(shareCiphertextComponents.length)) *
                    shareEncryptionModulusBitLength);
        expect(publicInputBitLength % 8n).toBe(0n);
        const publicInputByteLength = publicInputBitLength / 8n;
        // The expanded witness also carries each decomposed coefficient.
        const expandedWitnessByteLength =
            (boundedCoefficientCount + sharingPolynomialDegree * ringDegree) *
            fieldElementByteLength;
        const encodedOracleFieldElementCount =
            (4n * ligero.witnessRowCount + 5n * repetitionCount) * codeLength;
        const encodedOracleByteLength =
            encodedOracleFieldElementCount * fieldElementByteLength;
        // The setup storage variance ceiling is 3 GiB.
        const setupStorageVarianceCeilingByteLength = 3n << 30n;

        expect(compilePublicEncryptedSharingProofResourceCensus()).toEqual({
            binaryDecompositionConstraintCountPerContributor:
                binaryRingElementCount * ringDegree,
            binaryEndpointConstraintCountPerContributor:
                sharingPolynomialDegree * ringDegree,
            binaryDecompositionRingElementCountPerContributor:
                binaryRingElementCount,
            boundedCoefficientCountPerContributor: boundedCoefficientCount,
            boundedRingElementCountPerContributor:
                ternaryRingElementCount + binaryRingElementCount,
            encodedProofOracleByteLengthPerContributor: encodedOracleByteLength,
            encodedProofOracleFieldElementCountPerContributor:
                encodedOracleFieldElementCount,
            exceedsSetupStorageVarianceCeiling:
                encodedOracleByteLength > setupStorageVarianceCeilingByteLength,
            expandedBoundedWitnessByteLengthPerContributor:
                expandedWitnessByteLength,
            fitsSetupProofBudgetBeforeFixedHashAndLiftingConstant:
                proofByteLength <= proofBudgetByteLength,
            interactiveSoundnessBitLength,
            ligeroCodeDimension: ligero.codeDimension,
            ligeroCodeLength: codeLength,
            ligeroMessageBlockLength: ligero.messageBlockLength,
            ligeroQueryCount: queryCount,
            ligeroRepetitionCount: repetitionCount,
            ligeroWitnessRowCount: ligero.witnessRowCount,
            linearConstraintCountPerContributor:
                linearRingEquationCount * ringDegree,
            optimisticCircuitConstraintCountPerContributor: constraintCount,
            optimisticLigeroProofByteLengthPerContributor: proofByteLength,
            optimisticTenProofCorpusByteLength:
                participantCount * proofByteLength,
            proofFieldElementBitLength: fieldBitLength,
            proofBudgetRemainingByteLengthPerContributor:
                proofBudgetByteLength - proofByteLength,
            publicInputByteLengthPerContributor: publicInputByteLength,
            publicInputPlusExpandedWitnessByteLengthPerContributor:
                publicInputByteLength + expandedWitnessByteLength,
            randomOracleOutputBitLength,
            sharingCoefficientDecompositionBitLength: decompositionBitLength,
            ternaryConstraintCountPerContributor:
                2n * ternaryRingElementCount * ringDegree,
            ternaryRingElementCountPerContributor: ternaryRingElementCount,
        });
    });
});
