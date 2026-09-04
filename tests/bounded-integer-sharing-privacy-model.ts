import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';

const reducedRingDegree = 8;
const corruptParticipantCount = 3;
const participantCount = candidateBgvParameterInputs.participantCount;
const statisticalPrivacyBitLength = 96n;
const maximumSecretDifferenceCoefficientMagnitude = 2n;
const sharePlaintextTransformExponent = 64n;
const productionInterpolationPointExponentStride =
    candidateBgvParameterInputs.polynomialModulusDegree /
    BigInt(reducedRingDegree);

if (
    candidateBgvParameterInputs.polynomialModulusDegree %
        BigInt(reducedRingDegree) !==
    0n
) {
    throw new Error(
        'The reduced interpolation ring does not divide the production ring.',
    );
}

type RingElement = readonly bigint[];

const zero = (): bigint[] =>
    Array.from({ length: reducedRingDegree }, () => 0n);
const one = (): bigint[] =>
    Array.from({ length: reducedRingDegree }, (_unused, index) =>
        index === 0 ? 1n : 0n,
    );
const add = (left: RingElement, right: RingElement): bigint[] =>
    left.map((value, index) => value + (right[index] ?? 0n));
const negate = (value: RingElement): bigint[] =>
    value.map((coefficient) => -coefficient);
const multiply = (left: RingElement, right: RingElement): bigint[] => {
    const result = zero();
    for (let leftIndex = 0; leftIndex < reducedRingDegree; leftIndex += 1) {
        for (
            let rightIndex = 0;
            rightIndex < reducedRingDegree;
            rightIndex += 1
        ) {
            const rawIndex = leftIndex + rightIndex;
            const index = rawIndex % reducedRingDegree;
            const sign = rawIndex >= reducedRingDegree ? -1n : 1n;
            result[index] =
                (result[index] ?? 0n) +
                sign * (left[leftIndex] ?? 0n) * (right[rightIndex] ?? 0n);
        }
    }
    return result;
};
const monomial = (exponent: number): bigint[] => {
    const normalized =
        ((exponent % (2 * reducedRingDegree)) + 2 * reducedRingDegree) %
        (2 * reducedRingDegree);
    const result = zero();
    result[normalized % reducedRingDegree] =
        normalized >= reducedRingDegree ? -1n : 1n;
    return result;
};
const equal = (left: RingElement, right: RingElement): boolean =>
    left.every((value, index) => value === right[index]);
const oneNorm = (value: RingElement): bigint =>
    value.reduce(
        (sum, coefficient) =>
            sum + (coefficient < 0n ? -coefficient : coefficient),
        0n,
    );

const modulo = (value: bigint, modulus: bigint): bigint => {
    const remainder = value % modulus;
    return remainder < 0n ? remainder + modulus : remainder;
};

const exponentiate = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    let factor = modulo(base, modulus);
    let remaining = exponent;
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) result = modulo(result * factor, modulus);
        factor = modulo(factor * factor, modulus);
        remaining >>= 1n;
    }
    return result;
};

type ProthPrimeCertificate = Readonly<{
    candidateCount: bigint;
    modulus: bigint;
    multiplier: bigint;
    transformExponent: bigint;
    witness: bigint;
}>;

const findProthPrimeAbove = (
    lowerBound: bigint,
    transformExponent: bigint,
): ProthPrimeCertificate => {
    const transformFactor = 1n << transformExponent;
    let multiplier = lowerBound / transformFactor + 1n;
    if (multiplier % 2n === 0n) multiplier += 1n;
    let candidateCount = 0n;
    while (multiplier < transformFactor) {
        candidateCount += 1n;
        const modulus = multiplier * transformFactor + 1n;
        for (let witness = 2n; witness <= 64n; witness += 1n) {
            if (
                exponentiate(witness, (modulus - 1n) / 2n, modulus) ===
                modulus - 1n
            ) {
                // Proth's theorem: multiplier is odd, multiplier < 2^exponent,
                // and this congruence together prove that modulus is prime.
                return {
                    candidateCount,
                    modulus,
                    multiplier,
                    transformExponent,
                    witness,
                };
            }
        }
        multiplier += 2n;
    }
    throw new Error('No certified Proth prime exists in the search interval.');
};

const multiplyPolynomials = (
    left: readonly RingElement[],
    right: readonly RingElement[],
): RingElement[] => {
    const result = Array.from({ length: left.length + right.length - 1 }, zero);
    for (let leftIndex = 0; leftIndex < left.length; leftIndex += 1) {
        for (let rightIndex = 0; rightIndex < right.length; rightIndex += 1) {
            result[leftIndex + rightIndex] = add(
                result[leftIndex + rightIndex] ?? zero(),
                multiply(
                    left[leftIndex] ?? zero(),
                    right[rightIndex] ?? zero(),
                ),
            );
        }
    }
    return result;
};

const evaluatePolynomial = (
    coefficients: readonly RingElement[],
    point: RingElement,
): bigint[] => {
    let result = zero();
    for (let index = coefficients.length - 1; index >= 0; index -= 1) {
        result = add(multiply(result, point), coefficients[index] ?? zero());
    }
    return result;
};

const combinations = (
    values: readonly number[],
    size: number,
): readonly (readonly number[])[] => {
    const result: number[][] = [];
    const choose = (offset: number, selected: number[]): void => {
        if (selected.length === size) {
            result.push([...selected]);
            return;
        }
        for (
            let index = offset;
            index <= values.length - (size - selected.length);
            index += 1
        ) {
            choose(index + 1, [...selected, values[index] ?? -1]);
        }
    };
    choose(0, []);
    return result;
};

const zeroAtCorruptPointsBasis = (
    corruptPositions: readonly number[],
): RingElement[] => {
    let result: RingElement[] = [one()];
    for (const position of corruptPositions) {
        const point = monomial(position);
        const inverseNegativePoint = negate(monomial(-position));
        result = multiplyPolynomials(result, [negate(point), one()]).map(
            (coefficient) => multiply(coefficient, inverseNegativePoint),
        );
    }
    if (!equal(evaluatePolynomial(result, zero()), one())) {
        throw new Error('The privacy basis has the wrong constant value.');
    }
    for (const position of corruptPositions) {
        if (!equal(evaluatePolynomial(result, monomial(position)), zero())) {
            throw new Error('The privacy basis does not vanish.');
        }
    }
    return result;
};

const maximumBlockTranslationOneNorm = (
    basis: readonly RingElement[],
): bigint => {
    let maximum = 0n;
    for (let mask = 0; mask < 1 << reducedRingDegree; mask += 1) {
        const secretDifference = Array.from(
            { length: reducedRingDegree },
            (_unused, index) =>
                (mask & (1 << index)) === 0
                    ? -maximumSecretDifferenceCoefficientMagnitude
                    : maximumSecretDifferenceCoefficientMagnitude,
        );
        const translationOneNorm = basis
            .slice(1)
            .reduce(
                (sum, coefficient) =>
                    sum + oneNorm(multiply(coefficient, secretDifference)),
                0n,
            );
        maximum = maximum > translationOneNorm ? maximum : translationOneNorm;
    }
    return maximum;
};

export type BoundedIntegerSharingPrivacyCensus = Readonly<{
    aggregateShareCoefficientBound: bigint;
    coefficientSamplingBound: bigint;
    corruptSubsetsChecked: number;
    maximumBasisNonconstantOneNorm: bigint;
    maximumBlockTranslationOneNorm: bigint;
    maximumHybridTranslationOneNorm: bigint;
    maximumProductionTranslationOneNormPerContribution: bigint;
    productionInterpolationPointExponentStride: bigint;
    reducedRingBlockCount: bigint;
    shareEncryptionModulusBitLength: bigint;
    sharePlaintextMinimumSpan: bigint;
    sharePlaintextModulus: bigint;
    sharePlaintextModulusBitLength: bigint;
    sharePlaintextPrimeCandidateCount: bigint;
    sharePlaintextPrimeMultiplier: bigint;
    sharePlaintextPrimeWitness: bigint;
    sharePlaintextSpanBitLength: bigint;
    sharePlaintextTransformExponent: bigint;
    statisticalPrivacyBitLength: bigint;
}>;

export const compileBoundedIntegerSharingPrivacyCensus =
    (): BoundedIntegerSharingPrivacyCensus => {
        const participantPositions = Array.from(
            { length: participantCount },
            (_unused, index) => index,
        );
        const corruptSubsets = Array.from(
            { length: corruptParticipantCount + 1 },
            (_unused, size) => combinations(participantPositions, size),
        ).flat();
        let maximumBasisNonconstantOneNorm = 0n;
        let maximumTranslationPerBlock = 0n;
        for (const corruptSubset of corruptSubsets) {
            const basis = zeroAtCorruptPointsBasis(corruptSubset);
            const basisNonconstantOneNorm = basis
                .slice(1)
                .reduce((sum, coefficient) => sum + oneNorm(coefficient), 0n);
            maximumBasisNonconstantOneNorm =
                maximumBasisNonconstantOneNorm > basisNonconstantOneNorm
                    ? maximumBasisNonconstantOneNorm
                    : basisNonconstantOneNorm;
            const blockTranslationOneNorm =
                maximumBlockTranslationOneNorm(basis);
            maximumTranslationPerBlock =
                maximumTranslationPerBlock > blockTranslationOneNorm
                    ? maximumTranslationPerBlock
                    : blockTranslationOneNorm;
        }

        const reducedRingBlockCount =
            productionInterpolationPointExponentStride;
        // Production uses alpha_j = X^(stride*j). Multiplication by every
        // basis coefficient therefore preserves the stride residue classes,
        // and each class is exactly one copy of Z[Z]/(Z^8+1). The exhaustive
        // reduced-ring maximum consequently lifts by the number of classes.
        const maximumProductionTranslationOneNormPerContribution =
            reducedRingBlockCount * maximumTranslationPerBlock;
        const maximumHybridTranslationOneNorm =
            BigInt(participantCount) *
            maximumProductionTranslationOneNormPerContribution;
        let coefficientSamplingBound = 1n;
        while (
            2n * coefficientSamplingBound + 1n <
            maximumHybridTranslationOneNorm *
                (1n << statisticalPrivacyBitLength)
        ) {
            coefficientSamplingBound *= 2n;
        }
        const requiredTranslationDenominator =
            maximumHybridTranslationOneNorm *
            (1n << statisticalPrivacyBitLength);
        if (
            2n * coefficientSamplingBound + 1n <
                requiredTranslationDenominator ||
            (coefficientSamplingBound > 1n &&
                coefficientSamplingBound + 1n >= requiredTranslationDenominator)
        ) {
            throw new Error(
                'The sharing coefficient bound is not the first power of two that meets the privacy inequality.',
            );
        }

        const aggregateShareCoefficientBound =
            BigInt(participantCount) *
            (1n + BigInt(corruptParticipantCount) * coefficientSamplingBound);
        const sharePlaintextMinimumSpan =
            2n * aggregateShareCoefficientBound + 1n;
        const sharePlaintextPrime = findProthPrimeAbove(
            sharePlaintextMinimumSpan - 1n,
            sharePlaintextTransformExponent,
        );
        if (
            sharePlaintextPrime.modulus < sharePlaintextMinimumSpan ||
            sharePlaintextPrime.modulus %
                (2n * candidateBgvParameterInputs.polynomialModulusDegree) !==
                1n
        ) {
            throw new Error(
                'The certified share plaintext prime fails the centered-span or transform gate.',
            );
        }
        const shareEncryptionModulus =
            sharePlaintextPrime.modulus *
            publicEncryptedSharingModelConstants.productionShareEncodingScale;

        return {
            aggregateShareCoefficientBound,
            coefficientSamplingBound,
            corruptSubsetsChecked: corruptSubsets.length,
            maximumBasisNonconstantOneNorm,
            maximumBlockTranslationOneNorm: maximumTranslationPerBlock,
            maximumHybridTranslationOneNorm,
            maximumProductionTranslationOneNormPerContribution,
            productionInterpolationPointExponentStride,
            reducedRingBlockCount,
            shareEncryptionModulusBitLength: BigInt(
                shareEncryptionModulus.toString(2).length,
            ),
            sharePlaintextMinimumSpan,
            sharePlaintextModulus: sharePlaintextPrime.modulus,
            sharePlaintextModulusBitLength: BigInt(
                sharePlaintextPrime.modulus.toString(2).length,
            ),
            sharePlaintextPrimeCandidateCount:
                sharePlaintextPrime.candidateCount,
            sharePlaintextPrimeMultiplier: sharePlaintextPrime.multiplier,
            sharePlaintextPrimeWitness: sharePlaintextPrime.witness,
            sharePlaintextSpanBitLength: BigInt(
                sharePlaintextMinimumSpan.toString(2).length,
            ),
            sharePlaintextTransformExponent:
                sharePlaintextPrime.transformExponent,
            statisticalPrivacyBitLength,
        };
    };
