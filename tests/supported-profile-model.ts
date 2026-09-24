import assert from 'node:assert/strict';

import {
    createFixedModulusBfvNoiseModel,
    deriveFloodedRelease,
    fixedModulusBfvInputs,
} from '#tests/fixed-modulus-bfv-model.js';
import { evaluateFixedModulusBfvRanking } from '#tests/fixed-modulus-bfv-ranking-model.js';
import { deriveReleaseShareLiftingLayout } from '#tests/release-share-lifting-model.js';
import {
    compileSupportedThresholdCompletionProfiles,
    compileThresholdCompletionProfile,
} from '#tests/threshold-completion-model.js';
import { deriveWideShareLiftingLayout } from '#tests/wide-share-lifting-model.js';

// Only the product ranges and the profile-independent BFV operands are
// fixed. Every threshold, interpolation bound, lifting width and modulus of
// a supported profile is derived from its participant and option counts.
const supportedOptionCounts = { minimum: 2, maximum: 20 } as const;
export const supportedProfileRules = {
    // Moduli are the largest primes t*k*2^(b-32)+1 below 2^b with odd k.
    modulusOddFactorBits: 32,
    ciphertextModulusBitStep: 32,
    releaseModulusBitStep: 48,
    prothWitnessLimit: 256n,
} as const;

const thresholdProfiles = new Map<
    number,
    ReturnType<typeof compileThresholdCompletionProfile>
>();
const thresholdsFor = (participantCount: number) => {
    let profile = thresholdProfiles.get(participantCount);
    if (profile === undefined) {
        profile = compileThresholdCompletionProfile(participantCount);
        thresholdProfiles.set(participantCount, profile);
    }
    return profile;
};

const bitLength = (value: bigint): number =>
    value <= 0n ? 0 : value.toString(2).length;
const ceilingPowerOfTwoExponent = (value: number): number => {
    let exponent = 0;
    while (2 ** exponent < value) exponent++;
    return exponent;
};

export type RingElement = readonly number[];

// Arithmetic in Z[X]/(X^degree+1) with safe-integer coefficients.
const multiplyElements = (left: RingElement, right: RingElement): number[] => {
    const degree = left.length;
    const result = new Array<number>(degree).fill(0);
    for (let first = 0; first < degree; first++) {
        const coefficient = left[first];
        if (coefficient === 0) continue;
        for (let second = 0; second < degree; second++) {
            const index = first + second;
            if (index < degree) result[index] += coefficient * right[second];
            else result[index - degree] -= coefficient * right[second];
        }
    }
    assert.ok(result.every((value) => Number.isSafeInteger(value)));
    return result;
};

// value * (1 - X^exponent): subtract the signed rotation by the exponent.
const multiplyByOneMinusMonomial = (
    value: RingElement,
    exponent: number,
): number[] => {
    const degree = value.length;
    const period = 2 * degree;
    const shift = ((exponent % period) + period) % period;
    const result = [...value];
    for (let index = 0; index < degree; index++) {
        const target = (index + shift) % period;
        if (target < degree) result[target] -= value[index];
        else result[target - degree] += value[index];
    }
    return result;
};

const monomialElement = (exponent: number, degree: number): number[] =>
    multiplyByOneMinusMonomial(new Array<number>(degree).fill(0), 0).map(
        (_unused, index) => {
            const period = 2 * degree;
            const reduced = ((exponent % period) + period) % period;
            if (index !== reduced % degree) return 0;
            return reduced < degree ? 1 : -1;
        },
    );

const oneNorm = (value: RingElement): number =>
    value.reduce((sum, coefficient) => sum + Math.abs(coefficient), 0);

// Visits every size-element subset of 0..count-1 in lexicographic order.
// The visited array is reused and must not be retained.
const forEachSubset = (
    count: number,
    size: number,
    visit: (subset: readonly number[]) => void,
): void => {
    if (size > count) return;
    const subset = Array.from({ length: size }, (_unused, index) => index);
    for (;;) {
        visit(subset);
        let position = size - 1;
        while (position >= 0 && subset[position] === count - size + position)
            position--;
        if (position < 0) return;
        subset[position]++;
        for (let next = position + 1; next < size; next++)
            subset[next] = subset[next - 1] + 1;
    }
};

// Roster position a maps to X^a in Z[X]/(X^R+1), where R is the smallest
// power of two whose 2R signed monomials separate every position. In the
// ciphertext ring this is the power (X^(N/R))^a.
export const interpolationRingDegree = (participantCount: number): number =>
    2 ** ceilingPowerOfTwoExponent(Math.ceil(participantCount / 2));

// The clearing factor 2^ceil(log2 d) makes every reconstruction
// coefficient integral; the derivation below checks this for each subset.
const reconstructionClearingFactor = (releaseThreshold: number): number =>
    2 ** ceilingPowerOfTwoExponent(releaseThreshold);

// For 0 < k < 2R write k = 2^v * odd. X^k has order 2R/2^v, so with
// L = R/2^v, (1 - X^k) * sum_{i<L} X^(k i) = 1 - X^(kL) = 2.
const doubledInverses = new Map<string, readonly number[]>();
const doubledInverseOfOneMinusMonomial = (
    exponent: number,
    degree: number,
): RingElement => {
    const key = `${degree}:${exponent}`;
    const cached = doubledInverses.get(key);
    if (cached !== undefined) return cached;
    const period = 2 * degree;
    const reduced = ((exponent % period) + period) % period;
    assert.notEqual(reduced, 0);
    let valuation = 0;
    while ((reduced >> valuation) % 2 === 0) valuation++;
    const result = new Array<number>(degree).fill(0);
    for (let index = 0; index < degree >> valuation; index++) {
        const term = monomialElement(reduced * index, degree);
        term.forEach((value, position) => (result[position] += value));
    }
    assert.deepEqual(multiplyByOneMinusMonomial(result, reduced), [
        2,
        ...new Array<number>(degree - 1).fill(0),
    ]);
    doubledInverses.set(key, result);
    return result;
};

// Products of doubled inverses, keyed by their sorted exponent prefix.
const doubledInverseProducts = new Map<string, readonly number[]>();
const doubledInverseProduct = (
    exponents: readonly number[],
    degree: number,
): RingElement => {
    const key = `${degree}:${exponents.join(',')}`;
    const cached = doubledInverseProducts.get(key);
    if (cached !== undefined) return cached;
    const product =
        exponents.length === 0
            ? monomialElement(0, degree)
            : multiplyElements(
                  doubledInverseProduct(exponents.slice(0, -1), degree),
                  doubledInverseOfOneMinusMonomial(
                      exponents[exponents.length - 1],
                      degree,
                  ),
              );
    doubledInverseProducts.set(key, product);
    return product;
};

// The Lagrange coefficient at zero is lambda_i(S) = prod_{j != i}
// 1/(1 - X^(a_i - a_j)), so it depends only on the differences. Its
// multiple by the clearing factor is returned as an integral element.
export const clearedReconstructionCoefficient = (
    participantCount: number,
    subset: readonly number[],
    member: number,
): RingElement => {
    const releaseThreshold =
        thresholdsFor(participantCount).resultReleaseThreshold;
    assert.equal(subset.length, releaseThreshold);
    assert.ok(subset.includes(member));
    const degree = interpolationRingDegree(participantCount);
    const period = 2 * degree;
    const differences = subset
        .filter((other) => other !== member)
        .map((other) => (((member - other) % period) + period) % period)
        .sort((left, right) => left - right);
    // clearingFactor * lambda = clearingFactor * numerator / 2^(d-1).
    const numerator = doubledInverseProduct(differences, degree);
    const divisorExponent =
        differences.length - ceilingPowerOfTwoExponent(releaseThreshold);
    if (divisorExponent <= 0)
        return numerator.map((value) => value * 2 ** -divisorExponent);
    const divisor = 2 ** divisorExponent;
    return numerator.map((value) => {
        assert.ok(
            value % divisor === 0,
            'A cleared reconstruction coefficient is fractional.',
        );
        return value / divisor;
    });
};

const interpolations = new Map<
    number,
    ReturnType<typeof computeReleaseInterpolation>
>();

const computeReleaseInterpolation = (participantCount: number) => {
    const releaseThreshold =
        thresholdsFor(participantCount).resultReleaseThreshold;
    const degree = interpolationRingDegree(participantCount);
    const period = 2 * degree;
    // Every subset has a translate inside the roster that contains position
    // zero, and translation preserves each coefficient.
    let maximumScaledReconstructionOneNorm = 0;
    forEachSubset(participantCount - 1, releaseThreshold - 1, (rest) => {
        const subset = [0, ...rest.map((position) => position + 1)];
        for (const member of subset)
            maximumScaledReconstructionOneNorm = Math.max(
                maximumScaledReconstructionOneNorm,
                oneNorm(
                    clearedReconstructionCoefficient(
                        participantCount,
                        subset,
                        member,
                    ),
                ),
            );
    });
    // Simulating honest h against a fixed set C of size d-1 scales by
    // 1/lambda_h(C+{h}) = prod_{j in C} (1 - X^(a_h - a_j)).
    const simulationNorms = new Map<string, number>();
    let maximumSimulationOneNorm = 0;
    let maximumJointSimulationOneNormSum = 0;
    forEachSubset(participantCount, releaseThreshold - 1, (fixedSet) => {
        let sum = 0;
        for (let honest = 0; honest < participantCount; honest++) {
            if (fixedSet.includes(honest)) continue;
            const exponents = fixedSet
                .map(
                    (position) =>
                        (((honest - position) % period) + period) % period,
                )
                .sort((left, right) => left - right);
            const key = exponents.join(',');
            let norm = simulationNorms.get(key);
            if (norm === undefined) {
                norm = oneNorm(
                    exponents.reduce<number[]>(
                        multiplyByOneMinusMonomial,
                        monomialElement(0, degree),
                    ),
                );
                simulationNorms.set(key, norm);
            }
            maximumSimulationOneNorm = Math.max(maximumSimulationOneNorm, norm);
            sum += norm;
        }
        maximumJointSimulationOneNormSum = Math.max(
            maximumJointSimulationOneNormSum,
            sum,
        );
    });
    return {
        participantCount,
        releaseThreshold,
        interpolationRingDegree: degree,
        clearingFactor: BigInt(reconstructionClearingFactor(releaseThreshold)),
        maximumScaledReconstructionOneNorm: BigInt(
            maximumScaledReconstructionOneNorm,
        ),
        maximumSimulationOneNorm: BigInt(maximumSimulationOneNorm),
        maximumJointSimulationOneNormSum: BigInt(
            maximumJointSimulationOneNormSum,
        ),
    };
};

export const deriveReleaseInterpolation = (participantCount: number) => {
    let interpolation = interpolations.get(participantCount);
    if (interpolation === undefined) {
        interpolation = computeReleaseInterpolation(participantCount);
        interpolations.set(participantCount, interpolation);
    }
    return interpolation;
};

const exponentiate = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    let factor = base % modulus;
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) === 1n) result = (result * factor) % modulus;
        factor = (factor * factor) % modulus;
    }
    return result;
};

export type TransformPrime = Readonly<{
    bits: number;
    modulus: bigint;
    oddFactor: bigint;
    exponent: number;
    witness: bigint;
}>;

const transformPrimes = new Map<number, TransformPrime>();

// Candidates t*k*2^(b-32)+1 are tried from the largest odd k with
// t*k < 2^32 downward. A failed base-two Fermat test proves a candidate
// composite; Proth's theorem proves the first remaining candidate prime.
export const largestTransformPrimeBelow = (bits: number): TransformPrime => {
    const cached = transformPrimes.get(bits);
    if (cached !== undefined) return cached;
    const oddFactorBits = supportedProfileRules.modulusOddFactorBits;
    const exponent = bits - oddFactorBits;
    assert.ok(exponent > oddFactorBits);
    const plaintextModulus = fixedModulusBfvInputs.plaintextModulus;
    let factor = ((1n << BigInt(oddFactorBits)) - 1n) / plaintextModulus;
    if (factor % 2n === 0n) factor -= 1n;
    for (; factor > 0n; factor -= 2n) {
        const oddFactor = plaintextModulus * factor;
        const modulus = oddFactor * (1n << BigInt(exponent)) + 1n;
        if (exponentiate(2n, modulus - 1n, modulus) !== 1n) continue;
        for (
            let witness = 2n;
            witness <= supportedProfileRules.prothWitnessLimit;
            witness++
        )
            if (
                exponentiate(witness, (modulus - 1n) / 2n, modulus) ===
                modulus - 1n
            ) {
                const prime = { bits, modulus, oddFactor, exponent, witness };
                transformPrimes.set(bits, prime);
                return prime;
            }
        throw new Error('A probable transform prime has no small witness.');
    }
    throw new Error('No transform prime exists below the bound.');
};

const undecodable = 'The accepted error support exceeds the BFV decoding cell.';

// Returns undefined when some operation of the ranking graph fails to decode.
export const deriveRankingNoise = (
    participantCount: number,
    optionCount: number,
    ciphertextModulus: bigint,
) => {
    try {
        const model = createFixedModulusBfvNoiseModel({
            ...fixedModulusBfvInputs,
            participantCount: BigInt(participantCount),
            ciphertextModulus,
        });
        const { comparison, result } = evaluateFixedModulusBfvRanking(
            Array.from({ length: participantCount }, () => model.fresh),
            optionCount,
            fixedModulusBfvInputs.comparisonBlockWidth,
            model,
        );
        return { model, comparison, result };
    } catch (error) {
        if (
            error instanceof assert.AssertionError &&
            error.message === undecodable
        )
            return undefined;
        throw error;
    }
};

// The release modulus has the smallest multiple of 48 bits for which the
// flooded release is correct and its limb lifting fits the proof field.
const deriveRelease = (
    participantCount: number,
    ciphertextModulus: bigint,
    ciphertextModulusBits: number,
    ranking: NonNullable<ReturnType<typeof deriveRankingNoise>>,
) => {
    const interpolation = deriveReleaseInterpolation(participantCount);
    const shareLifting = deriveSupportedShareLifting(participantCount);
    const step = supportedProfileRules.releaseModulusBitStep;
    for (let bits = 2 * step; bits < ciphertextModulusBits; bits += step) {
        const release = largestTransformPrimeBelow(bits);
        const flooded = deriveFloodedRelease({
            ...fixedModulusBfvInputs,
            ciphertextModulus,
            releaseModulus: release.modulus,
            evaluationError: ranking.result.error,
            secretOneNorm: ranking.model.secretOneNorm,
            interpolation,
        });
        if (!flooded.jointStatisticalBoundHolds || !flooded.releaseCorrect)
            continue;
        const lifting = deriveReleaseShareLiftingLayout({
            polynomialDegree: fixedModulusBfvInputs.polynomialDegree,
            releaseModulus: release.modulus,
            releaseNoiseBits: flooded.releaseNoiseBits,
            releaseThreshold: interpolation.releaseThreshold,
            aggregateSharingMaximum: shareLifting.aggregateSharingMaximum,
        });
        if (lifting.holds) return { release, flooded, lifting };
    }
    return undefined;
};

const shareLiftings = new Map<
    number,
    ReturnType<typeof deriveWideShareLiftingLayout>
>();

export const deriveSupportedShareLifting = (participantCount: number) => {
    let lifting = shareLiftings.get(participantCount);
    if (lifting === undefined) {
        lifting = deriveWideShareLiftingLayout({
            participantCount: BigInt(participantCount),
            sharingDegree:
                thresholdsFor(participantCount).resultReleaseThreshold - 1,
        });
        shareLiftings.set(participantCount, lifting);
    }
    return lifting;
};

// The ciphertext modulus has the smallest multiple of 32 bits for which
// every ranking operation decodes and a release modulus exists.
export const deriveSupportedProfile = (
    participantCount: number,
    optionCount: number,
) => {
    const thresholds = thresholdsFor(participantCount);
    assert.ok(
        Number.isSafeInteger(optionCount) &&
            optionCount >= supportedOptionCounts.minimum &&
            optionCount <= supportedOptionCounts.maximum,
        'optionCount is outside the supported range.',
    );
    const step = supportedProfileRules.ciphertextModulusBitStep;
    for (let bits = 3 * step; ; bits += step) {
        const ciphertext = largestTransformPrimeBelow(bits);
        const ranking = deriveRankingNoise(
            participantCount,
            optionCount,
            ciphertext.modulus,
        );
        if (ranking === undefined) continue;
        const release = deriveRelease(
            participantCount,
            ciphertext.modulus,
            bits,
            ranking,
        );
        if (release === undefined) continue;
        return {
            participantCount,
            optionCount,
            maximumCorruptParticipantCount:
                thresholds.maximumCorruptParticipantCount,
            inventoryCertificateThreshold:
                thresholds.inventoryCertificateThreshold,
            releaseThreshold: thresholds.resultReleaseThreshold,
            minimumTurnout: thresholds.minimumTurnout,
            ciphertext,
            release: release.release,
            gadgetLength: ranking.model.gadgetLength,
            comparisonDepth: ranking.comparison.depth,
            rankingDepth: ranking.result.depth,
            rankingError: ranking.result.error,
            multiplications: ranking.model.counts.multiplications,
            rotations: ranking.model.counts.rotations,
            releaseError: release.flooded.releaseError,
            releaseNoiseBits: release.flooded.releaseNoiseBits,
            releaseLifting: release.lifting,
            interpolation: deriveReleaseInterpolation(participantCount),
            shareLifting: deriveSupportedShareLifting(participantCount),
        };
    }
};

export const compileSupportedProfileCensus = () => {
    const participantCounts = compileSupportedThresholdCompletionProfiles().map(
        (profile) => profile.participantCount,
    );
    const optionCounts = Array.from(
        {
            length:
                supportedOptionCounts.maximum -
                supportedOptionCounts.minimum +
                1,
        },
        (_unused, index) => supportedOptionCounts.minimum + index,
    );
    const profiles = participantCounts.map((participantCount) =>
        optionCounts.map((optionCount) =>
            deriveSupportedProfile(participantCount, optionCount),
        ),
    );
    const flattened = profiles.flat();
    const ciphertextModuli = [
        ...new Map(
            flattened.map((profile) => [
                profile.ciphertext.bits,
                {
                    ...profile.ciphertext,
                    gadgetLength: profile.gadgetLength,
                    profileCount: flattened.filter(
                        (other) =>
                            other.ciphertext.bits === profile.ciphertext.bits,
                    ).length,
                },
            ]),
        ).values(),
    ].sort((left, right) => left.bits - right.bits);
    const releaseModuli = [
        ...new Map(
            flattened.map((profile) => [profile.release.bits, profile.release]),
        ).values(),
    ];
    return {
        participantCounts,
        optionCounts,
        profiles,
        ciphertextModuli,
        releaseModuli,
        maximumCiphertextModulusBits: Math.max(
            ...flattened.map((profile) => profile.ciphertext.bits),
        ),
        minimumCiphertextModulusBits: Math.min(
            ...flattened.map((profile) => profile.ciphertext.bits),
        ),
        releaseNoiseBitRange: [
            Math.min(...flattened.map((profile) => profile.releaseNoiseBits)),
            Math.max(...flattened.map((profile) => profile.releaseNoiseBits)),
        ] as const,
        maximumRankingDepth: Math.max(
            ...flattened.map((profile) => profile.rankingDepth),
        ),
        maximumRankingErrorBits: Math.max(
            ...flattened.map((profile) => bitLength(profile.rankingError)),
        ),
    };
};
