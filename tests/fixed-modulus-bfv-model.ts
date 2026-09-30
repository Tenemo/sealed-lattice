import assert from 'node:assert/strict';

// Operands shared by every supported profile. The contributor and option
// counts and both moduli are derived per profile by the supported-profile
// rules.
export const fixedModulusBfvInputs = {
    polynomialDegree: 65536n,
    plaintextSubringDegree: 32768n,
    plaintextModulus: 65537n,
    secretSupportWeight: 1024n,
    errorBound: 64n,
    gadgetBase: 1n << 144n,
    comparisonBlockWidth: 16,
    statisticalBits: 96,
} as const;

type NoiseParameters = Readonly<{
    // The setup contributors, whose secrets and key errors the aggregate
    // keys sum.
    contributorCount: bigint;
    polynomialDegree: bigint;
    plaintextSubringDegree: bigint;
    plaintextModulus: bigint;
    ciphertextModulus: bigint;
    secretSupportWeight: bigint;
    errorBound: bigint;
    gadgetBase: bigint;
    quantization?: 'scale-then-round' | 'round-then-scale';
}>;
type BfvNoiseValue = Readonly<{ error: bigint; depth: number }>;

const ceilingDivide = (numerator: bigint, denominator: bigint): bigint =>
    (numerator + denominator - 1n) / denominator;
const bitLength = (value: bigint): number => value.toString(2).length;
const ceilingLogarithm = (value: bigint): number =>
    value <= 1n ? 0 : bitLength(value - 1n);

export const verifyProthCertificate = (
    oddFactor: bigint,
    powerOfTwo: number,
    witness: bigint,
): bigint => {
    const factor = 1n << BigInt(powerOfTwo);
    assert.ok(oddFactor > 0n && oddFactor < factor && oddFactor % 2n === 1n);
    const modulus = oddFactor * factor + 1n;
    let power = witness % modulus;
    let result = 1n;
    for (let exponent = (modulus - 1n) / 2n; exponent > 0n; exponent >>= 1n) {
        if ((exponent & 1n) !== 0n) result = (result * power) % modulus;
        power = (power * power) % modulus;
    }
    assert.equal(result, modulus - 1n);
    return modulus;
};

// Bounds apply to centered ciphertext components and plaintexts in the
// specified subring. Both aggregate secrets have the stated one-norm bound:
// each is the sum of every contributor's secret of the support weight.
export const createFixedModulusBfvNoiseModel = (
    parameters: NoiseParameters,
) => {
    const {
        contributorCount,
        polynomialDegree,
        plaintextSubringDegree,
        plaintextModulus,
        ciphertextModulus,
        secretSupportWeight,
        errorBound,
        gadgetBase,
    } = parameters;
    assert.equal(ciphertextModulus % 2n, 1n);
    assert.equal(plaintextModulus % 2n, 1n);
    assert.equal(polynomialDegree % plaintextSubringDegree, 0n);
    const secretOneNorm = contributorCount * secretSupportWeight;
    const plaintextMaximumNorm = plaintextModulus / 2n;
    const plaintextOneNorm = plaintextSubringDegree * plaintextMaximumNorm;
    const plaintextProductMaximumNorm = plaintextOneNorm * plaintextMaximumNorm;
    const plaintextProductQuotient =
        (plaintextProductMaximumNorm + plaintextMaximumNorm) / plaintextModulus;
    const delta =
        (ciphertextModulus + plaintextModulus / 2n) / plaintextModulus;
    const scaleRemainder = ciphertextModulus - plaintextModulus * delta;
    const remainderMagnitude =
        scaleRemainder < 0n ? -scaleRemainder : scaleRemainder;
    const roundingFactor =
        parameters.quantization === 'round-then-scale' ? plaintextModulus : 1n;
    let gadgetLength = 0n;
    for (let power = 1n; power < ciphertextModulus; power *= gadgetBase)
        gadgetLength++;
    const externalProductError =
        gadgetLength *
        (gadgetBase - 1n) *
        contributorCount *
        polynomialDegree *
        errorBound;
    const relinearizationError =
        (2n * secretOneNorm + 1n) * externalProductError;
    const counts = {
        multiplications: 0,
        additions: 0,
        scalarProducts: 0,
        plaintextProducts: 0,
        rotations: 0,
        plaintextAdditions: 0,
    };
    const requireDecodable = (value: BfvNoiseValue): BfvNoiseValue => {
        assert.ok(
            2n *
                (plaintextModulus * value.error +
                    remainderMagnitude * plaintextMaximumNorm) <
                ciphertextModulus,
            'The accepted error support exceeds the BFV decoding cell.',
        );
        return value;
    };
    const add = (left: BfvNoiseValue, right: BfvNoiseValue): BfvNoiseValue => {
        counts.additions++;
        return requireDecodable({
            error: left.error + right.error + remainderMagnitude,
            depth: Math.max(left.depth, right.depth),
        });
    };
    const addPlaintext = (value: BfvNoiseValue): BfvNoiseValue => {
        counts.plaintextAdditions++;
        return requireDecodable({
            ...value,
            error: value.error + remainderMagnitude,
        });
    };
    const multiply = (
        left: BfvNoiseValue,
        right: BfvNoiseValue,
    ): BfvNoiseValue => {
        counts.multiplications++;
        const phaseLift = (value: BfvNoiseValue): bigint =>
            ((ciphertextModulus / 2n) * (secretOneNorm + 1n) +
                delta * plaintextMaximumNorm +
                value.error) /
            ciphertextModulus;
        const leftLift = phaseLift(left);
        const rightLift = phaseLift(right);
        const numerator =
            (ciphertextModulus - scaleRemainder) *
                plaintextOneNorm *
                (left.error + right.error) +
            plaintextModulus * polynomialDegree * left.error * right.error +
            ciphertextModulus *
                remainderMagnitude *
                (leftLift + rightLift) *
                plaintextOneNorm +
            ciphertextModulus *
                plaintextModulus *
                polynomialDegree *
                (leftLift * right.error + rightLift * left.error) +
            delta * remainderMagnitude * plaintextProductMaximumNorm +
            ciphertextModulus * remainderMagnitude * plaintextProductQuotient +
            roundingFactor *
                (ciphertextModulus / 2n) *
                (secretOneNorm + 1n) ** 2n;
        return requireDecodable({
            error:
                ceilingDivide(numerator, ciphertextModulus) +
                relinearizationError,
            depth: Math.max(left.depth, right.depth) + 1,
        });
    };
    const multiplyScalar = (value: BfvNoiseValue): BfvNoiseValue => {
        counts.scalarProducts++;
        return requireDecodable({
            ...value,
            error:
                plaintextMaximumNorm * value.error +
                remainderMagnitude *
                    ((plaintextMaximumNorm ** 2n + plaintextMaximumNorm) /
                        plaintextModulus),
        });
    };
    const multiplyPlaintext = (value: BfvNoiseValue): BfvNoiseValue => {
        counts.plaintextProducts++;
        return requireDecodable({
            ...value,
            error:
                plaintextOneNorm * value.error +
                remainderMagnitude * plaintextProductQuotient,
        });
    };
    const rotate = (value: BfvNoiseValue): BfvNoiseValue => {
        counts.rotations++;
        return requireDecodable({
            ...value,
            error: value.error + externalProductError,
        });
    };
    return {
        counts,
        gadgetLength,
        secretOneNorm,
        externalProductError,
        relinearizationError,
        scaleRemainder,
        fresh: requireDecodable({
            error: (2n * secretOneNorm + 1n) * errorBound,
            depth: 0,
        }),
        add,
        addPlaintext,
        multiply,
        multiplyScalar,
        multiplyPlaintext,
        rotate,
    };
};

export type ReleaseInterpolationBounds = Readonly<{
    releaseThreshold: number;
    clearingFactor: bigint;
    maximumScaledReconstructionOneNorm: bigint;
    maximumJointSimulationOneNormSum: bigint;
}>;

// Final modulus switch to the release modulus, the byte-aligned flooding
// width from the pointwise joint coupling, and KLLPS26 Theorem 3.1 (C2).
export const deriveFloodedRelease = (
    input: Readonly<{
        polynomialDegree: bigint;
        plaintextModulus: bigint;
        ciphertextModulus: bigint;
        releaseModulus: bigint;
        statisticalBits: number;
        evaluationError: bigint;
        secretOneNorm: bigint;
        interpolation: ReleaseInterpolationBounds;
    }>,
) => {
    const {
        polynomialDegree,
        plaintextModulus,
        ciphertextModulus,
        releaseModulus,
        statisticalBits,
        interpolation,
    } = input;
    const releaseError = ceilingDivide(
        2n * releaseModulus * plaintextModulus * input.evaluationError +
            2n *
                (ciphertextModulus - releaseModulus) *
                (plaintextModulus / 2n) +
            ciphertextModulus * plaintextModulus * (input.secretOneNorm + 1n),
        2n * ciphertextModulus * plaintextModulus,
    );
    const jointShift =
        polynomialDegree *
        interpolation.maximumJointSimulationOneNormSum *
        releaseError;
    const releaseNoiseBits =
        8 * Math.ceil((statisticalBits + ceilingLogarithm(jointShift)) / 8);
    const releaseNoiseRadius = 1n << BigInt(releaseNoiseBits - 1);
    const scaledCorrectnessLeft =
        (4n * releaseError + plaintextModulus) *
            (interpolation.clearingFactor + 1n) +
        4n *
            BigInt(interpolation.releaseThreshold) *
            interpolation.maximumScaledReconstructionOneNorm *
            releaseNoiseRadius;
    // Release decodes correctly when the bound stays strictly below the
    // limit; their ratio is the correctness margin.
    const releaseCorrectnessBound =
        2n * plaintextModulus * scaledCorrectnessLeft;
    const releaseCorrectnessLimit = 4n * releaseModulus;
    return {
        releaseError,
        releaseNoiseBits,
        jointStatisticalBoundHolds:
            jointShift << BigInt(statisticalBits) <=
            1n << BigInt(releaseNoiseBits),
        releaseCorrectnessBound,
        releaseCorrectnessLimit,
        releaseCorrect: releaseCorrectnessBound < releaseCorrectnessLimit,
    };
};
