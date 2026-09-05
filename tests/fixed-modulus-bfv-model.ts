import assert from 'node:assert/strict';

import { evaluateOddPolynomialBlocks } from '#tests/odd-polynomial-block-model.js';
import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';

export const fixedModulusBfvInputs = {
    participantCount: 10n,
    polynomialDegree: 65536n,
    plaintextSubringDegree: 32768n,
    plaintextModulus: 65537n,
    ciphertextModulus: 65537n * 65319n * (1n << 832n) + 1n,
    releaseModulus: 65537n * 65445n * (1n << 160n) + 1n,
    secretSupportWeight: 1024n,
    errorBound: 64n,
    gadgetBase: 1n << 144n,
    optionCount: 10,
    comparisonBlockWidth: 16,
    statisticalBits: 96,
} as const;

type NoiseParameters = Readonly<{
    participantCount: bigint;
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
// specified subring. Both aggregate secrets have the stated one-norm bound.
export const createFixedModulusBfvNoiseModel = (
    parameters: NoiseParameters,
) => {
    const {
        participantCount,
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
    const secretOneNorm = participantCount * secretSupportWeight;
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
        participantCount *
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

export const compileFixedModulusBfvCensus = () => {
    const parameters = fixedModulusBfvInputs;
    assert.equal(
        verifyProthCertificate(65537n * 65319n, 832, 7n),
        parameters.ciphertextModulus,
    );
    assert.equal(
        verifyProthCertificate(65537n * 65445n, 160, 7n),
        parameters.releaseModulus,
    );
    const model = createFixedModulusBfvNoiseModel(parameters);
    const sum = (values: readonly BfvNoiseValue[]): BfvNoiseValue => {
        assert.ok(values.length > 0);
        return values.slice(1).reduce(model.add, values[0]);
    };
    const powers = (input: BfvNoiseValue) => {
        const cache = new Map<number, BfvNoiseValue>([[1, input]]);
        const power = (exponent: number): BfvNoiseValue => {
            const existing = cache.get(exponent);
            if (existing) return existing;
            const value = model.multiply(
                power(Math.floor(exponent / 2)),
                power(Math.ceil(exponent / 2)),
            );
            cache.set(exponent, value);
            return value;
        };
        return power;
    };
    const input = model.addPlaintext(
        sum(
            Array.from(
                { length: Number(parameters.participantCount) },
                () => model.fresh,
            ),
        ),
    );
    const comparison = model.addPlaintext(
        evaluateOddPolynomialBlocks(
            input,
            2 * (10 - 1) * Number(parameters.participantCount) + 1,
            parameters.comparisonBlockWidth,
            {
                add: model.add,
                multiply: model.multiply,
                weight: model.multiplyScalar,
            },
        ),
    );
    let shifted = comparison;
    let rank = comparison;
    const windowWidth = 2 ** Math.ceil(Math.log2(parameters.optionCount));
    for (let offset = 1; offset < windowWidth; offset++) {
        shifted = model.rotate(shifted);
        rank = model.add(rank, shifted);
    }
    const rankPower = powers(rank);
    const result = model.addPlaintext(
        sum(
            Array.from({ length: parameters.optionCount - 1 }, (_, index) =>
                model.multiplyPlaintext(rankPower(index + 1)),
            ),
        ),
    );
    const releaseError = ceilingDivide(
        2n *
            parameters.releaseModulus *
            parameters.plaintextModulus *
            result.error +
            2n *
                (parameters.ciphertextModulus - parameters.releaseModulus) *
                (parameters.plaintextModulus / 2n) +
            parameters.ciphertextModulus *
                parameters.plaintextModulus *
                (model.secretOneNorm + 1n),
        2n * parameters.ciphertextModulus * parameters.plaintextModulus,
    );
    const interpolation = compileThresholdReleaseNoiseCensus();
    assert.equal(
        BigInt(interpolation.completionParticipantCount),
        parameters.participantCount,
    );
    assert.equal(
        parameters.polynomialDegree %
            BigInt(interpolation.spacedInterpolationSize / 2),
        0n,
    );
    const clearingFactor =
        1n << BigInt(Math.ceil(Math.log2(interpolation.releaseThreshold)));
    const jointShift =
        parameters.polynomialDegree *
        interpolation.exactMaximumJointSimulationCoefficientOneNormSum *
        releaseError;
    const releaseNoiseBits =
        8 *
        Math.ceil(
            (parameters.statisticalBits + ceilingLogarithm(jointShift)) / 8,
        );
    const releaseNoiseRadius = 1n << BigInt(releaseNoiseBits - 1);
    const scaledCorrectnessLeft =
        (4n * releaseError + parameters.plaintextModulus) *
            (clearingFactor + 1n) +
        4n *
            BigInt(interpolation.releaseThreshold) *
            interpolation.exactMaximumScaledReconstructionCoefficientOneNorm *
            releaseNoiseRadius;
    return {
        ...parameters,
        ...model.counts,
        gadgetLength: model.gadgetLength,
        comparisonDepth: comparison.depth,
        rankingDepth: result.depth,
        comparisonErrorBits: bitLength(comparison.error),
        rankingErrorBits: bitLength(result.error),
        releaseError,
        releaseNoiseBits,
        jointStatisticalBoundHolds:
            jointShift << BigInt(parameters.statisticalBits) <=
            1n << BigInt(releaseNoiseBits),
        releaseCorrect:
            2n * parameters.plaintextModulus * scaledCorrectnessLeft <
            4n * parameters.releaseModulus,
        publicKeyCorpusBytes:
            4n *
            model.gadgetLength *
            parameters.polynomialDegree *
            BigInt(Math.ceil(bitLength(parameters.ciphertextModulus) / 8)) *
            parameters.participantCount,
    };
};
