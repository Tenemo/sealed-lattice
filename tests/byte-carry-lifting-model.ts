import assert from 'node:assert/strict';

import {
    candidateBgvParameterInputs,
    compileCandidateBgvParameterCensus,
} from '#tests/candidate-bgv-parameter-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

const modulus = compileCandidateBgvParameterCensus().ciphertextModulus;
const field = compileSmallLimbProofFieldCensus().modulus;
const radix = 1n << 96n;
const quotientBound = 1n << 15n;
const carryBound = 1n << 23n;
const productionDegree = candidateBgvParameterInputs.polynomialModulusDegree;
const residualBound =
    (productionDegree + quotientBound + 2n) * (radix - 1n) +
    1n +
    carryBound * (radix + 1n);
assert.ok(residualBound < field);
const limbCount = Math.ceil(modulus.toString(2).length / 96);
const degree = 8;
type Ring = readonly bigint[];
const modulo = (value: bigint, coefficientModulus: bigint): bigint =>
    ((value % coefficientModulus) + coefficientModulus) % coefficientModulus;
const centered = (value: bigint, coefficientModulus: bigint): bigint => {
    const residue = modulo(value, coefficientModulus);
    return residue > coefficientModulus / 2n
        ? residue - coefficientModulus
        : residue;
};
const absolute = (value: bigint): bigint => (value < 0n ? -value : value);
const digit = (value: bigint, index: number): bigint =>
    (value < 0n ? -1n : 1n) *
    ((absolute(value) / radix ** BigInt(index)) % radix);
const maximumNorm = (values: Ring): bigint =>
    values.reduce(
        (maximum, value) =>
            absolute(value) > maximum ? absolute(value) : maximum,
        0n,
    );
const polynomialProduct = (left: Ring, right: Ring): bigint[] => {
    const product = Array.from({ length: 2 * degree - 1 }, () => 0n);
    left.forEach((coefficient, index) =>
        right.forEach(
            (other, offset) => (product[index + offset] += coefficient * other),
        ),
    );
    for (let index = product.length - 1; index >= degree; index--)
        product[index - degree] -= product[index];
    return product.slice(0, degree);
};
// Independent row-oriented convolution; this does not reduce a full product.
const convolutionRow = (left: Ring, right: Ring, row: number): bigint =>
    left.reduce(
        (sum, coefficient, index) =>
            sum +
            (row < index ? -1n : 1n) *
                coefficient *
                right[(row - index + degree) % degree],
        0n,
    );
const signedBytes = (value: bigint, width: number): bigint[] => {
    const offset = 1n << BigInt(8 * width - 1);
    const shifted = value + offset;
    assert.ok(shifted >= 0n && shifted < 1n << BigInt(8 * width));
    const bytes = Array.from(
        { length: width },
        (_, index) => (shifted >> BigInt(8 * index)) & 255n,
    );
    assert.equal(
        bytes.reduce(
            (sum, byte, index) => sum + (byte << BigInt(8 * index)),
            0n,
        ) - offset,
        value,
    );
    return bytes;
};
const power = (base: bigint, exponent: bigint): bigint => {
    let result = 1n;
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) !== 0n) result = (result * base) % field;
        base = (base * base) % field;
    }
    return result;
};

export const compileByteCarryLiftingCensus = () => {
    let randomState = 0x6a09e667f3bcc909n;
    const next = (): bigint =>
        (randomState =
            (randomState * 6364136223846793005n + 1442695040888963407n) &
            ((1n << 64n) - 1n));
    let equationCount = 0,
        maximumCarry = 0n,
        maximumQuotient = 0n;
    for (let trial = 0; trial < 32; trial++) {
        const small = (): bigint[] =>
            Array.from({ length: degree }, () =>
                trial === 0 ? 0n : trial === 1 ? 1n : (next() % 3n) - 1n,
            );
        const source = small(),
            destination = small(),
            error = small();
        const common = Array.from({ length: degree }, () =>
            centered((next() * modulus) / (1n << 64n), modulus),
        );
        const gadget = 1n << 600n;
        const product = polynomialProduct(destination, common);
        const publicValue = product.map((value, index) =>
            centered(-value + gadget * source[index] + error[index], modulus),
        );
        const numerator = publicValue.map(
            (value, index) =>
                value + product[index] - gadget * source[index] - error[index],
        );
        assert.ok(numerator.every((value) => value % modulus === 0n));
        const quotient = numerator.map((value) => value / modulus);
        quotient.forEach((value) => signedBytes(value, 2));
        maximumQuotient =
            maximumNorm(quotient) > maximumQuotient
                ? maximumNorm(quotient)
                : maximumQuotient;
        for (const value of [...common, ...publicValue, gadget, modulus])
            assert.equal(
                Array.from(
                    { length: limbCount },
                    (_, index) => digit(value, index) * radix ** BigInt(index),
                ).reduce((sum, term) => sum + term, 0n),
                value,
            );
        let carry = Array.from({ length: degree }, () => 0n);
        for (let limb = 0; limb < limbCount; limb++) {
            const commonDigits = common.map((value) => digit(value, limb));
            const nextCarry = Array.from({ length: degree }, (_, row) => {
                const partial =
                    digit(publicValue[row], limb) +
                    convolutionRow(commonDigits, destination, row) -
                    digit(gadget, limb) * source[row] -
                    (limb === 0 ? error[row] : 0n) -
                    digit(modulus, limb) * quotient[row] +
                    carry[row];
                assert.equal(partial % radix, 0n);
                const nextValue = partial / radix;
                signedBytes(nextValue, 3);
                assert.equal(partial - radix * nextValue, 0n);
                equationCount++;
                return nextValue;
            });
            maximumCarry =
                maximumNorm(nextCarry) > maximumCarry
                    ? maximumNorm(nextCarry)
                    : maximumCarry;
            carry = nextCarry;
        }
        assert.equal(maximumNorm(carry), 0n);
    }
    // b=p, r=s=e=z=0 is false modulo the large ciphertext modulus. An
    // unbounded carry can nevertheless satisfy every row modulo the proof p.
    assert.ok(field < modulus / 2n);
    const inverseRadix = power(radix, field - 2n);
    let cheatingCarry = 0n,
        largestCheatingCarry = 0n;
    let outOfRangeCarries = 0;
    for (let limb = 0; limb < limbCount; limb++) {
        const nextCarry = modulo(
            (digit(field, limb) + cheatingCarry) * inverseRadix,
            field,
        );
        assert.equal(
            modulo(
                digit(field, limb) + cheatingCarry - radix * nextCarry,
                field,
            ),
            0n,
        );
        const magnitude = absolute(centered(nextCarry, field));
        if (magnitude > carryBound) outOfRangeCarries++;
        largestCheatingCarry =
            magnitude > largestCheatingCarry ? magnitude : largestCheatingCarry;
        cheatingCarry = nextCarry;
    }
    assert.equal(cheatingCarry, 0n);
    assert.equal(largestCheatingCarry, (1n << 32n) - 1n);
    assert.equal(outOfRangeCarries, 1);

    for (const width of [2, 3]) {
        const boundary = 1n << BigInt(8 * width - 1);
        signedBytes(-boundary, width);
        signedBytes(boundary - 1n, width);
        assert.throws(() => signedBytes(-boundary - 1n, width));
        assert.throws(() => signedBytes(boundary, width));
    }
    return {
        degree,
        limbCount,
        radix,
        quotientBound,
        carryBound,
        residualBound,
        field,
        positiveIntegerEquations: equationCount,
        maximumCarry,
        maximumQuotient,
        aliasIntegerResidual: field,
        largestCheatingCarry,
        outOfRangeCarries,
    };
};
