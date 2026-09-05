import assert from 'node:assert/strict';

import { compileFixedModulusBfvCensus } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

const field = compileSmallLimbProofFieldCensus().modulus;
const parameters = compileFixedModulusBfvCensus();
const modulus = parameters.releaseModulus,
    radix = 1n << 48n,
    carryBound = 1n << 71n;
const residualBound =
    (12n * parameters.polynomialDegree + 3n) * (radix - 1n) ** 2n +
    5n * (radix - 1n) +
    carryBound * (radix + 1n);
const trueCarryBound =
    ((12n * parameters.polynomialDegree + 3n) * (radix - 1n) ** 2n +
        5n * (radix - 1n)) /
        (radix - 1n) +
    1n;
const trueQuotientBound =
    (4n * parameters.polynomialDegree * (modulus / 2n) * (1n << 119n) +
        4n * (1n << 143n) +
        modulus / 2n) /
    modulus;
assert.ok(residualBound < field);
assert.ok(trueCarryBound < carryBound);
assert.ok(trueQuotientBound < 1n << 143n);
const degree = 8;
type Polynomial = readonly bigint[];
const abs = (value: bigint): bigint => (value < 0n ? -value : value);
const mod = (value: bigint, coefficientModulus: bigint): bigint =>
    ((value % coefficientModulus) + coefficientModulus) % coefficientModulus;
const center = (value: bigint): bigint => {
    const reduced = mod(value, modulus);
    return reduced > modulus / 2n ? reduced - modulus : reduced;
};
const zero = (): bigint[] => Array.from({ length: degree }, () => 0n);
const product = (left: Polynomial, right: Polynomial): bigint[] => {
    const ordinary = Array.from({ length: 2 * degree - 1 }, () => 0n);
    left.forEach((value, index) =>
        right.forEach(
            (other, offset) => (ordinary[index + offset] += value * other),
        ),
    );
    for (let index = ordinary.length - 1; index >= degree; index--)
        ordinary[index - degree] -= ordinary[index];
    return ordinary.slice(0, degree);
};
const rowProduct = (left: Polynomial, right: Polynomial, row: number): bigint =>
    left.reduce(
        (sum, value, index) =>
            sum +
            (row < index ? -1n : 1n) *
                value *
                right[(row - index + degree) % degree],
        0n,
    );
const publicDigit = (value: bigint, index: number): bigint =>
    (value < 0n ? -1n : 1n) * ((abs(value) / radix ** BigInt(index)) % radix);
const privateDigits = (value: bigint, bits: number): bigint[] => {
    const radius = 1n << BigInt(bits - 1);
    assert.ok(value >= -radius && value < radius);
    const length = Math.ceil(bits / 48),
        raw = mod(value, 1n << BigInt(bits));
    const result = Array.from(
        { length },
        (_, index) => (raw / radix ** BigInt(index)) % radix,
    );
    if (value < 0n)
        result[length - 1] -= 1n << BigInt(bits - 48 * (length - 1));
    assert.equal(
        result.reduce(
            (sum, digit, index) => sum + digit * radix ** BigInt(index),
            0n,
        ),
        value,
    );
    return result;
};
export const compileReleaseShareLiftingCensus = () => {
    let state = 0x6a09e667f3bcc909n;
    const random = (): bigint =>
        (state =
            (state * 6364136223846793005n + 1442695040888963407n) &
            ((1n << 160n) - 1n));

    let checkedEquations = 0,
        maximumObservedCarry = 0n,
        maximumObservedQuotient = 0n;
    for (let trial = 0; trial < 32; trial++) {
        const share = zero().map(() =>
            trial === 0
                ? -(1n << 119n)
                : trial === 1
                  ? (1n << 119n) - 1n
                  : (random() % (1n << 120n)) - (1n << 119n),
        );
        const noise = zero().map(() =>
            trial === 0
                ? -(1n << 143n)
                : trial === 1
                  ? (1n << 143n) - 1n
                  : (random() % (1n << 144n)) - (1n << 143n),
        );
        const publicValue = zero().map(() =>
            center((random() * modulus) / (1n << 160n)),
        );
        const raw = product(publicValue, share).map(
            (value, index) => 4n * value + 4n * noise[index],
        );
        const partial = raw.map(center);
        const quotient = raw.map((value, index) => {
            assert.equal((value - partial[index]) % modulus, 0n);
            return (value - partial[index]) / modulus;
        });
        const shareDigits = share.map((value) => privateDigits(value, 120));
        const noiseDigits = noise.map((value) => privateDigits(value, 144));
        const quotientDigits = quotient.map((value) =>
            privateDigits(value, 144),
        );
        let carry = zero();
        for (let limb = 0; limb < 6; limb++) {
            carry = zero().map((_unused, position) => {
                let residual =
                    carry[position] -
                    (limb < 4 ? publicDigit(partial[position], limb) : 0n) +
                    (limb < 3 ? 4n * noiseDigits[position][limb] : 0n);
                for (let publicLimb = 0; publicLimb < 4; publicLimb++) {
                    const privateLimb = limb - publicLimb;
                    if (privateLimb < 0 || privateLimb >= 3) continue;
                    residual +=
                        4n *
                        rowProduct(
                            publicValue.map((value) =>
                                publicDigit(value, publicLimb),
                            ),
                            shareDigits.map((digits) => digits[privateLimb]),
                            position,
                        );
                    residual -=
                        publicDigit(modulus, publicLimb) *
                        quotientDigits[position][privateLimb];
                }
                assert.equal(residual % radix, 0n);
                const next = residual / radix;
                assert.ok(next >= -carryBound && next < carryBound);
                maximumObservedCarry =
                    abs(next) > maximumObservedCarry
                        ? abs(next)
                        : maximumObservedCarry;
                checkedEquations++;
                return next;
            });
        }
        assert.deepEqual(carry, zero());
        quotient.forEach(
            (value) =>
                (maximumObservedQuotient =
                    abs(value) > maximumObservedQuotient
                        ? abs(value)
                        : maximumObservedQuotient),
        );
    }
    const aliasCarry = (field - publicDigit(field, 0)) / radix;
    const secondAliasCarry = (aliasCarry - publicDigit(field, 1)) / radix;
    assert.equal(mod(-publicDigit(field, 0) - radix * aliasCarry, field), 0n);
    assert.equal(
        aliasCarry - publicDigit(field, 1) - radix * secondAliasCarry,
        0n,
    );
    assert.equal(secondAliasCarry - publicDigit(field, 2), 0n);
    assert.equal(aliasCarry, (1n << 80n) - 133n * (1n << 16n));
    assert.ok(aliasCarry >= carryBound);
    return {
        radix,
        carryBound,
        residualBound,
        proofPrime: field,
        trueCarryBound,
        trueQuotientBound,
        checkedEquations,
        maximumObservedCarry,
        maximumObservedQuotient,
        aliasCarry,
    };
};
