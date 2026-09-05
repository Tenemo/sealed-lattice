import assert from 'node:assert/strict';

import { verifyProthCertificate } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

const proofPrime = compileSmallLimbProofFieldCensus().modulus;
const scale = verifyProthCertificate(119n, 23, 3n);
const modulus = proofPrime * scale,
    radix = 1n << 96n,
    sharingRadius = 1n << 111n;
const degree = 8,
    participantCount = 10n,
    corruptCount = 3,
    productionWeight = 256n,
    errorBound = 64n;
const quotientBound = 1n << 15n,
    carryBound = 1n << 31n;
const residualBound =
    (productionWeight + quotientBound + 2n) * (radix - 1n) +
    scale * ((BigInt(corruptCount) * radix) / 2n + 1n) +
    errorBound +
    carryBound * (radix + 1n);
assert.ok(residualBound < proofPrime);
const trueQuotientBound =
    ((productionWeight + 1n) * (modulus / 2n) +
        scale * (1n + BigInt(corruptCount) * sharingRadius) +
        errorBound) /
    modulus;
const trueCarryBound =
    ((productionWeight + trueQuotientBound + 2n) * (radix - 1n) +
        scale * ((BigInt(corruptCount) * radix) / 2n + 1n) +
        errorBound) /
        (radix - 1n) +
    1n;
assert.ok(trueQuotientBound < quotientBound);
assert.ok(trueCarryBound < carryBound);
const privacyNumerator =
    participantCount *
    ((1n << BigInt(corruptCount)) - 1n) *
    2n *
    productionWeight;
assert.ok(privacyNumerator << 96n <= 2n * sharingRadius);
const aggregateSharingMaximum =
    participantCount * (1n + BigInt(corruptCount) * sharingRadius);
assert.ok(2n * aggregateSharingMaximum < proofPrime);
assert.ok(
    participantCount * (2n * productionWeight + 1n) * errorBound < 1n << 23n,
);
assert.ok(2n * (1n << 23n) < scale);
type Polynomial = readonly bigint[];
const abs = (value: bigint): bigint => (value < 0n ? -value : value);
const mod = (value: bigint, coefficientModulus: bigint): bigint =>
    ((value % coefficientModulus) + coefficientModulus) % coefficientModulus;
const center = (value: bigint): bigint => {
    const residue = mod(value, modulus);
    return residue > modulus / 2n ? residue - modulus : residue;
};
const zero = (): bigint[] => Array.from({ length: degree }, () => 0n);
const add = (left: Polynomial, right: Polynomial): bigint[] =>
    left.map((value, index) => value + right[index]);
const multiply = (left: Polynomial, right: Polynomial): bigint[] => {
    const result = zero();
    for (let first = 0; first < degree; first++)
        for (let second = 0; second < degree; second++) {
            const index = first + second;
            result[index % degree] +=
                (index >= degree ? -1n : 1n) * left[first] * right[second];
        }
    return result;
};
const monomial = (exponent: number): bigint[] =>
    zero().map((_unused, index) =>
        index === exponent % degree
            ? Math.floor(exponent / degree) % 2 === 0
                ? 1n
                : -1n
            : 0n,
    );
const digit = (value: bigint, index: number): bigint =>
    (value < 0n ? -1n : 1n) * ((abs(value) / radix ** BigInt(index)) % radix);
const rowProduct = (left: Polynomial, right: Polynomial, row: number): bigint =>
    left.reduce(
        (sum, value, index) =>
            sum +
            (row < index ? -1n : 1n) *
                value *
                right[(row - index + degree) % degree],
        0n,
    );
const signedRange = (value: bigint, bits: number): void => {
    const radius = 1n << BigInt(bits - 1);
    assert.ok(value >= -radius && value < radius);
};
export const compileWideShareLiftingCensus = () => {
    let state = 0x6a09e667f3bcc909n;
    const random = (): bigint =>
        (state =
            (state * 6364136223846793005n + 1442695040888963407n) &
            ((1n << 128n) - 1n));
    const sparse = (): bigint[] => {
        const result = zero();
        const first = Number(random() % 8n);
        const second = (first + 1 + Number(random() % 7n)) % degree;
        result[first] = 1n;
        result[second] = -1n;
        return result;
    };

    let checkedEquations = 0,
        maximumObservedCarry = 0n,
        maximumObservedQuotient = 0n;
    for (let trial = 0; trial < 32; trial++) {
        const secret = sparse(),
            recipient = sparse(),
            ephemeral = sparse();
        const common = zero().map(() =>
            center((random() * modulus) / (1n << 128n)),
        );
        const error = (): bigint[] =>
            zero().map(() =>
                trial === 0
                    ? -64n
                    : trial === 1
                      ? 63n
                      : (random() % 128n) - 64n,
            );
        const publicError = error(),
            cipherError = error();
        const publicKey = add(
            multiply(common, recipient).map((value) => -value),
            publicError,
        ).map(center);
        const coefficients = Array.from({ length: corruptCount }, () =>
            zero().map(() =>
                trial === 0
                    ? -sharingRadius
                    : trial === 1
                      ? sharingRadius - 1n
                      : (random() % (2n * sharingRadius)) - sharingRadius,
            ),
        );
        const point = trial % 16;
        const share = coefficients.reduce(
            (value, coefficient, index) =>
                add(
                    value,
                    multiply(monomial(point * (index + 1)), coefficient),
                ),
            [...secret],
        );
        const publicOffset = coefficients.reduce(
            (value, _coefficient, index) =>
                add(
                    value,
                    multiply(
                        monomial(point * (index + 1)),
                        zero().map(() => (scale * radix) / 2n),
                    ),
                ),
            zero(),
        );
        const low = coefficients.map((coefficient) =>
            coefficient.map((value) => mod(value, radix) - radix / 2n),
        );
        const high = coefficients.map((coefficient) =>
            coefficient.map((value) => (value - mod(value, radix)) / radix),
        );
        coefficients.forEach((coefficient, index) =>
            coefficient.forEach((value, position) => {
                signedRange(low[index][position], 96);
                signedRange(high[index][position], 16);
                assert.equal(
                    low[index][position] +
                        radix * high[index][position] +
                        radix / 2n,
                    value,
                );
            }),
        );
        const encrypted = add(
            add(
                multiply(publicKey, ephemeral),
                share.map((value) => scale * value),
            ),
            cipherError,
        ).map(center);
        const linearError = error();
        const linear = add(multiply(common, ephemeral), linearError).map(
            center,
        );
        const phase = add(encrypted, multiply(linear, recipient)).map(center);
        const rounded = (value: bigint): bigint =>
            value < 0n
                ? -((-value + scale / 2n) / scale)
                : (value + scale / 2n) / scale;
        assert.deepEqual(phase.map(rounded), share);
        const quotient = encrypted.map((value, position) => {
            const numerator =
                value -
                rowProduct(publicKey, ephemeral, position) -
                scale * share[position] -
                cipherError[position];
            assert.equal(numerator % modulus, 0n);
            const result = numerator / modulus;
            signedRange(result, 16);
            maximumObservedQuotient =
                abs(result) > maximumObservedQuotient
                    ? abs(result)
                    : maximumObservedQuotient;
            return result;
        });
        let carry = zero();
        for (let limb = 0; limb < 2; limb++) {
            const privateDigits = (limb === 0 ? low : high).reduce(
                (value, coefficient, index) =>
                    add(
                        value,
                        multiply(monomial(point * (index + 1)), coefficient),
                    ),
                zero(),
            );
            const publicDigits = publicKey.map((value) => digit(value, limb));
            carry = zero().map((_unused, position) => {
                const residual =
                    digit(encrypted[position], limb) -
                    rowProduct(publicDigits, ephemeral, position) -
                    scale * privateDigits[position] -
                    (limb === 0
                        ? scale * secret[position] + cipherError[position]
                        : 0n) -
                    digit(publicOffset[position], limb) -
                    digit(modulus, limb) * quotient[position] +
                    carry[position];
                assert.equal(residual % radix, 0n);
                const next = residual / radix;
                signedRange(next, 32);
                maximumObservedCarry =
                    abs(next) > maximumObservedCarry
                        ? abs(next)
                        : maximumObservedCarry;
                checkedEquations++;
                return next;
            });
        }
        assert.deepEqual(carry, zero());
    }
    // The false public coefficient p needs a carry outside the signed word.
    const aliasCarry = (proofPrime - digit(proofPrime, 0)) / radix;
    assert.equal(
        mod(-digit(proofPrime, 0) - radix * aliasCarry, proofPrime),
        0n,
    );
    assert.equal(-digit(proofPrime, 1) + aliasCarry, 0n);
    assert.equal(aliasCarry, (1n << 32n) - 1n);
    assert.ok(aliasCarry >= carryBound);
    return {
        proofPrime,
        scale,
        modulus,
        radix,
        sharingRadius,
        productionWeight,
        errorBound,
        residualBound,
        trueQuotientBound,
        trueCarryBound,
        quotientBound,
        carryBound,
        privacyNumerator,
        aggregateSharingMaximum,
        checkedEquations,
        maximumObservedCarry,
        maximumObservedQuotient,
        aliasCarry,
    };
};
