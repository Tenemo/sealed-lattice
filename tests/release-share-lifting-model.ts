import assert from 'node:assert/strict';

import { compileFixedModulusBfvCensus } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

const field = compileSmallLimbProofFieldCensus().modulus;
const limbBits = 48;
const radix = 1n << BigInt(limbBits),
    carryBound = 1n << 71n;
const bitLength = (value: bigint): number => value.toString(2).length;

export type ReleaseShareLiftingInput = Readonly<{
    polynomialDegree: bigint;
    releaseModulus: bigint;
    releaseNoiseBits: number;
    releaseThreshold: number;
    aggregateSharingMaximum: bigint;
}>;
const tenParticipantInput = (): ReleaseShareLiftingInput => {
    const parameters = compileFixedModulusBfvCensus();
    return {
        polynomialDegree: parameters.polynomialDegree,
        releaseModulus: parameters.releaseModulus,
        releaseNoiseBits: parameters.releaseNoiseBits,
        releaseThreshold: compileThresholdCompletionProfile(
            Number(parameters.participantCount),
        ).resultReleaseThreshold,
        aggregateSharingMaximum:
            compileWideShareLiftingCensus().aggregateSharingMaximum,
    };
};

// The release proof lifts c*(c1*S + e) = partial + Q_release*quotient into
// 48-bit limbs. Denominators clear with c = 2^ceil(log2 d), shares occupy
// whole bytes with a sign bit, and quotients occupy whole signed limbs.
export const deriveReleaseShareLiftingLayout = (
    input: ReleaseShareLiftingInput,
) => {
    const {
        polynomialDegree,
        releaseModulus: modulus,
        releaseNoiseBits: noiseBits,
        releaseThreshold,
    } = input;
    assert.ok(releaseThreshold >= 2);
    const clearingFactor =
        1n << BigInt(bitLength(BigInt(releaseThreshold - 1)));
    const shareBits =
        8 * Math.ceil((bitLength(input.aggregateSharingMaximum) + 1) / 8);
    const noiseRadius = 1n << BigInt(noiseBits - 1);
    const trueQuotientBound =
        (clearingFactor *
            polynomialDegree *
            (modulus / 2n) *
            (1n << BigInt(shareBits - 1)) +
            clearingFactor * noiseRadius +
            modulus / 2n) /
        modulus;
    const quotientBits =
        limbBits * Math.ceil((bitLength(trueQuotientBound) + 1) / limbBits);
    const noiseWordCount = Math.ceil(noiseBits / limbBits);
    const publicLimbs = Math.ceil(bitLength(modulus) / limbBits);
    const shareLimbs = Math.ceil(shareBits / limbBits);
    const quotientLimbs = quotientBits / limbBits;
    const outputLimbs = publicLimbs + Math.max(shareLimbs, quotientLimbs) - 1;
    // Each output limb receives at most min(public, private) limb products.
    const productTerms =
        clearingFactor *
            BigInt(Math.min(publicLimbs, shareLimbs)) *
            polynomialDegree +
        BigInt(Math.min(publicLimbs, quotientLimbs));
    const linearTerms = (1n + clearingFactor) * (radix - 1n);
    const residualBound =
        productTerms * (radix - 1n) ** 2n +
        linearTerms +
        carryBound * (radix + 1n);
    const trueCarryBound =
        (productTerms * (radix - 1n) ** 2n + linearTerms) / (radix - 1n) + 1n;
    const aliasCarry = (field - (field % radix)) / radix;
    return {
        ...input,
        clearingFactor,
        shareBits,
        quotientBits,
        noiseWordCount,
        publicLimbs,
        shareLimbs,
        quotientLimbs,
        outputLimbs,
        productTerms,
        radix,
        carryBound,
        residualBound,
        trueCarryBound,
        trueQuotientBound,
        aliasCarry,
        holds:
            noiseWordCount <= outputLimbs &&
            residualBound < field &&
            trueCarryBound < carryBound &&
            aliasCarry >= carryBound,
    };
};

const degree = 8;
type Polynomial = readonly bigint[];
const abs = (value: bigint): bigint => (value < 0n ? -value : value);
const mod = (value: bigint, coefficientModulus: bigint): bigint =>
    ((value % coefficientModulus) + coefficientModulus) % coefficientModulus;
const center = (value: bigint, modulus: bigint): bigint => {
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
export const compileReleaseShareLiftingCensus = (
    input: ReleaseShareLiftingInput = tenParticipantInput(),
) => {
    const layout = deriveReleaseShareLiftingLayout(input);
    assert.ok(layout.holds);
    const {
        releaseModulus: modulus,
        releaseNoiseBits: noiseBits,
        clearingFactor,
        shareBits,
        quotientBits,
        noiseWordCount,
        publicLimbs,
        shareLimbs,
        quotientLimbs,
        outputLimbs,
    } = layout;
    const noiseRadius = 1n << BigInt(noiseBits - 1);
    const shareRadius = 1n << BigInt(shareBits - 1);
    let state = 0x6a09e667f3bcc909n;
    const random = (): bigint =>
        (state =
            (state * 6364136223846793005n + 1442695040888963407n) &
            ((1n << 192n) - 1n));

    let checkedEquations = 0,
        maximumObservedCarry = 0n,
        maximumObservedQuotient = 0n;
    for (let trial = 0; trial < 32; trial++) {
        const share = zero().map(() =>
            trial === 0
                ? -shareRadius
                : trial === 1
                  ? shareRadius - 1n
                  : (random() % (2n * shareRadius)) - shareRadius,
        );
        const noise = zero().map(() =>
            trial === 0
                ? -noiseRadius
                : trial === 1
                  ? noiseRadius - 1n
                  : (random() % (2n * noiseRadius)) - noiseRadius,
        );
        const publicValue = zero().map(() =>
            center((random() * modulus) / (1n << 192n), modulus),
        );
        const raw = product(publicValue, share).map(
            (value, index) =>
                clearingFactor * value + clearingFactor * noise[index],
        );
        const partial = raw.map((value) => center(value, modulus));
        const quotient = raw.map((value, index) => {
            assert.equal((value - partial[index]) % modulus, 0n);
            return (value - partial[index]) / modulus;
        });
        const shareDigits = share.map((value) =>
            privateDigits(value, shareBits),
        );
        const noiseDigits = noise.map((value) =>
            privateDigits(value, noiseBits),
        );
        const quotientDigits = quotient.map((value) =>
            privateDigits(value, quotientBits),
        );
        let carry = zero();
        for (let limb = 0; limb < outputLimbs; limb++) {
            carry = zero().map((_unused, position) => {
                let residual =
                    carry[position] -
                    (limb < publicLimbs
                        ? publicDigit(partial[position], limb)
                        : 0n) +
                    (limb < noiseWordCount
                        ? clearingFactor * noiseDigits[position][limb]
                        : 0n);
                for (
                    let publicLimb = 0;
                    publicLimb < publicLimbs;
                    publicLimb++
                ) {
                    const privateLimb = limb - publicLimb;
                    if (privateLimb < 0) continue;
                    if (privateLimb < shareLimbs)
                        residual +=
                            clearingFactor *
                            rowProduct(
                                publicValue.map((value) =>
                                    publicDigit(value, publicLimb),
                                ),
                                shareDigits.map(
                                    (digits) => digits[privateLimb],
                                ),
                                position,
                            );
                    if (privateLimb < quotientLimbs)
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
    assert.equal(aliasCarry, layout.aliasCarry);
    return {
        ...layout,
        proofPrime: field,
        checkedEquations,
        maximumObservedCarry,
        maximumObservedQuotient,
    };
};
