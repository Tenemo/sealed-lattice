import { describe, expect, it } from 'vitest';

import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';
import {
    compileShareEncryptionCrossModulusCensus,
    verifyExactQuotients,
} from '#tests/share-encryption-cross-modulus-model.js';

const binaryDigitCount = (value: bigint): bigint => {
    let digitCount = 0n;
    while (1n << digitCount <= value) digitCount += 1n;
    return digitCount;
};

// Every vector over the given values with the given length.
const vectorsOver = (values: readonly bigint[], length: number): bigint[][] =>
    length === 0
        ? [[]]
        : vectorsOver(values, length - 1).flatMap((prefix) =>
              values.map((value) => [...prefix, value]),
          );

const floorDivide = (numerator: bigint, denominator: bigint): bigint =>
    numerator >= 0n
        ? numerator / denominator
        : -((-numerator + denominator - 1n) / denominator);

// The nearest integer to value / modulus; an odd modulus leaves no ties.
const nearestQuotient = (value: bigint, modulus: bigint): bigint =>
    floorDivide(2n * value + modulus, 2n * modulus);

// A product in Z[X]/(X^N + 1), where X^N wraps to -1.
const negacyclicProduct = (
    left: readonly bigint[],
    right: readonly bigint[],
): bigint[] =>
    left.map((_unused, index) => {
        let coefficient = 0n;
        left.forEach((leftValue, leftIndex) => {
            const rightIndex = index - leftIndex;
            coefficient +=
                rightIndex >= 0
                    ? leftValue * right[rightIndex]
                    : -leftValue * right[rightIndex + right.length];
        });
        return coefficient;
    });

// The model's reduced-ring execution: one key and one two-component
// ciphertext per recipient over degree four, from the same deterministic
// inputs. A centered value v - Q*round(v/Q) makes each integer quotient
// -round(v/Q) for the uncentered v, so no numerator is divided here.
const toyRingDegree = 4;
const toySmall = (seed: number): bigint[] =>
    Array.from({ length: toyRingDegree }, (_unused, index) =>
        BigInt(((seed * 17 + index * 11) % 3) - 1),
    );
const toyQuotients = (
    modulus: bigint,
    encodingScale: bigint,
    recipientCount: number,
): bigint[] => {
    const centered = (value: bigint): bigint =>
        value - modulus * nearestQuotient(value, modulus);
    const quotients: bigint[] = [];
    for (let recipient = 0; recipient < recipientCount; recipient += 1) {
        const seed = 100 + recipient;
        const commonA = Array.from(
            { length: toyRingDegree },
            (_unused, index) =>
                centered(
                    BigInt(((seed + index * 3) % 5) - 2) * (modulus / 5n) +
                        BigInt(seed * 65_537 + index * 104_729),
                ),
        );
        const keyError = toySmall(300 + recipient);
        const keyValue = negacyclicProduct(
            commonA,
            toySmall(200 + recipient),
        ).map((value, index) => -value + keyError[index]);
        const publicKey = keyValue.map(centered);
        const coins = toySmall(400 + recipient);
        const firstError = toySmall(500 + recipient);
        const secondError = toySmall(600 + recipient);
        const firstValue = negacyclicProduct(publicKey, coins).map(
            (value, index) =>
                value +
                firstError[index] +
                encodingScale * BigInt((recipient + 1) * (index + 2) - 17),
        );
        const secondValue = negacyclicProduct(commonA, coins).map(
            (value, index) => value + secondError[index],
        );
        for (const value of [...keyValue, ...firstValue, ...secondValue]) {
            quotients.push(-nearestQuotient(value, modulus));
        }
    }
    return quotients;
};

describe('share-encryption cross-modulus model', () => {
    it('attains the centered key-equation numerator bound exactly over a small odd modulus', () => {
        // Every centered public pair modulo 5 and every ternary witness pair
        // over Z[X]/(X^2 + 1), for the integer numerator pk + a*s - e.
        const modulus = 5n;
        const ringDegree = 2;
        const centeredVectors = vectorsOver([-2n, -1n, 0n, 1n, 2n], ringDegree);
        const ternaryVectors = vectorsOver([-1n, 0n, 1n], ringDegree);
        let maximumNumeratorMagnitude = 0n;
        for (const commonA of centeredVectors) {
            for (const secret of ternaryVectors) {
                const product = negacyclicProduct(commonA, secret);
                for (const publicKey of centeredVectors) {
                    for (const error of ternaryVectors) {
                        for (let index = 0; index < ringDegree; index += 1) {
                            const numerator =
                                publicKey[index] +
                                product[index] -
                                error[index];
                            const magnitude =
                                numerator < 0n ? -numerator : numerator;
                            if (magnitude > maximumNumeratorMagnitude) {
                                maximumNumeratorMagnitude = magnitude;
                            }
                        }
                    }
                }
            }
        }
        expect(maximumNumeratorMagnitude).toBe(
            (BigInt(ringDegree) + 1n) * (modulus / 2n) + 1n,
        );
    });

    it('covers exactly the symmetric range with ternary digits of power-of-two weight', () => {
        for (let digitCount = 1; digitCount <= 6; digitCount += 1) {
            const reachable = new Set(
                vectorsOver([-1n, 0n, 1n], digitCount).map((digits) =>
                    digits.reduce(
                        (sum, digit, position) =>
                            sum + digit * (1n << BigInt(position)),
                        0n,
                    ),
                ),
            );
            // Every sum lies in [-(2^L - 1), 2^L - 1], so this many distinct
            // sums fill the whole interval.
            const limit = (1n << BigInt(digitCount)) - 1n;
            expect(reachable.size).toBe(Number(2n * limit + 1n));
        }
    });

    it('rejects a changed residue and a quotient beyond its bound', () => {
        // The check is generic, so a small composite odd modulus shaped like a
        // plaintext prime times an encoding scale stands in for Q.
        const shareEncryptionModulus = 17n * 97n;
        const maximumQuotientBound = 5n;
        expect(
            verifyExactQuotients(
                [
                    maximumQuotientBound * shareEncryptionModulus,
                    -maximumQuotientBound * shareEncryptionModulus,
                    0n,
                ],
                shareEncryptionModulus,
                maximumQuotientBound,
            ),
        ).toBe(maximumQuotientBound);
        for (const changedNumerator of [
            maximumQuotientBound * shareEncryptionModulus + 1n,
            -1n,
        ]) {
            expect(() =>
                verifyExactQuotients(
                    [changedNumerator],
                    shareEncryptionModulus,
                    maximumQuotientBound,
                ),
            ).toThrow('A cross-modulus equation has no integer quotient.');
        }
        for (const excessiveQuotient of [
            maximumQuotientBound + 1n,
            -maximumQuotientBound - 1n,
        ]) {
            expect(() =>
                verifyExactQuotients(
                    [excessiveQuotient * shareEncryptionModulus],
                    shareEncryptionModulus,
                    maximumQuotientBound,
                ),
            ).toThrow('A cross-modulus quotient exceeds its bound.');
        }
    });

    it('derives every bound and count from the pinned moduli and an independent toy execution', () => {
        const sharing = compileBoundedIntegerSharingPrivacyCensus();
        const fieldModulus = compileCandidateSetupProofFieldCensus().modulus;
        const encodingScale =
            publicEncryptedSharingModelConstants.productionShareEncodingScale;
        const ringDegree = candidateBgvParameterInputs.polynomialModulusDegree;
        const participantCount = BigInt(
            candidateBgvParameterInputs.participantCount,
        );
        // Release needs max(f + 1, 2) shares for f = floor((n - 1) / 3), so
        // the sharing polynomial has one fewer nonconstant coefficient.
        const releaseThreshold = (participantCount - 1n) / 3n + 1n;
        const sharingPolynomialDegree =
            (releaseThreshold > 2n ? releaseThreshold : 2n) - 1n;
        // The share-encryption modulus is the plaintext modulus times the
        // encoding scale, so a scaled share decodes exactly.
        const shareEncryptionModulus =
            sharing.sharePlaintextModulus * encodingScale;
        expect(sharing.shareEncryptionModulus).toBe(shareEncryptionModulus);
        // A share is a ternary secret plus f coefficients of magnitude at most
        // R, each moved by a monomial evaluation point without growth.
        const shareCoefficientBound =
            1n + sharingPolynomialDegree * sharing.coefficientSamplingBound;
        expect(sharing.perContributionShareCoefficientBound).toBe(
            shareCoefficientBound,
        );

        // pk + a*s - e and c1 - a*u - e2 add N + 1 centered public terms and
        // one ternary error; c0 - pk*u - e1 - scale*m also adds the share.
        const keyNumeratorBound =
            (ringDegree + 1n) * (shareEncryptionModulus / 2n) + 1n;
        const firstNumeratorBound =
            keyNumeratorBound + encodingScale * shareCoefficientBound;
        // Each quotient bound is the least B with B*Q at or above its numerator
        // bound. With Q far above N and the share term below Q/2, that is
        // N/2 + 1 for every equation.
        const quotientBound = ringDegree / 2n + 1n;
        for (const numeratorBound of [keyNumeratorBound, firstNumeratorBound]) {
            expect(
                quotientBound * shareEncryptionModulus,
            ).toBeGreaterThanOrEqual(numeratorBound);
            expect((quotientBound - 1n) * shareEncryptionModulus).toBeLessThan(
                numeratorBound,
            );
        }
        const maximumEmbeddedEquationMagnitude =
            firstNumeratorBound + shareEncryptionModulus * quotientBound;
        // Every prime with b bits is at least 2^(b - 1), so the least safe b
        // is the first with 2^(b - 1) above the embedded magnitude.
        let minimumProofFieldElementBitLength = 1n;
        while (
            1n << (minimumProofFieldElementBitLength - 1n) <=
            maximumEmbeddedEquationMagnitude
        ) {
            minimumProofFieldElementBitLength += 1n;
        }
        // L ternary digits of power-of-two weight reach +-(2^L - 1).
        let quotientDigitCount = 0n;
        while ((1n << quotientDigitCount) - 1n < quotientBound) {
            quotientDigitCount += 1n;
        }
        // The centered interval [-B, B] has 2B + 1 values.
        let quotientSignedEncodingBitLength = 0n;
        while (
            1n << quotientSignedEncodingBitLength <
            2n * quotientBound + 1n
        ) {
            quotientSignedEncodingBitLength += 1n;
        }
        // One quotient for the share-encryption key and one for each
        // component of each recipient ciphertext.
        const quotientRingElementCount = 1n + participantCount * 2n;

        // The candidate field dominates the embedded equations and the BGV
        // ciphertext modulus. A malicious quotient anywhere in the digit
        // range still stays below the same bit floor.
        expect(fieldModulus).toBeGreaterThan(maximumEmbeddedEquationMagnitude);
        expect(fieldModulus).toBeGreaterThan(
            candidateBgvParameterInputs.ciphertextModulusPrimeFactors.reduce(
                (product, prime) => product * prime,
                1n,
            ),
        );
        expect(
            firstNumeratorBound +
                shareEncryptionModulus * ((1n << quotientDigitCount) - 1n),
        ).toBeLessThan(1n << (minimumProofFieldElementBitLength - 1n));

        const quotients = toyQuotients(
            shareEncryptionModulus,
            encodingScale,
            candidateBgvParameterInputs.participantCount,
        );
        const toyMaximumObservedQuotientMagnitude = quotients.reduce(
            (maximum, quotient) => {
                const magnitude = quotient < 0n ? -quotient : quotient;
                return magnitude > maximum ? magnitude : maximum;
            },
            0n,
        );
        // Some toy equation wraps modulo Q, so its quotient witness is used.
        expect(toyMaximumObservedQuotientMagnitude).toBeGreaterThan(0n);

        expect(compileShareEncryptionCrossModulusCensus()).toEqual({
            candidateProofFieldElementBitLength: binaryDigitCount(fieldModulus),
            ciphertextFirstQuotientBound: quotientBound,
            ciphertextSecondQuotientBound: quotientBound,
            maximumEmbeddedEquationMagnitude,
            maximumQuotientBound: quotientBound,
            minimumProofFieldElementBitLength,
            perContributionShareCoefficientBound: shareCoefficientBound,
            quotientNormDecompositionLength: quotientDigitCount,
            quotientSignedEncodingBitLength,
            quotientNormDigitRingElementCountPerContributor:
                quotientRingElementCount * quotientDigitCount,
            quotientRingElementCountPerContributor: quotientRingElementCount,
            shareEncryptionKeyQuotientBound: quotientBound,
            shareEncryptionModulus,
            toyCoefficientEquationCount: quotients.length,
            toyMaximumObservedQuotientMagnitude,
            // A multiple of Q plus one is never a multiple of Q.
            toyTamperRejected: true,
        });
    });
});
