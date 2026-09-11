import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { compileCandidateBgvParameterCensus } from '#tests/candidate-bgv-parameter-model.js';
import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';

const toyRingDegree = 4;
const shareEncryptionEquationCountPerCiphertext = 2n;
const shareEncryptionKeyEquationCountPerContributor = 1n;

type RingElement = readonly bigint[];

const absolute = (value: bigint): bigint => (value < 0n ? -value : value);
const maximum = (...values: readonly bigint[]): bigint =>
    values.reduce((result, value) => (result > value ? result : value), 0n);
const ceilingDivide = (numerator: bigint, denominator: bigint): bigint =>
    (numerator + denominator - 1n) / denominator;
const bitLength = (value: bigint): bigint =>
    BigInt(absolute(value).toString(2).length);
const modulo = (value: bigint, modulus: bigint): bigint => {
    const remainder = value % modulus;
    return remainder < 0n ? remainder + modulus : remainder;
};
const centered = (value: bigint, modulus: bigint): bigint => {
    const residue = modulo(value, modulus);
    return residue > modulus / 2n ? residue - modulus : residue;
};
const add = (left: RingElement, right: RingElement): bigint[] =>
    left.map((value, index) => value + (right[index] ?? 0n));
const subtract = (left: RingElement, right: RingElement): bigint[] =>
    left.map((value, index) => value - (right[index] ?? 0n));
const scale = (value: RingElement, scalar: bigint): bigint[] =>
    value.map((coefficient) => coefficient * scalar);
const multiply = (left: RingElement, right: RingElement): bigint[] => {
    const result = Array.from({ length: left.length }, () => 0n);
    for (let leftIndex = 0; leftIndex < left.length; leftIndex += 1) {
        for (let rightIndex = 0; rightIndex < right.length; rightIndex += 1) {
            const rawIndex = leftIndex + rightIndex;
            const wraps = rawIndex >= left.length;
            const index = wraps ? rawIndex - left.length : rawIndex;
            const product = (left[leftIndex] ?? 0n) * (right[rightIndex] ?? 0n);
            result[index] =
                (result[index] ?? 0n) + (wraps ? -product : product);
        }
    }
    return result;
};
const centerRing = (value: RingElement, modulus: bigint): bigint[] =>
    value.map((coefficient) => centered(coefficient, modulus));
const deterministicTernary = (seed: number): bigint[] =>
    Array.from({ length: toyRingDegree }, (_unused, index) =>
        BigInt(((seed * 17 + index * 11) % 3) - 1),
    );
const deterministicPublic = (seed: number, modulus: bigint): bigint[] =>
    Array.from({ length: toyRingDegree }, (_unused, index) =>
        centered(
            BigInt(((seed + index * 3) % 5) - 2) * (modulus / 5n) +
                BigInt(seed * 65_537 + index * 104_729),
            modulus,
        ),
    );

const verifyExactQuotients = (
    numerator: RingElement,
    modulus: bigint,
    quotientBound: bigint,
): bigint => {
    let observedMaximum = 0n;
    for (const coefficient of numerator) {
        if (coefficient % modulus !== 0n) {
            throw new Error(
                'A cross-modulus equation has no integer quotient.',
            );
        }
        const quotient = coefficient / modulus;
        if (absolute(quotient) > quotientBound) {
            throw new Error('A cross-modulus quotient exceeds its bound.');
        }
        observedMaximum = maximum(observedMaximum, absolute(quotient));
    }
    return observedMaximum;
};

export type ShareEncryptionCrossModulusCensus = Readonly<{
    candidateProofFieldElementBitLength: bigint;
    ciphertextFirstQuotientBound: bigint;
    ciphertextSecondQuotientBound: bigint;
    maximumEmbeddedEquationMagnitude: bigint;
    maximumQuotientBound: bigint;
    minimumProofFieldElementBitLength: bigint;
    perContributionShareCoefficientBound: bigint;
    quotientNormDecompositionLength: bigint;
    quotientSignedEncodingBitLength: bigint;
    quotientNormDigitRingElementCountPerContributor: bigint;
    quotientRingElementCountPerContributor: bigint;
    shareEncryptionKeyQuotientBound: bigint;
    shareEncryptionModulus: bigint;
    toyCoefficientEquationCount: number;
    toyMaximumObservedQuotientMagnitude: bigint;
    toyTamperRejected: boolean;
}>;

export const compileShareEncryptionCrossModulusCensus =
    (): ShareEncryptionCrossModulusCensus => {
        const sharing = compileBoundedIntegerSharingPrivacyCensus();
        const candidateBgv = compileCandidateBgvParameterCensus();
        const setupProofField = compileCandidateSetupProofFieldCensus();
        const ringDegree =
            publicEncryptedSharingModelConstants.productionPolynomialModulusDegree;
        const participantCount =
            publicEncryptedSharingModelConstants.productionParticipantCount;
        const encodingScale =
            publicEncryptedSharingModelConstants.productionShareEncodingScale;
        const shareEncryptionModulus = sharing.shareEncryptionModulus;
        const centeredPublicCoefficientBound =
            (shareEncryptionModulus - 1n) / 2n;
        const shareEncryptionKeyNumeratorBound =
            (ringDegree + 1n) * centeredPublicCoefficientBound + 1n;
        const ciphertextSecondNumeratorBound = shareEncryptionKeyNumeratorBound;
        const ciphertextFirstNumeratorBound =
            shareEncryptionKeyNumeratorBound +
            encodingScale * sharing.perContributionShareCoefficientBound;
        const shareEncryptionKeyQuotientBound = ceilingDivide(
            shareEncryptionKeyNumeratorBound,
            shareEncryptionModulus,
        );
        const ciphertextSecondQuotientBound = ceilingDivide(
            ciphertextSecondNumeratorBound,
            shareEncryptionModulus,
        );
        const ciphertextFirstQuotientBound = ceilingDivide(
            ciphertextFirstNumeratorBound,
            shareEncryptionModulus,
        );
        const maximumQuotientBound = maximum(
            shareEncryptionKeyQuotientBound,
            ciphertextFirstQuotientBound,
            ciphertextSecondQuotientBound,
        );
        const maximumEmbeddedEquationMagnitude = maximum(
            shareEncryptionKeyNumeratorBound +
                shareEncryptionModulus * shareEncryptionKeyQuotientBound,
            ciphertextFirstNumeratorBound +
                shareEncryptionModulus * ciphertextFirstQuotientBound,
            ciphertextSecondNumeratorBound +
                shareEncryptionModulus * ciphertextSecondQuotientBound,
        );
        const minimumProofFieldElementBitLength =
            bitLength(maximumEmbeddedEquationMagnitude) + 1n;
        const candidateProofFieldElementBitLength =
            setupProofField.modulusBitLength;
        if (
            setupProofField.modulus <= maximumEmbeddedEquationMagnitude ||
            setupProofField.modulus <= candidateBgv.ciphertextModulus
        ) {
            throw new Error(
                'The candidate proof field does not dominate both embedded moduli.',
            );
        }
        if (
            candidateProofFieldElementBitLength <
            minimumProofFieldElementBitLength
        ) {
            throw new Error(
                'The candidate proof field can wrap a cross-modulus equation.',
            );
        }
        const quotientRingElementCountPerContributor =
            shareEncryptionKeyEquationCountPerContributor +
            participantCount * shareEncryptionEquationCountPerCiphertext;
        const quotientNormDecompositionLength = bitLength(maximumQuotientBound);
        // A norm decomposition counts ternary digits, not serialized bits.
        // The centered interval has 2B+1 values and needs ceil(log2(2B+1)) bits.
        const quotientSignedEncodingBitLength = bitLength(
            2n * maximumQuotientBound,
        );
        const quotientNormDigitRingElementCountPerContributor =
            quotientRingElementCountPerContributor *
            quotientNormDecompositionLength;

        const recipientKeys = Array.from(
            { length: Number(participantCount) },
            (_unused, recipient) => {
                const commonA = deterministicPublic(
                    100 + recipient,
                    shareEncryptionModulus,
                );
                const secret = deterministicTernary(200 + recipient);
                const error = deterministicTernary(300 + recipient);
                const publicKey = centerRing(
                    add(scale(multiply(commonA, secret), -1n), error),
                    shareEncryptionModulus,
                );
                return { commonA, error, publicKey, secret };
            },
        );
        let toyCoefficientEquationCount = 0;
        let toyMaximumObservedQuotientMagnitude = 0n;
        for (const { commonA, error, publicKey, secret } of recipientKeys) {
            toyMaximumObservedQuotientMagnitude = maximum(
                toyMaximumObservedQuotientMagnitude,
                verifyExactQuotients(
                    subtract(add(publicKey, multiply(commonA, secret)), error),
                    shareEncryptionModulus,
                    shareEncryptionKeyQuotientBound,
                ),
            );
            toyCoefficientEquationCount += toyRingDegree;
        }

        let firstCiphertextNumerator: bigint[] | undefined;
        for (
            let recipient = 0;
            recipient < recipientKeys.length;
            recipient += 1
        ) {
            const key = recipientKeys[recipient];
            if (key === undefined)
                throw new Error('A recipient key is absent.');
            const coins = deterministicTernary(400 + recipient);
            const firstError = deterministicTernary(500 + recipient);
            const secondError = deterministicTernary(600 + recipient);
            const message = Array.from(
                { length: toyRingDegree },
                (_unused, index) => BigInt((recipient + 1) * (index + 2) - 17),
            );
            const first = centerRing(
                add(
                    add(multiply(key.publicKey, coins), firstError),
                    scale(message, encodingScale),
                ),
                shareEncryptionModulus,
            );
            const second = centerRing(
                add(multiply(key.commonA, coins), secondError),
                shareEncryptionModulus,
            );
            const firstNumerator = subtract(
                subtract(
                    subtract(first, multiply(key.publicKey, coins)),
                    firstError,
                ),
                scale(message, encodingScale),
            );
            firstCiphertextNumerator ??= firstNumerator;
            toyMaximumObservedQuotientMagnitude = maximum(
                toyMaximumObservedQuotientMagnitude,
                verifyExactQuotients(
                    firstNumerator,
                    shareEncryptionModulus,
                    ciphertextFirstQuotientBound,
                ),
                verifyExactQuotients(
                    subtract(
                        subtract(second, multiply(key.commonA, coins)),
                        secondError,
                    ),
                    shareEncryptionModulus,
                    ciphertextSecondQuotientBound,
                ),
            );
            toyCoefficientEquationCount += 2 * toyRingDegree;
        }
        if (firstCiphertextNumerator === undefined) {
            throw new Error('No share ciphertext equation was tested.');
        }
        const tamperedNumerator = firstCiphertextNumerator.map(
            (value, index) => (index === 0 ? value + 1n : value),
        );
        const toyTamperRejected = tamperedNumerator.some(
            (coefficient) => coefficient % shareEncryptionModulus !== 0n,
        );
        if (!toyTamperRejected) {
            throw new Error(
                'A changed public ciphertext retained its quotient.',
            );
        }

        return {
            candidateProofFieldElementBitLength,
            ciphertextFirstQuotientBound,
            ciphertextSecondQuotientBound,
            maximumEmbeddedEquationMagnitude,
            maximumQuotientBound,
            minimumProofFieldElementBitLength,
            perContributionShareCoefficientBound:
                sharing.perContributionShareCoefficientBound,
            quotientNormDecompositionLength,
            quotientSignedEncodingBitLength,
            quotientNormDigitRingElementCountPerContributor,
            quotientRingElementCountPerContributor,
            shareEncryptionKeyQuotientBound,
            shareEncryptionModulus,
            toyCoefficientEquationCount,
            toyMaximumObservedQuotientMagnitude,
            toyTamperRejected,
        };
    };
