import type { FieldElement, FieldElementEncoding } from '@sealed-lattice/types';

export const fieldModulus = 65_537;
export const maximumCanonicalFieldElement = fieldModulus - 1;
export const fieldElementByteLength = 3;

const lowercaseHexBytePattern = /^[0-9a-f]{6}$/u;

export const isCanonicalFieldElement = (value: number): value is FieldElement =>
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value < fieldModulus &&
    !Object.is(value, -0);

export const assertCanonicalFieldElement = (
    value: number,
    fieldName = 'field element',
): FieldElement => {
    if (!isCanonicalFieldElement(value)) {
        throw new RangeError(
            `${fieldName} must be an integer in 0..${String(maximumCanonicalFieldElement)}.`,
        );
    }

    return value;
};

export const normalizeFieldElement = (value: number): FieldElement => {
    if (!Number.isSafeInteger(value)) {
        throw new RangeError('Field elements must be derived from integers.');
    }

    const integerValue = Object.is(value, -0) ? 0 : value;

    return ((integerValue % fieldModulus) + fieldModulus) % fieldModulus;
};

export const centeredFieldElement = (value: FieldElement): number => {
    const canonicalValue = assertCanonicalFieldElement(value);
    const midpoint = (fieldModulus - 1) / 2;

    return canonicalValue > midpoint
        ? canonicalValue - fieldModulus
        : canonicalValue;
};

export const encodeFieldElement = (value: FieldElement): string => {
    const canonicalValue = assertCanonicalFieldElement(value);
    const firstByte = (canonicalValue >> 16) & 0xff;
    const secondByte = (canonicalValue >> 8) & 0xff;
    const thirdByte = canonicalValue & 0xff;

    return [firstByte, secondByte, thirdByte]
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
};

export const decodeFieldElement = (bytesHex: string): FieldElement => {
    if (!lowercaseHexBytePattern.test(bytesHex)) {
        throw new RangeError(
            'Field element encoding must be exactly three lowercase hex bytes.',
        );
    }

    const value = Number.parseInt(bytesHex, 16);

    return assertCanonicalFieldElement(value, 'encoded field element');
};

export const describeFieldElement = (
    value: FieldElement,
): FieldElementEncoding => {
    const canonicalValue = assertCanonicalFieldElement(value);

    return {
        bytesHex: encodeFieldElement(canonicalValue),
        centeredValue: centeredFieldElement(canonicalValue),
        value: canonicalValue,
    };
};

export const addFieldElements = (
    left: FieldElement,
    right: FieldElement,
): FieldElement =>
    normalizeFieldElement(
        assertCanonicalFieldElement(left, 'left field element') +
            assertCanonicalFieldElement(right, 'right field element'),
    );

export const subtractFieldElements = (
    left: FieldElement,
    right: FieldElement,
): FieldElement =>
    normalizeFieldElement(
        assertCanonicalFieldElement(left, 'left field element') -
            assertCanonicalFieldElement(right, 'right field element'),
    );

export const negateFieldElement = (value: FieldElement): FieldElement =>
    normalizeFieldElement(-assertCanonicalFieldElement(value));

export const multiplyFieldElements = (
    left: FieldElement,
    right: FieldElement,
): FieldElement =>
    normalizeFieldElement(
        assertCanonicalFieldElement(left, 'left field element') *
            assertCanonicalFieldElement(right, 'right field element'),
    );

export const exponentiateFieldElement = (
    base: FieldElement,
    exponent: number,
): FieldElement => {
    if (!Number.isInteger(exponent) || exponent < 0) {
        throw new RangeError('Field exponent must be a non-negative integer.');
    }

    let remainingExponent = exponent;
    let accumulatedValue: FieldElement = 1;
    let currentBase = assertCanonicalFieldElement(base, 'base field element');

    while (remainingExponent > 0) {
        if (remainingExponent % 2 === 1) {
            accumulatedValue = multiplyFieldElements(
                accumulatedValue,
                currentBase,
            );
        }
        currentBase = multiplyFieldElements(currentBase, currentBase);
        remainingExponent = Math.floor(remainingExponent / 2);
    }

    return accumulatedValue;
};

export const invertFieldElement = (value: FieldElement): FieldElement => {
    const canonicalValue = assertCanonicalFieldElement(value);
    if (canonicalValue === 0) {
        throw new RangeError('Zero has no inverse in GF(65537).');
    }

    let previousCoefficient = 0;
    let currentCoefficient = 1;
    let previousRemainder = fieldModulus;
    let currentRemainder = canonicalValue;

    while (currentRemainder !== 0) {
        const quotient = Math.floor(previousRemainder / currentRemainder);
        const nextCoefficient =
            previousCoefficient - quotient * currentCoefficient;
        const nextRemainder = previousRemainder - quotient * currentRemainder;

        previousCoefficient = currentCoefficient;
        currentCoefficient = nextCoefficient;
        previousRemainder = currentRemainder;
        currentRemainder = nextRemainder;
    }

    return normalizeFieldElement(previousCoefficient);
};

export const divideFieldElements = (
    numerator: FieldElement,
    denominator: FieldElement,
): FieldElement =>
    multiplyFieldElements(
        assertCanonicalFieldElement(numerator, 'field numerator'),
        invertFieldElement(
            assertCanonicalFieldElement(denominator, 'field denominator'),
        ),
    );

export const sumFieldElements = (
    values: readonly FieldElement[],
): FieldElement =>
    values.reduce<FieldElement>(
        (sum, value) => addFieldElements(sum, value),
        0,
    );
