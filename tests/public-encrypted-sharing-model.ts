import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';

const productionPolynomialModulusDegree =
    candidateBgvParameterInputs.polynomialModulusDegree;
const productionParticipantCount = BigInt(
    candidateBgvParameterInputs.participantCount,
);
const maximumSmallCoefficientMagnitude = 1n;

const modulo = (value: bigint, modulus: bigint): bigint => {
    const remainder = value % modulus;
    return remainder < 0n ? remainder + modulus : remainder;
};

const exponentiate = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    let factor = modulo(base, modulus);
    let remaining = exponent;
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) {
            result = modulo(result * factor, modulus);
        }
        factor = modulo(factor * factor, modulus);
        remaining >>= 1n;
    }
    return result;
};

const inverse = (value: bigint, primeModulus: bigint): bigint =>
    exponentiate(value, primeModulus - 2n, primeModulus);

const isPrime = (candidate: bigint): boolean => {
    if (candidate < 2n) return false;
    if (candidate % 2n === 0n) return candidate === 2n;
    for (let divisor = 3n; divisor * divisor <= candidate; divisor += 2n) {
        if (candidate % divisor === 0n) return false;
    }
    return true;
};

const productionSingleCiphertextNoiseCoefficientBound =
    2n *
        productionPolynomialModulusDegree *
        maximumSmallCoefficientMagnitude ** 2n +
    maximumSmallCoefficientMagnitude;
const productionAggregateNoiseCoefficientBound =
    productionParticipantCount *
    productionSingleCiphertextNoiseCoefficientBound;
const findFirstTransformPrimeAbove = (
    lowerBound: bigint,
    transformOrder: bigint,
): bigint => {
    let candidate =
        ((lowerBound + transformOrder - 1n) / transformOrder) * transformOrder +
        1n;
    while (!isPrime(candidate)) candidate += transformOrder;
    return candidate;
};
const productionShareEncodingScale = findFirstTransformPrimeAbove(
    2n * productionAggregateNoiseCoefficientBound,
    2n * productionPolynomialModulusDegree,
);
const productionShareEncodingScaleBitLength = BigInt(
    productionShareEncodingScale.toString(2).length,
);

export const publicEncryptedSharingModelConstants = {
    maximumSmallCoefficientMagnitude,
    productionAggregateNoiseCoefficientBound,
    productionParticipantCount,
    productionPolynomialModulusDegree,
    productionShareEncodingScale,
    productionShareEncodingScaleBitLength,
    productionSingleCiphertextNoiseCoefficientBound,
} as const;

type RingElement = readonly bigint[];
type Ciphertext = Readonly<{
    first: RingElement;
    second: RingElement;
}>;

const ringAdd = (
    left: RingElement,
    right: RingElement,
    modulus: bigint,
): bigint[] =>
    left.map((value, index) => modulo(value + (right[index] ?? 0n), modulus));

const ringMultiply = (
    left: RingElement,
    right: RingElement,
    modulus: bigint,
): bigint[] => {
    if (left.length !== right.length) {
        throw new RangeError('Ring operands have different degrees.');
    }
    const result = Array.from({ length: left.length }, () => 0n);
    for (let leftIndex = 0; leftIndex < left.length; leftIndex += 1) {
        for (let rightIndex = 0; rightIndex < right.length; rightIndex += 1) {
            const rawIndex = leftIndex + rightIndex;
            const wraps = rawIndex >= left.length;
            const index = wraps ? rawIndex - left.length : rawIndex;
            const product = (left[leftIndex] ?? 0n) * (right[rightIndex] ?? 0n);
            result[index] = modulo(
                (result[index] ?? 0n) + (wraps ? -product : product),
                modulus,
            );
        }
    }
    return result;
};

const scaleRing = (
    value: RingElement,
    scalar: bigint,
    modulus: bigint,
): bigint[] =>
    value.map((coefficient) => modulo(coefficient * scalar, modulus));

const deterministicTernary = (seed: number, length: number): bigint[] =>
    Array.from({ length }, (_unused, index) =>
        BigInt(((seed * 17 + index * 11) % 3) - 1),
    );

const evaluateSharingPolynomial = (
    coefficients: readonly RingElement[],
    point: bigint,
    modulus: bigint,
): bigint[] => {
    const result = Array.from(
        { length: coefficients[0]?.length ?? 0 },
        () => 0n,
    );
    for (let index = coefficients.length - 1; index >= 0; index -= 1) {
        for (
            let coefficient = 0;
            coefficient < result.length;
            coefficient += 1
        ) {
            result[coefficient] = modulo(
                (result[coefficient] ?? 0n) * point +
                    (coefficients[index]?.[coefficient] ?? 0n),
                modulus,
            );
        }
    }
    return result;
};

const encryptShare = (
    publicKey: RingElement,
    commonA: RingElement,
    share: RingElement,
    encryptionCoins: RingElement,
    firstError: RingElement,
    secondError: RingElement,
    encodingScale: bigint,
    ciphertextModulus: bigint,
): Ciphertext => ({
    first: ringAdd(
        ringAdd(
            ringMultiply(publicKey, encryptionCoins, ciphertextModulus),
            firstError,
            ciphertextModulus,
        ),
        scaleRing(share, encodingScale, ciphertextModulus),
        ciphertextModulus,
    ),
    second: ringAdd(
        ringMultiply(commonA, encryptionCoins, ciphertextModulus),
        secondError,
        ciphertextModulus,
    ),
});

const decryptShare = (
    ciphertext: Ciphertext,
    secretKey: RingElement,
    plaintextModulus: bigint,
    encodingScale: bigint,
    ciphertextModulus: bigint,
): bigint[] =>
    ringAdd(
        ciphertext.first,
        ringMultiply(ciphertext.second, secretKey, ciphertextModulus),
        ciphertextModulus,
    ).map(
        (coefficient) =>
            ((coefficient + encodingScale / 2n) / encodingScale) %
            plaintextModulus,
    );

const combinations = (
    values: readonly number[],
    size: number,
): readonly (readonly number[])[] => {
    const result: number[][] = [];
    const choose = (offset: number, selected: number[]): void => {
        if (selected.length === size) {
            result.push([...selected]);
            return;
        }
        for (
            let index = offset;
            index <= values.length - (size - selected.length);
            index += 1
        ) {
            choose(index + 1, [...selected, values[index] ?? -1]);
        }
    };
    choose(0, []);
    return result;
};

const reconstructAtZero = (
    shares: readonly Readonly<{ point: bigint; value: RingElement }>[],
    modulus: bigint,
): bigint[] => {
    const result = Array.from(
        { length: shares[0]?.value.length ?? 0 },
        () => 0n,
    );
    for (const share of shares) {
        let numerator = 1n;
        let denominator = 1n;
        for (const other of shares) {
            if (other.point === share.point) continue;
            numerator = modulo(numerator * -other.point, modulus);
            denominator = modulo(
                denominator * (share.point - other.point),
                modulus,
            );
        }
        const weight = modulo(
            numerator * inverse(denominator, modulus),
            modulus,
        );
        for (let index = 0; index < result.length; index += 1) {
            result[index] = modulo(
                (result[index] ?? 0n) + weight * (share.value[index] ?? 0n),
                modulus,
            );
        }
    }
    return result;
};

export type PublicEncryptedSharingCensus = Readonly<{
    aggregateCiphertextsChecked: number;
    authorizedReconstructionSubsetsChecked: number;
    contributorRecipientCiphertextsChecked: number;
    productionAggregateNoiseCoefficientBound: bigint;
    productionShareEncodingScale: bigint;
    productionShareEncodingScaleBitLength: bigint;
    productionSingleCiphertextNoiseCoefficientBound: bigint;
    tamperedCiphertextChangedShare: boolean;
    toyRingDegree: number;
}>;

export const verifyPublicEncryptedSharingModel =
    (): PublicEncryptedSharingCensus => {
        if (
            !isPrime(productionShareEncodingScale) ||
            (productionShareEncodingScale - 1n) %
                (2n * productionPolynomialModulusDegree) !==
                0n ||
            productionShareEncodingScale <=
                2n * productionAggregateNoiseCoefficientBound
        ) {
            throw new Error('The production share scale fails its exact gate.');
        }

        const participantCount = 10;
        const threshold = 4;
        const ringDegree = 4;
        const plaintextModulus = 65_537n;
        const encodingScale = productionShareEncodingScale;
        const ciphertextModulus = plaintextModulus * encodingScale;
        const commonA = [12_345n, 23_456n, 34_567n, 45_678n];

        const recipientSecrets = Array.from(
            { length: participantCount },
            (_unused, recipient) =>
                deterministicTernary(100 + recipient, ringDegree),
        );
        const recipientPublicKeys = recipientSecrets.map(
            (secretKey, recipient) =>
                ringAdd(
                    scaleRing(
                        ringMultiply(commonA, secretKey, ciphertextModulus),
                        -1n,
                        ciphertextModulus,
                    ),
                    deterministicTernary(200 + recipient, ringDegree),
                    ciphertextModulus,
                ),
        );

        const sharingPolynomials = Array.from(
            { length: participantCount },
            (_unused, contributor) =>
                Array.from({ length: threshold }, (_unused2, degree) =>
                    degree === 0
                        ? deterministicTernary(300 + contributor, ringDegree)
                        : Array.from(
                              { length: ringDegree },
                              (_unused3, index) =>
                                  BigInt(
                                      (contributor * 1_009 +
                                          degree * 313 +
                                          index * 37) %
                                          Number(plaintextModulus),
                                  ),
                          ),
                ),
        );
        const aggregateSecret = sharingPolynomials.reduce(
            (sum, polynomial) =>
                ringAdd(sum, polynomial[0] ?? [], plaintextModulus),
            Array.from({ length: ringDegree }, () => 0n),
        );

        const aggregateCiphertexts = Array.from(
            { length: participantCount },
            () => ({
                first: Array.from({ length: ringDegree }, () => 0n),
                second: Array.from({ length: ringDegree }, () => 0n),
            }),
        );
        let contributorRecipientCiphertextsChecked = 0;
        for (
            let contributor = 0;
            contributor < participantCount;
            contributor += 1
        ) {
            for (
                let recipient = 0;
                recipient < participantCount;
                recipient += 1
            ) {
                const share = evaluateSharingPolynomial(
                    sharingPolynomials[contributor] ?? [],
                    BigInt(recipient + 1),
                    plaintextModulus,
                );
                const ciphertext = encryptShare(
                    recipientPublicKeys[recipient] ?? [],
                    commonA,
                    share,
                    deterministicTernary(
                        400 + contributor * participantCount + recipient,
                        ringDegree,
                    ),
                    deterministicTernary(
                        600 + contributor * participantCount + recipient,
                        ringDegree,
                    ),
                    deterministicTernary(
                        800 + contributor * participantCount + recipient,
                        ringDegree,
                    ),
                    encodingScale,
                    ciphertextModulus,
                );
                const aggregate = aggregateCiphertexts[recipient];
                if (aggregate === undefined) {
                    throw new Error('An aggregate ciphertext is absent.');
                }
                aggregateCiphertexts[recipient] = {
                    first: ringAdd(
                        aggregate.first,
                        ciphertext.first,
                        ciphertextModulus,
                    ),
                    second: ringAdd(
                        aggregate.second,
                        ciphertext.second,
                        ciphertextModulus,
                    ),
                };
                contributorRecipientCiphertextsChecked += 1;
            }
        }

        const aggregateShares = aggregateCiphertexts.map(
            (ciphertext, recipient) => {
                const actual = decryptShare(
                    ciphertext,
                    recipientSecrets[recipient] ?? [],
                    plaintextModulus,
                    encodingScale,
                    ciphertextModulus,
                );
                const expected = sharingPolynomials.reduce(
                    (sum, polynomial) =>
                        ringAdd(
                            sum,
                            evaluateSharingPolynomial(
                                polynomial,
                                BigInt(recipient + 1),
                                plaintextModulus,
                            ),
                            plaintextModulus,
                        ),
                    Array.from({ length: ringDegree }, () => 0n),
                );
                if (actual.some((value, index) => value !== expected[index])) {
                    throw new Error(
                        'An aggregate share decrypted incorrectly.',
                    );
                }
                return actual;
            },
        );

        const firstAggregateCiphertext = aggregateCiphertexts[0];
        if (firstAggregateCiphertext === undefined) {
            throw new Error('The first aggregate ciphertext is absent.');
        }
        const tamperedCiphertext = {
            first: firstAggregateCiphertext.first.map((value, index) =>
                index === 0
                    ? modulo(value + encodingScale, ciphertextModulus)
                    : value,
            ),
            second: firstAggregateCiphertext.second,
        };
        const tamperedShare = decryptShare(
            tamperedCiphertext,
            recipientSecrets[0] ?? [],
            plaintextModulus,
            encodingScale,
            ciphertextModulus,
        );
        const tamperedCiphertextChangedShare = tamperedShare.some(
            (value, index) => value !== aggregateShares[0]?.[index],
        );
        if (!tamperedCiphertextChangedShare) {
            throw new Error('A ciphertext tamper did not change the share.');
        }

        const subsets = combinations(
            Array.from({ length: participantCount }, (_unused, index) => index),
            threshold,
        );
        for (const subset of subsets) {
            const reconstructed = reconstructAtZero(
                subset.map((recipient) => ({
                    point: BigInt(recipient + 1),
                    value: aggregateShares[recipient] ?? [],
                })),
                plaintextModulus,
            );
            if (
                reconstructed.some(
                    (value, index) => value !== aggregateSecret[index],
                )
            ) {
                throw new Error(
                    'An authorized subset reconstructed incorrectly.',
                );
            }
        }

        return {
            aggregateCiphertextsChecked: aggregateCiphertexts.length,
            authorizedReconstructionSubsetsChecked: subsets.length,
            contributorRecipientCiphertextsChecked,
            productionAggregateNoiseCoefficientBound,
            productionShareEncodingScale,
            productionShareEncodingScaleBitLength,
            productionSingleCiphertextNoiseCoefficientBound,
            tamperedCiphertextChangedShare,
            toyRingDegree: ringDegree,
        };
    };
