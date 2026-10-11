const coefficientModulus = 65_537n;
const ringDegree = 8;
const participantCount = 10;
const maximumCorruptParticipantCount = 3;
const releaseThreshold = 4;
const gadgetLength = 3;
const automorphismExponent = 3;

type RingElement = readonly bigint[];
type RingVector = readonly RingElement[];

const modulo = (value: bigint): bigint => {
    const remainder = value % coefficientModulus;
    return remainder < 0n ? remainder + coefficientModulus : remainder;
};

const exponentiate = (base: bigint, exponent: bigint): bigint => {
    let result = 1n;
    let factor = modulo(base);
    let remaining = exponent;
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) result = modulo(result * factor);
        factor = modulo(factor * factor);
        remaining >>= 1n;
    }
    return result;
};

const inverse = (value: bigint): bigint => {
    const normalized = modulo(value);
    if (normalized === 0n) throw new RangeError('Zero has no inverse.');
    return exponentiate(normalized, coefficientModulus - 2n);
};

const ringCoefficient = (value: RingElement, index: number): bigint => {
    const coefficient = value[index];
    if (coefficient === undefined) {
        throw new Error('A ring coefficient is absent.');
    }
    return coefficient;
};

const vectorElement = (value: RingVector, index: number): RingElement => {
    const element = value[index];
    if (element === undefined) {
        throw new Error('A ring-vector element is absent.');
    }
    return element;
};

const createRing = (coefficient: (index: number) => bigint): RingElement =>
    Array.from({ length: ringDegree }, (_unused, index) =>
        modulo(coefficient(index)),
    );

const zero = (): RingElement => createRing(() => 0n);
const one = (): RingElement => createRing((index) => (index === 0 ? 1n : 0n));
const monomial = (exponent: number): RingElement => {
    const reducedExponent = exponent % (2 * ringDegree);
    const coefficientIndex = reducedExponent % ringDegree;
    const sign = reducedExponent >= ringDegree ? -1n : 1n;
    return createRing((index) => (index === coefficientIndex ? sign : 0n));
};
const equal = (left: RingElement, right: RingElement): boolean =>
    left.every(
        (coefficient, index) => coefficient === ringCoefficient(right, index),
    );
const add = (left: RingElement, right: RingElement): RingElement =>
    createRing(
        (index) => ringCoefficient(left, index) + ringCoefficient(right, index),
    );
const negate = (value: RingElement): RingElement =>
    createRing((index) => -ringCoefficient(value, index));
const subtract = (left: RingElement, right: RingElement): RingElement =>
    add(left, negate(right));
const scale = (value: RingElement, scalar: bigint): RingElement =>
    createRing((index) => ringCoefficient(value, index) * modulo(scalar));
const centeredOneNorm = (value: RingElement): bigint =>
    value.reduce((sum, coefficient) => {
        const centered =
            coefficient > coefficientModulus / 2n
                ? coefficient - coefficientModulus
                : coefficient;
        return sum + (centered < 0n ? -centered : centered);
    }, 0n);

const multiply = (left: RingElement, right: RingElement): RingElement => {
    const result = Array.from({ length: ringDegree }, () => 0n);
    for (let leftIndex = 0; leftIndex < ringDegree; leftIndex += 1) {
        for (let rightIndex = 0; rightIndex < ringDegree; rightIndex += 1) {
            const exponent = leftIndex + rightIndex;
            const target = exponent % ringDegree;
            const sign = exponent >= ringDegree ? -1n : 1n;
            result[target] = modulo(
                (result[target] ?? 0n) +
                    sign *
                        ringCoefficient(left, leftIndex) *
                        ringCoefficient(right, rightIndex),
            );
        }
    }
    return result;
};

const ringInverse = (value: RingElement): RingElement => {
    const matrix = Array.from({ length: ringDegree }, (_unused, row) => [
        ...Array.from({ length: ringDegree }, (_unusedColumn, column) =>
            ringCoefficient(
                multiply(
                    value,
                    createRing((index) => (index === column ? 1n : 0n)),
                ),
                row,
            ),
        ),
        row === 0 ? 1n : 0n,
    ]);

    for (let column = 0; column < ringDegree; column += 1) {
        const pivot = matrix.findIndex(
            (row, rowIndex) =>
                rowIndex >= column && modulo(row[column] ?? 0n) !== 0n,
        );
        if (pivot < 0) {
            throw new RangeError('The ring element is not invertible.');
        }
        [matrix[column], matrix[pivot]] = [matrix[pivot], matrix[column]];
        const pivotInverse = inverse(matrix[column]?.[column] ?? 0n);
        matrix[column] = matrix[column].map((entry) =>
            modulo(entry * pivotInverse),
        );
        for (let row = 0; row < ringDegree; row += 1) {
            if (row === column) continue;
            const factor = matrix[row]?.[column] ?? 0n;
            if (factor === 0n) continue;
            matrix[row] = matrix[row].map((entry, index) =>
                modulo(entry - factor * (matrix[column]?.[index] ?? 0n)),
            );
        }
    }

    const result = createRing((index) => matrix[index]?.[ringDegree] ?? 0n);
    if (!equal(multiply(value, result), one())) {
        throw new Error('The computed ring inverse is incorrect.');
    }
    return result;
};

const automorphism = (value: RingElement): RingElement => {
    const result = Array.from({ length: ringDegree }, () => 0n);
    for (let index = 0; index < ringDegree; index += 1) {
        const exponent = index * automorphismExponent;
        const target = exponent % ringDegree;
        const quotient = Math.floor(exponent / ringDegree);
        const sign = quotient % 2 === 0 ? 1n : -1n;
        result[target] = modulo(
            (result[target] ?? 0n) + sign * ringCoefficient(value, index),
        );
    }
    return result;
};

const sum = (values: readonly RingElement[]): RingElement =>
    values.reduce(add, zero());
const createVector = (factory: (index: number) => RingElement): RingVector =>
    Array.from({ length: gadgetLength }, (_unused, index) => factory(index));
const vectorAdd = (left: RingVector, right: RingVector): RingVector =>
    left.map((entry, index) => add(entry, vectorElement(right, index)));
const vectorSum = (values: readonly RingVector[]): RingVector =>
    values.reduce(
        vectorAdd,
        createVector(() => zero()),
    );
const vectorMultiply = (scalar: RingElement, values: RingVector): RingVector =>
    values.map((entry) => multiply(scalar, entry));
const vectorEqual = (left: RingVector, right: RingVector): boolean =>
    left.every((entry, index) => equal(entry, vectorElement(right, index)));

const evaluateSharingPolynomial = (
    coefficients: readonly RingElement[],
    point: RingElement,
): RingElement => {
    let result = zero();
    for (let index = coefficients.length - 1; index >= 0; index -= 1) {
        result = add(
            multiply(result, point),
            vectorElement(coefficients, index),
        );
    }
    return result;
};

const lagrangeAtZero = (
    points: readonly RingElement[],
    selectedIndex: number,
): RingElement => {
    const selectedPoint = points[selectedIndex];
    if (selectedPoint === undefined) {
        throw new Error('A selected interpolation point is absent.');
    }
    let numerator = one();
    let denominator = one();
    for (let index = 0; index < points.length; index += 1) {
        if (index === selectedIndex) continue;
        const point = points[index];
        if (point === undefined) {
            throw new Error('An interpolation point is absent.');
        }
        numerator = multiply(numerator, negate(point));
        denominator = multiply(denominator, subtract(selectedPoint, point));
    }
    return multiply(numerator, ringInverse(denominator));
};

const combinations = (size: number, choose: number): readonly number[][] => {
    const result: number[][] = [];
    const visit = (start: number, selected: number[]): void => {
        if (selected.length === choose) {
            result.push([...selected]);
            return;
        }
        for (
            let index = start;
            index <= size - (choose - selected.length);
            index += 1
        ) {
            selected.push(index);
            visit(index + 1, selected);
            selected.pop();
        }
    };
    visit(0, []);
    return result;
};

export type ThresholdKeyAggregationCensus = Readonly<{
    aggregatePublicKeyEquationCount: number;
    authorizedReleaseSetCount: number;
    coefficientModulus: bigint;
    gadgetLength: number;
    maximumScaledReconstructionCoefficientOneNorm: bigint;
    maximumSimulationCoefficientOneNorm: bigint;
    monomialInterpolationPointCount: number;
    participantCount: number;
    releaseEquationCount: number;
    releaseThreshold: number;
    ringDegree: number;
    tamperedShareChangedReconstruction: boolean;
    wrongTargetChangedPartialDecryption: boolean;
}>;

export const verifyThresholdKeyAggregationModel =
    (): ThresholdKeyAggregationCensus => {
        let randomState = 0x6a09_e667;
        const nextRandom = (): number => {
            randomState ^= randomState << 13;
            randomState ^= randomState >>> 17;
            randomState ^= randomState << 5;
            return randomState >>> 0;
        };
        const randomRing = (): RingElement =>
            createRing(() => BigInt(nextRandom()) % coefficientModulus);
        const smallRing = (): RingElement =>
            createRing(() => BigInt((nextRandom() % 3) - 1));

        const commonA = createVector(randomRing);
        const commonU = createVector(randomRing);
        const commonRotationKey = createVector(randomRing);
        const gadget = createVector((index) =>
            createRing((coefficient) =>
                coefficient === 0 ? 1n << BigInt(index * 4) : 0n,
            ),
        );

        const contributions = Array.from({ length: participantCount }, () => {
            const secret = smallRing();
            const auxiliarySecret = smallRing();
            const sharingPolynomial = [
                secret,
                ...Array.from(
                    { length: maximumCorruptParticipantCount },
                    randomRing,
                ),
            ];
            const encryptionError = createVector(smallRing);
            const firstRelinearizationError = createVector(smallRing);
            const secondRelinearizationError = createVector(smallRing);
            const rotationError = createVector(smallRing);
            return {
                secret,
                auxiliarySecret,
                sharingPolynomial,
                encryptionError,
                firstRelinearizationError,
                secondRelinearizationError,
                rotationError,
                encryptionKey: vectorAdd(
                    vectorMultiply(negate(secret), commonA),
                    encryptionError,
                ),
                firstRelinearizationKey: vectorAdd(
                    vectorAdd(
                        vectorMultiply(negate(auxiliarySecret), commonA),
                        vectorMultiply(secret, gadget),
                    ),
                    firstRelinearizationError,
                ),
                secondRelinearizationKey: vectorAdd(
                    vectorAdd(
                        vectorMultiply(negate(secret), commonU),
                        vectorMultiply(negate(auxiliarySecret), gadget),
                    ),
                    secondRelinearizationError,
                ),
                rotationKey: vectorAdd(
                    vectorAdd(
                        vectorMultiply(negate(secret), commonRotationKey),
                        vectorMultiply(automorphism(secret), gadget),
                    ),
                    rotationError,
                ),
            };
        });

        const globalSecret = sum(contributions.map(({ secret }) => secret));
        const globalAuxiliarySecret = sum(
            contributions.map(({ auxiliarySecret }) => auxiliarySecret),
        );
        const equations = [
            vectorEqual(
                vectorSum(
                    contributions.map(({ encryptionKey }) => encryptionKey),
                ),
                vectorAdd(
                    vectorMultiply(negate(globalSecret), commonA),
                    vectorSum(
                        contributions.map(
                            ({ encryptionError }) => encryptionError,
                        ),
                    ),
                ),
            ),
            vectorEqual(
                vectorSum(
                    contributions.map(
                        ({ firstRelinearizationKey }) =>
                            firstRelinearizationKey,
                    ),
                ),
                vectorAdd(
                    vectorAdd(
                        vectorMultiply(negate(globalAuxiliarySecret), commonA),
                        vectorMultiply(globalSecret, gadget),
                    ),
                    vectorSum(
                        contributions.map(
                            ({ firstRelinearizationError }) =>
                                firstRelinearizationError,
                        ),
                    ),
                ),
            ),
            vectorEqual(
                vectorSum(
                    contributions.map(
                        ({ secondRelinearizationKey }) =>
                            secondRelinearizationKey,
                    ),
                ),
                vectorAdd(
                    vectorAdd(
                        vectorMultiply(negate(globalSecret), commonU),
                        vectorMultiply(negate(globalAuxiliarySecret), gadget),
                    ),
                    vectorSum(
                        contributions.map(
                            ({ secondRelinearizationError }) =>
                                secondRelinearizationError,
                        ),
                    ),
                ),
            ),
            vectorEqual(
                vectorSum(contributions.map(({ rotationKey }) => rotationKey)),
                vectorAdd(
                    vectorAdd(
                        vectorMultiply(negate(globalSecret), commonRotationKey),
                        vectorMultiply(automorphism(globalSecret), gadget),
                    ),
                    vectorSum(
                        contributions.map(({ rotationError }) => rotationError),
                    ),
                ),
            ),
        ];
        if (equations.some((equation) => !equation)) {
            throw new Error(
                'An aggregated evaluation-key equation changed its secret.',
            );
        }

        const participantPoints = Array.from(
            { length: participantCount },
            (_unused, index) => monomial(index),
        );
        const aggregateShares = participantPoints.map((point) =>
            sum(
                contributions.map(({ sharingPolynomial }) =>
                    evaluateSharingPolynomial(sharingPolynomial, point),
                ),
            ),
        );
        const ciphertextLinearTerm = randomRing();
        const plaintext = smallRing();
        const ciphertextError = smallRing();
        const ciphertextConstant = subtract(
            add(plaintext, ciphertextError),
            multiply(ciphertextLinearTerm, globalSecret),
        );
        const releaseSets = combinations(participantCount, releaseThreshold);
        let maximumScaledReconstructionCoefficientOneNorm = 0n;
        let maximumSimulationCoefficientOneNorm = 0n;
        for (const releaseSet of releaseSets) {
            const points = releaseSet.map((index) => {
                const point = participantPoints[index];
                if (point === undefined) {
                    throw new Error('A release point is absent.');
                }
                return point;
            });
            const coefficients = points.map((_point, index) =>
                lagrangeAtZero(points, index),
            );
            for (const coefficient of coefficients) {
                const scaledReconstructionCoefficientOneNorm = centeredOneNorm(
                    scale(coefficient, 4n),
                );
                const simulationCoefficientOneNorm = centeredOneNorm(
                    ringInverse(coefficient),
                );
                maximumScaledReconstructionCoefficientOneNorm =
                    maximumScaledReconstructionCoefficientOneNorm >
                    scaledReconstructionCoefficientOneNorm
                        ? maximumScaledReconstructionCoefficientOneNorm
                        : scaledReconstructionCoefficientOneNorm;
                maximumSimulationCoefficientOneNorm =
                    maximumSimulationCoefficientOneNorm >
                    simulationCoefficientOneNorm
                        ? maximumSimulationCoefficientOneNorm
                        : simulationCoefficientOneNorm;
            }
            const reconstructedSecret = sum(
                releaseSet.map((participant, index) =>
                    multiply(
                        vectorElement(aggregateShares, participant),
                        vectorElement(coefficients, index),
                    ),
                ),
            );
            if (!equal(reconstructedSecret, globalSecret)) {
                throw new Error(
                    'An authorized set reconstructed another secret.',
                );
            }
            const combined = add(
                ciphertextConstant,
                sum(
                    releaseSet.map((participant, index) =>
                        multiply(
                            multiply(
                                ciphertextLinearTerm,
                                vectorElement(aggregateShares, participant),
                            ),
                            vectorElement(coefficients, index),
                        ),
                    ),
                ),
            );
            if (!equal(combined, add(plaintext, ciphertextError))) {
                throw new Error(
                    'An authorized set reconstructed another plaintext.',
                );
            }
        }

        const tamperedShares = [...aggregateShares];
        tamperedShares[0] = add(
            vectorElement(tamperedShares, 0),
            createRing((index) => (index === 0 ? 1n : 0n)),
        );
        const firstReleaseSet = releaseSets[0];
        if (firstReleaseSet === undefined) {
            throw new Error('The release-set inventory is empty.');
        }
        const firstPoints = firstReleaseSet.map((index) => {
            const point = participantPoints[index];
            if (point === undefined) {
                throw new Error('A release point is absent.');
            }
            return point;
        });
        const tamperedSecret = sum(
            firstReleaseSet.map((participant, index) =>
                multiply(
                    vectorElement(tamperedShares, participant),
                    lagrangeAtZero(firstPoints, index),
                ),
            ),
        );
        const tamperedShareChangedReconstruction = !equal(
            tamperedSecret,
            globalSecret,
        );
        if (!tamperedShareChangedReconstruction) {
            throw new Error('A tampered share was algebraically invisible.');
        }

        const decryptionMultiplier = 4n;
        const simulationMultiplier = 4n;
        const floodingNoise = aggregateShares.map((_share, participant) =>
            createRing(
                (index) => BigInt(((participant + 1) * (index + 3)) % 5) - 2n,
            ),
        );
        const partialDecryptions = aggregateShares.map((share, participant) =>
            add(
                scale(
                    multiply(ciphertextLinearTerm, share),
                    decryptionMultiplier,
                ),
                scale(
                    vectorElement(floodingNoise, participant),
                    simulationMultiplier,
                ),
            ),
        );
        for (const releaseSet of releaseSets) {
            const points = releaseSet.map((index) =>
                vectorElement(participantPoints, index),
            );
            const coefficients = points.map((_point, index) =>
                lagrangeAtZero(points, index),
            );
            const combined = add(
                scale(ciphertextConstant, decryptionMultiplier),
                sum(
                    releaseSet.map((participant, index) =>
                        multiply(
                            vectorElement(partialDecryptions, participant),
                            vectorElement(coefficients, index),
                        ),
                    ),
                ),
            );
            const expected = add(
                scale(add(plaintext, ciphertextError), decryptionMultiplier),
                sum(
                    releaseSet.map((participant, index) =>
                        multiply(
                            scale(
                                vectorElement(floodingNoise, participant),
                                simulationMultiplier,
                            ),
                            vectorElement(coefficients, index),
                        ),
                    ),
                ),
            );
            if (!equal(combined, expected)) {
                throw new Error(
                    'A release subset violated the partial-decryption equation.',
                );
            }
        }

        const wrongTargetLinearTerm = add(ciphertextLinearTerm, one());
        const wrongTargetPartialDecryption = add(
            scale(
                multiply(
                    wrongTargetLinearTerm,
                    vectorElement(aggregateShares, 0),
                ),
                decryptionMultiplier,
            ),
            scale(vectorElement(floodingNoise, 0), simulationMultiplier),
        );
        const wrongTargetChangedPartialDecryption = !equal(
            wrongTargetPartialDecryption,
            vectorElement(partialDecryptions, 0),
        );
        if (!wrongTargetChangedPartialDecryption) {
            throw new Error(
                'A wrong target reused the same partial decryption.',
            );
        }

        return {
            aggregatePublicKeyEquationCount: equations.length,
            authorizedReleaseSetCount: releaseSets.length,
            coefficientModulus,
            gadgetLength,
            maximumScaledReconstructionCoefficientOneNorm,
            maximumSimulationCoefficientOneNorm,
            monomialInterpolationPointCount: participantPoints.length,
            participantCount,
            releaseEquationCount: releaseSets.length,
            releaseThreshold,
            ringDegree,
            tamperedShareChangedReconstruction,
            wrongTargetChangedPartialDecryption,
        };
    };
