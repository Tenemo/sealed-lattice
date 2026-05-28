import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    FieldElement,
    InterpolationCoefficientReport,
    LagrangeCoefficient,
    ShamirPolynomial,
    ShamirSharePoint,
    WorstCaseInterpolationCoefficientReport,
} from '@sealed-lattice/types';

import {
    addFieldElements,
    assertCanonicalFieldElement,
    centeredFieldElement,
    divideFieldElements,
    multiplyFieldElements,
    negateFieldElement,
    subtractFieldElements,
} from './field.js';

const defaultMaximumExhaustiveSubsetCount = 250_000;
const maximumSupportedRosterSize = 50;

const assertPositiveRosterPosition = (rosterPosition: number): number => {
    if (
        !Number.isSafeInteger(rosterPosition) ||
        rosterPosition <= 0 ||
        !Number.isInteger(rosterPosition)
    ) {
        throw new RangeError(
            'Roster interpolation points must be positive nonzero integers.',
        );
    }
    if (rosterPosition > maximumSupportedRosterSize) {
        throw new RangeError('Roster interpolation points must be in 1..50.');
    }

    return rosterPosition;
};

const assertSupportedRosterAndThreshold = (
    rosterSize: number,
    threshold: number,
): void => {
    if (
        !Number.isSafeInteger(rosterSize) ||
        rosterSize < 1 ||
        rosterSize > maximumSupportedRosterSize
    ) {
        throw new RangeError('Roster size must be an integer in 1..50.');
    }
    if (
        !Number.isSafeInteger(threshold) ||
        threshold < 1 ||
        threshold > rosterSize
    ) {
        throw new RangeError(
            'Interpolation threshold must be between one and rosterSize.',
        );
    }
};

export const createShamirPolynomial = (
    secret: FieldElement,
    nonconstantCoefficients: readonly FieldElement[],
): ShamirPolynomial => ({
    coefficients: [
        assertCanonicalFieldElement(secret, 'Shamir secret'),
        ...nonconstantCoefficients.map((coefficient) =>
            assertCanonicalFieldElement(coefficient, 'Shamir coefficient'),
        ),
    ],
});

const evaluateShamirPolynomial = (
    polynomial: ShamirPolynomial,
    rosterPosition: number,
): FieldElement => {
    if (polynomial.coefficients.length === 0) {
        throw new RangeError(
            'Shamir polynomial must contain at least the constant coefficient.',
        );
    }

    const point = assertPositiveRosterPosition(rosterPosition);
    let evaluation: FieldElement = 0;

    for (
        let coefficientIndex = polynomial.coefficients.length - 1;
        coefficientIndex >= 0;
        coefficientIndex -= 1
    ) {
        const coefficient = assertCanonicalFieldElement(
            polynomial.coefficients[coefficientIndex],
            'Shamir polynomial coefficient',
        );
        evaluation = addFieldElements(
            multiplyFieldElements(evaluation, point),
            coefficient,
        );
    }

    return evaluation;
};

export const evaluateShamirPolynomialForRoster = (
    polynomial: ShamirPolynomial,
    rosterSize: number,
): readonly ShamirSharePoint[] => {
    if (
        !Number.isSafeInteger(rosterSize) ||
        rosterSize < 1 ||
        rosterSize > maximumSupportedRosterSize
    ) {
        throw new RangeError('Roster size must be an integer in 1..50.');
    }

    return Array.from({ length: rosterSize }, (_unused, rosterIndex) => {
        const rosterPosition = rosterIndex + 1;

        return {
            rosterPosition,
            value: evaluateShamirPolynomial(polynomial, rosterPosition),
        };
    });
};

const validateDistinctSharePoints = (
    sharePoints: readonly ShamirSharePoint[],
): void => {
    const seenRosterPositions = new Set<number>();

    for (const sharePoint of sharePoints) {
        assertPositiveRosterPosition(sharePoint.rosterPosition);
        assertCanonicalFieldElement(sharePoint.value, 'Shamir share value');
        if (seenRosterPositions.has(sharePoint.rosterPosition)) {
            throw new RangeError(
                'Shamir interpolation points must be distinct.',
            );
        }
        seenRosterPositions.add(sharePoint.rosterPosition);
    }
};

const validateContributorRosterPositions = (
    rosterSize: number,
    threshold: number,
    contributorRosterPositions: readonly number[],
): readonly number[] => {
    assertSupportedRosterAndThreshold(rosterSize, threshold);

    if (contributorRosterPositions.length !== threshold) {
        throw new RangeError(
            'Contributor set size must exactly match the interpolation threshold.',
        );
    }

    const seenRosterPositions = new Set<number>();
    const validatedRosterPositions = contributorRosterPositions.map(
        (rosterPosition) => {
            assertPositiveRosterPosition(rosterPosition);
            if (rosterPosition > rosterSize) {
                throw new RangeError(
                    'Contributor roster position must be within the roster.',
                );
            }
            if (seenRosterPositions.has(rosterPosition)) {
                throw new RangeError(
                    'Contributor roster positions must be distinct.',
                );
            }
            seenRosterPositions.add(rosterPosition);

            return rosterPosition;
        },
    );

    return validatedRosterPositions;
};

const deriveLagrangeCoefficientsAtZero = (
    contributorRosterPositions: readonly number[],
): readonly LagrangeCoefficient[] => {
    const seenRosterPositions = new Set<number>();
    const validatedPositions = contributorRosterPositions.map(
        (rosterPosition) => {
            assertPositiveRosterPosition(rosterPosition);
            if (seenRosterPositions.has(rosterPosition)) {
                throw new RangeError(
                    'Lagrange contributor positions must be distinct.',
                );
            }
            seenRosterPositions.add(rosterPosition);

            return rosterPosition;
        },
    );

    return validatedPositions.map((rosterPosition, selectedIndex) => {
        let coefficient: FieldElement = 1;

        validatedPositions.forEach((otherRosterPosition, otherIndex) => {
            if (otherIndex === selectedIndex) {
                return;
            }

            coefficient = multiplyFieldElements(
                coefficient,
                divideFieldElements(
                    negateFieldElement(otherRosterPosition),
                    subtractFieldElements(rosterPosition, otherRosterPosition),
                ),
            );
        });

        return {
            coefficient,
            centeredCoefficient: centeredFieldElement(coefficient),
            rosterPosition,
        };
    });
};

export const interpolateShamirConstantTerm = (
    sharePoints: readonly ShamirSharePoint[],
): FieldElement => {
    if (sharePoints.length === 0) {
        throw new RangeError('At least one Shamir share is required.');
    }
    if (sharePoints.length > maximumSupportedRosterSize) {
        throw new RangeError('At most 50 Shamir shares are supported.');
    }

    validateDistinctSharePoints(sharePoints);

    const coefficients = deriveLagrangeCoefficientsAtZero(
        sharePoints.map((sharePoint) => sharePoint.rosterPosition),
    );

    return sharePoints.reduce<FieldElement>((interpolatedValue, sharePoint) => {
        const coefficient = coefficients.find(
            (candidate) =>
                candidate.rosterPosition === sharePoint.rosterPosition,
        );
        if (coefficient === undefined) {
            throw new Error('Missing Lagrange coefficient for share point.');
        }

        return addFieldElements(
            interpolatedValue,
            multiplyFieldElements(sharePoint.value, coefficient.coefficient),
        );
    }, 0);
};

export const deriveInterpolationCoefficientReport = (input: {
    readonly contributorRosterPositions: readonly number[];
    readonly rosterSize: number;
    readonly threshold: number;
}): InterpolationCoefficientReport => {
    const contributorRosterPositions = validateContributorRosterPositions(
        input.rosterSize,
        input.threshold,
        input.contributorRosterPositions,
    );
    const coefficients = deriveLagrangeCoefficientsAtZero(
        contributorRosterPositions,
    );
    const centeredAbsCoefficients = coefficients.map((coefficient) =>
        Math.abs(coefficient.centeredCoefficient),
    );
    const maxCenteredAbsCoefficient = Math.max(...centeredAbsCoefficients);
    const centeredL1CoefficientSum = centeredAbsCoefficients.reduce(
        (sum, absCoefficient) => sum + absCoefficient,
        0,
    );
    const reportPayload = {
        centeredL1CoefficientSum,
        coefficients,
        contributorRosterPositions,
        maxCenteredAbsCoefficient,
        rosterSize: input.rosterSize,
        threshold: input.threshold,
    };

    return {
        ...reportPayload,
        reportHash: deriveProtocolHash(
            'InterpolationCoefficientReportHash',
            reportPayload,
        ),
    };
};

const countCombinations = (rosterSize: number, threshold: number): number => {
    let combinationCount = 1;

    for (
        let selectedCount = 1;
        selectedCount <= threshold;
        selectedCount += 1
    ) {
        combinationCount =
            (combinationCount * (rosterSize - threshold + selectedCount)) /
            selectedCount;
    }

    return Math.round(combinationCount);
};

const visitCombinations = (
    rosterSize: number,
    threshold: number,
    visitor: (contributorRosterPositions: readonly number[]) => void,
): void => {
    const currentCombination: number[] = [];

    const visitFrom = (nextRosterPosition: number): void => {
        if (currentCombination.length === threshold) {
            visitor(currentCombination);
            return;
        }

        const remainingSlots = threshold - currentCombination.length;
        const maximumStart = rosterSize - remainingSlots + 1;

        for (
            let rosterPosition = nextRosterPosition;
            rosterPosition <= maximumStart;
            rosterPosition += 1
        ) {
            currentCombination.push(rosterPosition);
            visitFrom(rosterPosition + 1);
            currentCombination.pop();
        }
    };

    visitFrom(1);
};

export const deriveWorstCaseInterpolationCoefficientReport = (input: {
    readonly maximumExhaustiveSubsetCount?: number;
    readonly rosterSize: number;
    readonly threshold: number;
}): WorstCaseInterpolationCoefficientReport => {
    assertSupportedRosterAndThreshold(input.rosterSize, input.threshold);

    const exhaustiveSubsetCount = countCombinations(
        input.rosterSize,
        input.threshold,
    );
    const maximumExhaustiveSubsetCount =
        input.maximumExhaustiveSubsetCount ??
        defaultMaximumExhaustiveSubsetCount;

    if (exhaustiveSubsetCount > maximumExhaustiveSubsetCount) {
        throw new RangeError(
            'Worst-case interpolation report requires too many contributor subsets for exhaustive local generation.',
        );
    }

    let maxCenteredAbsCoefficient = -1;
    let maxCenteredL1CoefficientSum = -1;
    let maxCenteredAbsContributorRosterPositions: readonly number[] = [];
    let maxCenteredL1ContributorRosterPositions: readonly number[] = [];
    let maxCenteredAbsCoefficients: readonly LagrangeCoefficient[] = [];
    let maxCenteredL1Coefficients: readonly LagrangeCoefficient[] = [];

    visitCombinations(input.rosterSize, input.threshold, (positions) => {
        const report = deriveInterpolationCoefficientReport({
            contributorRosterPositions: [...positions],
            rosterSize: input.rosterSize,
            threshold: input.threshold,
        });

        if (report.maxCenteredAbsCoefficient > maxCenteredAbsCoefficient) {
            maxCenteredAbsCoefficient = report.maxCenteredAbsCoefficient;
            maxCenteredAbsContributorRosterPositions = [
                ...report.contributorRosterPositions,
            ];
            maxCenteredAbsCoefficients = [...report.coefficients];
        }
        if (report.centeredL1CoefficientSum > maxCenteredL1CoefficientSum) {
            maxCenteredL1CoefficientSum = report.centeredL1CoefficientSum;
            maxCenteredL1ContributorRosterPositions = [
                ...report.contributorRosterPositions,
            ];
            maxCenteredL1Coefficients = [...report.coefficients];
        }
    });

    const reportPayload = {
        exhaustiveSubsetCount,
        maxCenteredAbsCoefficient,
        maxCenteredAbsContributorRosterPositions,
        maxCenteredAbsCoefficients,
        maxCenteredL1CoefficientSum,
        maxCenteredL1ContributorRosterPositions,
        maxCenteredL1Coefficients,
        rosterSize: input.rosterSize,
        threshold: input.threshold,
    };

    return {
        ...reportPayload,
        reportHash: deriveProtocolHash(
            'WorstCaseInterpolationCoefficientReportHash',
            reportPayload,
        ),
    };
};
