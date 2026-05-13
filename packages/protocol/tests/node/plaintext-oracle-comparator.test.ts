import { describe, expect, it } from 'vitest';

import {
    deriveComparatorPolynomialSet,
    evaluateFieldPolynomial,
    normalizeFieldElement,
} from '../../src/index';
import type { ComparatorPolynomialSet } from '../../src/index';

import { comparatorPolynomialVectors } from './plaintext-oracle-test-vectors';

describe('plaintext comparator polynomial oracle', () => {
    it('matches comparator polynomial vectors and evaluates boundary cases', () => {
        const comparator = deriveComparatorPolynomialSet(
            comparatorPolynomialVectors.rosterSize,
        );

        expect(comparator).toMatchObject({
            comparatorDigest: comparatorPolynomialVectors.comparatorDigest,
            domainMaximum: comparatorPolynomialVectors.domainMaximum,
            domainMinimum: comparatorPolynomialVectors.domainMinimum,
        });
        expect(comparator.greaterThanCoefficients).toHaveLength(
            comparatorPolynomialVectors.greaterThanCoefficientCount,
        );
        expect(comparator.equalCoefficients).toHaveLength(
            comparatorPolynomialVectors.equalCoefficientCount,
        );
        expect(comparator.greaterThanCoefficients.slice(0, 10)).toEqual(
            comparatorPolynomialVectors.firstGreaterThanCoefficients,
        );
        expect(comparator.greaterThanCoefficients.slice(-10)).toEqual(
            comparatorPolynomialVectors.lastGreaterThanCoefficients,
        );
        expect(comparator.equalCoefficients.slice(0, 10)).toEqual(
            comparatorPolynomialVectors.firstEqualCoefficients,
        );
        expect(comparator.equalCoefficients.slice(-10)).toEqual(
            comparatorPolynomialVectors.lastEqualCoefficients,
        );

        for (const evaluationCase of comparatorPolynomialVectors.evaluationCases) {
            const xValue = normalizeFieldElement(evaluationCase.value);

            expect(
                evaluateFieldPolynomial(
                    comparator.greaterThanCoefficients,
                    xValue,
                ),
            ).toBe(evaluationCase.greaterThan);
            expect(
                evaluateFieldPolynomial(comparator.equalCoefficients, xValue),
            ).toBe(evaluationCase.equal);
        }
    });

    it('evaluates GT and EQ correctly across the full comparator domain', () => {
        const comparator: ComparatorPolynomialSet =
            deriveComparatorPolynomialSet(20);

        for (
            let domainValue = comparator.domainMinimum;
            domainValue <= comparator.domainMaximum;
            domainValue += 1
        ) {
            const xValue = normalizeFieldElement(domainValue);

            expect(
                evaluateFieldPolynomial(
                    comparator.greaterThanCoefficients,
                    xValue,
                ),
                `GT failed at ${String(domainValue)}`,
            ).toBe(domainValue > 0 ? 1 : 0);
            expect(
                evaluateFieldPolynomial(comparator.equalCoefficients, xValue),
                `EQ failed at ${String(domainValue)}`,
            ).toBe(domainValue === 0 ? 1 : 0);
        }
    });

    it('matches n=50 comparator boundary fixtures at -450 and +450', () => {
        const comparator = deriveComparatorPolynomialSet(
            comparatorPolynomialVectors.maximumRosterBoundaryCase.rosterSize,
        );

        expect(comparator).toMatchObject({
            comparatorDigest:
                comparatorPolynomialVectors.maximumRosterBoundaryCase
                    .comparatorDigest,
            domainMaximum:
                comparatorPolynomialVectors.maximumRosterBoundaryCase
                    .domainMaximum,
            domainMinimum:
                comparatorPolynomialVectors.maximumRosterBoundaryCase
                    .domainMinimum,
        });
        expect(comparator.greaterThanCoefficients).toHaveLength(
            comparatorPolynomialVectors.maximumRosterBoundaryCase
                .greaterThanCoefficientCount,
        );
        expect(comparator.equalCoefficients).toHaveLength(
            comparatorPolynomialVectors.maximumRosterBoundaryCase
                .equalCoefficientCount,
        );

        for (const evaluationCase of comparatorPolynomialVectors
            .maximumRosterBoundaryCase.evaluationCases) {
            const xValue = normalizeFieldElement(evaluationCase.value);

            expect(
                evaluateFieldPolynomial(
                    comparator.greaterThanCoefficients,
                    xValue,
                ),
            ).toBe(evaluationCase.greaterThan);
            expect(
                evaluateFieldPolynomial(comparator.equalCoefficients, xValue),
            ).toBe(evaluationCase.equal);
        }
    });
});
