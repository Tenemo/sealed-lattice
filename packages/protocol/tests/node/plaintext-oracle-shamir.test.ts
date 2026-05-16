import { describe, expect, it } from 'vitest';

import { deriveThresholdProfile } from '../../src/lifecycle/thresholds';
import {
    deriveInterpolationCoefficientReport,
    deriveWorstCaseInterpolationCoefficientReport,
    evaluateShamirPolynomialForRoster,
    interpolateShamirConstantTerm,
    normalizeFieldElement,
} from '../../src/plaintext-oracle/index';

import {
    collectContributorPositionSets,
    createDeterministicPolynomial,
    selectSpreadContributorPositions,
    shamirVectors,
} from './plaintext-oracle-test-vectors';

describe('plaintext oracle Shamir and interpolation', () => {
    it('matches deterministic Shamir vectors and reconstructs the secret', () => {
        const shares = evaluateShamirPolynomialForRoster(
            shamirVectors.polynomial,
            20,
        );

        expect(shares).toEqual(shamirVectors.shares);

        const selectedShares =
            shamirVectors.selectedContributorRosterPositions.map(
                (rosterPosition) =>
                    shares.find(
                        (share) => share.rosterPosition === rosterPosition,
                    )!,
            );

        expect(interpolateShamirConstantTerm(selectedShares)).toBe(
            shamirVectors.polynomial.coefficients[0],
        );
    });

    it.each([3, 19, 20, 30, 40, 50])(
        'reconstructs for supported roster size %d using threshold profile',
        (rosterSize) => {
            const thresholdProfile = deriveThresholdProfile({
                rosterSize,
                unsafeMicroRosterAcknowledged: rosterSize < 20,
            });
            const polynomial = createDeterministicPolynomial(
                normalizeFieldElement(rosterSize * 19),
                thresholdProfile.pvssThreshold,
            );
            const shares = evaluateShamirPolynomialForRoster(
                polynomial,
                rosterSize,
            );
            const contributorRosterPositions = selectSpreadContributorPositions(
                rosterSize,
                thresholdProfile.pvssThreshold,
            );
            const selectedShares = contributorRosterPositions.map(
                (rosterPosition) =>
                    shares.find(
                        (share) => share.rosterPosition === rosterPosition,
                    )!,
            );

            expect(interpolateShamirConstantTerm(selectedShares)).toBe(
                polynomial.coefficients[0],
            );
        },
    );

    it.each([3, 4, 5, 6, 7, 8])(
        'reconstructs every first-valid contributor set for small roster size %d',
        (rosterSize) => {
            const thresholdProfile = deriveThresholdProfile({
                rosterSize,
                unsafeMicroRosterAcknowledged: true,
            });
            const secret = normalizeFieldElement(rosterSize * 23);
            const polynomial = createDeterministicPolynomial(
                secret,
                thresholdProfile.pvssThreshold,
            );
            const shares = evaluateShamirPolynomialForRoster(
                polynomial,
                rosterSize,
            );

            for (const contributorRosterPositions of collectContributorPositionSets(
                rosterSize,
                thresholdProfile.pvssThreshold,
            )) {
                const selectedShares = contributorRosterPositions.map(
                    (rosterPosition) =>
                        shares.find(
                            (share) => share.rosterPosition === rosterPosition,
                        )!,
                );

                expect(interpolateShamirConstantTerm(selectedShares)).toBe(
                    secret,
                );
            }
        },
    );

    it('matches selected and mandatory interpolation coefficient reports', () => {
        const selectedReport = deriveInterpolationCoefficientReport({
            contributorRosterPositions:
                shamirVectors.selectedContributorRosterPositions,
            rosterSize: 20,
            threshold: 7,
        });

        expect(selectedReport).toMatchObject({
            centeredL1CoefficientSum:
                shamirVectors.selectedContributorReport
                    .centeredL1CoefficientSum,
            coefficients: shamirVectors.selectedContributorReport.coefficients,
            maxCenteredAbsCoefficient:
                shamirVectors.selectedContributorReport
                    .maxCenteredAbsCoefficient,
            reportDigest: shamirVectors.selectedContributorReport.reportDigest,
        });

        const worstCaseReport = deriveWorstCaseInterpolationCoefficientReport({
            rosterSize: 20,
            threshold: 7,
        });

        expect(worstCaseReport).toMatchObject(
            shamirVectors.mandatoryWorstCaseReport,
        );
    });

    it('rejects zero, duplicate, and undersized interpolation inputs', () => {
        expect(() =>
            interpolateShamirConstantTerm([{ rosterPosition: 0, value: 1 }]),
        ).toThrow('positive nonzero');
        expect(() =>
            interpolateShamirConstantTerm([
                { rosterPosition: 1, value: 1 },
                { rosterPosition: 1, value: 2 },
            ]),
        ).toThrow('distinct');
        expect(() =>
            deriveInterpolationCoefficientReport({
                contributorRosterPositions: [1, 2],
                rosterSize: 20,
                threshold: 7,
            }),
        ).toThrow('exactly match');
        expect(() =>
            evaluateShamirPolynomialForRoster(
                createDeterministicPolynomial(1, 2),
                51,
            ),
        ).toThrow('1..50');
        expect(() =>
            deriveWorstCaseInterpolationCoefficientReport({
                rosterSize: 51,
                threshold: 1,
            }),
        ).toThrow('1..50');
    });
});
