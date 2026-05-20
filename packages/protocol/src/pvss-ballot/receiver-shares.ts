import type {
    BallotPolynomialSet,
    FieldElement,
    PvssBallotRosterEntry,
    ReceiverShareVector,
    ThresholdProfile,
} from '@sealed-lattice/types';

import {
    assertCanonicalFieldElement,
    normalizeFieldElement,
} from '../plaintext-oracle/field.js';
import { evaluateShamirPolynomialForRoster } from '../plaintext-oracle/shamir.js';

import { deriveBallotPolynomialSetDigest } from './ballot-polynomials.js';
import {
    pvssBallotShareVectorWidth,
    requireNoRefusals,
    sortRosterEntries,
    validateRosterEntries,
} from './common.js';

export const deriveReceiverShareVectors = (input: {
    readonly polynomialSet: BallotPolynomialSet;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): readonly ReceiverShareVector[] => {
    requireNoRefusals(
        validateRosterEntries(input.rosterEntries, input.thresholdProfile),
    );
    if (
        input.polynomialSet.optionPolynomials.length < 1 ||
        input.polynomialSet.optionPolynomials.length >
            pvssBallotShareVectorWidth
    ) {
        throw new RangeError(
            'Receiver share vectors require one to twenty option polynomials.',
        );
    }
    if (
        input.polynomialSet.pvssThreshold !==
        input.thresholdProfile.pvssThreshold
    ) {
        throw new RangeError(
            'Receiver share vectors require the threshold profile used by the ballot polynomial set.',
        );
    }
    const recomputedPolynomialSetDigest = deriveBallotPolynomialSetDigest({
        normalizedBallot: input.polynomialSet.normalizedBallot,
        optionPolynomials: input.polynomialSet.optionPolynomials,
        pvssThreshold: input.polynomialSet.pvssThreshold,
    });
    if (
        input.polynomialSet.ballotPolynomialSetDigest !==
        recomputedPolynomialSetDigest
    ) {
        throw new RangeError(
            'Receiver share vectors require a canonical ballot polynomial set digest.',
        );
    }

    const seenOptionIndexes = new Set<number>();
    const seenOptionOrdinals = new Set<number>();
    input.polynomialSet.optionPolynomials.forEach(
        (optionPolynomial, optionIndex) => {
            if (
                optionPolynomial.optionIndex !== optionIndex ||
                optionPolynomial.optionOrdinal !== optionIndex + 1 ||
                seenOptionIndexes.has(optionPolynomial.optionIndex) ||
                seenOptionOrdinals.has(optionPolynomial.optionOrdinal) ||
                optionPolynomial.polynomial.coefficients.length !==
                    input.thresholdProfile.pvssThreshold
            ) {
                throw new RangeError(
                    'Receiver share vectors require canonical option polynomial slots.',
                );
            }
            seenOptionIndexes.add(optionPolynomial.optionIndex);
            seenOptionOrdinals.add(optionPolynomial.optionOrdinal);
            optionPolynomial.polynomial.coefficients.forEach(
                (coefficient, coefficientIndex) =>
                    assertCanonicalFieldElement(
                        coefficient,
                        `option polynomial coefficient ${String(coefficientIndex)}`,
                    ),
            );
        },
    );

    const sharesByOption = input.polynomialSet.optionPolynomials.map(
        (optionPolynomial) =>
            evaluateShamirPolynomialForRoster(
                optionPolynomial.polynomial,
                input.thresholdProfile.rosterSize,
            ),
    );

    return sortRosterEntries(input.rosterEntries).map((entry) => {
        const optionShares = sharesByOption.map((shares) => {
            const sharePoint = shares.find(
                (candidate) =>
                    candidate.rosterPosition === entry.rosterPosition,
            );
            if (sharePoint === undefined) {
                throw new Error('Missing receiver share point.');
            }

            return sharePoint.value;
        });
        const shareVector = [
            ...optionShares,
            ...Array.from(
                {
                    length: pvssBallotShareVectorWidth - optionShares.length,
                },
                () => normalizeFieldElement(0),
            ),
        ];

        return {
            receiverIdentity: entry.participantIdentity,
            receiverRosterPosition: entry.rosterPosition,
            optionCount: optionShares.length,
            shareVectorWidth: pvssBallotShareVectorWidth,
            shareVector,
        };
    });
};

export const assertCanonicalReceiverShareVector = (
    shareVector: ReceiverShareVector,
): void => {
    if (
        shareVector.shareVectorWidth !== pvssBallotShareVectorWidth ||
        shareVector.shareVector.length !== pvssBallotShareVectorWidth ||
        shareVector.optionCount < 1 ||
        shareVector.optionCount > pvssBallotShareVectorWidth
    ) {
        throw new RangeError(
            'Receiver share vector must use the fixed ballot width and valid option count.',
        );
    }
    shareVector.shareVector.forEach((fieldElement, fieldIndex) => {
        assertCanonicalFieldElement(
            fieldElement,
            `receiver share vector field ${String(fieldIndex)}`,
        );
    });
    const padding = shareVector.shareVector.slice(shareVector.optionCount);
    if (padding.some((fieldElement) => fieldElement !== 0)) {
        throw new RangeError('Receiver share vector padding must be zero.');
    }
};

export const addShareVectors = (
    left: readonly FieldElement[],
    right: readonly FieldElement[],
): readonly FieldElement[] => {
    if (
        left.length !== pvssBallotShareVectorWidth ||
        right.length !== pvssBallotShareVectorWidth
    ) {
        throw new RangeError(
            'Share-vector addition requires fixed-width vectors.',
        );
    }

    return left.map((leftFieldElement, fieldIndex) =>
        normalizeFieldElement(leftFieldElement + (right[fieldIndex] ?? 0)),
    );
};
