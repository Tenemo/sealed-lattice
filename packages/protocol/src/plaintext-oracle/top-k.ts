import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ComparatorPolynomialSet,
    FieldElement,
    NormalizedPlaintextScoreBallot,
    PlaintextScore,
    PlaintextScoreBallotInput,
    PlaintextTally,
    PlaintextTopKOracle,
    PlaintextTopKRankingEntry,
    PollSpec,
} from '@sealed-lattice/types';

import {
    derivePollSpecDigest,
    validatePollSpec,
} from '../lifecycle/poll-spec.js';

import {
    addFieldElements,
    divideFieldElements,
    multiplyFieldElements,
    normalizeFieldElement,
    subtractFieldElements,
} from './field.js';
import { deriveSparseTopKTarget } from './sparse-target.js';

const supportedScores = new Set<number>([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

const toPlaintextScore = (score: number): PlaintextScore => {
    if (!supportedScores.has(score)) {
        throw new RangeError('Scores must be integers in 1..10.');
    }

    return score as PlaintextScore;
};

const assertPollSpecShape = (pollSpec: PollSpec): void => {
    const validation = validatePollSpec(pollSpec);
    if (!validation.ok) {
        throw new RangeError(
            'Plaintext oracle poll specification must pass lifecycle validation.',
        );
    }
    if (
        pollSpec.scoreDomain.min !== 1 ||
        pollSpec.scoreDomain.max !== 10 ||
        pollSpec.scoreDomain.skippedOptionScore !== 1 ||
        pollSpec.tiePolicy !== 'HigherScoreThenLowerOptionIndex'
    ) {
        throw new RangeError(
            'Plaintext oracle requires the frozen 1..10 score domain and higher-score tie policy.',
        );
    }
    if (
        pollSpec.options.length < 1 ||
        pollSpec.options.length > 20 ||
        pollSpec.topOptionCount < 1 ||
        pollSpec.topOptionCount > pollSpec.options.length
    ) {
        throw new RangeError('Plaintext oracle poll specification is invalid.');
    }
};

export const normalizePlaintextScoreBallot = (
    pollSpec: PollSpec,
    ballot: PlaintextScoreBallotInput,
): NormalizedPlaintextScoreBallot => {
    assertPollSpecShape(pollSpec);

    if (ballot.scores.length > pollSpec.options.length) {
        throw new RangeError(
            'Score ballot cannot contain more entries than poll options.',
        );
    }

    const scores = Array.from(
        { length: pollSpec.options.length },
        (_unused, optionIndex) => {
            const score = ballot.scores[optionIndex];

            return toPlaintextScore(score ?? 1);
        },
    );

    return ballot.voterIdentity === undefined
        ? { scores }
        : {
              scores,
              voterIdentity: ballot.voterIdentity,
          };
};

const derivePlaintextTally = (input: {
    readonly ballots: readonly PlaintextScoreBallotInput[];
    readonly maximumRosterSize?: number;
    readonly pollSpec: PollSpec;
}): PlaintextTally => {
    const maximumRosterSize = input.maximumRosterSize ?? 50;

    assertPollSpecShape(input.pollSpec);
    if (
        !Number.isInteger(maximumRosterSize) ||
        maximumRosterSize < 1 ||
        maximumRosterSize > 50
    ) {
        throw new RangeError(
            'Plaintext tally maximum roster size must be in 1..50.',
        );
    }
    if (input.ballots.length > maximumRosterSize) {
        throw new RangeError('Plaintext tally cannot exceed maximum roster.');
    }

    const normalizedBallots = input.ballots.map((ballot) =>
        normalizePlaintextScoreBallot(input.pollSpec, ballot),
    );
    const optionTallies = Array.from(
        { length: input.pollSpec.options.length },
        (_unused, optionIndex) =>
            normalizedBallots.reduce(
                (sum, ballot) => sum + ballot.scores[optionIndex],
                0,
            ),
    );
    const maximumTally = maximumRosterSize * input.pollSpec.scoreDomain.max;
    if (optionTallies.some((tally) => tally > maximumTally)) {
        throw new RangeError('Plaintext tally exceeds the no-wrap bound.');
    }

    const tallyFieldElements = optionTallies.map((tally) =>
        normalizeFieldElement(tally),
    );
    const pollSpecDigest = derivePollSpecDigest(input.pollSpec);
    const tallyPayload = {
        maximumRosterSize,
        normalizedBallots,
        optionTallies,
        pollSpecDigest,
        tallyFieldElements,
    };

    return {
        ...tallyPayload,
        tallyDigest: deriveProtocolDigest('PlaintextTallyDigest', tallyPayload),
    };
};

const derivePlaintextTopKRanking = (
    tally: Pick<PlaintextTally, 'optionTallies'>,
): readonly PlaintextTopKRankingEntry[] =>
    tally.optionTallies
        .map((totalScore, optionIndex) => ({
            optionIndex,
            optionOrdinal: optionIndex + 1,
            rank: 0,
            totalScore,
        }))
        .sort(
            (left, right) =>
                right.totalScore - left.totalScore ||
                left.optionIndex - right.optionIndex,
        )
        .map((entry, rank) => ({
            ...entry,
            rank,
        }));

const multiplyPolynomialByLinearTerm = (
    coefficients: readonly FieldElement[],
    root: FieldElement,
): readonly FieldElement[] => {
    const output = Array.from(
        { length: coefficients.length + 1 },
        () => 0 as FieldElement,
    );

    coefficients.forEach((coefficient, coefficientIndex) => {
        output[coefficientIndex] = addFieldElements(
            output[coefficientIndex],
            multiplyFieldElements(coefficient, normalizeFieldElement(-root)),
        );
        output[coefficientIndex + 1] = addFieldElements(
            output[coefficientIndex + 1],
            coefficient,
        );
    });

    return output;
};

const interpolateFieldPolynomial = (
    points: readonly {
        readonly xValue: FieldElement;
        readonly y: FieldElement;
    }[],
): readonly FieldElement[] => {
    if (points.length === 0) {
        throw new RangeError('Polynomial interpolation requires points.');
    }

    const dividedDifferences = points.map((point) => point.y);

    for (let order = 1; order < points.length; order += 1) {
        for (
            let pointIndex = points.length - 1;
            pointIndex >= order;
            pointIndex -= 1
        ) {
            dividedDifferences[pointIndex] = divideFieldElements(
                subtractFieldElements(
                    dividedDifferences[pointIndex],
                    dividedDifferences[pointIndex - 1],
                ),
                subtractFieldElements(
                    points[pointIndex].xValue,
                    points[pointIndex - order].xValue,
                ),
            );
        }
    }

    let coefficients: readonly FieldElement[] = [dividedDifferences[0]];
    let basis: readonly FieldElement[] = [1];

    for (let order = 1; order < points.length; order += 1) {
        basis = multiplyPolynomialByLinearTerm(basis, points[order - 1].xValue);
        coefficients = Array.from(
            { length: Math.max(coefficients.length, basis.length) },
            (_unused, coefficientIndex) =>
                addFieldElements(
                    coefficients[coefficientIndex] ?? 0,
                    multiplyFieldElements(
                        dividedDifferences[order],
                        basis[coefficientIndex] ?? 0,
                    ),
                ),
        );
    }

    return coefficients;
};

export const evaluateFieldPolynomial = (
    coefficients: readonly FieldElement[],
    xValue: FieldElement,
): FieldElement => {
    let evaluation: FieldElement = 0;

    for (
        let coefficientIndex = coefficients.length - 1;
        coefficientIndex >= 0;
        coefficientIndex -= 1
    ) {
        evaluation = addFieldElements(
            multiplyFieldElements(evaluation, xValue),
            coefficients[coefficientIndex],
        );
    }

    return evaluation;
};

export const deriveComparatorPolynomialSet = (
    rosterSize: number,
): ComparatorPolynomialSet => {
    if (!Number.isInteger(rosterSize) || rosterSize < 1 || rosterSize > 50) {
        throw new RangeError('Comparator roster size must be in 1..50.');
    }

    const domainMinimum = -9 * rosterSize;
    const domainMaximum = 9 * rosterSize;
    const points = Array.from(
        { length: domainMaximum - domainMinimum + 1 },
        (_unused, domainOffset) => {
            const domainValue = domainMinimum + domainOffset;

            return {
                domainValue,
                xValue: normalizeFieldElement(domainValue),
            };
        },
    );
    const greaterThanCoefficients = interpolateFieldPolynomial(
        points.map((point) => ({
            xValue: point.xValue,
            y: point.domainValue > 0 ? 1 : 0,
        })),
    );
    const equalCoefficients = interpolateFieldPolynomial(
        points.map((point) => ({
            xValue: point.xValue,
            y: point.domainValue === 0 ? 1 : 0,
        })),
    );
    const comparatorPayload = {
        domainMaximum,
        domainMinimum,
        equalCoefficients,
        greaterThanCoefficients,
        rosterSize,
    };

    return {
        ...comparatorPayload,
        comparatorDigest: deriveProtocolDigest(
            'TopKCircuitDigest',
            comparatorPayload,
        ),
    };
};

export const derivePlaintextTopKOracle = (input: {
    readonly ballots: readonly PlaintextScoreBallotInput[];
    readonly maximumRosterSize?: number;
    readonly pollSpec: PollSpec;
}): PlaintextTopKOracle => {
    const tally = derivePlaintextTally(input);
    const ranking = derivePlaintextTopKRanking(tally);
    const sparseTarget = deriveSparseTopKTarget({
        optionCount: input.pollSpec.options.length,
        ranking,
        topOptionCount: input.pollSpec.topOptionCount,
    });
    const comparatorDomainMinimum = -9 * (input.maximumRosterSize ?? 50);
    const comparatorDomainMaximum = 9 * (input.maximumRosterSize ?? 50);
    const oraclePayload = {
        comparatorDomainMaximum,
        comparatorDomainMinimum,
        ranking,
        sparseTarget,
        tallyDigest: tally.tallyDigest,
        topOptionCount: input.pollSpec.topOptionCount,
    };

    return {
        ...oraclePayload,
        oracleDigest: deriveProtocolDigest(
            'PlaintextTopKOracleDigest',
            oraclePayload,
        ),
        tally,
    };
};
