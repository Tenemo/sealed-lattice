import type {
    FieldElement,
    PlaintextScoreBallotInput,
    PollSpecInput,
    ShamirPolynomial,
    ShamirSharePoint,
    SparseTopKTarget,
} from '@sealed-lattice/types';
import { expect } from 'vitest';

import { validatePollSpec } from '#packages/protocol/src/lifecycle/poll-spec';
import {
    createShamirPolynomial,
    deriveSparseTopKTargetHash,
    normalizeFieldElement,
} from '#packages/protocol/src/plaintext-oracle/index';
import comparatorPolynomialVectorsJson from '#test-vectors/plaintext-oracle/comparator-polynomials.json';
import fieldVectorsJson from '#test-vectors/plaintext-oracle/field.json';
import shamirVectorsJson from '#test-vectors/plaintext-oracle/shamir.json';
import sparseTargetVectorsJson from '#test-vectors/plaintext-oracle/sparse-target.json';
import topKVectorsJson from '#test-vectors/plaintext-oracle/top-k.json';

type FieldVectors = {
    readonly encodings: readonly {
        readonly bytesHex: string;
        readonly value: FieldElement;
    }[];
    readonly inverseCases: readonly {
        readonly inverse: FieldElement;
        readonly product: FieldElement;
        readonly value: FieldElement;
    }[];
    readonly modulus: number;
    readonly schemaVersion: 1;
};

type ShamirVectors = {
    readonly stressWorstCaseReport: {
        readonly exhaustiveSubsetCount: number;
        readonly maxCenteredAbsCoefficient: number;
        readonly maxCenteredAbsContributorRosterPositions: readonly number[];
        readonly maxCenteredL1CoefficientSum: number;
        readonly maxCenteredL1ContributorRosterPositions: readonly number[];
        readonly reportHash: string;
        readonly rosterSize: number;
        readonly threshold: number;
    };
    readonly polynomial: ShamirPolynomial;
    readonly schemaVersion: 1;
    readonly selectedContributorReport: {
        readonly centeredL1CoefficientSum: number;
        readonly coefficients: readonly {
            readonly centeredCoefficient: number;
            readonly coefficient: FieldElement;
            readonly rosterPosition: number;
        }[];
        readonly maxCenteredAbsCoefficient: number;
        readonly reportHash: string;
    };
    readonly selectedContributorRosterPositions: readonly number[];
    readonly shares: readonly ShamirSharePoint[];
};

type TopKVectors = {
    readonly ballots: readonly PlaintextScoreBallotInput[];
    readonly expected: {
        readonly oracleHash: string;
        readonly optionTallies: readonly number[];
        readonly rankingOptionOrdinals: readonly number[];
        readonly selectedOptionOrdinals: readonly number[];
        readonly tallyHash: string;
        readonly tallyFieldElements: readonly FieldElement[];
        readonly targetIdSlots: readonly FieldElement[];
        readonly targetOrderSlots: readonly FieldElement[];
    };
    readonly fullTieCase: {
        readonly ballots: readonly PlaintextScoreBallotInput[];
        readonly expectedOracleHash: string;
        readonly expectedRankingOptionOrdinals: readonly number[];
        readonly expectedTargetIdSlots: readonly FieldElement[];
        readonly expectedTargetOrderSlots: readonly FieldElement[];
        readonly pollSpecInput: PollSpecInput;
    };
    readonly maximumNoWrapCase: {
        readonly ballotCount: number;
        readonly expectedMaximumTally: number;
        readonly expectedOracleHash: string;
        readonly expectedRankingOptionOrdinals: readonly number[];
        readonly expectedTallyHash: string;
        readonly expectedTargetIdSlots: readonly FieldElement[];
        readonly expectedTargetOrderSlots: readonly FieldElement[];
        readonly pollSpecInput: PollSpecInput;
        readonly score: number;
    };
    readonly maximumRosterSize: number;
    readonly pollSpecInput: PollSpecInput;
    readonly schemaVersion: 1;
    readonly topOneClearWinnerCase: {
        readonly ballots: readonly PlaintextScoreBallotInput[];
        readonly expectedOptionTallies: readonly number[];
        readonly expectedOracleHash: string;
        readonly expectedRankingOptionOrdinals: readonly number[];
        readonly expectedSelectedOptionOrdinals: readonly number[];
        readonly expectedTallyHash: string;
        readonly expectedTargetIdSlots: readonly FieldElement[];
        readonly expectedTargetOrderSlots: readonly FieldElement[];
        readonly pollSpecInput: PollSpecInput;
    };
};

type SparseTargetVectors = {
    readonly expectedSelectedOptionOrdinals: readonly number[];
    readonly layoutHash: string;
    readonly schemaVersion: 1;
    readonly target: SparseTopKTarget;
    readonly targetHash: string;
};

type ComparatorPolynomialVectors = {
    readonly comparatorHash: string;
    readonly domainMaximum: number;
    readonly domainMinimum: number;
    readonly equalCoefficientCount: number;
    readonly evaluationCases: readonly {
        readonly equal: FieldElement;
        readonly greaterThan: FieldElement;
        readonly value: number;
    }[];
    readonly firstEqualCoefficients: readonly FieldElement[];
    readonly firstGreaterThanCoefficients: readonly FieldElement[];
    readonly greaterThanCoefficientCount: number;
    readonly lastEqualCoefficients: readonly FieldElement[];
    readonly lastGreaterThanCoefficients: readonly FieldElement[];
    readonly maximumRosterBoundaryCase: {
        readonly comparatorHash: string;
        readonly domainMaximum: number;
        readonly domainMinimum: number;
        readonly equalCoefficientCount: number;
        readonly evaluationCases: readonly {
            readonly equal: FieldElement;
            readonly greaterThan: FieldElement;
            readonly value: number;
        }[];
        readonly greaterThanCoefficientCount: number;
        readonly rosterSize: number;
    };
    readonly rosterSize: number;
    readonly schemaVersion: 1;
};

export const fieldVectors = fieldVectorsJson as FieldVectors;
export const shamirVectors = shamirVectorsJson as ShamirVectors;
export const topKVectors = topKVectorsJson as TopKVectors;
export const sparseTargetVectors =
    sparseTargetVectorsJson as SparseTargetVectors;
export const comparatorPolynomialVectors =
    comparatorPolynomialVectorsJson as ComparatorPolynomialVectors;

export const assertValidPollSpec = (
    input: PollSpecInput,
): ReturnType<typeof validatePollSpec> & {
    readonly ok: true;
} => {
    const validation = validatePollSpec(input);

    expect(validation.ok).toBe(true);
    if (!validation.ok) {
        throw new Error('Expected poll spec fixture to validate.');
    }

    return validation;
};

export const selectSpreadContributorPositions = (
    rosterSize: number,
    threshold: number,
): readonly number[] => {
    if (threshold === 1) {
        return [rosterSize];
    }

    const positions = new Set<number>([1, rosterSize]);
    let candidatePosition = 2;

    while (positions.size < threshold) {
        positions.add(candidatePosition);
        candidatePosition += 2;
        if (candidatePosition > rosterSize) {
            candidatePosition = 3;
        }
    }

    return [...positions].sort((left, right) => left - right);
};

export const collectContributorPositionSets = (
    rosterSize: number,
    threshold: number,
): readonly (readonly number[])[] => {
    const positionSets: number[][] = [];
    const currentPositionSet: number[] = [];

    const visitFrom = (nextRosterPosition: number): void => {
        if (currentPositionSet.length === threshold) {
            positionSets.push([...currentPositionSet]);
            return;
        }

        const remainingSlots = threshold - currentPositionSet.length;
        const maximumStart = rosterSize - remainingSlots + 1;

        for (
            let rosterPosition = nextRosterPosition;
            rosterPosition <= maximumStart;
            rosterPosition += 1
        ) {
            currentPositionSet.push(rosterPosition);
            visitFrom(rosterPosition + 1);
            currentPositionSet.pop();
        }
    };

    visitFrom(1);

    return positionSets;
};

export const createDeterministicPolynomial = (
    secret: FieldElement,
    threshold: number,
): ShamirPolynomial =>
    createShamirPolynomial(
        secret,
        Array.from({ length: threshold - 1 }, (_unused, coefficientIndex) =>
            normalizeFieldElement(
                (coefficientIndex + 3) * (coefficientIndex + 11),
            ),
        ),
    );

export const mutateSparseTarget = (
    target: SparseTopKTarget,
    overrides: Partial<Omit<SparseTopKTarget, 'targetHash'>>,
): SparseTopKTarget => {
    const targetWithoutHash = {
        forbiddenSemanticSlots:
            overrides.forbiddenSemanticSlots ?? target.forbiddenSemanticSlots,
        layoutHash: overrides.layoutHash ?? target.layoutHash,
        optionCount: overrides.optionCount ?? target.optionCount,
        targetIdSlots: overrides.targetIdSlots ?? target.targetIdSlots,
        targetOrderSlots: overrides.targetOrderSlots ?? target.targetOrderSlots,
        topOptionCount: overrides.topOptionCount ?? target.topOptionCount,
    };

    return {
        ...targetWithoutHash,
        targetHash: deriveSparseTopKTargetHash(targetWithoutHash),
    };
};
