import type { FieldElement } from './field.js';
import type { ProtocolHash } from './protocol-hash.js';
import type { SparseTopKTarget } from './target-result.js';

/** Polynomial over `GF(65537)` with the constant term at index zero. */
export type ShamirPolynomial = {
    readonly coefficients: readonly FieldElement[];
};

/** One Shamir evaluation at the one-based roster point `alpha = rosterPosition`. */
export type ShamirSharePoint = {
    readonly rosterPosition: number;
    readonly value: FieldElement;
};

/** Lagrange coefficient at zero for one selected roster position. */
export type LagrangeCoefficient = {
    readonly coefficient: FieldElement;
    readonly centeredCoefficient: number;
    readonly rosterPosition: number;
};

/** Coefficients and summary bounds for one interpolation contributor set. */
export type InterpolationCoefficientReport = {
    readonly centeredL1CoefficientSum: number;
    readonly coefficients: readonly LagrangeCoefficient[];
    readonly contributorRosterPositions: readonly number[];
    readonly maxCenteredAbsCoefficient: number;
    readonly reportHash: ProtocolHash;
    readonly rosterSize: number;
    readonly threshold: number;
};

/** Exhaustive worst-case interpolation report for a bounded roster profile. */
export type WorstCaseInterpolationCoefficientReport = {
    readonly exhaustiveSubsetCount: number;
    readonly maxCenteredAbsCoefficient: number;
    readonly maxCenteredAbsContributorRosterPositions: readonly number[];
    readonly maxCenteredAbsCoefficients: readonly LagrangeCoefficient[];
    readonly maxCenteredL1CoefficientSum: number;
    readonly maxCenteredL1ContributorRosterPositions: readonly number[];
    readonly maxCenteredL1Coefficients: readonly LagrangeCoefficient[];
    readonly reportHash: ProtocolHash;
    readonly rosterSize: number;
    readonly threshold: number;
};

/** Supported normalized score value for one option. */
export type PlaintextScore = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10;

/** Input ballot before unset options are normalized. */
export type PlaintextScoreBallotInput = {
    readonly scores: readonly (number | undefined)[];
    readonly voterIdentity?: string;
};

/** Ballot after unset options have been filled with score one. */
export type NormalizedPlaintextScoreBallot = {
    readonly scores: readonly PlaintextScore[];
    readonly voterIdentity?: string;
};

/** Plaintext score tally used as the reference oracle for later encrypted paths. */
export type PlaintextTally = {
    readonly maximumRosterSize: number;
    readonly normalizedBallots: readonly NormalizedPlaintextScoreBallot[];
    readonly optionTallies: readonly number[];
    readonly pollSpecHash: ProtocolHash;
    readonly tallyHash: ProtocolHash;
    readonly tallyFieldElements: readonly FieldElement[];
};

/** One ranked option in the plaintext top-k oracle. */
export type PlaintextTopKRankingEntry = {
    readonly optionIndex: number;
    readonly optionOrdinal: number;
    readonly rank: number;
    readonly totalScore: number;
};

/** Comparator polynomials over the bounded tally-difference domain. */
export type ComparatorPolynomialSet = {
    readonly comparatorHash: ProtocolHash;
    readonly domainMaximum: number;
    readonly domainMinimum: number;
    readonly equalCoefficients: readonly FieldElement[];
    readonly greaterThanCoefficients: readonly FieldElement[];
    readonly rosterSize: number;
};

/** Plaintext top-k oracle output consumed by future encrypted tally paths. */
export type PlaintextTopKOracle = {
    readonly comparatorDomainMaximum: number;
    readonly comparatorDomainMinimum: number;
    readonly oracleHash: ProtocolHash;
    readonly ranking: readonly PlaintextTopKRankingEntry[];
    readonly sparseTarget: SparseTopKTarget;
    readonly tally: PlaintextTally;
    readonly topOptionCount: number;
};
