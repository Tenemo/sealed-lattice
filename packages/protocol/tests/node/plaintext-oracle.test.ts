import { describe, expect, it } from 'vitest';

import comparatorPolynomialVectorsJson from '../../../../test-vectors/plaintext-oracle/comparator-polynomials.json';
import fieldVectorsJson from '../../../../test-vectors/plaintext-oracle/field.json';
import shamirVectorsJson from '../../../../test-vectors/plaintext-oracle/shamir.json';
import sparseTargetVectorsJson from '../../../../test-vectors/plaintext-oracle/sparse-target.json';
import topKVectorsJson from '../../../../test-vectors/plaintext-oracle/top-k.json';
import {
    addFieldElements,
    createShamirPolynomial,
    decodeFieldElement,
    decodeSparseTopKTarget,
    deriveComparatorPolynomialSet,
    deriveInterpolationCoefficientReport,
    derivePlaintextTopKOracle,
    deriveSparseTopKTarget,
    deriveSparseTopKTargetDigest,
    deriveThresholdProfile,
    deriveWorstCaseInterpolationCoefficientReport,
    encodeFieldElement,
    evaluateFieldPolynomial,
    evaluateShamirPolynomialForRoster,
    exponentiateFieldElement,
    fieldModulus,
    interpolateShamirConstantTerm,
    invertFieldElement,
    multiplyFieldElements,
    normalizeFieldElement,
    subtractFieldElements,
    validatePollSpec,
} from '../../src/index';
import type {
    ComparatorPolynomialSet,
    FieldElement,
    PlaintextScoreBallotInput,
    PlaintextTopKRankingEntry,
    PollSpecInput,
    ShamirPolynomial,
    ShamirSharePoint,
    SparseTopKTarget,
} from '../../src/index';

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
    readonly mandatoryWorstCaseReport: {
        readonly exhaustiveSubsetCount: number;
        readonly maxCenteredAbsCoefficient: number;
        readonly maxCenteredAbsContributorRosterPositions: readonly number[];
        readonly maxCenteredL1CoefficientSum: number;
        readonly maxCenteredL1ContributorRosterPositions: readonly number[];
        readonly reportDigest: string;
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
        readonly reportDigest: string;
    };
    readonly selectedContributorRosterPositions: readonly number[];
    readonly shares: readonly ShamirSharePoint[];
};

type TopKVectors = {
    readonly ballots: readonly PlaintextScoreBallotInput[];
    readonly expected: {
        readonly oracleDigest: string;
        readonly optionTallies: readonly number[];
        readonly rankingOptionOrdinals: readonly number[];
        readonly selectedOptionOrdinals: readonly number[];
        readonly tallyDigest: string;
        readonly tallyFieldElements: readonly FieldElement[];
        readonly targetIdSlots: readonly FieldElement[];
        readonly targetOrderSlots: readonly FieldElement[];
    };
    readonly fullTieCase: {
        readonly ballots: readonly PlaintextScoreBallotInput[];
        readonly expectedOracleDigest: string;
        readonly expectedRankingOptionOrdinals: readonly number[];
        readonly expectedTargetIdSlots: readonly FieldElement[];
        readonly expectedTargetOrderSlots: readonly FieldElement[];
        readonly pollSpecInput: PollSpecInput;
    };
    readonly maximumNoWrapCase: {
        readonly ballotCount: number;
        readonly expectedMaximumTally: number;
        readonly expectedOracleDigest: string;
        readonly expectedRankingOptionOrdinals: readonly number[];
        readonly expectedTallyDigest: string;
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
        readonly expectedOracleDigest: string;
        readonly expectedRankingOptionOrdinals: readonly number[];
        readonly expectedSelectedOptionOrdinals: readonly number[];
        readonly expectedTallyDigest: string;
        readonly expectedTargetIdSlots: readonly FieldElement[];
        readonly expectedTargetOrderSlots: readonly FieldElement[];
        readonly pollSpecInput: PollSpecInput;
    };
};

type SparseTargetVectors = {
    readonly expectedSelectedOptionOrdinals: readonly number[];
    readonly layoutDigest: string;
    readonly layoutId: 'WinnerRankTopK-v1';
    readonly schemaVersion: 1;
    readonly target: SparseTopKTarget;
    readonly targetDigest: string;
};

type ComparatorPolynomialVectors = {
    readonly comparatorDigest: string;
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
        readonly comparatorDigest: string;
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

const fieldVectors = fieldVectorsJson as FieldVectors;
const shamirVectors = shamirVectorsJson as ShamirVectors;
const topKVectors = topKVectorsJson as TopKVectors;
const sparseTargetVectors = sparseTargetVectorsJson as SparseTargetVectors;
const comparatorPolynomialVectors =
    comparatorPolynomialVectorsJson as ComparatorPolynomialVectors;

const assertValidPollSpec = (
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

const selectSpreadContributorPositions = (
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

const collectContributorPositionSets = (
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

const createDeterministicPolynomial = (
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

const mutateSparseTarget = (
    target: SparseTopKTarget,
    overrides: Partial<Omit<SparseTopKTarget, 'targetDigest'>>,
): SparseTopKTarget => {
    const targetWithoutDigest = {
        forbiddenSemanticSlots:
            overrides.forbiddenSemanticSlots ?? target.forbiddenSemanticSlots,
        layoutDigest: overrides.layoutDigest ?? target.layoutDigest,
        layoutId: overrides.layoutId ?? target.layoutId,
        optionCount: overrides.optionCount ?? target.optionCount,
        targetIdSlots: overrides.targetIdSlots ?? target.targetIdSlots,
        targetOrderSlots: overrides.targetOrderSlots ?? target.targetOrderSlots,
        topOptionCount: overrides.topOptionCount ?? target.topOptionCount,
    };

    return {
        ...targetWithoutDigest,
        targetDigest: deriveSparseTopKTargetDigest(targetWithoutDigest),
    };
};

describe('plaintext oracle field arithmetic', () => {
    it('matches canonical field encoding and inverse vectors', () => {
        expect(fieldVectors.modulus).toBe(fieldModulus);

        for (const vector of fieldVectors.encodings) {
            expect(encodeFieldElement(vector.value)).toBe(vector.bytesHex);
            expect(decodeFieldElement(vector.bytesHex)).toBe(vector.value);
        }

        for (const vector of fieldVectors.inverseCases) {
            expect(invertFieldElement(vector.value)).toBe(vector.inverse);
            expect(multiplyFieldElements(vector.value, vector.inverse)).toBe(
                vector.product,
            );
        }
    });

    it('satisfies finite-field invariants over edge-heavy examples', () => {
        const examples: readonly FieldElement[] = [
            0, 1, 2, 3, 17, 32768, 32769, 65536,
        ];

        for (const left of examples) {
            for (const right of examples) {
                expect(addFieldElements(left, right)).toBe(
                    addFieldElements(right, left),
                );
                expect(multiplyFieldElements(left, right)).toBe(
                    multiplyFieldElements(right, left),
                );
                expect(
                    subtractFieldElements(addFieldElements(left, right), right),
                ).toBe(left);
            }

            if (left !== 0) {
                expect(
                    multiplyFieldElements(left, invertFieldElement(left)),
                ).toBe(1);
                expect(exponentiateFieldElement(left, fieldModulus - 1)).toBe(
                    1,
                );
            }
        }
    });

    it('rejects malformed field encodings and invalid inversions', () => {
        expect(() => decodeFieldElement('')).toThrow(
            'exactly three lowercase hex bytes',
        );
        expect(() => decodeFieldElement('010001')).toThrow('0..65536');
        expect(() => invertFieldElement(0)).toThrow('Zero has no inverse');
    });
});

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
        'reconstructs every first-come contributor set for small roster size %d',
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
    });
});

describe('plaintext tally and top-k oracle', () => {
    it('matches deterministic top-k vectors including skipped-score normalization', () => {
        const pollSpec = assertValidPollSpec(topKVectors.pollSpecInput);
        const oracle = derivePlaintextTopKOracle({
            ballots: topKVectors.ballots,
            maximumRosterSize: topKVectors.maximumRosterSize,
            pollSpec: pollSpec.normalized,
        });

        expect(oracle.tally.optionTallies).toEqual(
            topKVectors.expected.optionTallies,
        );
        expect(oracle.tally.tallyFieldElements).toEqual(
            topKVectors.expected.tallyFieldElements,
        );
        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.expected.rankingOptionOrdinals,
        );
        expect(
            decodeSparseTopKTarget({
                expectedLayoutDigest: oracle.sparseTarget.layoutDigest,
                target: oracle.sparseTarget,
            }).selectedOptionOrdinals,
        ).toEqual(topKVectors.expected.selectedOptionOrdinals);
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.expected.targetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.expected.targetOrderSlots,
        );
        expect(oracle.tally.tallyDigest).toBe(topKVectors.expected.tallyDigest);
        expect(oracle.oracleDigest).toBe(topKVectors.expected.oracleDigest);
    });

    it('uses lower option index as the full-ranking tie breaker', () => {
        const pollSpec = assertValidPollSpec(
            topKVectors.fullTieCase.pollSpecInput,
        );
        const oracle = derivePlaintextTopKOracle({
            ballots: topKVectors.fullTieCase.ballots,
            maximumRosterSize: 20,
            pollSpec: pollSpec.normalized,
        });

        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.fullTieCase.expectedRankingOptionOrdinals,
        );
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.fullTieCase.expectedTargetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.fullTieCase.expectedTargetOrderSlots,
        );
        expect(oracle.oracleDigest).toBe(
            topKVectors.fullTieCase.expectedOracleDigest,
        );
    });

    it('covers K_top = 1 with a single clear winner', () => {
        const pollSpec = assertValidPollSpec(
            topKVectors.topOneClearWinnerCase.pollSpecInput,
        );
        const oracle = derivePlaintextTopKOracle({
            ballots: topKVectors.topOneClearWinnerCase.ballots,
            maximumRosterSize: 20,
            pollSpec: pollSpec.normalized,
        });
        const decoding = decodeSparseTopKTarget({
            expectedLayoutDigest: oracle.sparseTarget.layoutDigest,
            target: oracle.sparseTarget,
        });

        expect(oracle.tally.optionTallies).toEqual(
            topKVectors.topOneClearWinnerCase.expectedOptionTallies,
        );
        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.topOneClearWinnerCase.expectedRankingOptionOrdinals,
        );
        expect(decoding.ok).toBe(true);
        expect(decoding.selectedOptionOrdinals).toEqual(
            topKVectors.topOneClearWinnerCase.expectedSelectedOptionOrdinals,
        );
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.topOneClearWinnerCase.expectedTargetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.topOneClearWinnerCase.expectedTargetOrderSlots,
        );
        expect(oracle.tally.tallyDigest).toBe(
            topKVectors.topOneClearWinnerCase.expectedTallyDigest,
        );
        expect(oracle.oracleDigest).toBe(
            topKVectors.topOneClearWinnerCase.expectedOracleDigest,
        );
    });

    it('covers the maximum n=50, m=20 no-wrap tally and full ranking', () => {
        const pollSpec = assertValidPollSpec(
            topKVectors.maximumNoWrapCase.pollSpecInput,
        );
        const ballots = Array.from(
            { length: topKVectors.maximumNoWrapCase.ballotCount },
            () => ({
                scores: Array.from(
                    { length: pollSpec.normalized.options.length },
                    () => topKVectors.maximumNoWrapCase.score,
                ),
            }),
        );
        const oracle = derivePlaintextTopKOracle({
            ballots,
            maximumRosterSize: topKVectors.maximumNoWrapCase.ballotCount,
            pollSpec: pollSpec.normalized,
        });

        expect(Math.max(...oracle.tally.optionTallies)).toBe(
            topKVectors.maximumNoWrapCase.expectedMaximumTally,
        );
        expect(oracle.tally.optionTallies).toEqual(
            Array.from(
                { length: pollSpec.normalized.options.length },
                () => topKVectors.maximumNoWrapCase.expectedMaximumTally,
            ),
        );
        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.maximumNoWrapCase.expectedRankingOptionOrdinals,
        );
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.maximumNoWrapCase.expectedTargetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.maximumNoWrapCase.expectedTargetOrderSlots,
        );
        expect(oracle.tally.tallyDigest).toBe(
            topKVectors.maximumNoWrapCase.expectedTallyDigest,
        );
        expect(oracle.oracleDigest).toBe(
            topKVectors.maximumNoWrapCase.expectedOracleDigest,
        );
    });

    it('rejects malformed score vectors and no-wrap violations', () => {
        const pollSpec = assertValidPollSpec(topKVectors.pollSpecInput);

        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [0, 1, 1, 1] }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('1..10');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [1, 1, 1, 11] }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('1..10');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [1, 1, 1, 1, 1] }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('more entries than poll options');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: Array.from({ length: 21 }, () => ({
                    scores: [10, 10, 10, 10],
                })),
                maximumRosterSize: 20,
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('cannot exceed maximum roster');
    });
});

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

describe('sparse target decoder oracle', () => {
    const validRanking = [
        {
            optionIndex: 0,
            optionOrdinal: 1,
            rank: 0,
            totalScore: 30,
        },
        {
            optionIndex: 1,
            optionOrdinal: 2,
            rank: 1,
            totalScore: 20,
        },
        {
            optionIndex: 2,
            optionOrdinal: 3,
            rank: 2,
            totalScore: 10,
        },
    ] as const satisfies readonly PlaintextTopKRankingEntry[];

    it('decodes the WinnerRankTopK-v1 target vector', () => {
        expect(sparseTargetVectors.layoutId).toBe('WinnerRankTopK-v1');
        const decoding = decodeSparseTopKTarget({
            expectedLayoutDigest: sparseTargetVectors.layoutDigest,
            target: sparseTargetVectors.target,
        });

        expect(decoding.ok).toBe(true);
        expect(decoding.targetDigest).toBe(sparseTargetVectors.targetDigest);
        expect(decoding.selectedOptionOrdinals).toEqual(
            sparseTargetVectors.expectedSelectedOptionOrdinals,
        );
        expect(decoding.refusedObjects).toEqual([]);
    });

    it.each([
        {
            caseName: 'duplicate option index',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    optionIndex: 0,
                    optionOrdinal: 1,
                },
                validRanking[2],
            ],
        },
        {
            caseName: 'duplicate rank',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    rank: 0,
                },
                validRanking[2],
            ],
        },
        {
            caseName: 'rank outside the option range',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    rank: 5,
                },
                validRanking[2],
            ],
        },
        {
            caseName: 'ordinal that does not match the option index',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    optionOrdinal: 3,
                },
                validRanking[2],
            ],
        },
    ])('rejects malformed sparse target ranking: $caseName', ({ ranking }) => {
        expect(() =>
            deriveSparseTopKTarget({
                optionCount: 3,
                ranking,
                topOptionCount: 2,
            }),
        ).toThrow('ranking');
    });

    it.each([
        {
            caseName: 'duplicate option IDs',
            overrides: {
                targetIdSlots: [1, 1, 0, 0],
                targetOrderSlots: [2, 1, 0, 0],
            },
        },
        {
            caseName: 'missing order position',
            overrides: {
                targetIdSlots: [1, 2, 0, 0],
                targetOrderSlots: [1, 0, 0, 0],
            },
        },
        {
            caseName: 'duplicate order positions',
            overrides: {
                targetIdSlots: [1, 2, 0, 0],
                targetOrderSlots: [1, 1, 0, 0],
            },
        },
        {
            caseName: 'out-of-range ordinal',
            overrides: {
                targetIdSlots: [1, 5, 0, 0],
                targetOrderSlots: [2, 1, 0, 0],
            },
        },
        {
            caseName: 'nonzero forbidden semantic slot',
            overrides: {
                forbiddenSemanticSlots: [0, 1, 0, 0],
            },
        },
        {
            caseName: 'missing forbidden semantic slots',
            overrides: {
                forbiddenSemanticSlots: [],
            },
        },
        {
            caseName: 'extra forbidden semantic slot',
            overrides: {
                forbiddenSemanticSlots: [0, 0, 0, 0, 0],
            },
        },
    ])('rejects malformed sparse target: $caseName', ({ overrides }) => {
        const mutatedTarget = mutateSparseTarget(
            sparseTargetVectors.target,
            overrides as Partial<Omit<SparseTopKTarget, 'targetDigest'>>,
        );
        const decoding = decodeSparseTopKTarget({
            expectedLayoutDigest: sparseTargetVectors.layoutDigest,
            target: mutatedTarget,
        });

        expect(decoding.ok).toBe(false);
        expect(decoding.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'SparseTargetInvalid' }),
            ]),
        );
    });

    it('rejects a target under the wrong layout digest even when the payload is self-consistent', () => {
        const decoding = decodeSparseTopKTarget({
            expectedLayoutDigest: 'wrong-layout-digest',
            target: sparseTargetVectors.target,
        });

        expect(decoding.ok).toBe(false);
        expect(decoding.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'SparseTargetInvalid' }),
            ]),
        );
    });
});
