import type { FieldElement, RefusalRecord } from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';
import {
    assertCanonicalFieldElement,
    exponentiateFieldElement,
    fieldModulus,
} from '../plaintext-oracle/field.js';
import { pvssBallotShareVectorWidth } from '../pvss-ballot/common.js';

const minimumScore = 1;
const maximumScore = 10;
const oneHotScoreWidth = 10;

type BallotPrivacyRelationReceiverInput = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverShareVector: readonly number[];
};

export type BallotPrivacyRelationCompilerInput = {
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly pvssThreshold: number;
    readonly normalizedScores: readonly number[];
    readonly scoreMembershipWitnesses: readonly (readonly number[])[];
    readonly shamirCoefficients: readonly (readonly number[])[];
    readonly receivers: readonly BallotPrivacyRelationReceiverInput[];
};

type BallotPrivacyScoreMembershipConstraint = {
    readonly optionIndex: number;
    readonly oneHotSum: number;
    readonly reconstructedScore: number;
};

type BallotPrivacyShamirQuotientConstraint = {
    readonly optionIndex: number;
    readonly receiverRosterPosition: number;
    readonly evaluatedInteger: number;
    readonly shareRepresentative: FieldElement;
    readonly quotient: number;
};

type BallotPrivacyRelationCompilation = {
    readonly ok: true;
    readonly relationLabel: 'BallotPrivacyPvssRelation';
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly pvssThreshold: number;
    readonly scoreMembershipConstraints: readonly BallotPrivacyScoreMembershipConstraint[];
    readonly shamirQuotientConstraints: readonly BallotPrivacyShamirQuotientConstraint[];
    readonly maximumAbsoluteShamirQuotient: number;
};

type BallotPrivacyRelationCompilationResult =
    | BallotPrivacyRelationCompilation
    | {
          readonly ok: false;
          readonly refusedObjects: readonly RefusalRecord[];
          readonly unresolvedReason: 'BallotPrivacyRelationInvalid';
      };

const isPositiveSafeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value > 0 && !Object.is(value, -0);

const addRelationRefusal = (
    refusedObjects: RefusalRecord[],
    message: string,
): void => {
    refusedObjects.push(createRefusal('BallotPackageInvalid', message));
};

const validateRelationDimensions = (
    input: BallotPrivacyRelationCompilerInput,
    refusedObjects: RefusalRecord[],
): void => {
    if (
        !isPositiveSafeInteger(input.optionCount) ||
        input.optionCount > pvssBallotShareVectorWidth
    ) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one to twenty options.',
        );
    }
    if (
        !isPositiveSafeInteger(input.rosterSize) ||
        !isPositiveSafeInteger(input.pvssThreshold) ||
        input.pvssThreshold > input.rosterSize
    ) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires a valid roster size and PVSS threshold.',
        );
    }
    if (input.normalizedScores.length !== input.optionCount) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one normalized score per option.',
        );
    }
    if (input.scoreMembershipWitnesses.length !== input.optionCount) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one score-membership witness per option.',
        );
    }
    if (input.shamirCoefficients.length !== input.optionCount) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one Shamir coefficient row per option.',
        );
    }
};

const compileScoreMembershipConstraints = (
    input: BallotPrivacyRelationCompilerInput,
    refusedObjects: RefusalRecord[],
): readonly BallotPrivacyScoreMembershipConstraint[] => {
    const constraints: BallotPrivacyScoreMembershipConstraint[] = [];

    input.normalizedScores.forEach((score, optionIndex) => {
        if (
            !Number.isSafeInteger(score) ||
            score < minimumScore ||
            score > maximumScore ||
            Object.is(score, -0)
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation score is outside the frozen score domain.',
            );
        }

        const oneHotWitness = input.scoreMembershipWitnesses[optionIndex] ?? [];
        if (oneHotWitness.length !== oneHotScoreWidth) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation requires a ten-entry one-hot score witness.',
            );
        }

        const oneHotSum = oneHotWitness.reduce(
            (runningSum, witnessEntry) => runningSum + witnessEntry,
            0,
        );
        const reconstructedScore = oneHotWitness.reduce(
            (runningScore, witnessEntry, witnessIndex) =>
                runningScore + (witnessIndex + 1) * witnessEntry,
            0,
        );
        if (
            oneHotWitness.some(
                (witnessEntry) => witnessEntry !== 0 && witnessEntry !== 1,
            ) ||
            oneHotSum !== 1 ||
            reconstructedScore !== score
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation score-membership witness is not one-hot.',
            );
        }

        constraints.push({
            optionIndex,
            oneHotSum,
            reconstructedScore,
        });
    });

    return constraints;
};

const compileReceiverMap = (
    input: BallotPrivacyRelationCompilerInput,
    refusedObjects: RefusalRecord[],
): ReadonlyMap<number, BallotPrivacyRelationReceiverInput> => {
    const receiversByRosterPosition = new Map<
        number,
        BallotPrivacyRelationReceiverInput
    >();
    const receiverIdentities = new Set<string>();

    if (input.receivers.length !== input.rosterSize) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one receiver entry for every roster position.',
        );
    }

    for (const receiver of input.receivers) {
        if (receiver.receiverIdentity.length === 0) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver identities must be non-empty.',
            );
        }
        if (receiverIdentities.has(receiver.receiverIdentity)) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver identities must be unique.',
            );
        }
        receiverIdentities.add(receiver.receiverIdentity);

        if (
            !isPositiveSafeInteger(receiver.receiverRosterPosition) ||
            receiver.receiverRosterPosition > input.rosterSize
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver roster positions must be one-based and in range.',
            );
            continue;
        }
        if (receiversByRosterPosition.has(receiver.receiverRosterPosition)) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver roster positions must be unique.',
            );
        }
        receiversByRosterPosition.set(
            receiver.receiverRosterPosition,
            receiver,
        );

        if (
            receiver.receiverShareVector.length !== pvssBallotShareVectorWidth
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver share vectors must use the fixed width.',
            );
        }
        receiver.receiverShareVector.forEach((shareRepresentative) => {
            try {
                assertCanonicalFieldElement(
                    shareRepresentative,
                    'receiver share representative',
                );
            } catch {
                addRelationRefusal(
                    refusedObjects,
                    'Ballot privacy relation receiver share vector contains a non-canonical field representative.',
                );
            }
        });
        if (
            receiver.receiverShareVector
                .slice(input.optionCount)
                .some((paddingElement) => paddingElement !== 0)
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver share-vector padding must be zero.',
            );
        }
    }

    for (
        let expectedRosterPosition = 1;
        expectedRosterPosition <= input.rosterSize;
        expectedRosterPosition += 1
    ) {
        if (!receiversByRosterPosition.has(expectedRosterPosition)) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receivers must cover every roster position exactly once.',
            );
            break;
        }
    }

    return receiversByRosterPosition;
};

const compileShamirQuotientConstraints = (
    input: BallotPrivacyRelationCompilerInput,
    receiversByRosterPosition: ReadonlyMap<
        number,
        BallotPrivacyRelationReceiverInput
    >,
    refusedObjects: RefusalRecord[],
): {
    readonly constraints: readonly BallotPrivacyShamirQuotientConstraint[];
    readonly maximumAbsoluteShamirQuotient: number;
} => {
    const constraints: BallotPrivacyShamirQuotientConstraint[] = [];
    let maximumAbsoluteShamirQuotient = 0;

    input.shamirCoefficients.forEach((coefficientRow) => {
        if (coefficientRow.length !== input.pvssThreshold - 1) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation Shamir coefficient rows must have degree less than the PVSS threshold.',
            );
        }
        coefficientRow.forEach((coefficient) => {
            try {
                assertCanonicalFieldElement(coefficient, 'Shamir coefficient');
            } catch {
                addRelationRefusal(
                    refusedObjects,
                    'Ballot privacy relation Shamir coefficients must be canonical field representatives.',
                );
            }
        });
    });

    for (
        let receiverRosterPosition = 1;
        receiverRosterPosition <= input.rosterSize;
        receiverRosterPosition += 1
    ) {
        const receiver = receiversByRosterPosition.get(receiverRosterPosition);
        if (receiver === undefined) {
            continue;
        }
        let receiverPoint: FieldElement;
        try {
            receiverPoint = assertCanonicalFieldElement(
                receiverRosterPosition,
                'receiver roster position',
            );
        } catch {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver roster position is not a canonical field element.',
            );
            continue;
        }

        input.normalizedScores.forEach((score, optionIndex) => {
            const coefficientRow = input.shamirCoefficients[optionIndex] ?? [];
            let evaluatedInteger = score;
            coefficientRow.forEach((coefficient, coefficientIndex) => {
                const fieldPower = exponentiateFieldElement(
                    receiverPoint,
                    coefficientIndex + 1,
                );
                evaluatedInteger += coefficient * fieldPower;
            });

            let shareRepresentative: FieldElement;
            try {
                shareRepresentative = assertCanonicalFieldElement(
                    receiver.receiverShareVector[optionIndex] ?? -1,
                    'receiver share representative',
                );
            } catch {
                addRelationRefusal(
                    refusedObjects,
                    'Ballot privacy relation receiver share representative is not canonical.',
                );
                return;
            }
            const quotientNumerator = evaluatedInteger - shareRepresentative;
            if (quotientNumerator % fieldModulus !== 0) {
                addRelationRefusal(
                    refusedObjects,
                    'Ballot privacy relation Shamir quotient constraint is not exact.',
                );
                return;
            }
            const quotient = quotientNumerator / fieldModulus;
            maximumAbsoluteShamirQuotient = Math.max(
                maximumAbsoluteShamirQuotient,
                Math.abs(quotient),
            );
            constraints.push({
                optionIndex,
                receiverRosterPosition,
                evaluatedInteger,
                shareRepresentative,
                quotient,
            });
        });
    }

    return {
        constraints,
        maximumAbsoluteShamirQuotient,
    };
};

export const compileBallotPrivacyRelation = (
    input: BallotPrivacyRelationCompilerInput,
): BallotPrivacyRelationCompilationResult => {
    const refusedObjects: RefusalRecord[] = [];

    validateRelationDimensions(input, refusedObjects);
    const scoreMembershipConstraints = compileScoreMembershipConstraints(
        input,
        refusedObjects,
    );
    const receiversByRosterPosition = compileReceiverMap(input, refusedObjects);
    const { constraints, maximumAbsoluteShamirQuotient } =
        compileShamirQuotientConstraints(
            input,
            receiversByRosterPosition,
            refusedObjects,
        );

    if (refusedObjects.length > 0) {
        return {
            ok: false,
            refusedObjects,
            unresolvedReason: 'BallotPrivacyRelationInvalid',
        };
    }

    return {
        ok: true,
        relationLabel: 'BallotPrivacyPvssRelation',
        optionCount: input.optionCount,
        rosterSize: input.rosterSize,
        pvssThreshold: input.pvssThreshold,
        scoreMembershipConstraints,
        shamirQuotientConstraints: constraints,
        maximumAbsoluteShamirQuotient,
    };
};
