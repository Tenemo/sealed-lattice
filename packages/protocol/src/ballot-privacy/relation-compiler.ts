import type { FieldElement, RefusalRecord } from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';
import {
    assertCanonicalFieldElement,
    exponentiateFieldElement,
    fieldModulus,
} from '../plaintext-oracle/field.js';

import {
    ballotPrivacyScoreBucketCount,
    getBallotPrivacyEncodedShareVectorWidth,
    getBallotPrivacyScalarCoordinateIndex,
    getBallotPrivacyScoreBucketCoordinateIndex,
} from './protocol-parameters.js';
import {
    ballotPrivacyMaximumOptionCount,
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMinimumOptionCount,
    ballotPrivacyMinimumUnsafeParticipantCount,
} from './supported-dimensions.js';

const minimumScore = 1;
const maximumScore = 10;

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
    readonly scoreOneHotWitnesses: readonly (readonly number[])[];
    readonly encodedCoordinateShamirCoefficients: readonly (readonly number[])[];
    readonly receivers: readonly BallotPrivacyRelationReceiverInput[];
};

type BallotPrivacyEncodedCoordinateRole = 'ScalarScore' | 'ScoreBucket';

type BallotPrivacyEncodedCoordinate = {
    readonly encodedCoordinateIndex: number;
    readonly optionIndex: number;
    readonly coordinateRole: BallotPrivacyEncodedCoordinateRole;
    readonly scoreBucketValue?: number;
    readonly constantTerm: number;
};

type BallotPrivacyScoreMembershipConstraint = {
    readonly optionIndex: number;
    readonly oneHotSum: number;
    readonly reconstructedScore: number;
};

type BallotPrivacyShamirQuotientConstraint = {
    readonly encodedCoordinateIndex: number;
    readonly optionIndex: number;
    readonly coordinateRole: BallotPrivacyEncodedCoordinateRole;
    readonly scoreBucketValue?: number;
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
    readonly shareVectorWidth: number;
    readonly encodedCoordinateCount: number;
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
    const encodedShareVectorWidth = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    if (
        !isPositiveSafeInteger(input.optionCount) ||
        input.optionCount < ballotPrivacyMinimumOptionCount ||
        input.optionCount > ballotPrivacyMaximumOptionCount
    ) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires two to twenty options.',
        );
    }
    if (
        !isPositiveSafeInteger(input.rosterSize) ||
        input.rosterSize < ballotPrivacyMinimumUnsafeParticipantCount ||
        input.rosterSize > ballotPrivacyMaximumParticipantCount ||
        !isPositiveSafeInteger(input.pvssThreshold) ||
        input.pvssThreshold > input.rosterSize
    ) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires three to fifty participants and a valid PVSS threshold.',
        );
    }
    if (input.normalizedScores.length !== input.optionCount) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one normalized score per option.',
        );
    }
    if (input.scoreOneHotWitnesses.length !== input.optionCount) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one score one-hot witness per option.',
        );
    }
    if (
        input.encodedCoordinateShamirCoefficients.length !==
        encodedShareVectorWidth
    ) {
        addRelationRefusal(
            refusedObjects,
            'Ballot privacy relation requires one Shamir coefficient row per encoded coordinate.',
        );
    }
};

const compileScoreMembershipConstraints = (
    input: BallotPrivacyRelationCompilerInput,
    refusedObjects: RefusalRecord[],
): {
    readonly constraints: readonly BallotPrivacyScoreMembershipConstraint[];
    readonly encodedCoordinates: readonly BallotPrivacyEncodedCoordinate[];
} => {
    const constraints: BallotPrivacyScoreMembershipConstraint[] = [];
    const encodedCoordinates: BallotPrivacyEncodedCoordinate[] = [];

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

        const oneHotWitness = input.scoreOneHotWitnesses[optionIndex] ?? [];
        if (oneHotWitness.length !== ballotPrivacyScoreBucketCount) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation requires a ten-entry one-hot score witness.',
            );
        }

        let oneHotSum = 0;
        let reconstructedScore = 0;
        let witnessEntriesAreBoolean = true;
        for (
            let scoreBucketOffset = 0;
            scoreBucketOffset < ballotPrivacyScoreBucketCount;
            scoreBucketOffset += 1
        ) {
            const witnessEntry = oneHotWitness[scoreBucketOffset];
            const entryIsBoolean =
                (witnessEntry === 0 || witnessEntry === 1) &&
                !Object.is(witnessEntry, -0);
            if (!entryIsBoolean) {
                witnessEntriesAreBoolean = false;
            }
            if (Number.isSafeInteger(witnessEntry)) {
                oneHotSum += witnessEntry;
                reconstructedScore += (scoreBucketOffset + 1) * witnessEntry;
            }
        }

        if (
            !witnessEntriesAreBoolean ||
            oneHotSum !== 1 ||
            reconstructedScore !== score
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation score one-hot witness is not a valid score encoding.',
            );
        }

        constraints.push({
            optionIndex,
            oneHotSum,
            reconstructedScore,
        });
        encodedCoordinates.push({
            constantTerm: score,
            coordinateRole: 'ScalarScore',
            encodedCoordinateIndex:
                getBallotPrivacyScalarCoordinateIndex(optionIndex),
            optionIndex,
        });
        for (
            let scoreBucketValue = minimumScore;
            scoreBucketValue <= maximumScore;
            scoreBucketValue += 1
        ) {
            const witnessEntry = oneHotWitness[scoreBucketValue - 1];
            encodedCoordinates.push({
                constantTerm: Number.isSafeInteger(witnessEntry)
                    ? witnessEntry
                    : -1,
                coordinateRole: 'ScoreBucket',
                encodedCoordinateIndex:
                    getBallotPrivacyScoreBucketCoordinateIndex(
                        optionIndex,
                        scoreBucketValue,
                    ),
                optionIndex,
                scoreBucketValue,
            });
        }
    });

    return {
        constraints,
        encodedCoordinates,
    };
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
    const expectedShareVectorWidth = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

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
            receiver.receiverShareVector.length > expectedShareVectorWidth &&
            receiver.receiverShareVector
                .slice(expectedShareVectorWidth)
                .some((paddingElement) => paddingElement !== 0)
        ) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver share-vector padding must be zero.',
            );
        }
        if (receiver.receiverShareVector.length !== expectedShareVectorWidth) {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation receiver share vectors must use the encoded width.',
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

const validateEncodedCoordinateConstants = (
    encodedCoordinates: readonly BallotPrivacyEncodedCoordinate[],
    refusedObjects: RefusalRecord[],
): void => {
    for (const encodedCoordinate of encodedCoordinates) {
        try {
            assertCanonicalFieldElement(
                encodedCoordinate.constantTerm,
                'encoded coordinate constant term',
            );
        } catch {
            addRelationRefusal(
                refusedObjects,
                'Ballot privacy relation encoded coordinate constants must be canonical field representatives.',
            );
        }
    }
};

const compileShamirQuotientConstraints = (
    input: BallotPrivacyRelationCompilerInput,
    encodedCoordinates: readonly BallotPrivacyEncodedCoordinate[],
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

    validateEncodedCoordinateConstants(encodedCoordinates, refusedObjects);
    input.encodedCoordinateShamirCoefficients.forEach((coefficientRow) => {
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

        for (const encodedCoordinate of encodedCoordinates) {
            const coefficientRow =
                input.encodedCoordinateShamirCoefficients[
                    encodedCoordinate.encodedCoordinateIndex
                ] ?? [];
            let evaluatedInteger = encodedCoordinate.constantTerm;
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
                    receiver.receiverShareVector[
                        encodedCoordinate.encodedCoordinateIndex
                    ] ?? -1,
                    'receiver share representative',
                );
            } catch {
                addRelationRefusal(
                    refusedObjects,
                    'Ballot privacy relation receiver share representative is not canonical.',
                );
                continue;
            }
            const quotientNumerator = evaluatedInteger - shareRepresentative;
            if (quotientNumerator % fieldModulus !== 0) {
                addRelationRefusal(
                    refusedObjects,
                    'Ballot privacy relation Shamir quotient constraint is not exact.',
                );
                continue;
            }
            const quotient = quotientNumerator / fieldModulus;
            maximumAbsoluteShamirQuotient = Math.max(
                maximumAbsoluteShamirQuotient,
                Math.abs(quotient),
            );
            constraints.push({
                coordinateRole: encodedCoordinate.coordinateRole,
                encodedCoordinateIndex:
                    encodedCoordinate.encodedCoordinateIndex,
                evaluatedInteger,
                optionIndex: encodedCoordinate.optionIndex,
                quotient,
                receiverRosterPosition,
                scoreBucketValue: encodedCoordinate.scoreBucketValue,
                shareRepresentative,
            });
        }
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
    const shareVectorWidth = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    validateRelationDimensions(input, refusedObjects);
    const { constraints: scoreMembershipConstraints, encodedCoordinates } =
        compileScoreMembershipConstraints(input, refusedObjects);
    const receiversByRosterPosition = compileReceiverMap(input, refusedObjects);
    const { constraints, maximumAbsoluteShamirQuotient } =
        compileShamirQuotientConstraints(
            input,
            encodedCoordinates,
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
        shareVectorWidth,
        encodedCoordinateCount: encodedCoordinates.length,
        scoreMembershipConstraints,
        shamirQuotientConstraints: constraints,
        maximumAbsoluteShamirQuotient,
    };
};
