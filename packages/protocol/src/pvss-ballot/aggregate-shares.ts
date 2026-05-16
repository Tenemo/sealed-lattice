import { canonicalJson, deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPackageWitness,
    CanonicalBallotSet,
    CountedBallotPackage,
    FieldElement,
    PvssBallotRosterEntry,
    ReceiverShareVector,
    TestReceiverShareOpeningPayload,
    TestShareCommitmentWitness,
    TestAggregateShare,
    TestAggregateShareSet,
    TestAggregateShareWitness,
    ThresholdProfile,
} from '@sealed-lattice/types';

import {
    addFieldElements,
    assertCanonicalFieldElement,
    normalizeFieldElement,
} from '../plaintext-oracle/field.js';
import { interpolateShamirConstantTerm } from '../plaintext-oracle/shamir.js';

import { deriveBallotPolynomialSetDigest } from './ballot-polynomials.js';
import {
    pvssBallotShareVectorWidth,
    requireNoRefusals,
    sortRosterEntries,
    validateRosterEntries,
} from './common.js';
import {
    addShareVectors,
    deriveReceiverShareVectors,
} from './receiver-shares.js';
import {
    deriveTestReceiverShareOpeningPayloadDigest,
    deriveTestShareCommitmentDigest,
    verifyTestShareCommitmentOpening,
} from './test-share-commitments.js';

const zeroShareVector = (): readonly FieldElement[] =>
    Array.from({ length: pvssBallotShareVectorWidth }, () => 0 as FieldElement);

const fieldVectorsEqual = (
    left: readonly FieldElement[],
    right: readonly FieldElement[],
): boolean =>
    left.length === right.length &&
    left.every(
        (fieldElement, fieldIndex) => fieldElement === right[fieldIndex],
    );

const sameCanonicalObject = (left: unknown, right: unknown): boolean =>
    canonicalJson(left) === canonicalJson(right);

const receiverKey = (
    trusteeIdentity: string,
    trusteeRosterPosition: number,
): string => [trusteeIdentity, trusteeRosterPosition].join('\u0000');

const buildUniqueMap = <Value>(
    values: readonly Value[],
    keyForValue: (value: Value) => string,
    duplicateMessage: string,
): Map<string, Value> => {
    const mappedValues = new Map<string, Value>();

    for (const value of values) {
        const key = keyForValue(value);
        if (mappedValues.has(key)) {
            throw new RangeError(duplicateMessage);
        }
        mappedValues.set(key, value);
    }

    return mappedValues;
};

const assertPolynomialSetMatchesPackage = (
    candidate: CountedBallotPackage,
    witness: BallotPackageWitness,
    thresholdProfile: ThresholdProfile,
): void => {
    const polynomialSet = witness.polynomialSet;
    const recomputedPolynomialSetDigest = deriveBallotPolynomialSetDigest({
        normalizedBallot: polynomialSet.normalizedBallot,
        optionPolynomials: polynomialSet.optionPolynomials,
        pvssThreshold: polynomialSet.pvssThreshold,
    });

    if (
        polynomialSet.ballotPolynomialSetDigest !==
            recomputedPolynomialSetDigest ||
        polynomialSet.ballotPolynomialSetDigest !==
            candidate.ballotPackage.ballotPolynomialSetDigest
    ) {
        throw new RangeError(
            'Counted ballot witness polynomial set does not match the counted package digest.',
        );
    }
    if (
        polynomialSet.pvssThreshold !== thresholdProfile.pvssThreshold ||
        polynomialSet.normalizedBallot.scores.length !==
            candidate.ballotPackage.optionCount ||
        polynomialSet.optionPolynomials.length !==
            candidate.ballotPackage.optionCount
    ) {
        throw new RangeError(
            'Counted ballot witness polynomial set does not match the counted package shape.',
        );
    }

    polynomialSet.optionPolynomials.forEach((optionPolynomial, optionIndex) => {
        const expectedScore =
            polynomialSet.normalizedBallot.scores[optionIndex];

        if (
            optionPolynomial.optionIndex !== optionIndex ||
            optionPolynomial.optionOrdinal !== optionIndex + 1 ||
            optionPolynomial.polynomial.coefficients.length !==
                thresholdProfile.pvssThreshold ||
            optionPolynomial.polynomial.coefficients[0] !== expectedScore
        ) {
            throw new RangeError(
                'Counted ballot witness polynomial set is not canonical for the counted package.',
            );
        }
        optionPolynomial.polynomial.coefficients.forEach(
            (coefficient, coefficientIndex) =>
                assertCanonicalFieldElement(
                    coefficient,
                    `ballot polynomial coefficient ${String(coefficientIndex)}`,
                ),
        );
    });
};

const assertReceiverWitnessesMatchPackage = (input: {
    readonly candidate: CountedBallotPackage;
    readonly witness: BallotPackageWitness;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): void => {
    const { candidate, witness } = input;
    const expectedReceiverShareVectors = deriveReceiverShareVectors({
        polynomialSet: witness.polynomialSet,
        rosterEntries: input.rosterEntries,
        thresholdProfile: input.thresholdProfile,
    });
    const shareVectorsByReceiver = buildUniqueMap<ReceiverShareVector>(
        witness.receiverShareVectors,
        (shareVector) =>
            receiverKey(
                shareVector.trusteeIdentity,
                shareVector.trusteeRosterPosition,
            ),
        'Counted ballot witness receiver shares must be unique.',
    );
    const commitmentWitnessesByReceiver =
        buildUniqueMap<TestShareCommitmentWitness>(
            witness.shareCommitmentWitnesses,
            (commitmentWitness) =>
                receiverKey(
                    commitmentWitness.commitment.trusteeIdentity,
                    commitmentWitness.commitment.trusteeRosterPosition,
                ),
            'Counted ballot witness commitment openings must be unique.',
        );
    const receiverPayloadsByReceiver =
        buildUniqueMap<TestReceiverShareOpeningPayload>(
            witness.receiverPayloads,
            (payload) =>
                receiverKey(
                    payload.receiverIdentity,
                    payload.receiverRosterPosition,
                ),
            'Counted ballot witness receiver payloads must be unique.',
        );
    const digestContext = {
        ceremonyId: candidate.ballotPackage.ceremonyId,
        duplicateBallotPolicyDigest:
            candidate.ballotPackage.duplicateBallotPolicyDigest,
        electionManifestDigest: candidate.ballotPackage.electionManifestDigest,
        pollSpecDigest: candidate.ballotPackage.pollSpecDigest,
        rosterDigest: candidate.ballotPackage.rosterDigest,
        thresholdProfileDigest: candidate.ballotPackage.thresholdProfileDigest,
        voterIdentity: candidate.ballotPackage.voterIdentity,
        voterRosterPosition: candidate.ballotPackage.voterRosterPosition,
    };

    if (
        witness.receiverShareVectors.length !== input.rosterEntries.length ||
        witness.shareCommitmentWitnesses.length !==
            input.rosterEntries.length ||
        witness.receiverPayloads.length !== input.rosterEntries.length
    ) {
        throw new RangeError(
            'Counted ballot witness must carry exactly one receiver witness for every roster entry.',
        );
    }

    expectedReceiverShareVectors.forEach(
        (expectedShareVector, receiverIndex) => {
            const key = receiverKey(
                expectedShareVector.trusteeIdentity,
                expectedShareVector.trusteeRosterPosition,
            );
            const shareVector = shareVectorsByReceiver.get(key);
            const commitmentWitness = commitmentWitnessesByReceiver.get(key);
            const payload = receiverPayloadsByReceiver.get(key);
            const commitmentReference =
                candidate.ballotPackage.receiverShareCommitments[receiverIndex];
            const payloadReference =
                candidate.ballotPackage.receiverPayloadDigests[receiverIndex];

            if (
                shareVector === undefined ||
                commitmentWitness === undefined ||
                payload === undefined ||
                commitmentReference === undefined ||
                payloadReference === undefined
            ) {
                throw new RangeError(
                    'Counted ballot witness is missing receiver material for a counted package.',
                );
            }
            if (
                shareVector.optionCount !== expectedShareVector.optionCount ||
                shareVector.shareVectorWidth !==
                    expectedShareVector.shareVectorWidth ||
                !fieldVectorsEqual(
                    shareVector.shareVector,
                    expectedShareVector.shareVector,
                )
            ) {
                throw new RangeError(
                    'Counted ballot witness receiver shares do not match the counted package polynomial set.',
                );
            }
            if (
                commitmentReference.trusteeIdentity !==
                    expectedShareVector.trusteeIdentity ||
                commitmentReference.trusteeRosterPosition !==
                    expectedShareVector.trusteeRosterPosition ||
                payloadReference.receiverIdentity !==
                    expectedShareVector.trusteeIdentity ||
                payloadReference.receiverRosterPosition !==
                    expectedShareVector.trusteeRosterPosition
            ) {
                throw new RangeError(
                    'Counted ballot package receiver references do not match the frozen roster order.',
                );
            }

            const commitmentWithoutDigest = {
                objectType: commitmentWitness.commitment.objectType,
                trusteeIdentity: commitmentWitness.commitment.trusteeIdentity,
                trusteeRosterPosition:
                    commitmentWitness.commitment.trusteeRosterPosition,
                commitmentValues: commitmentWitness.commitment.commitmentValues,
            };
            const payloadWithoutDigest = {
                objectType: payload.objectType,
                receiverIdentity: payload.receiverIdentity,
                receiverRosterPosition: payload.receiverRosterPosition,
                shareVector: payload.shareVector,
                openingVector: payload.openingVector,
            };

            if (
                commitmentWitness.commitment.objectType !==
                    'TestShareCommitment' ||
                payload.objectType !== 'TestReceiverShareOpeningPayload' ||
                commitmentWitness.commitment.shareCommitmentDigest !==
                    deriveTestShareCommitmentDigest({
                        commitment: commitmentWithoutDigest,
                        context: digestContext,
                        ballotPolynomialSetDigest:
                            witness.polynomialSet.ballotPolynomialSetDigest,
                    }) ||
                payload.payloadDigest !==
                    deriveTestReceiverShareOpeningPayloadDigest({
                        context: digestContext,
                        payload: payloadWithoutDigest,
                    }) ||
                commitmentWitness.commitment.shareCommitmentDigest !==
                    commitmentReference.shareCommitmentDigest ||
                payload.payloadDigest !== payloadReference.payloadDigest ||
                !fieldVectorsEqual(
                    commitmentWitness.shareVector,
                    shareVector.shareVector,
                ) ||
                !fieldVectorsEqual(
                    payload.shareVector,
                    shareVector.shareVector,
                ) ||
                !fieldVectorsEqual(
                    payload.openingVector,
                    commitmentWitness.openingVector,
                ) ||
                !verifyTestShareCommitmentOpening(commitmentWitness)
            ) {
                throw new RangeError(
                    'Counted ballot witness receiver commitment material does not match the counted package digest references.',
                );
            }
        },
    );
};

const assertCountedWitnessMatchesPackage = (input: {
    readonly candidate: CountedBallotPackage;
    readonly witness: BallotPackageWitness;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): void => {
    if (
        input.witness.ballotPackage.ballotPackageDigest !==
            input.candidate.ballotPackage.ballotPackageDigest ||
        !sameCanonicalObject(
            input.witness.ballotPackage,
            input.candidate.ballotPackage,
        )
    ) {
        throw new RangeError(
            'Counted ballot witness package shell does not match the counted ballot package.',
        );
    }

    assertPolynomialSetMatchesPackage(
        input.candidate,
        input.witness,
        input.thresholdProfile,
    );
    assertReceiverWitnessesMatchPackage(input);
};

const buildWitnessByDigest = (
    ballotWitnesses: readonly BallotPackageWitness[],
): Map<string, BallotPackageWitness> => {
    const witnessByDigest = new Map<string, BallotPackageWitness>();
    const canonicalShellByDigest = new Map<string, string>();

    for (const witness of ballotWitnesses) {
        const ballotPackageDigest = witness.ballotPackage.ballotPackageDigest;
        const canonicalShell = canonicalJson(witness.ballotPackage);
        const previousCanonicalShell =
            canonicalShellByDigest.get(ballotPackageDigest);

        if (
            previousCanonicalShell !== undefined &&
            previousCanonicalShell !== canonicalShell
        ) {
            throw new RangeError(
                'Aggregate share derivation rejects non-identical witness package shells with the same digest.',
            );
        }
        canonicalShellByDigest.set(ballotPackageDigest, canonicalShell);
        if (!witnessByDigest.has(ballotPackageDigest)) {
            witnessByDigest.set(ballotPackageDigest, witness);
        }
    }

    return witnessByDigest;
};

export const deriveAggregateShareCommitmentDigest = (input: {
    readonly aggregateShare: Omit<
        TestAggregateShare,
        'aggregateShareCommitmentDigest'
    >;
    readonly ballotSetDigest: string;
}): string =>
    deriveProtocolDigest('AggregateShareCommitmentDigest', {
        aggregateCommitmentValues:
            input.aggregateShare.aggregateCommitmentValues,
        aggregateShareVector: input.aggregateShare.aggregateShareVector,
        ballotSetDigest: input.ballotSetDigest,
        objectType: input.aggregateShare.objectType,
        shareVectorWidth: input.aggregateShare.shareVectorWidth,
        trusteeIdentity: input.aggregateShare.trusteeIdentity,
        trusteeRosterPosition: input.aggregateShare.trusteeRosterPosition,
    });

export const deriveTestAggregateShares = (input: {
    readonly ballotSet: CanonicalBallotSet;
    readonly ballotWitnesses: readonly BallotPackageWitness[];
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): TestAggregateShareSet => {
    requireNoRefusals(
        validateRosterEntries(input.rosterEntries, input.thresholdProfile),
    );
    if (!input.ballotSet.ok || input.ballotSet.ballotSetDigest === undefined) {
        throw new RangeError(
            'Aggregate share derivation requires an accepted canonical ballot set.',
        );
    }
    const ballotSetDigest = input.ballotSet.ballotSetDigest;

    const witnessByDigest = buildWitnessByDigest(input.ballotWitnesses);
    const countedWitnesses = input.ballotSet.countedBallots.map((candidate) => {
        const witness = witnessByDigest.get(
            candidate.ballotPackage.ballotPackageDigest,
        );
        if (witness === undefined) {
            throw new RangeError(
                'Aggregate share derivation requires witnesses for every counted ballot.',
            );
        }

        assertCountedWitnessMatchesPackage({
            candidate,
            witness,
            rosterEntries: input.rosterEntries,
            thresholdProfile: input.thresholdProfile,
        });

        return witness;
    });

    const aggregateShares = sortRosterEntries(input.rosterEntries).map(
        (entry): TestAggregateShareWitness => {
            let aggregateShareVector = zeroShareVector();
            let aggregateOpeningVector = zeroShareVector();
            let aggregateCommitmentValues = zeroShareVector();

            for (const witness of countedWitnesses) {
                const share = witness.receiverShareVectors.find(
                    (candidate) =>
                        candidate.trusteeIdentity ===
                            entry.participantIdentity &&
                        candidate.trusteeRosterPosition ===
                            entry.rosterPosition,
                );
                const commitmentWitness = witness.shareCommitmentWitnesses.find(
                    (candidate) =>
                        candidate.commitment.trusteeIdentity ===
                            entry.participantIdentity &&
                        candidate.commitment.trusteeRosterPosition ===
                            entry.rosterPosition,
                );

                if (share === undefined || commitmentWitness === undefined) {
                    throw new RangeError(
                        'Aggregate share derivation requires every counted ballot to carry every receiver share.',
                    );
                }
                if (!verifyTestShareCommitmentOpening(commitmentWitness)) {
                    throw new RangeError(
                        'Aggregate share derivation requires valid test commitment openings.',
                    );
                }

                aggregateShareVector = addShareVectors(
                    aggregateShareVector,
                    share.shareVector,
                );
                aggregateOpeningVector = addShareVectors(
                    aggregateOpeningVector,
                    commitmentWitness.openingVector,
                );
                aggregateCommitmentValues = addShareVectors(
                    aggregateCommitmentValues,
                    commitmentWitness.commitment.commitmentValues,
                );
            }

            const aggregateShareWithoutDigest = {
                objectType: 'TestAggregateShare' as const,
                trusteeIdentity: entry.participantIdentity,
                trusteeRosterPosition: entry.rosterPosition,
                shareVectorWidth: pvssBallotShareVectorWidth,
                aggregateShareVector,
                aggregateCommitmentValues,
            };

            return {
                aggregateOpeningVector,
                aggregateShare: {
                    ...aggregateShareWithoutDigest,
                    aggregateShareCommitmentDigest:
                        deriveAggregateShareCommitmentDigest({
                            aggregateShare: aggregateShareWithoutDigest,
                            ballotSetDigest,
                        }),
                },
            };
        },
    );

    return {
        ballotSetDigest,
        aggregateShares,
    };
};

export const verifyTestAggregateShareOpening = (
    witness: TestAggregateShareWitness,
): boolean => {
    if (
        witness.aggregateOpeningVector.length !== pvssBallotShareVectorWidth ||
        witness.aggregateShare.aggregateShareVector.length !==
            pvssBallotShareVectorWidth ||
        witness.aggregateShare.aggregateCommitmentValues.length !==
            pvssBallotShareVectorWidth
    ) {
        return false;
    }

    return witness.aggregateShare.aggregateShareVector.every(
        (fieldElement, fieldIndex) =>
            addFieldElements(
                fieldElement,
                normalizeFieldElement(
                    witness.aggregateOpeningVector[fieldIndex] ?? 0,
                ),
            ) === witness.aggregateShare.aggregateCommitmentValues[fieldIndex],
    );
};

export const reconstructAggregateTallyFromShares = (input: {
    readonly aggregateShares: readonly TestAggregateShare[];
    readonly optionCount: number;
    readonly thresholdProfile: ThresholdProfile;
}): readonly FieldElement[] => {
    if (input.aggregateShares.length !== input.thresholdProfile.pvssThreshold) {
        throw new RangeError(
            'Aggregate reconstruction requires exactly the PVSS threshold number of shares.',
        );
    }
    if (
        input.optionCount < 1 ||
        input.optionCount > pvssBallotShareVectorWidth
    ) {
        throw new RangeError(
            'Aggregate reconstruction requires a valid option count.',
        );
    }

    const seenRosterPositions = new Set<number>();
    for (const aggregateShare of input.aggregateShares) {
        if (seenRosterPositions.has(aggregateShare.trusteeRosterPosition)) {
            throw new RangeError(
                'Aggregate reconstruction requires distinct trustee positions.',
            );
        }
        seenRosterPositions.add(aggregateShare.trusteeRosterPosition);
        if (
            aggregateShare.shareVectorWidth !== pvssBallotShareVectorWidth ||
            aggregateShare.aggregateShareVector.length !==
                pvssBallotShareVectorWidth
        ) {
            throw new RangeError(
                'Aggregate reconstruction requires fixed-width aggregate shares.',
            );
        }
        aggregateShare.aggregateShareVector.forEach(
            (fieldElement, fieldIndex) =>
                assertCanonicalFieldElement(
                    fieldElement,
                    `aggregate share field ${String(fieldIndex)}`,
                ),
        );
    }

    return Array.from({ length: input.optionCount }, (_unused, optionIndex) =>
        interpolateShamirConstantTerm(
            input.aggregateShares.map((share) => ({
                rosterPosition: share.trusteeRosterPosition,
                value: share.aggregateShareVector[optionIndex] ?? 0,
            })),
        ),
    );
};
