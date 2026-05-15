import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPackageWitness,
    CanonicalBallotSet,
    FieldElement,
    PvssBallotRosterEntry,
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

import {
    pvssBallotShareVectorWidth,
    requireNoRefusals,
    sortRosterEntries,
    validateRosterEntries,
} from './common.js';
import { addShareVectors } from './receiver-shares.js';
import { verifyTestShareCommitmentOpening } from './test-share-commitments.js';

const zeroShareVector = (): readonly FieldElement[] =>
    Array.from({ length: pvssBallotShareVectorWidth }, () => 0 as FieldElement);

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

    const witnessByDigest = new Map(
        input.ballotWitnesses.map((witness) => [
            witness.ballotPackage.ballotPackageDigest,
            witness,
        ]),
    );
    const countedWitnesses = input.ballotSet.countedBallots.map((candidate) => {
        const witness = witnessByDigest.get(
            candidate.ballotPackage.ballotPackageDigest,
        );
        if (witness === undefined) {
            throw new RangeError(
                'Aggregate share derivation requires witnesses for every counted ballot.',
            );
        }

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
