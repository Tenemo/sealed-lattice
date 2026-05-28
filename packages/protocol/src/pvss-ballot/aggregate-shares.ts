import { canonicalJson, deriveProtocolHash } from '@sealed-lattice/crypto';
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

import { deriveBallotPolynomialSetHash } from './ballot-polynomials.js';
import { deriveBallotSetHashFromCanonicalSet } from './ballot-set.js';
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
    deriveTestReceiverShareOpeningPayloadHash,
    deriveTestShareCommitmentHash,
    verifyTestShareCommitmentOpening,
} from './test-share-commitments.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;

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
    receiverIdentity: string,
    receiverRosterPosition: number,
): string => [receiverIdentity, receiverRosterPosition].join('\u0000');

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
    const recomputedPolynomialSetHash = deriveBallotPolynomialSetHash({
        normalizedBallot: polynomialSet.normalizedBallot,
        optionPolynomials: polynomialSet.optionPolynomials,
        pvssThreshold: polynomialSet.pvssThreshold,
    });

    if (
        polynomialSet.ballotPolynomialSetHash !== recomputedPolynomialSetHash ||
        polynomialSet.ballotPolynomialSetHash !==
            candidate.ballotPackage.ballotPolynomialSetHash
    ) {
        throw new RangeError(
            'Counted ballot witness polynomial set does not match the counted package hash.',
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
                shareVector.receiverIdentity,
                shareVector.receiverRosterPosition,
            ),
        'Counted ballot witness receiver shares must be unique.',
    );
    const commitmentWitnessesByReceiver =
        buildUniqueMap<TestShareCommitmentWitness>(
            witness.shareCommitmentWitnesses,
            (commitmentWitness) =>
                receiverKey(
                    commitmentWitness.commitment.receiverIdentity,
                    commitmentWitness.commitment.receiverRosterPosition,
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
    const hashContext = {
        ceremonyId: candidate.ballotPackage.ceremonyId,
        duplicateBallotPolicyHash:
            candidate.ballotPackage.duplicateBallotPolicyHash,
        electionManifestHash: candidate.ballotPackage.electionManifestHash,
        pollSpecHash: candidate.ballotPackage.pollSpecHash,
        rosterHash: candidate.ballotPackage.rosterHash,
        thresholdProfileHash: candidate.ballotPackage.thresholdProfileHash,
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
                expectedShareVector.receiverIdentity,
                expectedShareVector.receiverRosterPosition,
            );
            const shareVector = shareVectorsByReceiver.get(key);
            const commitmentWitness = commitmentWitnessesByReceiver.get(key);
            const payload = receiverPayloadsByReceiver.get(key);
            const commitmentReference =
                candidate.ballotPackage.receiverShareCommitments[receiverIndex];
            const payloadReference =
                candidate.ballotPackage.receiverPayloadHashes[receiverIndex];

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
                commitmentReference.receiverIdentity !==
                    expectedShareVector.receiverIdentity ||
                commitmentReference.receiverRosterPosition !==
                    expectedShareVector.receiverRosterPosition ||
                payloadReference.receiverIdentity !==
                    expectedShareVector.receiverIdentity ||
                payloadReference.receiverRosterPosition !==
                    expectedShareVector.receiverRosterPosition
            ) {
                throw new RangeError(
                    'Counted ballot package receiver references do not match the frozen roster order.',
                );
            }

            const commitmentWithoutHash = {
                objectType: commitmentWitness.commitment.objectType,
                receiverIdentity: commitmentWitness.commitment.receiverIdentity,
                receiverRosterPosition:
                    commitmentWitness.commitment.receiverRosterPosition,
                commitmentValues: commitmentWitness.commitment.commitmentValues,
            };
            const payloadWithoutHash = {
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
                commitmentWitness.commitment.shareCommitmentHash !==
                    deriveTestShareCommitmentHash({
                        commitment: commitmentWithoutHash,
                        context: hashContext,
                        ballotPolynomialSetHash:
                            witness.polynomialSet.ballotPolynomialSetHash,
                    }) ||
                payload.payloadHash !==
                    deriveTestReceiverShareOpeningPayloadHash({
                        context: hashContext,
                        payload: payloadWithoutHash,
                    }) ||
                commitmentWitness.commitment.shareCommitmentHash !==
                    commitmentReference.shareCommitmentHash ||
                payload.payloadHash !== payloadReference.payloadHash ||
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
                    'Counted ballot witness receiver commitment material does not match the counted package hash references.',
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
        input.witness.ballotPackage.ballotPackageHash !==
            input.candidate.ballotPackage.ballotPackageHash ||
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

const buildWitnessByHash = (
    ballotWitnesses: readonly BallotPackageWitness[],
): Map<string, BallotPackageWitness> => {
    const witnessByHash = new Map<string, BallotPackageWitness>();
    const canonicalShellByHash = new Map<string, string>();

    for (const witness of ballotWitnesses) {
        const ballotPackageHash = witness.ballotPackage.ballotPackageHash;
        const canonicalShell = canonicalJson(witness.ballotPackage);
        const previousCanonicalShell =
            canonicalShellByHash.get(ballotPackageHash);

        if (
            previousCanonicalShell !== undefined &&
            previousCanonicalShell !== canonicalShell
        ) {
            throw new RangeError(
                'Aggregate share derivation rejects non-identical witness package shells with the same hash.',
            );
        }
        canonicalShellByHash.set(ballotPackageHash, canonicalShell);
        if (!witnessByHash.has(ballotPackageHash)) {
            witnessByHash.set(ballotPackageHash, witness);
        }
    }

    return witnessByHash;
};

const deriveAggregateShareCommitmentHash = (input: {
    readonly aggregateShare: Omit<
        TestAggregateShare,
        'aggregateShareCommitmentHash'
    >;
    readonly ballotSetHash: string;
}): string =>
    deriveProtocolHash('AggregateShareCommitmentHash', {
        aggregateCommitmentValues:
            input.aggregateShare.aggregateCommitmentValues,
        aggregateShareVector: input.aggregateShare.aggregateShareVector,
        ballotSetHash: input.ballotSetHash,
        objectType: input.aggregateShare.objectType,
        shareVectorWidth: input.aggregateShare.shareVectorWidth,
        trusteeIdentity: input.aggregateShare.trusteeIdentity,
        trusteeRosterPosition: input.aggregateShare.trusteeRosterPosition,
    });

const assertAcceptedBallotSetHashMatchesPayload = (
    ballotSet: CanonicalBallotSet,
): string => {
    if (!ballotSet.ok || ballotSet.ballotSetHash === undefined) {
        throw new RangeError(
            'Aggregate share derivation requires an accepted canonical ballot set.',
        );
    }

    const expectedHash = deriveBallotSetHashFromCanonicalSet(ballotSet);
    if (ballotSet.ballotSetHash !== expectedHash) {
        throw new RangeError(
            'Aggregate share derivation requires the counted ballots to match the canonical ballot-set hash.',
        );
    }

    return ballotSet.ballotSetHash;
};

export const deriveTestAggregateShares = (input: {
    readonly ballotSet: CanonicalBallotSet;
    readonly ballotWitnesses: readonly BallotPackageWitness[];
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): TestAggregateShareSet => {
    requireNoRefusals(
        validateRosterEntries(input.rosterEntries, input.thresholdProfile),
    );
    const ballotSetHash = assertAcceptedBallotSetHashMatchesPayload(
        input.ballotSet,
    );

    const witnessByHash = buildWitnessByHash(input.ballotWitnesses);
    const countedWitnesses = input.ballotSet.countedBallots.map((candidate) => {
        const witness = witnessByHash.get(
            candidate.ballotPackage.ballotPackageHash,
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
                        candidate.receiverIdentity ===
                            entry.participantIdentity &&
                        candidate.receiverRosterPosition ===
                            entry.rosterPosition,
                );
                const commitmentWitness = witness.shareCommitmentWitnesses.find(
                    (candidate) =>
                        candidate.commitment.receiverIdentity ===
                            entry.participantIdentity &&
                        candidate.commitment.receiverRosterPosition ===
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

            const aggregateShareWithoutHash = {
                objectType: 'TestAggregateShare' as const,
                ballotSetHash,
                trusteeIdentity: entry.participantIdentity,
                trusteeRosterPosition: entry.rosterPosition,
                shareVectorWidth: pvssBallotShareVectorWidth,
                aggregateShareVector,
                aggregateCommitmentValues,
            };

            return {
                aggregateOpeningVector,
                aggregateShare: {
                    ...aggregateShareWithoutHash,
                    aggregateShareCommitmentHash:
                        deriveAggregateShareCommitmentHash({
                            aggregateShare: aggregateShareWithoutHash,
                            ballotSetHash,
                        }),
                },
            };
        },
    );

    return {
        ballotSetHash,
        aggregateShares,
    };
};

export const verifyTestAggregateShareOpening = (
    witness: TestAggregateShareWitness,
): boolean => {
    if (
        witness.aggregateShare.objectType !== 'TestAggregateShare' ||
        !protocolHashPattern.test(witness.aggregateShare.ballotSetHash) ||
        !protocolHashPattern.test(
            witness.aggregateShare.aggregateShareCommitmentHash,
        ) ||
        witness.aggregateOpeningVector.length !== pvssBallotShareVectorWidth ||
        witness.aggregateShare.aggregateShareVector.length !==
            pvssBallotShareVectorWidth ||
        witness.aggregateShare.aggregateCommitmentValues.length !==
            pvssBallotShareVectorWidth
    ) {
        return false;
    }

    try {
        return witness.aggregateShare.aggregateShareVector.every(
            (fieldElement, fieldIndex) => {
                assertCanonicalFieldElement(
                    fieldElement,
                    `aggregate share field ${String(fieldIndex)}`,
                );
                assertCanonicalFieldElement(
                    witness.aggregateOpeningVector[fieldIndex] ?? 0,
                    `aggregate opening field ${String(fieldIndex)}`,
                );
                assertCanonicalFieldElement(
                    witness.aggregateShare.aggregateCommitmentValues[
                        fieldIndex
                    ] ?? 0,
                    `aggregate commitment field ${String(fieldIndex)}`,
                );

                return (
                    addFieldElements(
                        fieldElement,
                        normalizeFieldElement(
                            witness.aggregateOpeningVector[fieldIndex] ?? 0,
                        ),
                    ) ===
                    witness.aggregateShare.aggregateCommitmentValues[fieldIndex]
                );
            },
        );
    } catch {
        return false;
    }
};

export const reconstructAggregateTallyFromShares = (input: {
    readonly aggregateShares: readonly TestAggregateShare[];
    readonly ballotSetHash?: string;
    readonly optionCount: number;
    readonly thresholdProfile: ThresholdProfile;
}): readonly FieldElement[] => {
    if (input.aggregateShares.length !== input.thresholdProfile.pvssThreshold) {
        throw new RangeError(
            'Aggregate reconstruction requires exactly the PVSS threshold number of shares.',
        );
    }
    if (
        input.ballotSetHash !== undefined &&
        !protocolHashPattern.test(input.ballotSetHash)
    ) {
        throw new RangeError(
            'Aggregate reconstruction requires a canonical expected ballot-set hash.',
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
    const ballotSetHashes = new Set<string>();
    for (const aggregateShare of input.aggregateShares) {
        if (
            aggregateShare.objectType !== 'TestAggregateShare' ||
            !protocolHashPattern.test(aggregateShare.ballotSetHash) ||
            !protocolHashPattern.test(
                aggregateShare.aggregateShareCommitmentHash,
            )
        ) {
            throw new RangeError(
                'Aggregate reconstruction requires shares bound to a canonical ballot set hash.',
            );
        }
        const aggregateShareWithoutHash = {
            objectType: aggregateShare.objectType,
            ballotSetHash: aggregateShare.ballotSetHash,
            trusteeIdentity: aggregateShare.trusteeIdentity,
            trusteeRosterPosition: aggregateShare.trusteeRosterPosition,
            shareVectorWidth: aggregateShare.shareVectorWidth,
            aggregateShareVector: aggregateShare.aggregateShareVector,
            aggregateCommitmentValues: aggregateShare.aggregateCommitmentValues,
        };
        if (
            aggregateShare.aggregateShareCommitmentHash !==
            deriveAggregateShareCommitmentHash({
                aggregateShare: aggregateShareWithoutHash,
                ballotSetHash: aggregateShare.ballotSetHash,
            })
        ) {
            throw new RangeError(
                'Aggregate reconstruction requires canonical aggregate share commitment Hashes.',
            );
        }
        ballotSetHashes.add(aggregateShare.ballotSetHash);
        if (
            input.ballotSetHash !== undefined &&
            aggregateShare.ballotSetHash !== input.ballotSetHash
        ) {
            throw new RangeError(
                'Aggregate reconstruction requires shares for the expected ballot set.',
            );
        }
        if (
            !Number.isSafeInteger(aggregateShare.trusteeRosterPosition) ||
            aggregateShare.trusteeRosterPosition < 1 ||
            aggregateShare.trusteeRosterPosition >
                input.thresholdProfile.rosterSize
        ) {
            throw new RangeError(
                'Aggregate reconstruction requires trustee positions within the frozen roster.',
            );
        }
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
        if (
            aggregateShare.aggregateShareVector
                .slice(input.optionCount)
                .some((fieldElement) => fieldElement !== 0)
        ) {
            throw new RangeError(
                'Aggregate reconstruction requires zero-padded aggregate share vectors.',
            );
        }
    }
    if (ballotSetHashes.size !== 1) {
        throw new RangeError(
            'Aggregate reconstruction requires all shares to bind the same ballot set.',
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
