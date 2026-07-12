import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

const witnessCount = foundationProfile.participantCount - 1;
const witnessQuorum = foundationProfile.stateWitnessQuorum;
const byzantineWitnessCount = foundationProfile.activeFaultBound;
const witnessPositions = Array.from(
    { length: witnessCount },
    (_, witnessPosition) => witnessPosition,
);
const maximumUnsigned64 = (1n << 64n) - 1n;

const combinations = <Value>(
    values: readonly Value[],
    selectedCount: number,
): Value[][] => {
    const selectedValues: Value[][] = [];

    const visit = (startIndex: number, prefix: readonly Value[]): void => {
        if (prefix.length === selectedCount) {
            selectedValues.push([...prefix]);
            return;
        }
        const remainingSelectionCount = selectedCount - prefix.length;
        for (
            let valueIndex = startIndex;
            valueIndex <= values.length - remainingSelectionCount;
            valueIndex += 1
        ) {
            visit(valueIndex + 1, [...prefix, values[valueIndex]]);
        }
    };

    visit(0, []);
    return selectedValues;
};

const intersection = (
    leftPositions: readonly number[],
    rightPositions: readonly number[],
): number[] => {
    const rightPositionSet = new Set(rightPositions);
    return leftPositions.filter((position) => rightPositionSet.has(position));
};

const difference = (
    positions: readonly number[],
    removedPositions: readonly number[],
): number[] => {
    const removedPositionSet = new Set(removedPositions);
    return positions.filter((position) => !removedPositionSet.has(position));
};

type ConflictingBranch = 'first' | 'second';
type RecoveryPreservation = ConflictingBranch | 'empty';

type StableWitnessState = Readonly<{
    outputBranch?: ConflictingBranch;
    recoveryVote?: RecoveryPreservation;
    reservationBranch?: ConflictingBranch;
}>;

type SafetyModelState = Readonly<{
    certifiedOutputBranches: readonly ConflictingBranch[];
    stableWitnesses: readonly StableWitnessState[];
}>;

type SafetyModelOperation =
    | Readonly<{
          branch: ConflictingBranch;
          kind: 'reservation';
      }>
    | Readonly<{
          branch: ConflictingBranch;
          kind: 'output';
      }>
    | Readonly<{
          kind: 'recovery';
          preservation: RecoveryPreservation;
      }>;

const safetyModelOperations: readonly SafetyModelOperation[] = [
    { branch: 'first', kind: 'reservation' },
    { branch: 'second', kind: 'reservation' },
    { branch: 'first', kind: 'output' },
    { branch: 'second', kind: 'output' },
    { kind: 'recovery', preservation: 'first' },
    { kind: 'recovery', preservation: 'second' },
    { kind: 'recovery', preservation: 'empty' },
];

const stableWitnessCanLock = (
    witnessState: StableWitnessState,
    operation: SafetyModelOperation,
): boolean => {
    if (operation.kind === 'reservation') {
        return (
            (witnessState.reservationBranch === undefined ||
                witnessState.reservationBranch === operation.branch) &&
            (witnessState.outputBranch === undefined ||
                witnessState.outputBranch === operation.branch)
        );
    }
    if (operation.kind === 'output') {
        return (
            witnessState.reservationBranch === operation.branch &&
            (witnessState.outputBranch === undefined ||
                witnessState.outputBranch === operation.branch)
        );
    }
    if (
        witnessState.recoveryVote !== undefined &&
        witnessState.recoveryVote !== operation.preservation
    ) {
        return false;
    }
    if (operation.preservation === 'empty') {
        return (
            witnessState.reservationBranch === undefined &&
            witnessState.outputBranch === undefined
        );
    }

    return (
        (witnessState.reservationBranch === undefined ||
            witnessState.reservationBranch === operation.preservation) &&
        (witnessState.outputBranch === undefined ||
            witnessState.outputBranch === operation.preservation)
    );
};

const lockStableWitness = (
    witnessState: StableWitnessState,
    operation: SafetyModelOperation,
): StableWitnessState => {
    if (operation.kind === 'reservation') {
        return {
            ...witnessState,
            reservationBranch: operation.branch,
        };
    }
    if (operation.kind === 'output') {
        return {
            ...witnessState,
            outputBranch: operation.branch,
        };
    }
    if (operation.preservation === 'empty') {
        return {
            ...witnessState,
            recoveryVote: operation.preservation,
        };
    }

    return {
        ...witnessState,
        recoveryVote: operation.preservation,
        reservationBranch:
            witnessState.reservationBranch ?? operation.preservation,
    };
};

const encodeSafetyModelState = (state: SafetyModelState): string =>
    JSON.stringify({
        certifiedOutputBranches: [...state.certifiedOutputBranches].sort(),
        stableWitnesses: state.stableWitnesses.map((witnessState) => [
            witnessState.reservationBranch ?? '-',
            witnessState.outputBranch ?? '-',
            witnessState.recoveryVote ?? '-',
        ]),
    });

describe('Non-forking state executable safety model', () => {
    it('checks every producer-sequence boundary used by adjacent epochs', () => {
        const deriveProducerSequence = (
            voteKind: 'output' | 'recovery' | 'reservation',
            subjectEpoch: bigint,
        ): bigint | undefined => {
            const sequence =
                voteKind === 'reservation'
                    ? 3n * subjectEpoch + 1n
                    : voteKind === 'output'
                      ? 3n * subjectEpoch + 2n
                      : 3n * subjectEpoch;

            return sequence <= maximumUnsigned64 ? sequence : undefined;
        };

        let checkedEpochCount = 0;
        for (let epoch = 0n; epoch < 10_000n; epoch += 1n) {
            const reservationSequence = deriveProducerSequence(
                'reservation',
                epoch,
            );
            const outputSequence = deriveProducerSequence('output', epoch);
            const nextRecoverySequence = deriveProducerSequence(
                'recovery',
                epoch + 1n,
            );
            const nextReservationSequence = deriveProducerSequence(
                'reservation',
                epoch + 1n,
            );
            const actualSequences = [
                reservationSequence,
                outputSequence,
                nextRecoverySequence,
                nextReservationSequence,
            ];
            const expectedSequences = [
                3n * epoch + 1n,
                3n * epoch + 2n,
                3n * epoch + 3n,
                3n * epoch + 4n,
            ];
            if (
                actualSequences.some(
                    (sequence, sequenceIndex) =>
                        sequence !== expectedSequences[sequenceIndex],
                )
            ) {
                throw new Error(
                    'State witness producer sequences are not contiguous across an epoch boundary.',
                );
            }
            checkedEpochCount += 1;
        }
        expect(checkedEpochCount).toBe(10_000);

        const largestOutputEpoch = (maximumUnsigned64 - 2n) / 3n;
        expect(
            deriveProducerSequence('output', largestOutputEpoch),
        ).toBeLessThanOrEqual(maximumUnsigned64);
        expect(
            deriveProducerSequence('output', largestOutputEpoch + 1n),
        ).toBeUndefined();
        const largestRecoveryEpoch = maximumUnsigned64 / 3n;
        expect(
            deriveProducerSequence('recovery', largestRecoveryEpoch),
        ).toBeLessThanOrEqual(maximumUnsigned64);
        expect(
            deriveProducerSequence('recovery', largestRecoveryEpoch + 1n),
        ).toBeUndefined();
    });

    it('exhausts every allowed quorum and independent-failure assignment', () => {
        const quorums = combinations(witnessPositions, witnessQuorum);
        const byzantineWitnessSets = combinations(
            witnessPositions,
            byzantineWitnessCount,
        );
        let checkedAssignments = 0;
        let minimumStableHonestIntersection = witnessCount;

        for (const byzantineWitnesses of byzantineWitnessSets) {
            const possibleAdditionalFailures = difference(
                witnessPositions,
                byzantineWitnesses,
            );
            for (const additionalFailedWitness of possibleAdditionalFailures) {
                const unreliableWitnesses = [
                    ...byzantineWitnesses,
                    additionalFailedWitness,
                ];
                for (const firstQuorum of quorums) {
                    for (const secondQuorum of quorums) {
                        const stableHonestIntersection = difference(
                            intersection(firstQuorum, secondQuorum),
                            unreliableWitnesses,
                        );
                        minimumStableHonestIntersection = Math.min(
                            minimumStableHonestIntersection,
                            stableHonestIntersection.length,
                        );
                        if (stableHonestIntersection.length === 0) {
                            throw new Error(
                                'Allowed witness failures admitted conflicting quorum certificates.',
                            );
                        }
                        checkedAssignments += 1;
                    }
                }
            }
        }

        expect(checkedAssignments).toBe(653_184);
        expect(minimumStableHonestIntersection).toBe(1);
        expect(
            witnessCount - byzantineWitnessCount,
            'Byzantine withholding must leave fewer witnesses than the quorum.',
        ).toBeLessThan(witnessQuorum);
    });

    it('finds the declared boundary when two additional failure domains can fork', () => {
        const quorums = combinations(witnessPositions, witnessQuorum);
        let counterexample:
            | Readonly<{
                  byzantineWitnesses: readonly number[];
                  additionalFailedWitnesses: readonly number[];
                  firstQuorum: readonly number[];
                  secondQuorum: readonly number[];
              }>
            | undefined;

        search: for (const byzantineWitnesses of combinations(
            witnessPositions,
            byzantineWitnessCount,
        )) {
            for (const additionalFailedWitnesses of combinations(
                difference(witnessPositions, byzantineWitnesses),
                2,
            )) {
                const unreliableWitnesses = [
                    ...byzantineWitnesses,
                    ...additionalFailedWitnesses,
                ];
                for (const firstQuorum of quorums) {
                    for (const secondQuorum of quorums) {
                        if (
                            difference(
                                intersection(firstQuorum, secondQuorum),
                                unreliableWitnesses,
                            ).length === 0
                        ) {
                            counterexample = {
                                byzantineWitnesses,
                                additionalFailedWitnesses,
                                firstQuorum,
                                secondQuorum,
                            };
                            break search;
                        }
                    }
                }
            }
        }

        expect(counterexample).toBeDefined();
        expect(counterexample?.firstQuorum).not.toEqual(
            counterexample?.secondQuorum,
        );
    });

    it('explores partial locks, conflicting outputs, and recovery preservation', () => {
        const stableWitnessCount = witnessCount - byzantineWitnessCount - 1;
        const minimumStableWitnessesPerCertificate =
            witnessQuorum - byzantineWitnessCount - 1;
        const stableWitnessPositions = Array.from(
            { length: stableWitnessCount },
            (_, witnessPosition) => witnessPosition,
        );
        const lockSubsets = [
            ...combinations(stableWitnessPositions, 1),
            ...combinations(
                stableWitnessPositions,
                minimumStableWitnessesPerCertificate,
            ),
        ];
        let currentStates = new Map<string, SafetyModelState>();
        const initialState: SafetyModelState = {
            certifiedOutputBranches: [],
            stableWitnesses: Array.from(
                { length: stableWitnessCount },
                () => ({}),
            ),
        };
        currentStates.set(encodeSafetyModelState(initialState), initialState);
        let exploredTransitionCount = 0;
        let reachedCertifiedOutput = false;

        for (let scheduleDepth = 0; scheduleDepth < 5; scheduleDepth += 1) {
            const nextStates = new Map<string, SafetyModelState>();
            for (const state of currentStates.values()) {
                for (const operation of safetyModelOperations) {
                    for (const lockSubset of lockSubsets) {
                        if (
                            !lockSubset.every((witnessPosition) =>
                                stableWitnessCanLock(
                                    state.stableWitnesses[witnessPosition],
                                    operation,
                                ),
                            )
                        ) {
                            continue;
                        }
                        const stableWitnesses = state.stableWitnesses.map(
                            (witnessState, witnessPosition) =>
                                lockSubset.includes(witnessPosition)
                                    ? lockStableWitness(witnessState, operation)
                                    : witnessState,
                        );
                        const operationCanCertify =
                            lockSubset.length >=
                            minimumStableWitnessesPerCertificate;
                        const certifiedOutputBranches =
                            operation.kind === 'output' && operationCanCertify
                                ? [
                                      ...new Set([
                                          ...state.certifiedOutputBranches,
                                          operation.branch,
                                      ]),
                                  ]
                                : state.certifiedOutputBranches;
                        if (certifiedOutputBranches.length > 1) {
                            throw new Error(
                                'The executable state model certified conflicting exact outputs.',
                            );
                        }
                        reachedCertifiedOutput ||=
                            certifiedOutputBranches.length > 0;
                        const nextState = {
                            certifiedOutputBranches,
                            stableWitnesses,
                        } satisfies SafetyModelState;
                        nextStates.set(
                            encodeSafetyModelState(nextState),
                            nextState,
                        );
                        exploredTransitionCount += 1;
                    }
                }
            }
            currentStates = nextStates;
        }

        expect(reachedCertifiedOutput).toBe(true);
        expect(exploredTransitionCount).toBeGreaterThan(10_000);
    });
});
