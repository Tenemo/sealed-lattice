import { describe, expect, it } from 'vitest';

type SemanticTarget = Readonly<{
    actionIdentity: string;
    finalityPolicyIdentity: string;
    inputInventoryIdentity: string;
    outputOrdinal: number;
    predecessorIdentity: string;
    preparationIdentity: string;
    rosterIdentity: string;
    suiteAndCompilerIdentity: string;
}>;

type FinalitySignature = Readonly<{
    participantPosition: number;
    semanticTargetIdentity: string;
    signatureCarrier: string;
}>;

type FinalitySignerState = Readonly<{
    durableSignatureCarrier?: string;
    durableTargetIdentity?: string;
    participantPosition: number;
    retired: boolean;
}>;

type SigningCut =
    'before-persist' | 'after-persist-before-publish' | 'after-publish';

const independentlyToleratedHonestStateFailures = 1;

const corruptionThresholdForRoster = (participantCount: number): number =>
    Math.floor((participantCount - 1) / 3);

const minimumDirectFinalityQuorum = (participantCount: number): number =>
    Math.ceil(
        (participantCount +
            corruptionThresholdForRoster(participantCount) +
            independentlyToleratedHonestStateFailures +
            1) /
            2,
    );

const minimumQuorumIntersection = (
    participantCount: number,
    quorumSize: number,
): number => 2 * quorumSize - participantCount;

const minimumStableHonestIntersection = (
    participantCount: number,
    quorumSize: number,
): number =>
    minimumQuorumIntersection(participantCount, quorumSize) -
    corruptionThresholdForRoster(participantCount) -
    independentlyToleratedHonestStateFailures;

const chooseParticipantPositions = (
    participantPositions: readonly number[],
    selectionSize: number,
    startPosition = 0,
    prefix: number[] = [],
    selections: number[][] = [],
): readonly (readonly number[])[] => {
    if (prefix.length === selectionSize) {
        selections.push([...prefix]);
        return selections;
    }

    for (
        let position = startPosition;
        position <=
        participantPositions.length - (selectionSize - prefix.length);
        position += 1
    ) {
        prefix.push(participantPositions[position]);
        chooseParticipantPositions(
            participantPositions,
            selectionSize,
            position + 1,
            prefix,
            selections,
        );
        prefix.pop();
    }

    return selections;
};

const intersectParticipantPositions = (
    left: readonly number[],
    right: readonly number[],
): readonly number[] => {
    const rightPositions = new Set(right);
    return left.filter((position) => rightPositions.has(position));
};

const semanticTargetIdentity = (target: SemanticTarget): string =>
    JSON.stringify(target);

const deterministicSignatureCarrier = (
    participantPosition: number,
    targetIdentity: string,
): string => `signature:${String(participantPosition)}:${targetIdentity}`;

const attemptFinalitySignature = (
    state: FinalitySignerState,
    target: SemanticTarget,
    signingCut: SigningCut,
): Readonly<{
    publishedSignature?: FinalitySignature;
    refused: boolean;
    state: FinalitySignerState;
}> => {
    if (state.retired) return { refused: true, state };

    const targetIdentity = semanticTargetIdentity(target);
    if (
        state.durableTargetIdentity !== undefined &&
        state.durableTargetIdentity !== targetIdentity
    ) {
        return { refused: true, state };
    }

    if (signingCut === 'before-persist') {
        return { refused: false, state };
    }

    const signatureCarrier =
        state.durableSignatureCarrier ??
        deterministicSignatureCarrier(
            state.participantPosition,
            targetIdentity,
        );
    const durableState = {
        ...state,
        durableSignatureCarrier: signatureCarrier,
        durableTargetIdentity: targetIdentity,
    };
    if (signingCut === 'after-persist-before-publish') {
        return { refused: false, state: durableState };
    }

    return {
        publishedSignature: {
            participantPosition: state.participantPosition,
            semanticTargetIdentity: targetIdentity,
            signatureCarrier,
        },
        refused: false,
        state: durableState,
    };
};

const restoreFinalitySigner = (
    participantPosition: number,
    durableState: FinalitySignerState | undefined,
): FinalitySignerState =>
    durableState ?? { participantPosition, retired: true };

const verifyFinalityCertificate = (
    target: SemanticTarget,
    signatures: readonly FinalitySignature[],
    participantCount: number,
): Readonly<{ semanticTargetIdentity: string }> | undefined => {
    const targetIdentity = semanticTargetIdentity(target);
    const signerPositions = new Set<number>();
    for (const signature of signatures) {
        if (
            signature.participantPosition < 0 ||
            signature.participantPosition >= participantCount ||
            signature.semanticTargetIdentity !== targetIdentity ||
            signature.signatureCarrier !==
                deterministicSignatureCarrier(
                    signature.participantPosition,
                    targetIdentity,
                ) ||
            signerPositions.has(signature.participantPosition)
        ) {
            return undefined;
        }
        signerPositions.add(signature.participantPosition);
    }

    return signerPositions.size >= minimumDirectFinalityQuorum(participantCount)
        ? { semanticTargetIdentity: targetIdentity }
        : undefined;
};

const createTarget = (
    overrides: Partial<SemanticTarget> = {},
): SemanticTarget => ({
    actionIdentity: 'action',
    finalityPolicyIdentity: 'direct-finality-policy',
    inputInventoryIdentity: 'complete-input-inventory',
    outputOrdinal: 0,
    predecessorIdentity: 'predecessor',
    preparationIdentity: 'verified-preparation',
    rosterIdentity: 'roster',
    suiteAndCompilerIdentity: 'suite-and-compiler',
    ...overrides,
});

const createSignatures = (
    target: SemanticTarget,
    participantPositions: readonly number[],
): readonly FinalitySignature[] => {
    const targetIdentity = semanticTargetIdentity(target);
    return participantPositions.map((participantPosition) => ({
        participantPosition,
        semanticTargetIdentity: targetIdentity,
        signatureCarrier: deterministicSignatureCarrier(
            participantPosition,
            targetIdentity,
        ),
    }));
};

type ActionOutcome =
    | Readonly<{ kind: 'pending' }>
    | Readonly<{
          kind: 'verified-no-result';
          semanticTargetIdentity: string;
      }>
    | Readonly<{
          kind: 'verified-result';
          resultIdentity: string;
          semanticTargetIdentity: string;
      }>;

type OutcomeEvent =
    | Readonly<{ kind: 'invalid-contribution' }>
    | Readonly<{
          kind: 'finalized-empty-inventory';
          semanticTargetIdentity: string;
          usableBallotCount: number;
      }>
    | Readonly<{
          exactCodewordVerified: boolean;
          kind: 'result-candidate';
          resultIdentity: string;
          semanticTargetIdentity: string;
      }>;

const applyOutcomeEvent = (
    outcome: ActionOutcome,
    event: OutcomeEvent,
): ActionOutcome => {
    if (outcome.kind !== 'pending') return outcome;
    if (event.kind === 'invalid-contribution') return outcome;
    if (event.kind === 'finalized-empty-inventory') {
        return event.usableBallotCount === 0
            ? {
                  kind: 'verified-no-result',
                  semanticTargetIdentity: event.semanticTargetIdentity,
              }
            : outcome;
    }
    return event.exactCodewordVerified
        ? {
              kind: 'verified-result',
              resultIdentity: event.resultIdentity,
              semanticTargetIdentity: event.semanticTargetIdentity,
          }
        : outcome;
};

type VisitParticipantState = {
    finalitySigned: boolean;
    keyPublished: boolean;
    outputPublished: boolean;
    preparationPublished: boolean;
    recipientPassPublished: boolean;
    repairPublished: boolean;
    resultRetrieved: boolean;
    productiveVisitCount: number;
};

type VisitRelayState = {
    finalityCertificateAvailable: boolean;
    finalitySigners: Set<number>;
    keyPublishers: Set<number>;
    outputPublishers: Set<number>;
    preparationPublishers: Set<number>;
    recipientPassPublishers: Set<number>;
    repairPublishers: Set<number>;
    resultAvailable: boolean;
};

const runGeneratedVisitSchedule = (input: {
    allAbstain?: boolean;
    participantCount: number;
    requireRepair?: boolean;
    withholdOutputFrom?: number;
    withholdRecipientPassFrom?: number;
}): Readonly<{
    participantStates: readonly VisitParticipantState[];
    relayState: VisitRelayState;
}> => {
    const participantStates = Array.from(
        { length: input.participantCount },
        (): VisitParticipantState => ({
            finalitySigned: false,
            keyPublished: false,
            outputPublished: false,
            preparationPublished: false,
            recipientPassPublished: false,
            repairPublished: false,
            resultRetrieved: false,
            productiveVisitCount: 0,
        }),
    );
    const relayState: VisitRelayState = {
        finalityCertificateAvailable: false,
        finalitySigners: new Set(),
        keyPublishers: new Set(),
        outputPublishers: new Set(),
        preparationPublishers: new Set(),
        recipientPassPublishers: new Set(),
        repairPublishers: new Set(),
        resultAvailable: false,
    };

    const visit = (participantPosition: number): boolean => {
        const participantState = participantStates[participantPosition];
        let productive = false;

        if (!participantState.keyPublished) {
            participantState.keyPublished = true;
            relayState.keyPublishers.add(participantPosition);
            productive = true;
        } else if (
            relayState.keyPublishers.size === input.participantCount &&
            !participantState.preparationPublished
        ) {
            participantState.preparationPublished = true;
            relayState.preparationPublishers.add(participantPosition);
            productive = true;
        } else if (
            relayState.preparationPublishers.size === input.participantCount &&
            !participantState.recipientPassPublished &&
            input.withholdRecipientPassFrom !== participantPosition
        ) {
            participantState.recipientPassPublished = true;
            relayState.recipientPassPublishers.add(participantPosition);
            productive = true;
        } else if (
            relayState.recipientPassPublishers.size ===
                input.participantCount &&
            input.requireRepair === true &&
            !participantState.repairPublished
        ) {
            participantState.repairPublished = true;
            relayState.repairPublishers.add(participantPosition);
            productive = true;
        } else if (
            relayState.recipientPassPublishers.size ===
                input.participantCount &&
            (input.requireRepair !== true ||
                relayState.repairPublishers.size === input.participantCount) &&
            !participantState.finalitySigned
        ) {
            participantState.finalitySigned = true;
            relayState.finalitySigners.add(participantPosition);
            relayState.finalityCertificateAvailable =
                relayState.finalitySigners.size >=
                minimumDirectFinalityQuorum(input.participantCount);
            productive = true;
            if (
                relayState.finalityCertificateAvailable &&
                input.allAbstain !== true &&
                input.withholdOutputFrom !== participantPosition
            ) {
                participantState.outputPublished = true;
                relayState.outputPublishers.add(participantPosition);
            }
        } else if (
            relayState.finalityCertificateAvailable &&
            !participantState.outputPublished &&
            input.withholdOutputFrom !== participantPosition
        ) {
            participantState.outputPublished = true;
            relayState.outputPublishers.add(participantPosition);
            productive = true;
        }

        relayState.resultAvailable =
            (input.allAbstain === true &&
                relayState.finalityCertificateAvailable) ||
            relayState.outputPublishers.size === input.participantCount;
        if (relayState.resultAvailable && !participantState.resultRetrieved) {
            participantState.resultRetrieved = true;
            productive = true;
        }
        if (productive) participantState.productiveVisitCount += 1;
        return productive;
    };

    for (let visitWave = 0; visitWave < 8; visitWave += 1) {
        let waveWasProductive = false;
        for (
            let participantPosition = 0;
            participantPosition < input.participantCount;
            participantPosition += 1
        ) {
            waveWasProductive = visit(participantPosition) || waveWasProductive;
        }
        if (
            participantStates.every(
                (participantState) => participantState.resultRetrieved,
            ) ||
            !waveWasProductive
        ) {
            break;
        }
    }

    return { participantStates, relayState };
};

describe('direct finality quorum model', () => {
    it('derives the minimal quorum for every admitted roster size', () => {
        const derivedQuorums = [];
        for (
            let participantCount = 3;
            participantCount <= 20;
            participantCount += 1
        ) {
            const quorumSize = minimumDirectFinalityQuorum(participantCount);
            derivedQuorums.push(quorumSize);
            expect(
                minimumStableHonestIntersection(participantCount, quorumSize),
            ).toBeGreaterThanOrEqual(1);
            expect(
                minimumStableHonestIntersection(
                    participantCount,
                    quorumSize - 1,
                ),
            ).toBeLessThan(1);
        }

        expect(derivedQuorums).toEqual([
            3, 4, 4, 5, 6, 6, 7, 8, 8, 9, 10, 10, 11, 12, 12, 13, 14, 14,
        ]);
    });

    it('exhausts completion-roster quorum pairs, corrupt triples, and one honest rollback', () => {
        const participantCount = 10;
        const participantPositions = Array.from(
            { length: participantCount },
            (_value, participantPosition) => participantPosition,
        );
        const quorumSets = chooseParticipantPositions(
            participantPositions,
            minimumDirectFinalityQuorum(participantCount),
        );
        const corruptionSets = chooseParticipantPositions(
            participantPositions,
            corruptionThresholdForRoster(participantCount),
        );
        let casesChecked = 0;
        let minimumStableHonestSigners = participantCount;

        for (let leftIndex = 0; leftIndex < quorumSets.length; leftIndex += 1) {
            for (
                let rightIndex = leftIndex + 1;
                rightIndex < quorumSets.length;
                rightIndex += 1
            ) {
                const sharedSigners = intersectParticipantPositions(
                    quorumSets[leftIndex],
                    quorumSets[rightIndex],
                );
                for (const corruptionSet of corruptionSets) {
                    const corruptPositions = new Set(corruptionSet);
                    const sharedHonestSigners = sharedSigners.filter(
                        (position) => !corruptPositions.has(position),
                    );
                    for (const rolledBackSigner of sharedHonestSigners) {
                        const stableHonestSignerCount =
                            sharedHonestSigners.filter(
                                (position) => position !== rolledBackSigner,
                            ).length;
                        minimumStableHonestSigners = Math.min(
                            minimumStableHonestSigners,
                            stableHonestSignerCount,
                        );
                        casesChecked += 1;
                    }
                }
            }
        }

        expect(quorumSets).toHaveLength(45);
        expect(corruptionSets).toHaveLength(120);
        expect(casesChecked).toBeGreaterThan(0);
        expect(minimumStableHonestSigners).toBe(2);
    });

    it('shows why seven signatures fail after one honest rollback', () => {
        const leftQuorum = [0, 1, 2, 3, 4, 5, 6];
        const rightQuorum = [0, 1, 2, 3, 7, 8, 9];
        const corruptParticipants = new Set([0, 1, 2]);
        const rolledBackHonestSigner = 3;
        const stableHonestIntersection = intersectParticipantPositions(
            leftQuorum,
            rightQuorum,
        ).filter(
            (position) =>
                !corruptParticipants.has(position) &&
                position !== rolledBackHonestSigner,
        );

        expect(stableHonestIntersection).toEqual([]);
        expect(minimumDirectFinalityQuorum(10)).toBe(8);
    });
});

describe('direct finality signer state', () => {
    it('persists before publication and resumes only the identical signature', () => {
        const target = createTarget();
        const initialState: FinalitySignerState = {
            participantPosition: 4,
            retired: false,
        };

        const beforePersist = attemptFinalitySignature(
            initialState,
            target,
            'before-persist',
        );
        expect(beforePersist.publishedSignature).toBeUndefined();
        expect(beforePersist.state.durableTargetIdentity).toBeUndefined();

        const afterPersist = attemptFinalitySignature(
            initialState,
            target,
            'after-persist-before-publish',
        );
        expect(afterPersist.publishedSignature).toBeUndefined();
        expect(afterPersist.state.durableTargetIdentity).toBe(
            semanticTargetIdentity(target),
        );

        const resumed = attemptFinalitySignature(
            restoreFinalitySigner(4, afterPersist.state),
            target,
            'after-publish',
        );
        const replayed = attemptFinalitySignature(
            resumed.state,
            target,
            'after-publish',
        );
        expect(replayed.publishedSignature).toEqual(resumed.publishedSignature);
        expect(
            attemptFinalitySignature(
                replayed.state,
                createTarget({ predecessorIdentity: 'stale-predecessor' }),
                'after-publish',
            ).refused,
        ).toBe(true);
    });

    it('retires after missing durable state instead of repairing from relay claims', () => {
        const restored = restoreFinalitySigner(2, undefined);
        const signingAttempt = attemptFinalitySignature(
            restored,
            createTarget(),
            'after-publish',
        );

        expect(restored.retired).toBe(true);
        expect(signingAttempt.publishedSignature).toBeUndefined();
        expect(signingAttempt.refused).toBe(true);
    });

    it('binds the semantic target rather than a certificate carrier', () => {
        const target = createTarget();
        const firstCarrier = createSignatures(target, [0, 1, 2, 3, 4, 5, 6, 7]);
        const secondCarrier = createSignatures(
            target,
            [9, 8, 7, 6, 5, 4, 3, 2],
        );

        expect(verifyFinalityCertificate(target, firstCarrier, 10)).toEqual(
            verifyFinalityCertificate(target, secondCarrier, 10),
        );
        expect(
            verifyFinalityCertificate(
                target,
                [...firstCarrier.slice(0, 7), firstCarrier[0]],
                10,
            ),
        ).toBeUndefined();
        expect(
            verifyFinalityCertificate(
                target,
                [
                    ...firstCarrier.slice(0, 7),
                    ...createSignatures(
                        createTarget({ actionIdentity: 'other-action' }),
                        [8],
                    ),
                ],
                10,
            ),
        ).toBeUndefined();
    });
});

describe('post-finality outcome model', () => {
    it('keeps invalid or missing contributions pending', () => {
        const pending: ActionOutcome = { kind: 'pending' };

        expect(
            applyOutcomeEvent(pending, { kind: 'invalid-contribution' }),
        ).toEqual(pending);
        expect(
            applyOutcomeEvent(pending, {
                exactCodewordVerified: false,
                kind: 'result-candidate',
                resultIdentity: 'attacker-result',
                semanticTargetIdentity: 'target',
            }),
        ).toEqual(pending);
    });

    it('finalizes no result only for a finalized empty usable inventory', () => {
        const pending: ActionOutcome = { kind: 'pending' };

        expect(
            applyOutcomeEvent(pending, {
                kind: 'finalized-empty-inventory',
                semanticTargetIdentity: 'target',
                usableBallotCount: 0,
            }),
        ).toEqual({
            kind: 'verified-no-result',
            semanticTargetIdentity: 'target',
        });
        expect(
            applyOutcomeEvent(pending, {
                kind: 'finalized-empty-inventory',
                semanticTargetIdentity: 'target',
                usableBallotCount: 1,
            }),
        ).toEqual(pending);
    });

    it('never revokes a verified result after later invalid candidates', () => {
        const verified = applyOutcomeEvent(
            { kind: 'pending' },
            {
                exactCodewordVerified: true,
                kind: 'result-candidate',
                resultIdentity: 'canonical-result',
                semanticTargetIdentity: 'target',
            },
        );

        expect(
            applyOutcomeEvent(verified, { kind: 'invalid-contribution' }),
        ).toEqual(verified);
        expect(
            applyOutcomeEvent(verified, {
                exactCodewordVerified: true,
                kind: 'result-candidate',
                resultIdentity: 'conflicting-result',
                semanticTargetIdentity: 'target',
            }),
        ).toEqual(verified);
    });
});

describe('generated direct-finality visit schedule', () => {
    it('counts result retrieval in the exact six-visit completion graph', () => {
        const schedule = runGeneratedVisitSchedule({ participantCount: 10 });
        expect(schedule.relayState.resultAvailable).toBe(true);
        expect(
            schedule.participantStates.every(
                (participantState) => participantState.resultRetrieved,
            ),
        ).toBe(true);
        expect(
            Math.max(
                ...schedule.participantStates.map(
                    (participantState) => participantState.productiveVisitCount,
                ),
            ),
        ).toBe(6);
    });

    it('retrieves an all-abstain terminal in five productive visits', () => {
        const schedule = runGeneratedVisitSchedule({
            allAbstain: true,
            participantCount: 10,
        });
        expect(schedule.relayState.resultAvailable).toBe(true);
        expect(
            Math.max(
                ...schedule.participantStates.map(
                    (participantState) => participantState.productiveVisitCount,
                ),
            ),
        ).toBe(5);
    });

    it('leaves missing passes and post-finality withholding pending', () => {
        const missingPass = runGeneratedVisitSchedule({
            participantCount: 10,
            withholdRecipientPassFrom: 9,
        });
        expect(missingPass.relayState.finalityCertificateAvailable).toBe(false);
        expect(missingPass.relayState.resultAvailable).toBe(false);

        const missingOutput = runGeneratedVisitSchedule({
            participantCount: 10,
            withholdOutputFrom: 9,
        });
        expect(missingOutput.relayState.finalityCertificateAvailable).toBe(
            true,
        );
        expect(missingOutput.relayState.resultAvailable).toBe(false);
        expect(
            missingOutput.participantStates.some(
                (participantState) => participantState.resultRetrieved,
            ),
        ).toBe(false);
    });

    it('shows that a separate repair action adds a seventh visit', () => {
        const schedule = runGeneratedVisitSchedule({
            participantCount: 10,
            requireRepair: true,
        });
        const maximumProductiveVisitCount = Math.max(
            ...schedule.participantStates.map(
                (participantState) => participantState.productiveVisitCount,
            ),
        );

        expect(schedule.relayState.resultAvailable).toBe(true);
        expect(maximumProductiveVisitCount).toBe(7);
    });
});
