import { describe, expect, it } from 'vitest';

const participantCount = 10;
const finalityQuorum = 8;
const preCertificateSignerCount = finalityQuorum - 1;

type ComputationSchedule = Readonly<{
    participantPosition: number;
    joinOrder: readonly number[];
    preCertificateSigners: ReadonlySet<number>;
    certificateCompleter: number;
    certificateDeliveredDuringFinality: boolean;
    lastBodyPublisher: number;
    completeBodyInventoryDeliveredDuringPublication: boolean;
}>;

const joinOrdersByLastParticipant = (
    positions: readonly number[],
): number[][] =>
    positions.map((lastJoiner) => [
        ...positions.filter((position) => position !== lastJoiner),
        lastJoiner,
    ]);

const visitsThroughPreparation = (
    participantPosition: number,
    joinOrder: readonly number[],
): string[][] => {
    if (
        joinOrder.length !== participantCount ||
        new Set(joinOrder).size !== participantCount ||
        joinOrder.some(
            (position) => position < 0 || position >= participantCount,
        )
    ) {
        throw new Error('The join order must contain every participant once.');
    }
    const lastJoiner = joinOrder[joinOrder.length - 1];
    const visits = [['join-poll']];
    if (participantPosition === lastJoiner) {
        visits[0]?.push('confirm-roster', 'publish-preparation');
    } else {
        visits.push(['confirm-roster', 'publish-preparation']);
    }
    return visits;
};

const choosePositions = (
    positions: readonly number[],
    count: number,
    firstIndex = 0,
    prefix: readonly number[] = [],
): number[][] => {
    if (prefix.length === count) {
        return [[...prefix]];
    }
    const choices: number[][] = [];
    for (let index = firstIndex; index < positions.length; index += 1) {
        const position = positions[index];
        if (position !== undefined) {
            choices.push(
                ...choosePositions(positions, count, index + 1, [
                    ...prefix,
                    position,
                ]),
            );
        }
    }
    return choices;
};

const computationVisitTrace = ({
    participantPosition,
    joinOrder,
    preCertificateSigners,
    certificateCompleter,
    certificateDeliveredDuringFinality,
    lastBodyPublisher,
    completeBodyInventoryDeliveredDuringPublication,
}: ComputationSchedule): string[][] => {
    const visits = visitsThroughPreparation(participantPosition, joinOrder);
    visits.push(
        ['verify-complete-preparation', 'publish-source'],
        ['verify-complete-sources', 'publish-finality'],
    );
    if (preCertificateSigners.has(certificateCompleter)) {
        throw new Error('The certificate completer cannot be an early signer.');
    }
    const canPublishBodyDuringFinality =
        participantPosition === certificateCompleter ||
        certificateDeliveredDuringFinality;
    if (canPublishBodyDuringFinality) {
        visits[visits.length - 1]?.push(
            'verify-finality-certificate',
            'publish-body',
        );
    } else {
        visits.push(['verify-finality-certificate', 'publish-body']);
    }

    const publishedLastBody = participantPosition === lastBodyPublisher;
    const publicationVisit = visits[visits.length - 1];
    if (
        publishedLastBody &&
        completeBodyInventoryDeliveredDuringPublication &&
        publicationVisit !== undefined
    ) {
        publicationVisit.push('verify-complete-bodies', 'retrieve-result');
    } else {
        visits.push(['verify-complete-bodies', 'retrieve-result']);
    }
    return visits;
};

const allAbstainVisitTrace = (
    participantPosition: number,
    joinOrder: readonly number[],
    certificateCompleter: number,
    certificateDeliveredDuringFinality: boolean,
): string[][] => {
    const visits = visitsThroughPreparation(participantPosition, joinOrder);
    visits.push(
        ['verify-complete-preparation', 'publish-source'],
        ['verify-complete-sources', 'publish-finality'],
    );
    if (
        participantPosition === certificateCompleter ||
        certificateDeliveredDuringFinality
    ) {
        visits[visits.length - 1]?.push(
            'verify-finality-certificate',
            'retrieve-no-result',
        );
    } else {
        visits.push(['verify-finality-certificate', 'retrieve-no-result']);
    }
    return visits;
};

const durablePublicationActions = [
    'publish-preparation',
    'publish-source',
    'publish-finality',
    'publish-body',
] as const;

const applyCompletingRecovery = (
    ordinaryVisits: readonly (readonly string[])[],
    crashAfter: ReadonlySet<string>,
    transportRepairBefore: string,
): string[][] => {
    const recoveredVisits: string[][] = [];
    const observedCrashActions = new Set<string>();
    let transportRepairInserted = false;
    for (const visit of ordinaryVisits) {
        if (visit.includes(transportRepairBefore)) {
            recoveredVisits.push([
                'refetch-authentic-carrier',
                'remain-pending',
            ]);
            transportRepairInserted = true;
        }
        recoveredVisits.push([...visit]);
        for (const action of crashAfter) {
            if (visit.includes(action)) {
                recoveredVisits.push([
                    'cold-restart',
                    `resume-after:${action}`,
                ]);
                observedCrashActions.add(action);
            }
        }
    }
    if (
        observedCrashActions.size !== crashAfter.size ||
        !transportRepairInserted
    ) {
        throw new Error('The recovery schedule named an absent dependency.');
    }
    return recoveredVisits;
};

type RecoveryDependency = Readonly<{
    messagePresent: boolean;
    carrierAuthentic: boolean;
    mailboxUsable: boolean;
    localStateCurrent: boolean;
}>;

const recoveryOutcome = ({
    messagePresent,
    carrierAuthentic,
    mailboxUsable,
    localStateCurrent,
}: RecoveryDependency): 'progress' | 'pending' | 'retired-pending' => {
    if (!localStateCurrent) {
        return 'retired-pending';
    }
    if (!messagePresent || !carrierAuthentic || !mailboxUsable) {
        return 'pending';
    }
    return 'progress';
};

describe('completion-profile participant visit graph', () => {
    it('exhausts every join, signer, and delivery equivalence class at six visits', () => {
        const positions = Array.from(
            { length: participantCount },
            (_unused, position) => position,
        );
        const joinOrders = joinOrdersByLastParticipant(positions);
        const preCertificateSignerSets = choosePositions(
            positions,
            preCertificateSignerCount,
        );
        let casesChecked = 0;
        let minimumVisits = Number.POSITIVE_INFINITY;
        let maximumVisits = 0;
        let maximumLastJoinerVisits = 0;
        let maximumEarlierJoinerVisits = 0;
        const histogram = new Map<number, number>();

        for (const joinOrder of joinOrders) {
            const lastJoiner = joinOrder[joinOrder.length - 1];
            for (const signerPositions of preCertificateSignerSets) {
                const preCertificateSigners = new Set(signerPositions);
                const possibleCertificateCompleters = positions.filter(
                    (position) => !preCertificateSigners.has(position),
                );
                for (const certificateCompleter of possibleCertificateCompleters) {
                    if (preCertificateSigners.has(certificateCompleter)) {
                        throw new Error(
                            'The eighth signer was already counted.',
                        );
                    }
                    for (const lastBodyPublisher of positions) {
                        for (const certificateDeliveredDuringFinality of [
                            false,
                            true,
                        ]) {
                            for (const completeBodyInventoryDeliveredDuringPublication of [
                                false,
                                true,
                            ]) {
                                for (const participantPosition of positions) {
                                    const visitCount = computationVisitTrace({
                                        participantPosition,
                                        joinOrder,
                                        preCertificateSigners,
                                        certificateCompleter,
                                        certificateDeliveredDuringFinality,
                                        lastBodyPublisher,
                                        completeBodyInventoryDeliveredDuringPublication,
                                    }).length;
                                    minimumVisits = Math.min(
                                        minimumVisits,
                                        visitCount,
                                    );
                                    maximumVisits = Math.max(
                                        maximumVisits,
                                        visitCount,
                                    );
                                    if (participantPosition === lastJoiner) {
                                        maximumLastJoinerVisits = Math.max(
                                            maximumLastJoinerVisits,
                                            visitCount,
                                        );
                                    } else {
                                        maximumEarlierJoinerVisits = Math.max(
                                            maximumEarlierJoinerVisits,
                                            visitCount,
                                        );
                                    }
                                    histogram.set(
                                        visitCount,
                                        (histogram.get(visitCount) ?? 0) + 1,
                                    );
                                    casesChecked += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        expect(joinOrders).toHaveLength(10);
        expect(
            new Set(joinOrders.map((order) => order[order.length - 1])).size,
        ).toBe(10);
        expect(preCertificateSignerSets).toHaveLength(120);
        expect(casesChecked).toBe(1_440_000);
        expect(minimumVisits).toBe(3);
        expect(maximumVisits).toBe(6);
        expect(maximumLastJoinerVisits).toBe(5);
        expect(maximumEarlierJoinerVisits).toBe(6);
        expect([...histogram.keys()].sort()).toEqual([3, 4, 5, 6]);
    });

    it('counts all-abstain retrieval and bounded recovery without concurrent participants', () => {
        const positions = Array.from(
            { length: participantCount },
            (_unused, position) => position,
        );
        const joinOrders = joinOrdersByLastParticipant(positions);
        let allAbstainMaximum = 0;
        let allAbstainLastJoinerMaximum = 0;
        for (const joinOrder of joinOrders) {
            const lastJoiner = joinOrder[joinOrder.length - 1];
            for (const participantPosition of positions) {
                for (const certificateCompleter of positions) {
                    for (const certificateDeliveredDuringFinality of [
                        false,
                        true,
                    ]) {
                        const visitCount = allAbstainVisitTrace(
                            participantPosition,
                            joinOrder,
                            certificateCompleter,
                            certificateDeliveredDuringFinality,
                        ).length;
                        allAbstainMaximum = Math.max(
                            allAbstainMaximum,
                            visitCount,
                        );
                        if (participantPosition === lastJoiner) {
                            allAbstainLastJoinerMaximum = Math.max(
                                allAbstainLastJoinerMaximum,
                                visitCount,
                            );
                        }
                    }
                }
            }
        }
        expect(allAbstainMaximum).toBe(5);
        expect(allAbstainLastJoinerMaximum).toBe(4);

        const ordinaryMaximumTrace = computationVisitTrace({
            participantPosition: 0,
            joinOrder: [...positions.slice(0, 9), 9],
            preCertificateSigners: new Set(positions.slice(0, 7)),
            certificateCompleter: 8,
            certificateDeliveredDuringFinality: false,
            lastBodyPublisher: 9,
            completeBodyInventoryDeliveredDuringPublication: false,
        });
        expect(ordinaryMaximumTrace).toHaveLength(6);
        const threeCrashSelections = choosePositions(
            durablePublicationActions.map((_action, index) => index),
            3,
        );
        expect(threeCrashSelections).toHaveLength(4);
        for (const crashSelection of threeCrashSelections) {
            const crashAfter = new Set<string>(
                crashSelection.map((index) => {
                    const action = durablePublicationActions[index];
                    if (action === undefined) {
                        throw new Error('The crash selection is out of range.');
                    }
                    return action;
                }),
            );
            const recoveryTrace = applyCompletingRecovery(
                ordinaryMaximumTrace,
                crashAfter,
                'verify-complete-bodies',
            );
            expect(recoveryTrace).toHaveLength(10);
            expect(
                recoveryTrace.filter((visit) => visit.includes('cold-restart')),
            ).toHaveLength(3);
            expect(
                recoveryTrace.filter((visit) =>
                    visit.includes('refetch-authentic-carrier'),
                ),
            ).toHaveLength(1);
        }

        expect(
            recoveryOutcome({
                messagePresent: true,
                carrierAuthentic: true,
                mailboxUsable: false,
                localStateCurrent: true,
            }),
        ).toBe('pending');
        expect(
            recoveryOutcome({
                messagePresent: false,
                carrierAuthentic: false,
                mailboxUsable: false,
                localStateCurrent: true,
            }),
        ).toBe('pending');
        expect(
            recoveryOutcome({
                messagePresent: true,
                carrierAuthentic: true,
                mailboxUsable: true,
                localStateCurrent: false,
            }),
        ).toBe('retired-pending');
        expect(
            recoveryOutcome({
                messagePresent: true,
                carrierAuthentic: true,
                mailboxUsable: true,
                localStateCurrent: true,
            }),
        ).toBe('progress');
    });
});
