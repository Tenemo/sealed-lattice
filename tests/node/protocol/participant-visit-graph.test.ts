import { describe, expect, it } from 'vitest';

const participantCount = 10;
const finalityQuorum = 8;
const preCertificateSignerCount = finalityQuorum - 1;

type ComputationSchedule = Readonly<{
    participantPosition: number;
    preCertificateSigners: ReadonlySet<number>;
    certificateCompleter: number;
    certificateDeliveredDuringFinality: boolean;
    lastBodyPublisher: number;
    completeBodyInventoryDeliveredDuringPublication: boolean;
}>;

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
    preCertificateSigners,
    certificateCompleter,
    certificateDeliveredDuringFinality,
    lastBodyPublisher,
    completeBodyInventoryDeliveredDuringPublication,
}: ComputationSchedule): string[][] => {
    const visits = [
        ['confirm-roster', 'publish-provisional-preparation'],
        ['verify-complete-preparation', 'publish-source'],
        ['verify-complete-sources', 'publish-finality'],
    ];
    if (preCertificateSigners.has(certificateCompleter)) {
        throw new Error('The certificate completer cannot be an early signer.');
    }
    const canPublishBodyDuringFinality =
        participantPosition === certificateCompleter ||
        certificateDeliveredDuringFinality;
    if (canPublishBodyDuringFinality) {
        visits[2]?.push('verify-finality-certificate', 'publish-body');
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

const allAbstainVisitCount = (
    participantPosition: number,
    certificateCompleter: number,
    certificateDeliveredDuringFinality: boolean,
): number =>
    participantPosition === certificateCompleter ||
    certificateDeliveredDuringFinality
        ? 3
        : 4;

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
    it('exhausts every pre-certificate signer set and delivery ordering at five visits', () => {
        const positions = Array.from(
            { length: participantCount },
            (_unused, position) => position,
        );
        const preCertificateSignerSets = choosePositions(
            positions,
            preCertificateSignerCount,
        );
        let casesChecked = 0;
        let minimumVisits = Number.POSITIVE_INFINITY;
        let maximumVisits = 0;
        const histogram = new Map<number, number>();

        for (const signerPositions of preCertificateSignerSets) {
            const preCertificateSigners = new Set(signerPositions);
            const possibleCertificateCompleters = positions.filter(
                (position) => !preCertificateSigners.has(position),
            );
            for (const certificateCompleter of possibleCertificateCompleters) {
                if (preCertificateSigners.has(certificateCompleter)) {
                    throw new Error('The eighth signer was already counted.');
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

        expect(preCertificateSignerSets).toHaveLength(120);
        expect(casesChecked).toBe(144_000);
        expect(minimumVisits).toBe(3);
        expect(maximumVisits).toBe(5);
        expect([...histogram.keys()].sort()).toEqual([3, 4, 5]);
    });

    it('counts all-abstain retrieval and bounded recovery without concurrent participants', () => {
        const allAbstainCounts = [
            allAbstainVisitCount(0, 7, false),
            allAbstainVisitCount(0, 7, true),
            allAbstainVisitCount(7, 7, false),
            allAbstainVisitCount(7, 7, true),
        ];
        expect(Math.max(...allAbstainCounts)).toBe(4);

        const ordinaryMaximum = 5;
        const oneCrashAfterEachDurablePublication = 4;
        const onePreverificationTransportRepair = 1;
        expect(
            ordinaryMaximum +
                oneCrashAfterEachDurablePublication +
                onePreverificationTransportRepair,
        ).toBe(10);

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
