const minimumParticipantCount = 3;
const maximumParticipantCount = 20;

const requireParticipantCount = (participantCount: number): void => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < minimumParticipantCount ||
        participantCount > maximumParticipantCount
    ) {
        throw new RangeError(
            'participantCount is outside the supported range.',
        );
    }
};

// Cuts before work in one permitted asynchronous schedule of the certified
// clear setup. The closing stage collects the proposal and responses; target
// certification permanently closes the inventory, so the required organizer
// exception lasts through that cut. Published records remain retrievable
// after their sender leaves.
export const lifecycleAvailabilityStages = [
    'roster-fixed',
    'roster-confirmation-and-contribution',
    'setup-selection-and-endorsement',
    'setup-verification',
    'closing',
    'target-certification',
    'release',
] as const;

type LifecycleAvailabilityStage = (typeof lifecycleAvailabilityStages)[number];
type ParticipantFailure = Readonly<{
    participant: number;
    before: LifecycleAvailabilityStage;
}>;

// This is the required availability envelope, not a protocol that achieves
// it. Loss, state loss and refusal consume the same persistent participant
// set; a later stage never obtains a fresh failure allowance.
export const deriveLifecycleAvailability = (
    participantCount: number,
    organizer: number,
    failures: readonly ParticipantFailure[],
) => {
    requireParticipantCount(participantCount);
    const requirePosition = (position: number) => {
        if (
            !Number.isSafeInteger(position) ||
            position < 0 ||
            position >= participantCount
        )
            throw new RangeError(
                'A participant position is outside the roster.',
            );
    };
    requirePosition(organizer);
    const faultBound = Math.floor((participantCount - 1) / 3);
    const firstFailure = new Map<number, number>();
    for (const { participant, before } of failures) {
        requirePosition(participant);
        const stage = lifecycleAvailabilityStages.indexOf(before);
        if (stage < 0) throw new RangeError('Unknown lifecycle stage.');
        if (
            participant === organizer &&
            stage <= lifecycleAvailabilityStages.indexOf('target-certification')
        )
            throw new RangeError('The organizer is required through closing.');
        firstFailure.set(
            participant,
            Math.min(firstFailure.get(participant) ?? stage, stage),
        );
    }
    if (firstFailure.size > faultBound)
        throw new RangeError(
            'The total unavailable set exceeds the fault bound.',
        );
    const roster = Array.from(
        { length: participantCount },
        (_unused, participant) => participant,
    );
    return {
        roster,
        faultBound,
        requiredContinuerCount: participantCount - faultBound,
        stages: lifecycleAvailabilityStages.map((stage, index) => ({
            stage,
            availableParticipants: roster.filter(
                (participant) =>
                    (firstFailure.get(participant) ?? Infinity) > index,
            ),
        })),
    };
};

const binomial = (n: number, k: number): bigint => {
    if (!Number.isSafeInteger(n) || !Number.isSafeInteger(k)) {
        throw new TypeError('Binomial inputs must be safe integers.');
    }
    if (k < 0 || k > n) return 0n;

    let result = 1n;
    const reducedK = Math.min(k, n - k);
    for (let index = 1; index <= reducedK; index += 1) {
        result = (result * BigInt(n - reducedK + index)) / BigInt(index);
    }
    return result;
};

const popcount = (value: number): number => {
    let remaining = value >>> 0;
    let count = 0;
    while (remaining !== 0) {
        remaining &= remaining - 1;
        count += 1;
    }
    return count;
};

const masksAtMost = (
    participantCount: number,
    maximumSize: number,
): readonly number[] => {
    const masks: number[] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1) {
        if (popcount(mask) <= maximumSize) masks.push(mask);
    }
    return masks;
};

const masksExactly = (
    participantCount: number,
    size: number,
): readonly number[] => {
    const masks: number[] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1) {
        if (popcount(mask) === size) masks.push(mask);
    }
    return masks;
};

type SetClassCensus = Readonly<{
    classCount: number;
    caseCount: bigint;
    minimumHonestResponderCount: number;
}>;

// This separate post-setup stress census allows independent disappearance
// and corrupt-refusal sets, after setup is certified. It is
// stronger in responder count but does not establish the required lifecycle
// availability from roster fixing; deriveLifecycleAvailability owns that
// envelope, whose unavailable union is bounded by f.
const enumerateSetClassCensus = (
    participantCount: number,
    faultBound: number,
): SetClassCensus => {
    let classCount = 0;
    let caseCount = 0n;
    let minimumHonestResponderCount = participantCount;

    for (
        let corruptionCount = 0;
        corruptionCount <= faultBound;
        corruptionCount += 1
    ) {
        for (
            let disappearanceCount = 0;
            disappearanceCount <= faultBound;
            disappearanceCount += 1
        ) {
            const minimumOverlap = Math.max(
                0,
                corruptionCount + disappearanceCount - participantCount,
            );
            const maximumOverlap = Math.min(
                corruptionCount,
                disappearanceCount,
            );
            for (
                let overlap = minimumOverlap;
                overlap <= maximumOverlap;
                overlap += 1
            ) {
                const remainingCorruptCount = corruptionCount - overlap;
                minimumHonestResponderCount = Math.min(
                    minimumHonestResponderCount,
                    participantCount -
                        disappearanceCount -
                        remainingCorruptCount,
                );
                const corruptionAndDisappearanceCount =
                    binomial(participantCount, corruptionCount) *
                    binomial(corruptionCount, overlap) *
                    binomial(
                        participantCount - corruptionCount,
                        disappearanceCount - overlap,
                    );
                for (
                    let refusalCount = 0;
                    refusalCount <= remainingCorruptCount;
                    refusalCount += 1
                ) {
                    classCount += 1;
                    caseCount +=
                        corruptionAndDisappearanceCount *
                        binomial(remainingCorruptCount, refusalCount);
                }
            }
        }
    }

    return { classCount, caseCount, minimumHonestResponderCount };
};

type BruteForceCensus = Readonly<{
    certificatePairCount: bigint;
    lifecycleCaseCount: bigint;
    mandatoryReleaseParticipantCount: number;
    minimumCertificateIntersection: number;
    minimumHonestResponderCount: number;
}>;

const bruteForceSmallProfile = (
    participantCount: number,
    faultBound: number,
    certificateThreshold: number,
    releaseThreshold: number,
): BruteForceCensus => {
    const boundedMasks = masksAtMost(participantCount, faultBound);
    let lifecycleCaseCount = 0n;
    let minimumHonestResponderCount = participantCount;

    for (const corruptionMask of boundedMasks) {
        if (popcount(corruptionMask) >= releaseThreshold) {
            throw new Error('A corrupt set meets the release threshold.');
        }
        for (const disappearanceMask of boundedMasks) {
            const remainingCorruptMask = corruptionMask & ~disappearanceMask;
            const honestResponderMask =
                ((1 << participantCount) - 1) &
                ~disappearanceMask &
                ~remainingCorruptMask;
            const honestResponderCount = popcount(honestResponderMask);
            if (honestResponderCount < releaseThreshold) {
                throw new Error(
                    'A disappearance and corruption set defeats release.',
                );
            }
            minimumHonestResponderCount = Math.min(
                minimumHonestResponderCount,
                honestResponderCount,
            );

            let refusalMask = remainingCorruptMask;
            for (;;) {
                lifecycleCaseCount += 1n;
                if ((refusalMask & ~remainingCorruptMask) !== 0) {
                    throw new Error('A refusal lies outside the corrupt set.');
                }
                if (refusalMask === 0) break;
                refusalMask = (refusalMask - 1) & remainingCorruptMask;
            }
        }
    }

    const certificates = masksExactly(participantCount, certificateThreshold);
    let certificatePairCount = 0n;
    let minimumCertificateIntersection = participantCount;
    for (const left of certificates) {
        for (const right of certificates) {
            certificatePairCount += 1n;
            const intersection = popcount(left & right);
            if (intersection <= faultBound) {
                throw new Error(
                    'Two certificates lack an honest intersection.',
                );
            }
            minimumCertificateIntersection = Math.min(
                minimumCertificateIntersection,
                intersection,
            );
        }
    }

    const releaseSets = masksExactly(participantCount, releaseThreshold);
    let mandatoryReleaseParticipantMask = (1 << participantCount) - 1;
    for (const releaseSet of releaseSets) {
        mandatoryReleaseParticipantMask &= releaseSet;
    }

    return {
        certificatePairCount,
        lifecycleCaseCount,
        mandatoryReleaseParticipantCount: popcount(
            mandatoryReleaseParticipantMask,
        ),
        minimumCertificateIntersection,
        minimumHonestResponderCount,
    };
};

export type ThresholdCompletionProfile = Readonly<{
    participantCount: number;
    maximumCorruptParticipantCount: number;
    inventoryCertificateThreshold: number;
    resultReleaseThreshold: number;
    setupContributorCount: number;
    minimumTurnout: number;
    noResultForceableAtFullHonestTurnout: boolean;
    guaranteedHonestResponderCount: number;
    minimumHonestCertificateSignerCount: number;
    minimumCertificateIntersection: number;
    mandatoryReleaseParticipantCount: number;
    corruptionSetCount: bigint;
    disappearanceSetCount: bigint;
    corruptionDisappearanceRefusalClassCount: number;
    corruptionDisappearanceRefusalCaseCount: bigint;
    certificateSetCount: bigint;
    certificateIntersectionClassCount: number;
    orderedCertificatePairCount: bigint;
    bruteForceCrossChecked: boolean;
}>;

export const compileThresholdCompletionProfile = (
    participantCount: number,
): ThresholdCompletionProfile => {
    requireParticipantCount(participantCount);
    const maximumCorruptParticipantCount = Math.floor(
        (participantCount - 1) / 3,
    );
    const inventoryCertificateThreshold =
        participantCount - maximumCorruptParticipantCount;
    const resultReleaseThreshold = Math.max(
        maximumCorruptParticipantCount + 1,
        2,
    );
    // The setup selection takes exactly d contribution offers, so at least one
    // selected contributor is honest under the static corruption bound.
    const setupContributorCount = resultReleaseThreshold;
    const minimumTurnout = maximumCorruptParticipantCount + 2;
    const mandatoryReleaseParticipantCount =
        binomial(participantCount - 1, resultReleaseThreshold) === 0n
            ? participantCount
            : 0;
    if (mandatoryReleaseParticipantCount !== 0) {
        throw new Error('A named participant is mandatory for release.');
    }
    const guaranteedHonestResponderCount =
        participantCount - 2 * maximumCorruptParticipantCount;
    const minimumHonestCertificateSignerCount =
        inventoryCertificateThreshold - maximumCorruptParticipantCount;
    const minimumCertificateIntersection =
        2 * inventoryCertificateThreshold - participantCount;
    // With every honest participant voting, the adversary can omit f honest
    // ballots while every corrupt participant abstains.
    const noResultForceableAtFullHonestTurnout =
        participantCount - 2 * maximumCorruptParticipantCount < minimumTurnout;

    if (
        resultReleaseThreshold < 2 ||
        resultReleaseThreshold >= participantCount ||
        setupContributorCount < 2 ||
        setupContributorCount <= maximumCorruptParticipantCount ||
        setupContributorCount > participantCount ||
        minimumTurnout - maximumCorruptParticipantCount < 2 ||
        participantCount - maximumCorruptParticipantCount < minimumTurnout ||
        maximumCorruptParticipantCount >= resultReleaseThreshold ||
        guaranteedHonestResponderCount < resultReleaseThreshold ||
        minimumHonestCertificateSignerCount !==
            guaranteedHonestResponderCount ||
        minimumCertificateIntersection <= maximumCorruptParticipantCount
    ) {
        throw new Error(
            'The threshold construction violates a core invariant.',
        );
    }

    const setCensus = enumerateSetClassCensus(
        participantCount,
        maximumCorruptParticipantCount,
    );
    if (
        setCensus.minimumHonestResponderCount !== guaranteedHonestResponderCount
    ) {
        throw new Error('The set census disagrees with the liveness oracle.');
    }

    const certificateSetCount = binomial(
        participantCount,
        inventoryCertificateThreshold,
    );
    let certificatePairCount = 0n;
    let certificateIntersectionClassCount = 0;
    for (
        let intersection = minimumCertificateIntersection;
        intersection <= inventoryCertificateThreshold;
        intersection += 1
    ) {
        const classSize =
            certificateSetCount *
            binomial(inventoryCertificateThreshold, intersection) *
            binomial(
                participantCount - inventoryCertificateThreshold,
                inventoryCertificateThreshold - intersection,
            );
        if (classSize === 0n) continue;
        if (intersection <= maximumCorruptParticipantCount) {
            throw new Error('A certificate-intersection class is unsafe.');
        }
        certificateIntersectionClassCount += 1;
        certificatePairCount += classSize;
    }
    if (certificatePairCount !== certificateSetCount * certificateSetCount) {
        throw new Error('Certificate classes do not cover every ordered pair.');
    }

    const setCount = Array.from(
        { length: maximumCorruptParticipantCount + 1 },
        (_unused, size) => binomial(participantCount, size),
    ).reduce((sum, count) => sum + count, 0n);

    const bruteForceCrossChecked = participantCount <= 12;
    if (bruteForceCrossChecked) {
        const bruteForce = bruteForceSmallProfile(
            participantCount,
            maximumCorruptParticipantCount,
            inventoryCertificateThreshold,
            resultReleaseThreshold,
        );
        if (
            bruteForce.lifecycleCaseCount !== setCensus.caseCount ||
            bruteForce.minimumHonestResponderCount !==
                guaranteedHonestResponderCount ||
            bruteForce.minimumCertificateIntersection !==
                minimumCertificateIntersection ||
            bruteForce.mandatoryReleaseParticipantCount !==
                mandatoryReleaseParticipantCount ||
            bruteForce.certificatePairCount !== certificatePairCount
        ) {
            throw new Error(
                'The brute-force and class-counted models disagree.',
            );
        }
    }

    return {
        participantCount,
        maximumCorruptParticipantCount,
        inventoryCertificateThreshold,
        resultReleaseThreshold,
        setupContributorCount,
        minimumTurnout,
        noResultForceableAtFullHonestTurnout,
        guaranteedHonestResponderCount,
        minimumHonestCertificateSignerCount,
        minimumCertificateIntersection,
        mandatoryReleaseParticipantCount,
        corruptionSetCount: setCount,
        disappearanceSetCount: setCount,
        corruptionDisappearanceRefusalClassCount: setCensus.classCount,
        corruptionDisappearanceRefusalCaseCount: setCensus.caseCount,
        certificateSetCount,
        certificateIntersectionClassCount,
        orderedCertificatePairCount: certificatePairCount,
        bruteForceCrossChecked,
    };
};

export const compileSupportedThresholdCompletionProfiles =
    (): readonly ThresholdCompletionProfile[] =>
        Array.from(
            {
                length: maximumParticipantCount - minimumParticipantCount + 1,
            },
            (_unused, index) =>
                compileThresholdCompletionProfile(
                    minimumParticipantCount + index,
                ),
        );
