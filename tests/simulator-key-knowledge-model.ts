type RecoveryKey = 'fhe' | 'auxiliary';
type Reduction = Readonly<{
    name: string;
    recovery: RecoveryKey;
    unknownKey: RecoveryKey | 'recipient' | null;
    potentiallyBadKey: RecoveryKey | null;
    releaseSimulationAlreadyInstalled: boolean;
}>;

// Whole executions at neighboring hybrid endpoints. These are not key
// changes made midway through a participant's actual execution.
export const inputRecoveryReductions: readonly Reduction[] = [
    {
        name: 'Auxiliary aggregate key',
        recovery: 'fhe',
        unknownKey: 'auxiliary',
        potentiallyBadKey: 'auxiliary',
        releaseSimulationAlreadyInstalled: true,
    },
    {
        name: 'Honest-recipient sharing ciphertext',
        recovery: 'auxiliary',
        unknownKey: 'recipient',
        potentiallyBadKey: null,
        releaseSimulationAlreadyInstalled: true,
    },
    {
        name: 'FHE public and evaluation tuple',
        recovery: 'auxiliary',
        unknownKey: 'fhe',
        potentiallyBadKey: 'fhe',
        releaseSimulationAlreadyInstalled: true,
    },
    {
        name: 'Programmed aggregate FHE key',
        recovery: 'auxiliary',
        unknownKey: 'fhe',
        potentiallyBadKey: 'fhe',
        releaseSimulationAlreadyInstalled: true,
    },
    {
        name: 'Honest auxiliary ballot ciphertext',
        recovery: 'fhe',
        unknownKey: 'auxiliary',
        potentiallyBadKey: null,
        releaseSimulationAlreadyInstalled: true,
    },
    {
        name: 'Honest FHE ballot ciphertext',
        recovery: 'auxiliary',
        unknownKey: 'fhe',
        potentiallyBadKey: null,
        releaseSimulationAlreadyInstalled: true,
    },
];

export const verifyInputRecoveryKnowledge = (reduction: Reduction) =>
    reduction.recovery !== reduction.unknownKey &&
    reduction.recovery !== reduction.potentiallyBadKey &&
    reduction.releaseSimulationAlreadyInstalled;

export const availableExtractionRecipients = (
    count: number,
    corrupt: ReadonlySet<number>,
    unknown: ReadonlySet<number>,
) => {
    if (
        !Number.isSafeInteger(count) ||
        count < 3 ||
        count > 20 ||
        corrupt.size > Math.floor((count - 1) / 3) ||
        [...corrupt, ...unknown].some(
            (index) =>
                !Number.isSafeInteger(index) || index < 0 || index >= count,
        ) ||
        [...unknown].some((index) => corrupt.has(index))
    )
        throw new RangeError('Invalid recipient-key challenge profile.');
    const threshold = Math.floor((count - 1) / 3) + 1;
    const knownHonest = Array.from(
        { length: count },
        (_, index) => index,
    ).filter((index) => !corrupt.has(index) && !unknown.has(index));
    if (knownHonest.length < threshold) return;
    return knownHonest.slice(0, threshold);
};

export const compileSimulatorKeyKnowledgeCensus = () =>
    Array.from({ length: 18 }, (_, index) => {
        const participants = index + 3;
        const faults = Math.floor((participants - 1) / 3);
        const threshold = faults + 1;
        return {
            participants,
            faults,
            threshold,
            knownHonestWithOneChallenge: participants - faults - 1,
            maximumUnknownHonestKeys: participants - faults - threshold,
        };
    });
