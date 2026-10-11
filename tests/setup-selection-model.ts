import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

// Selection and chronology only. Signatures, registration commitments and
// contribution relations are ideal verified inputs here. This model creates
// no setup capability and makes no cryptographic privacy claim.
const deriveSetupSelection = (participantCount: number) => {
    const profile = compileThresholdCompletionProfile(participantCount);
    const faultBound = profile.maximumCorruptParticipantCount;
    const selectedCount = profile.resultReleaseThreshold;
    return {
        participantCount,
        faultBound,
        selectedCount,
        eligibleCount: selectedCount + faultBound,
        quorum: profile.inventoryCertificateThreshold,
    };
};

const choose = (population: number, size: number): bigint => {
    let value = 1n;
    for (let index = 1; index <= size; index++)
        value = (value * BigInt(population - index + 1)) / BigInt(index);
    return value;
};

export const compileSetupSelectionCensus = (participantCount: number) => {
    const profile = deriveSetupSelection(participantCount);
    return {
        ...profile,
        remainingEligibleCount: profile.eligibleCount - profile.faultBound,
        minimumHonestSelected: profile.selectedCount - profile.faultBound,
        minimumCertificateIntersection: 2 * profile.quorum - participantCount,
        possibleSelectedSets: choose(
            profile.eligibleCount,
            profile.selectedCount,
        ),
    };
};

// A participant endorses one list in the confirmed roster. A second carrier
// of the same list is a replay; a different list cannot consume the purpose
// again. Verification of a certificate is independent of the local choice.
export class SetupSelectionModel {
    readonly profile;
    private readonly endorsements = new Map<number, Set<string>>();
    private readonly corrupt: ReadonlySet<number>;

    constructor(
        readonly participantCount: number,
        corrupt: readonly number[] = [],
    ) {
        this.profile = deriveSetupSelection(participantCount);
        this.corrupt = new Set(corrupt);
        if (
            this.corrupt.size !== corrupt.length ||
            this.corrupt.size > this.profile.faultBound ||
            corrupt.some(
                (position) =>
                    !Number.isInteger(position) ||
                    position < 0 ||
                    position >= participantCount,
            )
        )
            throw new RangeError(
                'The static corruption set is outside the profile.',
            );
    }

    private selectionIdentity(
        selection: readonly number[],
    ): string | undefined {
        if (
            selection.length !== this.profile.selectedCount ||
            selection.some(
                (position, index) =>
                    !Number.isInteger(position) ||
                    position < 0 ||
                    position >= this.profile.eligibleCount ||
                    (index > 0 && selection[index - 1] >= position),
            )
        )
            return undefined;
        return selection.join(',');
    }

    endorse(signer: number, selection: readonly number[]): boolean {
        const identity = this.selectionIdentity(selection);
        if (
            identity === undefined ||
            !Number.isInteger(signer) ||
            signer < 0 ||
            signer >= this.participantCount
        )
            return false;
        const previous = this.endorsements.get(signer);
        if (previous !== undefined && !this.corrupt.has(signer))
            return previous.has(identity);
        const choices = previous ?? new Set<string>();
        choices.add(identity);
        this.endorsements.set(signer, choices);
        return true;
    }

    certificate(
        selection: readonly number[],
        signers: readonly number[],
    ): boolean {
        const identity = this.selectionIdentity(selection);
        return (
            identity !== undefined &&
            signers.length >= this.profile.quorum &&
            new Set(signers).size === signers.length &&
            signers.every(
                (signer) =>
                    this.endorsements.get(signer)?.has(identity) === true,
            )
        );
    }
}

// Even with every source fixed beforehand, selecting after the public
// coordinates open does not leave the selected aggregate uniform. In an
// idealized uniform-key game a corrupt coordinator chooses the smaller of
// c+x and c+y modulo p. This refutes a distributional shortcut, not RLWE.
export const selectedPublicCoordinateDistribution = (
    prime: number,
    fixedCorruptCoordinate: number,
) => {
    if (
        !Number.isInteger(prime) ||
        prime < 2 ||
        prime > 257 ||
        !Number.isInteger(fixedCorruptCoordinate)
    )
        throw new RangeError('Invalid finite selection experiment.');
    const counts = new Array<number>(prime).fill(0);
    const coordinate = (value: number) =>
        (((fixedCorruptCoordinate + value) % prime) + prime) % prime;
    for (let first = 0; first < prime; first++)
        for (let second = 0; second < prime; second++)
            counts[Math.min(coordinate(first), coordinate(second))]++;
    return counts;
};

// A fixed guessed selected set can be embedded before publication: replace
// one honest coordinate by U minus the other selected coordinates. For each
// guess, compare the entire public prefix with independent uniform honest
// coordinates; only afterward let the organizer choose its minimum sum.
// The gate predicate is a public postprocessing event, not conditioning U
// to be uniform after selection. This checks the affine bijection only.
export const uniformSelectedKeyEmbedding = (modulus: number) => {
    if (!Number.isInteger(modulus) || modulus < 2 || modulus > 31)
        throw new RangeError('Invalid finite key group.');
    const reduce = (value: number) => ((value % modulus) + modulus) % modulus;
    const selections = [
        [0, 1],
        [0, 2],
        [1, 2],
    ];
    const selected = (coordinates: readonly number[]) => {
        const sums = selections.map((positions) =>
            reduce(
                positions.reduce(
                    (sum, position) => sum + coordinates[position],
                    0,
                ),
            ),
        );
        return sums.indexOf(Math.min(...sums));
    };
    const reference = new Map<string, number>();
    for (let first = 0; first < modulus; first++)
        for (let second = 0; second < modulus; second++)
            reference.set(`${first},${second}`, selected([3, first, second]));
    const guesses = selections.map((selection, guessed) => {
        const pivot = selection.find((position) => position !== 0)!;
        const other = pivot === 1 ? 2 : 1;
        const prefixes = new Map<string, number>();
        let selectedPrefixes = 0;
        for (let retained = 0; retained < modulus; retained++) {
            for (let challenge = 0; challenge < modulus; challenge++) {
                const coordinates = [3, 0, 0];
                coordinates[other] = retained;
                coordinates[pivot] = reduce(
                    challenge -
                        selection
                            .filter((position) => position !== pivot)
                            .reduce(
                                (sum, position) => sum + coordinates[position],
                                0,
                            ),
                );
                const identity = `${coordinates[1]},${coordinates[2]}`;
                if (prefixes.has(identity))
                    throw new Error('The affine map is not injective.');
                const actual = selected(coordinates);
                prefixes.set(identity, actual);
                if (actual === guessed) {
                    const aggregate = reduce(
                        selection.reduce(
                            (sum, position) => sum + coordinates[position],
                            0,
                        ),
                    );
                    if (aggregate !== challenge)
                        throw new Error(
                            'The selected key differs from the challenge.',
                        );
                    selectedPrefixes++;
                }
            }
        }
        return { prefixes, selectedPrefixes };
    });
    return { reference, guesses };
};

// Exact affine encryption over a small prime isolates the setup-key
// dependency. This deliberately has no noise or cryptographic security.
// It is the equality c0 + s*c1 = m that selection cannot change afterward.
const modulus = 257n;
const residue = (value: bigint) => ((value % modulus) + modulus) % modulus;
const keyFor = (selection: readonly number[]) =>
    selection.reduce((sum, position) => sum + BigInt(position + 1), 0n);

export const closeOnlySelectionCounterexample = (participantCount: number) => {
    const profile = deriveSetupSelection(participantCount);
    if (profile.faultBound === 0)
        throw new RangeError('The fork needs a corrupt organizer.');
    const firstSelection = Array.from(
        { length: profile.selectedCount },
        (_unused, position) => position,
    );
    const secondSelection = firstSelection.map((position) => position + 1);
    const author = profile.faultBound;
    const scores = [1n, 10n];
    const randomness = [2n, 3n];
    const ciphertext = scores.map((score, option) => ({
        first: residue(
            score - 7n * keyFor(secondSelection) * randomness[option],
        ),
        second: residue(7n * randomness[option]),
    }));
    const decrypt = (selection: readonly number[]) =>
        ciphertext.map(({ first, second }) =>
            residue(first + keyFor(selection) * second),
        );
    // The organizer is corrupt. The author and f other honest recipients
    // hold this complete on-time ballot before the signed close request.
    const honestHolders = Array.from(
        { length: profile.faultBound + 1 },
        (_unused, index) => author + index,
    );
    // Enough other participants can respond and certify the first setup.
    // If setup is part of the response lock, the author need not be among
    // them. If it is not, even its own response does not fix the problem.
    const firstTargetSigners = Array.from(
        { length: participantCount },
        (_unused, position) => position,
    )
        .filter((position) => position !== author)
        .slice(0, profile.quorum);
    return {
        profile,
        firstSelection,
        secondSelection,
        author,
        honestHolders,
        firstTargetSigners,
        scores,
        originalPlaintext: decrypt(secondSelection),
        changedSetupPlaintext: decrypt(firstSelection),
    };
};

type Preparation = 'clear-certified' | 'recoverable-sealed';
type Stage = Readonly<{ name: string; prerequisite?: string }>;

// These are candidate protocol-stage paths, including registration and the
// existing certified close suffix. Collection, same-stage restart and status
// polling do not add nodes. An additional participant-dependent output must
// be a new node, so it cannot be hidden by renaming a stage.
export const preparationStagePath = (
    preparation: Preparation,
    organizer: boolean,
): readonly Stage[] => {
    const prefix = ['registration', 'roster-confirmation-and-contribution'];
    if (preparation === 'recoverable-sealed')
        prefix.push(
            'selection-and-echo',
            'ready',
            'delivery-and-opening-shares',
        );
    else prefix.push('selection-and-endorsement');
    prefix.push('setup-and-optional-ballot');
    const names = [
        ...prefix,
        organizer ? 'close-request-and-collection' : 'close-response',
        organizer ? 'close-proposal-and-target' : 'target',
        'release',
        'outcome-verification',
    ];
    return names.map((name, index) => ({
        name,
        ...(index === 0 ? {} : { prerequisite: names[index - 1] }),
    }));
};

export const countStagePath = (stages: readonly Stage[]): number => {
    const depths = new Map<string, number>();
    for (const { name, prerequisite } of stages) {
        if (
            depths.has(name) ||
            (prerequisite !== undefined && !depths.has(prerequisite))
        )
            throw new RangeError(
                'A stage has a duplicate or missing predecessor.',
            );
        depths.set(
            name,
            1 + (prerequisite === undefined ? 0 : depths.get(prerequisite)!),
        );
    }
    return Math.max(0, ...depths.values());
};
