const plaintextModulus = 65_537n;
const maximumParticipantCount = 20;
const maximumOptionCount = 20;
const maximumDifference = 9 * maximumParticipantCount;

const modulo = (value: bigint): bigint => {
    const remainder = value % plaintextModulus;
    return remainder < 0n ? remainder + plaintextModulus : remainder;
};

const exponentiate = (base: bigint, exponent: bigint): bigint => {
    let result = 1n;
    let factor = modulo(base);
    let remaining = exponent;
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) result = modulo(result * factor);
        factor = modulo(factor * factor);
        remaining >>= 1n;
    }
    return result;
};

const inverse = (value: bigint): bigint => {
    const normalized = modulo(value);
    if (normalized === 0n) throw new RangeError('Zero has no field inverse.');
    return exponentiate(normalized, plaintextModulus - 2n);
};

const evaluatePolynomial = (
    coefficients: readonly bigint[],
    value: bigint,
): bigint => {
    let result = 0n;
    for (let index = coefficients.length - 1; index >= 0; index -= 1) {
        result = modulo(result * modulo(value) + (coefficients[index] ?? 0n));
    }
    return result;
};

type InterpolationPoint = Readonly<{ input: bigint; output: bigint }>;

const interpolate = (points: readonly InterpolationPoint[]): bigint[] => {
    const inputs = points.map(({ input }) => modulo(input));
    const differences = points.map(({ output }) => modulo(output));
    for (let order = 1; order < points.length; order += 1) {
        for (let index = points.length - 1; index >= order; index -= 1) {
            differences[index] = modulo(
                ((differences[index] ?? 0n) - (differences[index - 1] ?? 0n)) *
                    inverse(
                        (inputs[index] ?? 0n) - (inputs[index - order] ?? 0n),
                    ),
            );
        }
    }

    let coefficients = [differences[differences.length - 1] ?? 0n];
    for (let index = points.length - 2; index >= 0; index -= 1) {
        const next = Array.from({ length: coefficients.length + 1 }, () => 0n);
        for (
            let coefficientIndex = 0;
            coefficientIndex < coefficients.length;
            coefficientIndex += 1
        ) {
            next[coefficientIndex] = modulo(
                (next[coefficientIndex] ?? 0n) -
                    (coefficients[coefficientIndex] ?? 0n) *
                        (inputs[index] ?? 0n),
            );
            next[coefficientIndex + 1] = modulo(
                (next[coefficientIndex + 1] ?? 0n) +
                    (coefficients[coefficientIndex] ?? 0n),
            );
        }
        next[0] = modulo((next[0] ?? 0n) + (differences[index] ?? 0n));
        coefficients = next;
    }
    while (
        coefficients.length > 1 &&
        coefficients[coefficients.length - 1] === 0n
    ) {
        coefficients.pop();
    }
    return coefficients;
};

const comparisonPoints = Array.from(
    { length: 2 * maximumDifference + 1 },
    (_unused, index) => {
        const difference = index - maximumDifference;
        return {
            input: BigInt(difference),
            output: difference >= 0 ? 1n : 0n,
        };
    },
);

const comparisonCoefficients = interpolate(comparisonPoints);
const strictComparisonCoefficients = interpolate(
    comparisonPoints.map(({ input }) => ({
        input,
        output: input > 0n ? 1n : 0n,
    })),
);

const equalityPolynomials = new Map<number, readonly (readonly bigint[])[]>();
for (let optionCount = 2; optionCount <= maximumOptionCount; optionCount += 1) {
    equalityPolynomials.set(
        optionCount,
        Array.from({ length: optionCount }, (_unused, requestedRank) =>
            interpolate(
                Array.from({ length: optionCount }, (_unused2, rank) => ({
                    input: BigInt(rank),
                    output: rank === requestedRank ? 1n : 0n,
                })),
            ),
        ),
    );
}

export type BallotInventoryEntry =
    | Readonly<{ kind: 'accepted'; scores: readonly number[] }>
    | Readonly<{ kind: 'not-accepted' }>;
export type RankingResult = Readonly<{
    kind: 'no-result' | 'result';
    orderedOptionPositions: readonly number[];
}>;

const requireProfile = (
    inventory: readonly BallotInventoryEntry[],
    optionCount: number,
    topCount: number,
): void => {
    if (inventory.length < 3 || inventory.length > maximumParticipantCount) {
        throw new RangeError(
            'The ballot count is outside the supported range.',
        );
    }
    if (optionCount < 2 || optionCount > maximumOptionCount) {
        throw new RangeError(
            'The option count is outside the supported range.',
        );
    }
    if (topCount < 1 || topCount > optionCount) {
        throw new RangeError('The result length is outside the option range.');
    }
    for (const entry of inventory) {
        if (entry.kind === 'not-accepted') continue;
        const ballot = entry.scores;
        if (
            ballot.length !== optionCount ||
            ballot.some(
                (score) =>
                    !Number.isSafeInteger(score) || score < 1 || score > 10,
            )
        ) {
            throw new RangeError(
                'An accepted ballot is not a complete score vector.',
            );
        }
    }
};

export const evaluateReferenceRanking = (
    inventory: readonly BallotInventoryEntry[],
    optionCount: number,
    topCount: number,
): RankingResult => {
    requireProfile(inventory, optionCount, topCount);
    const accepted = inventory.filter(
        (
            entry,
        ): entry is Readonly<{
            kind: 'accepted';
            scores: readonly number[];
        }> => entry.kind === 'accepted',
    );
    if (accepted.length === 0) {
        return { kind: 'no-result', orderedOptionPositions: [] };
    }
    const totals = Array.from({ length: optionCount }, () => 0);
    for (const { scores: ballot } of accepted) {
        for (let option = 0; option < optionCount; option += 1) {
            totals[option] = (totals[option] ?? 0) + (ballot[option] ?? 0);
        }
    }
    return {
        kind: 'result',
        orderedOptionPositions: Array.from(
            { length: optionCount },
            (_unused, option) => option,
        )
            .sort(
                (left, right) =>
                    (totals[right] ?? 0) - (totals[left] ?? 0) || left - right,
            )
            .slice(0, topCount),
    };
};

export const evaluatePolynomialRanking = (
    inventory: readonly BallotInventoryEntry[],
    optionCount: number,
    topCount: number,
): RankingResult => {
    requireProfile(inventory, optionCount, topCount);
    const accepted = inventory.filter(
        (
            entry,
        ): entry is Readonly<{
            kind: 'accepted';
            scores: readonly number[];
        }> => entry.kind === 'accepted',
    );
    if (accepted.length === 0) {
        return { kind: 'no-result', orderedOptionPositions: [] };
    }
    const totals = Array.from({ length: optionCount }, () => 0);
    for (const { scores: ballot } of accepted) {
        for (let option = 0; option < optionCount; option += 1) {
            totals[option] = (totals[option] ?? 0) + (ballot[option] ?? 0);
        }
    }

    const ranks = Array.from({ length: optionCount }, () => 0);
    for (let left = 0; left < optionCount; left += 1) {
        for (let right = left + 1; right < optionCount; right += 1) {
            const difference = (totals[left] ?? 0) - (totals[right] ?? 0);
            if (
                difference < -maximumDifference ||
                difference > maximumDifference
            ) {
                throw new Error(
                    'A total difference escaped the proven domain.',
                );
            }
            const leftAhead = Number(
                evaluatePolynomial(comparisonCoefficients, BigInt(difference)),
            );
            ranks[right] = (ranks[right] ?? 0) + leftAhead;
            ranks[left] = (ranks[left] ?? 0) + 1 - leftAhead;
        }
    }

    const polynomials = equalityPolynomials.get(optionCount);
    if (polynomials === undefined) {
        throw new Error('The rank-equality polynomials are absent.');
    }
    const orderedOptionPositions: number[] = [];
    for (let requestedRank = 0; requestedRank < topCount; requestedRank += 1) {
        let selectedCount = 0;
        let selectedPosition = 0;
        const polynomial = polynomials[requestedRank];
        if (polynomial === undefined) {
            throw new Error('A rank-equality polynomial is absent.');
        }
        for (let option = 0; option < optionCount; option += 1) {
            const indicator = Number(
                evaluatePolynomial(polynomial, BigInt(ranks[option] ?? -1)),
            );
            if (indicator !== 0 && indicator !== 1) {
                throw new Error('A rank indicator is not binary.');
            }
            selectedCount += indicator;
            selectedPosition += indicator * option;
        }
        if (selectedCount !== 1) {
            throw new Error(
                'A requested rank does not select exactly one option.',
            );
        }
        orderedOptionPositions.push(selectedPosition);
    }
    return { kind: 'result', orderedOptionPositions };
};

const evaluatePackedPolynomialRanking = (
    inventory: readonly BallotInventoryEntry[],
    optionCount: number,
    topCount: number,
): RankingResult => {
    requireProfile(inventory, optionCount, topCount);
    const accepted = inventory.filter(
        (
            entry,
        ): entry is Readonly<{
            kind: 'accepted';
            scores: readonly number[];
        }> => entry.kind === 'accepted',
    );
    if (accepted.length === 0) {
        return { kind: 'no-result', orderedOptionPositions: [] };
    }

    const totals = Array.from({ length: optionCount }, () => 0);
    for (const { scores } of accepted) {
        for (let option = 0; option < optionCount; option += 1) {
            totals[option] = (totals[option] ?? 0) + (scores[option] ?? 0);
        }
    }

    const ranks = Array.from({ length: optionCount }, () => 0n);
    for (let shift = 1; shift < optionCount; shift += 1) {
        for (let lowerOption = 0; lowerOption < optionCount; lowerOption += 1) {
            const higherOption = (lowerOption + shift) % optionCount;
            if (lowerOption >= higherOption) continue;
            const difference =
                (totals[lowerOption] ?? 0) - (totals[higherOption] ?? 0);
            const lowerOptionAhead = evaluatePolynomial(
                comparisonCoefficients,
                BigInt(difference),
            );
            ranks[lowerOption] = modulo(
                (ranks[lowerOption] ?? 0n) + 1n - lowerOptionAhead,
            );
            ranks[higherOption] = modulo(
                (ranks[higherOption] ?? 0n) + lowerOptionAhead,
            );
        }
    }

    const polynomials = equalityPolynomials.get(optionCount);
    if (polynomials === undefined) {
        throw new Error('The rank-equality polynomials are absent.');
    }
    const orderedOptionPositions: number[] = [];
    for (let requestedRank = 0; requestedRank < topCount; requestedRank += 1) {
        const polynomial = polynomials[requestedRank];
        if (polynomial === undefined) {
            throw new Error('A rank-equality polynomial is absent.');
        }
        let selectedCount = 0n;
        let selectedPosition = 0n;
        for (let option = 0; option < optionCount; option += 1) {
            const indicator = evaluatePolynomial(
                polynomial,
                ranks[option] ?? -1n,
            );
            selectedCount += indicator;
            selectedPosition += indicator * BigInt(option);
        }
        if (selectedCount !== 1n) {
            throw new Error(
                'A packed rank does not select exactly one option.',
            );
        }
        orderedOptionPositions.push(Number(selectedPosition));
    }
    return { kind: 'result', orderedOptionPositions };
};

type GraphNodeKind =
    | 'ciphertext-addition'
    | 'ciphertext-input'
    | 'ciphertext-multiplication'
    | 'plaintext-addition'
    | 'plaintext-multiplication'
    | 'rotation';

type GraphNode = Readonly<{
    depth: number;
    inputs: readonly number[];
    kind: GraphNodeKind;
}>;

export type RankingEvaluationGraph = Readonly<{
    materializedCiphertextNodeCount: number;
    scheduledPeakLiveCiphertextCount: number;
    scheduledPeakCiphertextByteLength: number;
    ciphertextInputCount: number;
    ciphertextAdditionCount: number;
    plaintextAdditionCount: number;
    ciphertextMultiplicationCount: number;
    plaintextMultiplicationCount: number;
    relinearizationCount: number;
    rotationCount: number;
    multiplicativeDepth: number;
}>;

class EvaluationGraph {
    readonly #nodes: GraphNode[] = [];

    input(): number {
        return this.#append('ciphertext-input');
    }

    add(left: number, right: number): number {
        return this.#append('ciphertext-addition', [left, right]);
    }

    addPlain(input: number): number {
        return this.#append('plaintext-addition', [input]);
    }

    multiply(left: number, right: number): number {
        return this.#append('ciphertext-multiplication', [left, right], 1);
    }

    multiplyPlain(input: number): number {
        return this.#append('plaintext-multiplication', [input]);
    }

    rotate(input: number): number {
        return this.#append('rotation', [input]);
    }

    densePowers(input: number, degree: number): readonly number[] {
        const powers = Array.from({ length: degree + 1 }, () => -1);
        powers[1] = input;
        for (let exponent = 2; exponent <= degree; exponent += 1) {
            const left = Math.floor(exponent / 2);
            powers[exponent] = this.multiply(
                powers[left] ?? -1,
                powers[exponent - left] ?? -1,
            );
        }
        return powers;
    }

    linearCombination(
        powers: readonly number[],
        coefficients: readonly bigint[],
    ): number {
        const terms: number[] = [];
        for (let exponent = 1; exponent < coefficients.length; exponent += 1) {
            if (coefficients[exponent] !== 0n) {
                terms.push(this.multiplyPlain(powers[exponent] ?? -1));
            }
        }
        if (terms.length === 0) {
            throw new Error('A polynomial block has no ciphertext term.');
        }
        let result = terms[0] ?? -1;
        for (let index = 1; index < terms.length; index += 1) {
            result = this.add(result, terms[index] ?? -1);
        }
        return coefficients[0] === 0n ? result : this.addPlain(result);
    }

    patersonStockmeyer(
        input: number,
        coefficients: readonly bigint[],
        blockSize: number,
    ): number {
        const giantDegree = Math.floor((coefficients.length - 1) / blockSize);
        const baby = this.densePowers(input, blockSize);
        const giant = this.densePowers(baby[blockSize] ?? -1, giantDegree);
        let result: number | undefined;
        let pendingConstant = false;
        for (let giantIndex = 0; giantIndex <= giantDegree; giantIndex += 1) {
            const block = coefficients.slice(
                giantIndex * blockSize,
                Math.min((giantIndex + 1) * blockSize, coefficients.length),
            );
            const hasVariable = block
                .slice(1)
                .some((coefficient) => coefficient !== 0n);
            let term: number;
            if (hasVariable) {
                const blockValue = this.linearCombination(baby, block);
                term =
                    giantIndex === 0
                        ? blockValue
                        : this.multiply(blockValue, giant[giantIndex] ?? -1);
            } else if (block[0] !== 0n && giantIndex > 0) {
                term = this.multiplyPlain(giant[giantIndex] ?? -1);
            } else if (block[0] !== 0n) {
                pendingConstant = true;
                continue;
            } else {
                continue;
            }
            result = result === undefined ? term : this.add(result, term);
        }
        if (result === undefined) {
            throw new Error('The polynomial produced no ciphertext term.');
        }
        return pendingConstant ? this.addPlain(result) : result;
    }

    summarize(outputNode: number): RankingEvaluationGraph {
        const counts = new Map<GraphNodeKind, number>();
        let multiplicativeDepth = 0;
        for (const node of this.#nodes) {
            counts.set(node.kind, (counts.get(node.kind) ?? 0) + 1);
            multiplicativeDepth = Math.max(multiplicativeDepth, node.depth);
        }

        const references = Array.from({ length: this.#nodes.length }, () => 0);
        for (const node of this.#nodes) {
            for (const input of node.inputs) {
                references[input] = (references[input] ?? 0) + 1;
            }
        }
        const dataModulusCount = multiplicativeDepth + 1;
        const ciphertextBytes = (depth: number): number =>
            113 + 2 * 32_768 * 8 * Math.max(1, dataModulusCount - depth);
        let liveCount = 0;
        let liveBytes = 0;
        let peakCount = 0;
        let peakBytes = 0;
        for (let index = 0; index < this.#nodes.length; index += 1) {
            const node = this.#nodes[index];
            if (node === undefined) throw new Error('A graph node is absent.');
            liveCount += 1;
            liveBytes += ciphertextBytes(node.depth);
            peakCount = Math.max(peakCount, liveCount);
            peakBytes = Math.max(peakBytes, liveBytes);
            for (const input of node.inputs) {
                references[input] = (references[input] ?? 0) - 1;
                if (references[input] === 0 && input !== outputNode) {
                    const released = this.#nodes[input];
                    if (released === undefined) {
                        throw new Error('A released graph node is absent.');
                    }
                    liveCount -= 1;
                    liveBytes -= ciphertextBytes(released.depth);
                }
            }
            if ((references[index] ?? 0) === 0 && index !== outputNode) {
                liveCount -= 1;
                liveBytes -= ciphertextBytes(node.depth);
            }
        }

        return {
            materializedCiphertextNodeCount: this.#nodes.length,
            scheduledPeakLiveCiphertextCount: peakCount,
            scheduledPeakCiphertextByteLength: peakBytes,
            ciphertextInputCount: counts.get('ciphertext-input') ?? 0,
            ciphertextAdditionCount: counts.get('ciphertext-addition') ?? 0,
            plaintextAdditionCount: counts.get('plaintext-addition') ?? 0,
            ciphertextMultiplicationCount:
                counts.get('ciphertext-multiplication') ?? 0,
            plaintextMultiplicationCount:
                counts.get('plaintext-multiplication') ?? 0,
            relinearizationCount: counts.get('ciphertext-multiplication') ?? 0,
            rotationCount: counts.get('rotation') ?? 0,
            multiplicativeDepth,
        };
    }

    #append(
        kind: GraphNodeKind,
        inputs: readonly number[] = [],
        depthIncrement = 0,
    ): number {
        if (
            inputs.some(
                (input) => input < 0 || this.#nodes[input] === undefined,
            )
        ) {
            throw new Error('A graph input is absent.');
        }
        const depth =
            inputs.reduce(
                (maximum, input) =>
                    Math.max(maximum, this.#nodes[input]?.depth ?? 0),
                0,
            ) + depthIncrement;
        this.#nodes.push({ depth, inputs: [...inputs], kind });
        return this.#nodes.length - 1;
    }
}

export const compilePackedRankingEvaluationGraph = (
    participantCount: number,
    optionCount: number,
    topCount: number,
    comparisonBlockSize = 24,
): RankingEvaluationGraph => {
    requireProfile(
        Array.from(
            { length: participantCount },
            () =>
                ({
                    kind: 'accepted',
                    scores: Array.from({ length: optionCount }, () => 1),
                }) as const,
        ),
        optionCount,
        topCount,
    );
    const graph = new EvaluationGraph();
    const encryptedBallots = Array.from({ length: participantCount }, () =>
        graph.input(),
    );
    let totals = encryptedBallots[0];
    if (totals === undefined) throw new Error('The first ballot is absent.');
    for (let index = 1; index < encryptedBallots.length; index += 1) {
        totals = graph.add(totals, encryptedBallots[index] ?? -1);
    }

    let rank: number | undefined;
    for (let shift = 1; shift < optionCount; shift += 1) {
        // Public masks retain exactly the lanes whose current option position is
        // lower than the shifted opponent position. Each unordered pair occurs
        // in exactly one such lane over all shifts. The plaintext multiplication
        // below also negates the rotated opponent, so the sum is current minus
        // opponent. H_ge therefore implements the canonical lower-position tie
        // rule without a second comparison polynomial.
        const negativeOpponent = graph.multiplyPlain(graph.rotate(totals));
        const difference = graph.add(totals, negativeOpponent);
        const lowerOptionAhead = graph.multiplyPlain(
            graph.patersonStockmeyer(
                difference,
                comparisonCoefficients,
                comparisonBlockSize,
            ),
        );
        // Negation is a free linear operation in this counting model. Adding the
        // public pair mask yields 1-lowerOptionAhead in the selected lanes.
        const lowerOptionBehind = graph.addPlain(lowerOptionAhead);
        const higherOptionRankContribution = graph.rotate(lowerOptionAhead);
        const pairRankContribution = graph.add(
            lowerOptionBehind,
            higherOptionRankContribution,
        );
        rank =
            rank === undefined
                ? pairRankContribution
                : graph.add(rank, pairRankContribution);
    }
    if (rank === undefined) {
        throw new Error('The comparison graph is empty.');
    }
    const rankPowers = graph.densePowers(rank, optionCount - 1);
    const polynomials = equalityPolynomials.get(optionCount);
    if (polynomials === undefined) {
        throw new Error('The equality-polynomial inventory is absent.');
    }

    let packedOutput: number | undefined;
    const reductionStepCount = Math.ceil(Math.log2(optionCount));
    for (let requestedRank = 0; requestedRank < topCount; requestedRank += 1) {
        const polynomial = polynomials[requestedRank];
        if (polynomial === undefined) {
            throw new Error('A rank-equality polynomial is absent.');
        }
        let selected = graph.multiplyPlain(
            graph.linearCombination(rankPowers, polynomial),
        );
        for (let step = 0; step < reductionStepCount; step += 1) {
            const maskedRotation = graph.multiplyPlain(graph.rotate(selected));
            selected = graph.add(selected, maskedRotation);
        }
        if (requestedRank > 0) selected = graph.rotate(selected);
        packedOutput =
            packedOutput === undefined
                ? selected
                : graph.add(packedOutput, selected);
    }
    if (packedOutput === undefined)
        throw new Error('The output graph is empty.');
    return graph.summarize(packedOutput);
};

const deterministicMatrix = (
    participantCount: number,
    optionCount: number,
    score: (participant: number, option: number) => number,
): BallotInventoryEntry[] =>
    Array.from(
        { length: participantCount },
        (_unused, participant) =>
            ({
                kind: 'accepted',
                scores: Array.from(
                    { length: optionCount },
                    (_unused2, option) => score(participant, option),
                ),
            }) as const,
    );

export type ExactRankingModelCensus = Readonly<{
    comparisonPolynomialDegree: number;
    comparisonPolynomialNonzeroCoefficientCount: number;
    exhaustiveComparisonPointCount: number;
    equalityDomainCount: number;
    testedParticipantOptionProfileCount: number;
    testedMatrixCount: number;
    testedTopCountExecutionCount: number;
}>;

export const verifyExactRankingModel = (): ExactRankingModelCensus => {
    if (comparisonCoefficients.length - 1 !== 2 * maximumDifference) {
        throw new Error('The comparison polynomial has the wrong degree.');
    }
    for (
        let difference = -maximumDifference;
        difference <= maximumDifference;
        difference += 1
    ) {
        if (
            evaluatePolynomial(comparisonCoefficients, BigInt(difference)) !==
                (difference >= 0 ? 1n : 0n) ||
            evaluatePolynomial(
                strictComparisonCoefficients,
                BigInt(difference),
            ) !== (difference > 0 ? 1n : 0n)
        ) {
            throw new Error(
                'A comparison polynomial disagrees with its oracle.',
            );
        }
    }
    for (const [optionCount, polynomials] of equalityPolynomials) {
        for (
            let requestedRank = 0;
            requestedRank < optionCount;
            requestedRank += 1
        ) {
            const polynomial = polynomials[requestedRank];
            if (polynomial === undefined)
                throw new Error('A polynomial is absent.');
            for (let rank = 0; rank < optionCount; rank += 1) {
                if (
                    evaluatePolynomial(polynomial, BigInt(rank)) !==
                    (rank === requestedRank ? 1n : 0n)
                ) {
                    throw new Error(
                        'A rank polynomial disagrees with its oracle.',
                    );
                }
            }
        }
    }

    let randomState = 0x9e37_79b9;
    const nextRandom = (): number => {
        randomState ^= randomState << 13;
        randomState ^= randomState >>> 17;
        randomState ^= randomState << 5;
        return randomState >>> 0;
    };
    let testedMatrixCount = 0;
    let testedTopCountExecutionCount = 0;
    for (let participants = 3; participants <= 20; participants += 1) {
        for (let options = 2; options <= 20; options += 1) {
            const cases: BallotInventoryEntry[][] = [
                deterministicMatrix(participants, options, () => 1),
                deterministicMatrix(participants, options, () => 10),
                [
                    {
                        kind: 'accepted',
                        scores: Array.from(
                            { length: options },
                            (_unused, option) => (option % 10) + 1,
                        ),
                    },
                    ...Array.from(
                        { length: participants - 1 },
                        () => ({ kind: 'not-accepted' }) as const,
                    ),
                ],
                Array.from(
                    { length: participants },
                    () => ({ kind: 'not-accepted' }) as const,
                ),
                deterministicMatrix(
                    participants,
                    options,
                    (participant, option) =>
                        ((participant + options - option) % 10) + 1,
                ),
                deterministicMatrix(
                    participants,
                    options,
                    (participant, option) =>
                        ((participant * 7 + option * 3) % 5) + 1,
                ),
            ];
            for (let sample = 0; sample < 8; sample += 1) {
                cases.push(
                    Array.from({ length: participants }, () =>
                        nextRandom() % 7 === 0
                            ? ({ kind: 'not-accepted' } as const)
                            : ({
                                  kind: 'accepted',
                                  scores: Array.from(
                                      { length: options },
                                      () => (nextRandom() % 10) + 1,
                                  ),
                              } as const),
                    ),
                );
            }
            for (const ballots of cases) {
                testedMatrixCount += 1;
                for (let topCount = 1; topCount <= options; topCount += 1) {
                    testedTopCountExecutionCount += 1;
                    const expected = evaluateReferenceRanking(
                        ballots,
                        options,
                        topCount,
                    );
                    const actual = evaluatePolynomialRanking(
                        ballots,
                        options,
                        topCount,
                    );
                    const packed = evaluatePackedPolynomialRanking(
                        ballots,
                        options,
                        topCount,
                    );
                    if (
                        JSON.stringify(actual) !== JSON.stringify(expected) ||
                        JSON.stringify(packed) !== JSON.stringify(expected)
                    ) {
                        throw new Error(
                            'The ranking circuit disagrees with its oracle.',
                        );
                    }
                }
            }
        }
    }

    return {
        comparisonPolynomialDegree: comparisonCoefficients.length - 1,
        comparisonPolynomialNonzeroCoefficientCount:
            comparisonCoefficients.filter((coefficient) => coefficient !== 0n)
                .length,
        exhaustiveComparisonPointCount: comparisonPoints.length,
        equalityDomainCount: equalityPolynomials.size,
        testedParticipantOptionProfileCount: 18 * 19,
        testedMatrixCount,
        testedTopCountExecutionCount,
    };
};

export const exactRankingModelConstants = {
    maximumDifference,
    maximumOptionCount,
    maximumParticipantCount,
    plaintextModulus,
} as const;
