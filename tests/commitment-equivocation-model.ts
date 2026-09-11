import { compileCommitmentExtractionBound } from '#tests/commitment-extraction-bound-model.js';

// Whole-message extension of ABKK22 Theorem 5.12's single-sender hybrid.
// The coefficient two is from AHU19 Theorem 3 (one-way to hiding).
// This models an ideal oracle; it does not establish the joint fixed-hash claim.
export const compileCommitmentEquivocationBound = (
    participantCount: number,
) => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported participant count.');
    const { quantumQueryCount } =
        compileCommitmentExtractionBound(participantCount);
    const saltBitLength = 512n;
    const honestCommitmentCount = BigInt(participantCount);
    // Apply the single-sender hybrid once per honest one-shot commitment.
    const numerator = 2n * honestCommitmentCount * quantumQueryCount;
    const denominator = 1n << (saltBitLength / 2n);
    let failureExponent = 0n;
    while (numerator << (failureExponent + 1n) <= denominator)
        failureExponent++;
    return {
        honestCommitmentCount,
        quantumQueryCount,
        saltBitLength,
        numerator,
        denominator,
        failureExponent,
        // One background oracle and one independent shadow oracle per sender.
        maximumControlledOracleCalls:
            (honestCommitmentCount + 1n) * quantumQueryCount,
    };
};

type ShadowVariant =
    | 'complete-slice'
    | 'first-message-only'
    | 'retain-shadow'
    | 'replace-full-output';

// Exact density-matrix enumeration for a bounded receiver: two classical
// queries choose its message, then one phase query depends on the commitment.
// The final block discloses the opening and the entire post-opening oracle.
export const compareCommitmentEquivocationHybrids = (
    messageCount: number,
    saltCount: number,
    variant: ShadowVariant,
    oracleOutputBits = 1,
    committedOutputBits = oracleOutputBits,
) => {
    const inputCount = messageCount * saltCount;
    if (
        !Number.isSafeInteger(messageCount) ||
        !Number.isSafeInteger(saltCount) ||
        !Number.isSafeInteger(oracleOutputBits) ||
        !Number.isSafeInteger(committedOutputBits) ||
        messageCount < 2 ||
        saltCount < 2 ||
        oracleOutputBits < 1 ||
        oracleOutputBits > 2 ||
        committedOutputBits < 1 ||
        committedOutputBits > oracleOutputBits ||
        inputCount * oracleOutputBits > 8
    )
        throw new RangeError('The finite oracle enumeration is too large.');
    const outputCount = 1 << oracleOutputBits;
    const commitmentCount = 1 << committedOutputBits;
    const prefixMask = commitmentCount - 1;
    const dimension = inputCount * outputCount;
    const real = new Map<string, Int32Array>();
    const simulated = new Map<string, Int32Array>();
    const value = (table: number, index: number) =>
        (table >>> (index * oracleOutputBits)) & (outputCount - 1);
    const replace = (table: number, index: number, replacementValue: number) =>
        (table & ~((outputCount - 1) << (index * oracleOutputBits))) |
        (replacementValue << (index * oracleOutputBits));
    const add = (
        blocks: Map<string, Int32Array>,
        key: string,
        phases: readonly number[],
        weight: number,
    ) => {
        let matrix = blocks.get(key);
        if (!matrix) {
            matrix = new Int32Array(dimension * dimension);
            blocks.set(key, matrix);
        }
        for (let row = 0; row < dimension; row++)
            for (let column = 0; column < dimension; column++)
                matrix[row * dimension + column] +=
                    weight * phases[row] * phases[column];
    };
    let realCases = 0;
    let simulatedCases = 0;
    for (
        let background = 0;
        background < outputCount ** inputCount;
        background++
    )
        for (let shadow = 0; shadow < outputCount ** messageCount; shadow++)
            for (let salt = 0; salt < saltCount; salt++) {
                let oracle = background;
                for (let message = 0; message < messageCount; message++)
                    if (variant !== 'first-message-only' || message === 0)
                        oracle = replace(
                            oracle,
                            message * saltCount + salt,
                            value(shadow, message),
                        );
                const answer =
                    value(oracle, 0) +
                    outputCount * value(oracle, inputCount - 1);
                const message = answer % messageCount;
                const point = message * saltCount + salt;
                const phases = (commitment: number) =>
                    Array.from({ length: dimension }, (_, index) => {
                        const query = Math.floor(index / outputCount);
                        const character = index % outputCount;
                        const response = value(
                            oracle,
                            (query + commitment) % inputCount,
                        );
                        const product = character & response;
                        const parity = (product & 1) ^ ((product >>> 1) & 1);
                        return parity === 0 ? 1 : -1;
                    });
                const key = (after: number, commitment: number) =>
                    [after, salt, message, answer, commitment].join(':');
                const commitment = value(background, point) & prefixMask;
                // Account for the simulator's additional uniform output draw.
                add(
                    real,
                    key(background, commitment),
                    phases(commitment),
                    commitmentCount,
                );
                realCases++;
                for (
                    let announced = 0;
                    announced < commitmentCount;
                    announced++
                ) {
                    const base =
                        variant === 'retain-shadow' ? oracle : background;
                    const replacement =
                        variant === 'replace-full-output'
                            ? announced
                            : (value(base, point) & ~prefixMask) | announced;
                    const after = replace(base, point, replacement);
                    add(simulated, key(after, announced), phases(announced), 1);
                    simulatedCases++;
                }
            }
    const keys = new Set([...real.keys(), ...simulated.keys()]);
    let differingEntries = 0;
    let absoluteEntryDifference = 0;
    let realTrace = 0;
    let simulatedTrace = 0;
    let firstDifference: string | undefined;
    for (const key of keys) {
        const left = real.get(key);
        const right = simulated.get(key);
        for (let index = 0; index < dimension * dimension; index++) {
            const leftValue = left?.[index] ?? 0;
            const rightValue = right?.[index] ?? 0;
            if (index % (dimension + 1) === 0) {
                realTrace += leftValue;
                simulatedTrace += rightValue;
            }
            if (leftValue !== rightValue) {
                differingEntries++;
                absoluteEntryDifference += Math.abs(leftValue - rightValue);
                firstDifference ??= `${key}/${index}: ${leftValue} versus ${rightValue}`;
            }
        }
    }
    return {
        messageCount,
        saltCount,
        oracleOutputBits,
        committedOutputBits,
        dimension,
        realCases,
        simulatedCases,
        classicalBlocks: keys.size,
        commonDenominator: simulatedCases * dimension,
        realTrace,
        simulatedTrace,
        differingEntries,
        absoluteEntryDifference,
        firstDifference,
    };
};

// A receiver can compare complete opening inputs and announced outputs without
// an oracle query. Independent simulated outputs cannot alias one input.
export const compareDuplicateCommitmentInputs = (distinctSenders: boolean) => {
    const saltCount = 2;
    const outputCount = 4;
    const inputCount = distinctSenders ? 4 : 2;
    let realEvents = 0;
    let simulatedEvents = 0;
    let realCases = 0;
    let simulatedCases = 0;
    for (let firstSalt = 0; firstSalt < saltCount; firstSalt++)
        for (let secondSalt = 0; secondSalt < saltCount; secondSalt++) {
            const firstInput = firstSalt;
            const secondInput = secondSalt + (distinctSenders ? saltCount : 0);
            for (let oracle = 0; oracle < outputCount ** inputCount; oracle++) {
                const firstOutput = (oracle >>> (2 * firstInput)) & 3;
                const secondOutput = (oracle >>> (2 * secondInput)) & 3;
                realEvents += Number(
                    firstInput === secondInput && firstOutput !== secondOutput,
                );
                realCases++;
            }
            for (let firstOutput = 0; firstOutput < outputCount; firstOutput++)
                for (
                    let secondOutput = 0;
                    secondOutput < outputCount;
                    secondOutput++
                ) {
                    simulatedEvents += Number(
                        firstInput === secondInput &&
                            firstOutput !== secondOutput,
                    );
                    simulatedCases++;
                }
        }
    return { realEvents, realCases, simulatedEvents, simulatedCases };
};
