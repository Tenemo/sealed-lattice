const identityByteLength = 64;
const allocationNonceByteLength = 32;
const chunkHeaderByteLength = 250;
const manifestHeaderByteLength = 176;
const manifestDescriptorByteLength = 78;
const completionParticipantCount = 10;
const completionOptionCount = 10;
const scoreBitWidth = 4;
const admittedLabelByteLength = 40;
const maximumChunkByteLength = 480_000;
const maximumChunkPayloadByteLength =
    maximumChunkByteLength - chunkHeaderByteLength;

type IndependentEncodingLengths = Readonly<{
    labelByteLength: number;
    tokenByteLength: number;
    initialWirePayloadByteLength: number;
    constantPayloadByteLength: number;
    linearPayloadByteLength: number;
    conjunctionPayloadByteLength: number;
    terminalPayloadByteLength: number;
    labelPairEntropyByteLength: number;
}>;

const independentEncodingLengths = (
    labelByteLength: number,
): IndependentEncodingLengths => {
    if (!Number.isSafeInteger(labelByteLength) || labelByteLength < 1) {
        throw new RangeError(
            'The label byte length must be a positive integer.',
        );
    }
    const tokenByteLength = labelByteLength + 1;
    return {
        labelByteLength,
        tokenByteLength,
        initialWirePayloadByteLength: 4 * tokenByteLength,
        constantPayloadByteLength: 4 * tokenByteLength,
        linearPayloadByteLength: 4 * 4 * tokenByteLength,
        conjunctionPayloadByteLength:
            140 * tokenByteLength +
            4 * tokenByteLength +
            1 +
            80 * labelByteLength +
            2 * (tokenByteLength + labelByteLength) +
            3 * tokenByteLength,
        terminalPayloadByteLength: 20 * tokenByteLength + 1,
        labelPairEntropyByteLength: 2 * labelByteLength + 1,
    };
};

const admittedEncodingLengths = independentEncodingLengths(
    admittedLabelByteLength,
);
const tokenByteLength = admittedEncodingLengths.tokenByteLength;
const linearPayloadByteLength = admittedEncodingLengths.linearPayloadByteLength;

type IndependentBooleanOperation =
    | Readonly<{ kind: 'constant'; value: boolean }>
    | Readonly<{ kind: 'linear'; leftWire: number; rightWire: number }>
    | Readonly<{
          kind: 'conjunction';
          leftWire: number;
          rightWire: number;
      }>
    | Readonly<{ kind: 'negation'; inputWire: number }>;

type IndependentChunkDescriptor = Readonly<{
    firstOperation: number;
    operationEnd: number;
    includesInitial: boolean;
    includesTerminal: boolean;
    logicalPayloadStart: number;
    logicalPayloadEnd: number;
    chunkByteLength: number;
    labelEntropyByteLength: number;
}>;

type IndependentPaddedTallyKmacCensus = Readonly<{
    labelKeyCount: number;
    continuationKeyCount: number;
    keyCount: number;
    labelOutputCount: number;
    continuationOutputCount: number;
    generationCallCount: number;
    selectedEvaluationCallCount: number;
    unavailableLabelReplacementCount: number;
    counterfactualContinuationReplacementCount: number;
    hiddenReplacementCount: number;
    maximumLabelFanOut: number;
    labelFanOutDistribution: readonly (readonly [number, number])[];
}>;

export type IndependentPaddedTallyWidthProjection = Readonly<{
    labelByteLength: number;
    tokenByteLength: number;
    initialWirePayloadByteLength: number;
    constantPayloadByteLength: number;
    linearPayloadByteLength: number;
    conjunctionPayloadByteLength: number;
    terminalPayloadByteLength: number;
    labelPairEntropyByteLength: number;
    logicalPayloadByteLength: number;
    participantChunkCorpusByteLength: number;
    completeChunkCorpusByteLength: number;
    participantLabelEntropyByteLength: number;
    completeLabelEntropyByteLength: number;
    manifestByteLength: number;
    chunkCount: number;
    chunkByteLengths: readonly number[];
    chunkLabelEntropyByteLengths: readonly number[];
    maximumChunkByteLength: number;
    maximumChunkLabelEntropyByteLength: number;
    maximumLiveWireCount: number;
    liveWireCountsAfterChunks: readonly number[];
    maximumGenerationCheckpointByteLength: number;
    maximumEvaluationCheckpointByteLength: number;
    maximumChunkGenerationRequestByteLength: number;
    maximumChunkEvaluationRequestByteLength: number;
    maximumChunkGenerationResponseByteLength: number;
    maximumChunkEvaluationResponseByteLength: number;
}>;

export type IndependentPaddedTallyKmacTheoremScreen = Readonly<{
    rateBitLength: number;
    capacityBitLength: number;
    keyBitLength: number;
    keyPrefixBitOffsetModuloRate: number;
    derivedKeySecurityBitLength: number;
    paddedKeyPrefixBlockCount: number;
    constructionEffectiveBlockBudget: number;
    quantumPrimitiveQueryBudget: number;
    challengedKeyCount: number;
    singleKeyAdvantageUpperBound: number;
    completeHybridAdvantageUpperBound: number;
    singleKeySecurityBitLength: number;
    completeHybridSecurityBitLength: number;
}>;

export type IndependentPaddedTallyModel = Readonly<{
    topCount: number;
    inputWireCount: number;
    operations: readonly IndependentBooleanOperation[];
    outputWires: readonly number[];
    constantCount: number;
    linearCount: number;
    conjunctionCount: number;
    negationCount: number;
    logicalPayloadByteLength: number;
    labelEntropyByteLength: number;
    descriptors: readonly IndependentChunkDescriptor[];
    maximumLiveWireCount: number;
    liveWireCountsAfterChunks: readonly number[];
    kmacCensus: IndependentPaddedTallyKmacCensus;
}>;

const operationPayloadByteLength = (
    operation: IndependentBooleanOperation,
    encodingLengths = admittedEncodingLengths,
): number => {
    switch (operation.kind) {
        case 'constant':
            return encodingLengths.constantPayloadByteLength;
        case 'linear':
            return encodingLengths.linearPayloadByteLength;
        case 'conjunction':
            return encodingLengths.conjunctionPayloadByteLength;
        case 'negation':
            return 0;
    }
};

const operationLabelPairCount = (
    operation: IndependentBooleanOperation,
): number => {
    switch (operation.kind) {
        case 'constant':
        case 'linear':
            return 4;
        case 'conjunction':
            return 43;
        case 'negation':
            return 0;
    }
};

const requireArrayItem = <T>(
    values: readonly T[],
    index: number,
    name: string,
): T => {
    const value = values[index];
    if (value === undefined) {
        throw new Error(`The independent tally model is missing ${name}.`);
    }
    return value;
};

class IndependentBooleanCircuitBuilder {
    readonly operations: IndependentBooleanOperation[] = [
        { kind: 'constant', value: false },
        { kind: 'constant', value: true },
    ];

    readonly #constantValues: Array<boolean | undefined>;
    readonly #falseConstantWire: number;
    readonly #trueConstantWire: number;

    constructor(private readonly inputWireCount: number) {
        this.#falseConstantWire = inputWireCount;
        this.#trueConstantWire = inputWireCount + 1;
        this.#constantValues = Array.from(
            { length: inputWireCount },
            () => undefined,
        );
        this.#constantValues.push(false, true);
    }

    appendConstant(value: boolean): number {
        return value ? this.#trueConstantWire : this.#falseConstantWire;
    }

    appendExclusiveOr(leftWire: number, rightWire: number): number {
        this.#requireWire(leftWire);
        this.#requireWire(rightWire);
        if (leftWire === rightWire) return this.#falseConstantWire;
        const leftConstant = this.#constantValues[leftWire];
        const rightConstant = this.#constantValues[rightWire];
        if (leftConstant !== undefined) {
            return leftConstant ? this.appendNegation(rightWire) : rightWire;
        }
        if (rightConstant !== undefined) {
            return rightConstant ? this.appendNegation(leftWire) : leftWire;
        }
        return this.#appendOperation({
            kind: 'linear',
            leftWire,
            rightWire,
        });
    }

    appendConjunction(leftWire: number, rightWire: number): number {
        this.#requireWire(leftWire);
        this.#requireWire(rightWire);
        if (leftWire === rightWire) return leftWire;
        const leftConstant = this.#constantValues[leftWire];
        const rightConstant = this.#constantValues[rightWire];
        if (leftConstant !== undefined) {
            return leftConstant ? rightWire : this.#falseConstantWire;
        }
        if (rightConstant !== undefined) {
            return rightConstant ? leftWire : this.#falseConstantWire;
        }
        return this.#appendOperation({
            kind: 'conjunction',
            leftWire,
            rightWire,
        });
    }

    appendNegation(inputWire: number): number {
        this.#requireWire(inputWire);
        const constant = this.#constantValues[inputWire];
        if (constant !== undefined) {
            return constant ? this.#falseConstantWire : this.#trueConstantWire;
        }
        return this.#appendOperation({ kind: 'negation', inputWire });
    }

    appendDisjunction(leftWire: number, rightWire: number): number {
        const exclusiveOrWire = this.appendExclusiveOr(leftWire, rightWire);
        const conjunctionWire = this.appendConjunction(leftWire, rightWire);
        return this.appendExclusiveOr(exclusiveOrWire, conjunctionWire);
    }

    #appendOperation(operation: IndependentBooleanOperation): number {
        const outputWire = this.inputWireCount + this.operations.length;
        this.operations.push(operation);
        this.#constantValues.push(undefined);
        return outputWire;
    }

    #requireWire(wire: number): void {
        if (
            !Number.isSafeInteger(wire) ||
            wire < 0 ||
            wire >= this.#constantValues.length
        ) {
            throw new Error('The independent tally model has an invalid wire.');
        }
    }
}

type IndependentFieldPairIdentifiers = readonly [
    number,
    number,
    number,
    number,
];

class IndependentLabelFanOutCensus {
    readonly outputCountPerLabel: number[] = [];

    newPair(): number {
        const identifier = this.outputCountPerLabel.length;
        this.outputCountPerLabel.push(0);
        return identifier;
    }

    newFieldPairs(): IndependentFieldPairIdentifiers {
        return [this.newPair(), this.newPair(), this.newPair(), this.newPair()];
    }

    appendLocalGate(left: number, right: number, output?: number): number {
        this.addOutputs(left, 2);
        this.addOutputs(right, 2);
        return output ?? this.newPair();
    }

    addOutputs(pair: number, count: number): void {
        const current = this.outputCountPerLabel[pair];
        if (current === undefined) {
            throw new Error('The independent KMAC census has an invalid pair.');
        }
        this.outputCountPerLabel[pair] = current + count;
    }

    multiplyFields(
        left: IndependentFieldPairIdentifiers,
        right: IndependentFieldPairIdentifiers,
    ): IndependentFieldPairIdentifiers {
        const products: number[] = [];
        for (let position = 0; position < 16; position += 1) {
            products.push(
                this.appendLocalGate(
                    requireArrayItem(
                        left,
                        Math.floor(position / 4),
                        'left field pair',
                    ),
                    requireArrayItem(right, position % 4, 'right field pair'),
                ),
            );
        }
        const product = (index: number): number =>
            requireArrayItem(products, index, 'field product pair');
        const c0 = product(0);
        const c1 = this.appendLocalGate(product(1), product(4));
        const c2 = this.appendLocalGate(
            this.appendLocalGate(product(2), product(5)),
            product(8),
        );
        const c3 = this.appendLocalGate(
            this.appendLocalGate(product(3), product(6)),
            this.appendLocalGate(product(9), product(12)),
        );
        const c4 = this.appendLocalGate(
            this.appendLocalGate(product(7), product(10)),
            product(13),
        );
        const c5 = this.appendLocalGate(product(11), product(14));
        const c6 = product(15);
        return [
            this.appendLocalGate(c0, c4),
            this.appendLocalGate(this.appendLocalGate(c1, c4), c5),
            this.appendLocalGate(this.appendLocalGate(c2, c5), c6),
            this.appendLocalGate(c3, c6),
        ];
    }
}

const compileIndependentKmacCensus = (
    inputWireCount: number,
    operations: readonly IndependentBooleanOperation[],
    outputWires: readonly number[],
): IndependentPaddedTallyKmacCensus => {
    const census = new IndependentLabelFanOutCensus();
    const wirePairs: Array<IndependentFieldPairIdentifiers | undefined> =
        Array.from({ length: inputWireCount + operations.length });
    for (let wire = 0; wire < inputWireCount; wire += 1) {
        wirePairs[wire] = census.newFieldPairs();
    }
    const fieldPairs = (wire: number): IndependentFieldPairIdentifiers => {
        const pairs = requireArrayItem(wirePairs, wire, 'wire pairs');
        if (pairs === undefined) {
            throw new Error('The independent KMAC census found a dead wire.');
        }
        return pairs;
    };

    for (const [operationIndex, operation] of operations.entries()) {
        const outputWire = inputWireCount + operationIndex;
        switch (operation.kind) {
            case 'constant':
                wirePairs[outputWire] = census.newFieldPairs();
                break;
            case 'linear': {
                const left = fieldPairs(operation.leftWire);
                const right = fieldPairs(operation.rightWire);
                wirePairs[outputWire] = [
                    census.appendLocalGate(left[0], right[0]),
                    census.appendLocalGate(left[1], right[1]),
                    census.appendLocalGate(left[2], right[2]),
                    census.appendLocalGate(left[3], right[3]),
                ];
                break;
            }
            case 'conjunction': {
                const product = census.multiplyFields(
                    fieldPairs(operation.leftWire),
                    fieldPairs(operation.rightWire),
                );
                const mask = census.newFieldPairs();
                const masked = census.newFieldPairs();
                for (let basis = 0; basis < 4; basis += 1) {
                    const productPair = requireArrayItem(
                        product,
                        basis,
                        'product pair',
                    );
                    const maskPair = requireArrayItem(mask, basis, 'mask pair');
                    const maskedPair = requireArrayItem(
                        masked,
                        basis,
                        'masked pair',
                    );
                    census.appendLocalGate(productPair, maskPair, maskedPair);
                    census.addOutputs(maskedPair, completionParticipantCount);
                }
                wirePairs[outputWire] = census.newFieldPairs();
                break;
            }
            case 'negation':
                wirePairs[outputWire] = fieldPairs(operation.inputWire);
                break;
        }
    }

    for (const outputWire of outputWires) {
        const input = fieldPairs(outputWire);
        const mask = census.newFieldPairs();
        const output = census.newFieldPairs();
        for (let basis = 0; basis < 4; basis += 1) {
            census.appendLocalGate(
                requireArrayItem(input, basis, 'terminal input pair'),
                requireArrayItem(mask, basis, 'terminal mask pair'),
                requireArrayItem(output, basis, 'terminal output pair'),
            );
        }
    }

    const labelFanOutDistribution = new Map<number, number>();
    let labelOutputCount = 0;
    for (const outputCount of census.outputCountPerLabel) {
        const emittedKeyCount = 2 * completionParticipantCount;
        labelFanOutDistribution.set(
            outputCount,
            (labelFanOutDistribution.get(outputCount) ?? 0) + emittedKeyCount,
        );
        labelOutputCount += outputCount * emittedKeyCount;
    }
    const conjunctionCount = operations.filter(
        (operation) => operation.kind === 'conjunction',
    ).length;
    const linearCount = operations.filter(
        (operation) => operation.kind === 'linear',
    ).length;
    const labelKeyCount =
        census.outputCountPerLabel.length * 2 * completionParticipantCount;
    const continuationKeyCount =
        conjunctionCount * 2 * completionParticipantCount;
    const continuationOutputCount = continuationKeyCount;
    const unavailableLabelReplacementCount = labelOutputCount / 2;
    const counterfactualContinuationReplacementCount =
        continuationOutputCount / 2;
    if (
        !Number.isSafeInteger(unavailableLabelReplacementCount) ||
        !Number.isSafeInteger(counterfactualContinuationReplacementCount)
    ) {
        throw new Error('The independent KMAC census is not pair symmetric.');
    }
    const localMultiplicationGateCount = 35;
    const selectedEvaluationCallCount =
        conjunctionCount *
            completionParticipantCount *
            (2 * localMultiplicationGateCount +
                4 * completionParticipantCount +
                1) +
        linearCount * completionParticipantCount * 4 * 2 +
        outputWires.length * completionParticipantCount * 4 * 2;
    const sortedDistribution = Array.from(
        labelFanOutDistribution.entries(),
    ).sort(([left], [right]) => left - right);
    const maximumLabelFanOut =
        sortedDistribution.length === 0
            ? 0
            : requireArrayItem(
                  sortedDistribution,
                  sortedDistribution.length - 1,
                  'label fan-out bucket',
              )[0];
    return {
        labelKeyCount,
        continuationKeyCount,
        keyCount: labelKeyCount + continuationKeyCount,
        labelOutputCount,
        continuationOutputCount,
        generationCallCount: labelOutputCount + continuationOutputCount,
        selectedEvaluationCallCount,
        unavailableLabelReplacementCount,
        counterfactualContinuationReplacementCount,
        hiddenReplacementCount:
            unavailableLabelReplacementCount +
            counterfactualContinuationReplacementCount,
        maximumLabelFanOut,
        labelFanOutDistribution: sortedDistribution,
    };
};

const appendFullAdder = (
    builder: IndependentBooleanCircuitBuilder,
    leftWire: number,
    rightWire: number,
    carryInputWire: number,
): readonly [number, number] => {
    const leftExclusiveOrRight = builder.appendExclusiveOr(leftWire, rightWire);
    const sumWire = builder.appendExclusiveOr(
        leftExclusiveOrRight,
        carryInputWire,
    );
    const firstCarryWire = builder.appendConjunction(leftWire, rightWire);
    const secondCarryWire = builder.appendConjunction(
        leftExclusiveOrRight,
        carryInputWire,
    );
    return [
        sumWire,
        builder.appendExclusiveOr(firstCarryWire, secondCarryWire),
    ];
};

const appendFixedWidthAddition = (
    builder: IndependentBooleanCircuitBuilder,
    leftWires: readonly number[],
    rightWires: readonly number[],
    width: number,
): number[] => {
    const zeroWire = builder.appendConstant(false);
    let carryWire = zeroWire;
    const outputWires: number[] = [];
    for (let bitPosition = 0; bitPosition < width; bitPosition += 1) {
        const [sumWire, nextCarryWire] = appendFullAdder(
            builder,
            leftWires[bitPosition] ?? zeroWire,
            rightWires[bitPosition] ?? zeroWire,
            carryWire,
        );
        outputWires.push(sumWire);
        carryWire = nextCarryWire;
    }
    return outputWires;
};

const appendCarrySaveSum = (
    builder: IndependentBooleanCircuitBuilder,
    numbers: readonly (readonly number[])[],
    width: number,
): number[] => {
    const columns: number[][] = Array.from({ length: width + 3 }, () => []);
    const zeroWire = builder.appendConstant(false);
    for (const numberWires of numbers) {
        for (const [bitPosition, wire] of numberWires.entries()) {
            if (bitPosition < width) {
                requireArrayItem(columns, bitPosition, 'sum column').push(wire);
            }
        }
    }
    for (let bitPosition = 0; bitPosition < width; bitPosition += 1) {
        const column = requireArrayItem(columns, bitPosition, 'sum column');
        while (column.length > 2) {
            const firstWire = column.pop();
            const secondWire = column.pop();
            const thirdWire = column.pop();
            if (
                firstWire === undefined ||
                secondWire === undefined ||
                thirdWire === undefined
            ) {
                throw new Error(
                    'The independent carry-save model underflowed.',
                );
            }
            const [sumWire, carryWire] = appendFullAdder(
                builder,
                firstWire,
                secondWire,
                thirdWire,
            );
            column.push(sumWire);
            requireArrayItem(columns, bitPosition + 1, 'carry column').push(
                carryWire,
            );
        }
    }
    const firstRow = Array.from(
        { length: width },
        (_, bitPosition) =>
            requireArrayItem(columns, bitPosition, 'first sum row')[0] ??
            zeroWire,
    );
    const secondRow = Array.from(
        { length: width },
        (_, bitPosition) =>
            requireArrayItem(columns, bitPosition, 'second sum row')[1] ??
            zeroWire,
    );
    return appendFixedWidthAddition(builder, firstRow, secondRow, width);
};

const appendUnsignedGreaterThan = (
    builder: IndependentBooleanCircuitBuilder,
    leftWires: readonly number[],
    rightWires: readonly number[],
): number => {
    const zeroWire = builder.appendConstant(false);
    let borrowWire = zeroWire;
    const width = Math.max(leftWires.length, rightWires.length);
    for (let bitPosition = 0; bitPosition < width; bitPosition += 1) {
        const leftWire = leftWires[bitPosition] ?? zeroWire;
        const rightWire = rightWires[bitPosition] ?? zeroWire;
        const negatedRightWire = builder.appendNegation(rightWire);
        const firstTermWire = builder.appendConjunction(
            negatedRightWire,
            leftWire,
        );
        const differenceWire = builder.appendExclusiveOr(rightWire, leftWire);
        const equalAtThisBitWire = builder.appendNegation(differenceWire);
        const secondTermWire = builder.appendConjunction(
            borrowWire,
            equalAtThisBitWire,
        );
        borrowWire = builder.appendExclusiveOr(firstTermWire, secondTermWire);
    }
    return borrowWire;
};

const appendConditionalSwap = (
    builder: IndependentBooleanCircuitBuilder,
    selectorWire: number,
    leftWires: readonly number[],
    rightWires: readonly number[],
): readonly [number[], number[]] => {
    if (leftWires.length !== rightWires.length) {
        throw new Error('The independent swap model has unequal rows.');
    }
    const swappedLeftWires: number[] = [];
    const swappedRightWires: number[] = [];
    for (const [wirePosition, leftWire] of leftWires.entries()) {
        const rightWire = requireArrayItem(
            rightWires,
            wirePosition,
            'right swap wire',
        );
        const differenceWire = builder.appendExclusiveOr(leftWire, rightWire);
        const selectedDifferenceWire = builder.appendConjunction(
            selectorWire,
            differenceWire,
        );
        swappedLeftWires.push(
            builder.appendExclusiveOr(leftWire, selectedDifferenceWire),
        );
        swappedRightWires.push(
            builder.appendExclusiveOr(rightWire, selectedDifferenceWire),
        );
    }
    return [swappedLeftWires, swappedRightWires];
};

const appendScoreValidity = (
    builder: IndependentBooleanCircuitBuilder,
    scoreWires: readonly number[],
): number => {
    const leastSignificantBit = requireArrayItem(
        scoreWires,
        0,
        'least-significant score bit',
    );
    const secondBit = requireArrayItem(scoreWires, 1, 'second score bit');
    const thirdBit = requireArrayItem(scoreWires, 2, 'third score bit');
    const mostSignificantBit = requireArrayItem(
        scoreWires,
        3,
        'most-significant score bit',
    );
    const lowBitsNonzero = builder.appendDisjunction(
        leastSignificantBit,
        secondBit,
    );
    const highBitsNonzero = builder.appendDisjunction(
        thirdBit,
        mostSignificantBit,
    );
    const scoreIsNonzero = builder.appendDisjunction(
        lowBitsNonzero,
        highBitsNonzero,
    );
    const twoLowBitsSet = builder.appendConjunction(
        secondBit,
        leastSignificantBit,
    );
    const valueAboveTenTail = builder.appendDisjunction(
        thirdBit,
        twoLowBitsSet,
    );
    const valueIsAboveTen = builder.appendConjunction(
        mostSignificantBit,
        valueAboveTenTail,
    );
    return builder.appendConjunction(
        scoreIsNonzero,
        builder.appendNegation(valueIsAboveTen),
    );
};

const bitWidthForMaximumValue = (maximumValue: number): number => {
    let width = 0;
    let remaining = maximumValue;
    while (remaining > 0) {
        width += 1;
        remaining = Math.floor(remaining / 2);
    }
    return width;
};

const compileIndependentChunkDescriptors = (
    inputWireCount: number,
    operations: readonly IndependentBooleanOperation[],
    outputCount: number,
    encodingLengths = admittedEncodingLengths,
): Readonly<{
    descriptors: readonly IndependentChunkDescriptor[];
    logicalPayloadByteLength: number;
    labelEntropyByteLength: number;
}> => {
    const operationOffsets: number[] = [];
    let logicalPayloadByteLength =
        inputWireCount * encodingLengths.initialWirePayloadByteLength;
    let labelEntropyByteLength =
        inputWireCount * 4 * encodingLengths.labelPairEntropyByteLength;
    for (const operation of operations) {
        operationOffsets.push(logicalPayloadByteLength);
        logicalPayloadByteLength += operationPayloadByteLength(
            operation,
            encodingLengths,
        );
        labelEntropyByteLength +=
            operationLabelPairCount(operation) *
            encodingLengths.labelPairEntropyByteLength;
    }
    const terminalPayloadStart = logicalPayloadByteLength;
    logicalPayloadByteLength +=
        outputCount * encodingLengths.terminalPayloadByteLength;
    labelEntropyByteLength +=
        outputCount * 8 * encodingLengths.labelPairEntropyByteLength;

    const descriptors: IndependentChunkDescriptor[] = [];
    let firstOperation = 0;
    let logicalPayloadStart = 0;
    let currentPayloadByteLength =
        inputWireCount * encodingLengths.initialWirePayloadByteLength;
    if (currentPayloadByteLength > maximumChunkPayloadByteLength) {
        throw new Error('The independent initial payload exceeded a chunk.');
    }
    const pushDescriptor = (
        operationEnd: number,
        logicalPayloadEnd: number,
        includesTerminal: boolean,
    ): void => {
        let pairCount = firstOperation === 0 ? inputWireCount * 4 : 0;
        for (
            let operationIndex = firstOperation;
            operationIndex < operationEnd;
            operationIndex += 1
        ) {
            pairCount += operationLabelPairCount(
                requireArrayItem(operations, operationIndex, 'chunk operation'),
            );
        }
        if (includesTerminal) pairCount += outputCount * 8;
        descriptors.push({
            firstOperation,
            operationEnd,
            includesInitial: firstOperation === 0,
            includesTerminal,
            logicalPayloadStart,
            logicalPayloadEnd,
            chunkByteLength:
                chunkHeaderByteLength +
                (logicalPayloadEnd - logicalPayloadStart),
            labelEntropyByteLength:
                pairCount * encodingLengths.labelPairEntropyByteLength,
        });
    };

    for (const [operationIndex, operation] of operations.entries()) {
        const payloadByteLength = operationPayloadByteLength(
            operation,
            encodingLengths,
        );
        if (payloadByteLength > maximumChunkPayloadByteLength) {
            throw new Error('An independent operation exceeded a chunk.');
        }
        if (
            currentPayloadByteLength + payloadByteLength >
            maximumChunkPayloadByteLength
        ) {
            pushDescriptor(
                operationIndex,
                requireArrayItem(
                    operationOffsets,
                    operationIndex,
                    'operation payload offset',
                ),
                false,
            );
            firstOperation = operationIndex;
            logicalPayloadStart = requireArrayItem(
                operationOffsets,
                operationIndex,
                'operation payload offset',
            );
            currentPayloadByteLength = 0;
        }
        currentPayloadByteLength += payloadByteLength;
    }

    const terminalByteLength =
        outputCount * encodingLengths.terminalPayloadByteLength;
    if (terminalByteLength > maximumChunkPayloadByteLength) {
        throw new Error('The independent terminal exceeded a chunk.');
    }
    if (
        currentPayloadByteLength + terminalByteLength >
        maximumChunkPayloadByteLength
    ) {
        pushDescriptor(operations.length, terminalPayloadStart, false);
        firstOperation = operations.length;
        logicalPayloadStart = terminalPayloadStart;
        pushDescriptor(operations.length, logicalPayloadByteLength, true);
    } else {
        pushDescriptor(operations.length, logicalPayloadByteLength, true);
    }
    if (
        descriptors.some(
            (descriptor) => descriptor.chunkByteLength > maximumChunkByteLength,
        )
    ) {
        throw new Error('The independent tally model exceeded a chunk.');
    }
    return {
        descriptors,
        logicalPayloadByteLength,
        labelEntropyByteLength,
    };
};

const compileIndependentWireLiveness = (
    inputWireCount: number,
    operations: readonly IndependentBooleanOperation[],
    outputWires: readonly number[],
    descriptors: readonly IndependentChunkDescriptor[],
): Readonly<{
    maximumLiveWireCount: number;
    liveWireCountsAfterChunks: readonly number[];
}> => {
    const wireCount = inputWireCount + operations.length;
    const terminalUse = operations.length;
    const lastWireUses: Array<number | undefined> = Array.from({
        length: wireCount,
    });
    const recordUse = (wire: number, operationIndex: number): void => {
        if (wire < 0 || wire >= inputWireCount + operationIndex) {
            throw new Error(
                'The independent liveness graph has a future wire.',
            );
        }
        lastWireUses[wire] = operationIndex;
    };
    for (const [operationIndex, operation] of operations.entries()) {
        switch (operation.kind) {
            case 'constant':
                break;
            case 'linear':
            case 'conjunction':
                recordUse(operation.leftWire, operationIndex);
                recordUse(operation.rightWire, operationIndex);
                break;
            case 'negation':
                recordUse(operation.inputWire, operationIndex);
                break;
        }
    }
    for (const outputWire of outputWires) {
        if (outputWire < 0 || outputWire >= wireCount) {
            throw new Error(
                'The independent liveness graph has an output gap.',
            );
        }
        lastWireUses[outputWire] = terminalUse;
    }

    const live = lastWireUses.map(
        (lastUse, wire) => wire < inputWireCount && lastUse !== undefined,
    );
    let liveCount = live.filter(Boolean).length;
    let maximumLiveWireCount = liveCount;
    let chunkBoundaryIndex = 0;
    const liveWireCountsAfterChunks: number[] = [];
    for (
        let operationIndex = 0;
        operationIndex < operations.length;
        operationIndex += 1
    ) {
        const outputWire = inputWireCount + operationIndex;
        const outputLastUse = lastWireUses[outputWire];
        if (outputLastUse !== undefined && outputLastUse > operationIndex) {
            live[outputWire] = true;
            liveCount += 1;
            maximumLiveWireCount = Math.max(maximumLiveWireCount, liveCount);
        }
        for (let wire = 0; wire < live.length; wire += 1) {
            if (live[wire] === true && lastWireUses[wire] === operationIndex) {
                live[wire] = false;
                liveCount -= 1;
            }
        }
        while (
            descriptors[chunkBoundaryIndex]?.operationEnd ===
            operationIndex + 1
        ) {
            liveWireCountsAfterChunks.push(
                descriptors[chunkBoundaryIndex]?.includesTerminal === true
                    ? 0
                    : liveCount,
            );
            chunkBoundaryIndex += 1;
        }
    }
    while (chunkBoundaryIndex < descriptors.length) {
        const descriptor = requireArrayItem(
            descriptors,
            chunkBoundaryIndex,
            'liveness chunk descriptor',
        );
        if (descriptor.operationEnd !== operations.length) {
            throw new Error(
                'The independent liveness graph has a boundary gap.',
            );
        }
        liveWireCountsAfterChunks.push(
            descriptor.includesTerminal ? 0 : liveCount,
        );
        chunkBoundaryIndex += 1;
    }
    if (liveWireCountsAfterChunks.length !== descriptors.length) {
        throw new Error('The independent liveness graph is incomplete.');
    }
    return { maximumLiveWireCount, liveWireCountsAfterChunks };
};

export const compileIndependentPaddedTallyModel = (
    topCount: number,
): IndependentPaddedTallyModel => {
    if (
        !Number.isSafeInteger(topCount) ||
        topCount < 1 ||
        topCount > completionOptionCount
    ) {
        throw new RangeError('topCount is outside the completion profile.');
    }
    const inputWireCount =
        completionParticipantCount *
        (1 + completionOptionCount * scoreBitWidth);
    const builder = new IndependentBooleanCircuitBuilder(inputWireCount);
    const ballotPresenceWires: number[] = [];
    const ballotScoreWires: number[][][] = [];
    let nextInputWire = 0;
    for (
        let participantPosition = 0;
        participantPosition < completionParticipantCount;
        participantPosition += 1
    ) {
        ballotPresenceWires.push(nextInputWire);
        nextInputWire += 1;
        const participantScores: number[][] = [];
        for (
            let optionPosition = 0;
            optionPosition < completionOptionCount;
            optionPosition += 1
        ) {
            participantScores.push(
                Array.from({ length: scoreBitWidth }, () => nextInputWire++),
            );
        }
        ballotScoreWires.push(participantScores);
    }
    if (nextInputWire !== inputWireCount) {
        throw new Error('The independent input mapping is incomplete.');
    }

    const falseConstantWire = builder.appendConstant(false);
    const effectiveScoreWires = Array.from(
        { length: completionParticipantCount },
        () =>
            Array.from({ length: completionOptionCount }, () =>
                Array.from({ length: scoreBitWidth }, () => falseConstantWire),
            ),
    );
    const participantSelectedWires: number[] = [];
    for (
        let participantPosition = 0;
        participantPosition < completionParticipantCount;
        participantPosition += 1
    ) {
        let ballotScoresValidWire = builder.appendConstant(true);
        const participantScores = requireArrayItem(
            ballotScoreWires,
            participantPosition,
            'participant score wires',
        );
        for (const scoreWires of participantScores) {
            ballotScoresValidWire = builder.appendConjunction(
                ballotScoresValidWire,
                appendScoreValidity(builder, scoreWires),
            );
        }
        const selectedBallotWire = builder.appendConjunction(
            requireArrayItem(
                ballotPresenceWires,
                participantPosition,
                'ballot presence wire',
            ),
            ballotScoresValidWire,
        );
        participantSelectedWires.push(selectedBallotWire);
        const participantEffectiveScores = requireArrayItem(
            effectiveScoreWires,
            participantPosition,
            'effective participant scores',
        );
        for (
            let optionPosition = 0;
            optionPosition < completionOptionCount;
            optionPosition += 1
        ) {
            const scoreWires = requireArrayItem(
                participantScores,
                optionPosition,
                'score wires',
            );
            const effectiveWires = requireArrayItem(
                participantEffectiveScores,
                optionPosition,
                'effective score wires',
            );
            for (
                let bitPosition = 0;
                bitPosition < scoreBitWidth;
                bitPosition += 1
            ) {
                effectiveWires[bitPosition] = builder.appendConjunction(
                    selectedBallotWire,
                    requireArrayItem(scoreWires, bitPosition, 'score bit wire'),
                );
            }
        }
    }

    let nonemptyOutputWire = falseConstantWire;
    for (const selectedWire of participantSelectedWires) {
        nonemptyOutputWire = builder.appendDisjunction(
            nonemptyOutputWire,
            selectedWire,
        );
    }
    const aggregateScoreBitWidth = bitWidthForMaximumValue(
        completionParticipantCount * 10,
    );
    const aggregateScoreWires = Array.from(
        { length: completionOptionCount },
        (_, optionPosition) =>
            appendCarrySaveSum(
                builder,
                effectiveScoreWires.map((participantScores) =>
                    requireArrayItem(
                        participantScores,
                        optionPosition,
                        'effective option score',
                    ),
                ),
                aggregateScoreBitWidth,
            ),
    );
    const optionPositionBitWidth = Math.max(
        1,
        bitWidthForMaximumValue(completionOptionCount - 1),
    );
    const orderedItems = aggregateScoreWires.map(
        (aggregateWires, optionPosition) => [
            ...aggregateWires,
            ...Array.from(
                { length: optionPositionBitWidth },
                (_, bitPosition) =>
                    builder.appendConstant(
                        ((optionPosition >> bitPosition) & 1) === 1,
                    ),
            ),
        ],
    );
    for (
        let outputPosition = 0;
        outputPosition < topCount;
        outputPosition += 1
    ) {
        for (
            let rightPosition = completionOptionCount - 1;
            rightPosition > outputPosition;
            rightPosition -= 1
        ) {
            const leftItem = requireArrayItem(
                orderedItems,
                rightPosition - 1,
                'left ordered item',
            );
            const rightItem = requireArrayItem(
                orderedItems,
                rightPosition,
                'right ordered item',
            );
            const selector = appendUnsignedGreaterThan(
                builder,
                rightItem.slice(0, aggregateScoreBitWidth),
                leftItem.slice(0, aggregateScoreBitWidth),
            );
            const [swappedLeft, swappedRight] = appendConditionalSwap(
                builder,
                selector,
                leftItem,
                rightItem,
            );
            orderedItems[rightPosition - 1] = swappedLeft;
            orderedItems[rightPosition] = swappedRight;
        }
    }
    const orderedOptionPositionWires = orderedItems
        .slice(0, topCount)
        .flatMap((item) => item.slice(aggregateScoreBitWidth));
    const outputWires = [
        ...participantSelectedWires,
        nonemptyOutputWire,
        ...orderedOptionPositionWires,
    ];
    const operations = Array.from(builder.operations);
    const descriptorModel = compileIndependentChunkDescriptors(
        inputWireCount,
        operations,
        outputWires.length,
    );
    const liveness = compileIndependentWireLiveness(
        inputWireCount,
        operations,
        outputWires,
        descriptorModel.descriptors,
    );
    const count = (kind: IndependentBooleanOperation['kind']): number =>
        operations.filter((operation) => operation.kind === kind).length;
    return {
        topCount,
        inputWireCount,
        operations,
        outputWires,
        constantCount: count('constant'),
        linearCount: count('linear'),
        conjunctionCount: count('conjunction'),
        negationCount: count('negation'),
        logicalPayloadByteLength: descriptorModel.logicalPayloadByteLength,
        labelEntropyByteLength: descriptorModel.labelEntropyByteLength,
        descriptors: descriptorModel.descriptors,
        maximumLiveWireCount: liveness.maximumLiveWireCount,
        liveWireCountsAfterChunks: liveness.liveWireCountsAfterChunks,
        kmacCensus: compileIndependentKmacCensus(
            inputWireCount,
            operations,
            outputWires,
        ),
    };
};

export const projectIndependentPaddedTallyWidth = (
    model: IndependentPaddedTallyModel,
    labelByteLength: number,
): IndependentPaddedTallyWidthProjection => {
    const encodingLengths = independentEncodingLengths(labelByteLength);
    const descriptorModel = compileIndependentChunkDescriptors(
        model.inputWireCount,
        model.operations,
        model.outputWires.length,
        encodingLengths,
    );
    const chunkByteLengths = descriptorModel.descriptors.map(
        (descriptor) => descriptor.chunkByteLength,
    );
    const chunkLabelEntropyByteLengths = descriptorModel.descriptors.map(
        (descriptor) => descriptor.labelEntropyByteLength,
    );
    const participantChunkCorpusByteLength = chunkByteLengths.reduce(
        (sum, byteLength) => sum + byteLength,
        0,
    );
    const maximumProjectedChunkByteLength = chunkByteLengths.reduce(
        (maximum, byteLength) => Math.max(maximum, byteLength),
        0,
    );
    const maximumChunkLabelEntropyByteLength =
        chunkLabelEntropyByteLengths.reduce(
            (maximum, byteLength) => Math.max(maximum, byteLength),
            0,
        );
    const liveness = compileIndependentWireLiveness(
        model.inputWireCount,
        model.operations,
        model.outputWires,
        descriptorModel.descriptors,
    );
    const generationCheckpointFixedHeaderByteLength = 4_632;
    const evaluationCheckpointFixedHeaderByteLength = 1_236;
    const checkpointTagByteLength = 40;
    const generationCheckpointByteLengths = [
        generationCheckpointFixedHeaderByteLength +
            model.inputWireCount +
            checkpointTagByteLength,
    ];
    const evaluationCheckpointBaseByteLength =
        evaluationCheckpointFixedHeaderByteLength +
        descriptorModel.descriptors.length *
            completionParticipantCount *
            identityByteLength +
        checkpointTagByteLength;
    const evaluationCheckpointByteLengths = [
        evaluationCheckpointBaseByteLength,
    ];
    for (
        let chunkIndex = 0;
        chunkIndex + 1 < descriptorModel.descriptors.length;
        chunkIndex += 1
    ) {
        const descriptor = requireArrayItem(
            descriptorModel.descriptors,
            chunkIndex,
            'checkpoint chunk descriptor',
        );
        const liveWireCount = requireArrayItem(
            liveness.liveWireCountsAfterChunks,
            chunkIndex,
            'checkpoint live-wire count',
        );
        const processedConjunctionCount = model.operations
            .slice(0, descriptor.operationEnd)
            .filter((operation) => operation.kind === 'conjunction').length;
        generationCheckpointByteLengths.push(
            generationCheckpointFixedHeaderByteLength +
                liveWireCount *
                    (4 + 4 * encodingLengths.labelPairEntropyByteLength) +
                2 * processedConjunctionCount * labelByteLength +
                (chunkIndex + 1) * identityByteLength +
                checkpointTagByteLength,
        );
        evaluationCheckpointByteLengths.push(
            evaluationCheckpointBaseByteLength +
                liveWireCount *
                    (4 +
                        completionParticipantCount *
                            4 *
                            encodingLengths.tokenByteLength),
        );
    }
    const maximumGenerationCheckpointByteLength =
        generationCheckpointByteLengths.reduce(
            (maximum, byteLength) => Math.max(maximum, byteLength),
            0,
        );
    const maximumEvaluationCheckpointByteLength =
        evaluationCheckpointByteLengths.reduce(
            (maximum, byteLength) => Math.max(maximum, byteLength),
            0,
        );
    let maximumChunkGenerationRequestByteLength = 0;
    let maximumChunkEvaluationRequestByteLength = 0;
    let maximumChunkGenerationResponseByteLength = 0;
    let maximumChunkEvaluationResponseByteLength = 0;
    for (const [
        chunkIndex,
        descriptor,
    ] of descriptorModel.descriptors.entries()) {
        const generationCheckpointByteLength = requireArrayItem(
            generationCheckpointByteLengths,
            chunkIndex,
            'generation checkpoint length',
        );
        const evaluationCheckpointByteLength = requireArrayItem(
            evaluationCheckpointByteLengths,
            chunkIndex,
            'evaluation checkpoint length',
        );
        maximumChunkGenerationRequestByteLength = Math.max(
            maximumChunkGenerationRequestByteLength,
            45 +
                generationCheckpointByteLength +
                descriptor.labelEntropyByteLength,
        );
        maximumChunkEvaluationRequestByteLength = Math.max(
            maximumChunkEvaluationRequestByteLength,
            47 + evaluationCheckpointByteLength + descriptor.chunkByteLength,
        );
        const isFinal = chunkIndex + 1 === descriptorModel.descriptors.length;
        maximumChunkGenerationResponseByteLength = Math.max(
            maximumChunkGenerationResponseByteLength,
            isFinal
                ? 141 +
                      descriptor.chunkByteLength +
                      manifestHeaderByteLength +
                      descriptorModel.descriptors.length *
                          manifestDescriptorByteLength
                : 77 +
                      descriptor.chunkByteLength +
                      requireArrayItem(
                          generationCheckpointByteLengths,
                          chunkIndex + 1,
                          'next generation checkpoint length',
                      ),
        );
        maximumChunkEvaluationResponseByteLength = Math.max(
            maximumChunkEvaluationResponseByteLength,
            isFinal
                ? 286 + 2 * model.topCount
                : 9 +
                      requireArrayItem(
                          evaluationCheckpointByteLengths,
                          chunkIndex + 1,
                          'next evaluation checkpoint length',
                      ),
        );
    }
    return {
        labelByteLength,
        tokenByteLength: encodingLengths.tokenByteLength,
        initialWirePayloadByteLength:
            encodingLengths.initialWirePayloadByteLength,
        constantPayloadByteLength: encodingLengths.constantPayloadByteLength,
        linearPayloadByteLength: encodingLengths.linearPayloadByteLength,
        conjunctionPayloadByteLength:
            encodingLengths.conjunctionPayloadByteLength,
        terminalPayloadByteLength: encodingLengths.terminalPayloadByteLength,
        labelPairEntropyByteLength: encodingLengths.labelPairEntropyByteLength,
        logicalPayloadByteLength: descriptorModel.logicalPayloadByteLength,
        participantChunkCorpusByteLength,
        completeChunkCorpusByteLength:
            participantChunkCorpusByteLength * completionParticipantCount,
        participantLabelEntropyByteLength:
            descriptorModel.labelEntropyByteLength,
        completeLabelEntropyByteLength:
            descriptorModel.labelEntropyByteLength * completionParticipantCount,
        manifestByteLength:
            manifestHeaderByteLength +
            descriptorModel.descriptors.length * manifestDescriptorByteLength,
        chunkCount: descriptorModel.descriptors.length,
        chunkByteLengths,
        chunkLabelEntropyByteLengths,
        maximumChunkByteLength: maximumProjectedChunkByteLength,
        maximumChunkLabelEntropyByteLength,
        maximumLiveWireCount: liveness.maximumLiveWireCount,
        liveWireCountsAfterChunks: liveness.liveWireCountsAfterChunks,
        maximumGenerationCheckpointByteLength,
        maximumEvaluationCheckpointByteLength,
        maximumChunkGenerationRequestByteLength,
        maximumChunkEvaluationRequestByteLength,
        maximumChunkGenerationResponseByteLength,
        maximumChunkEvaluationResponseByteLength,
    };
};

const leftEncodeByteLength = (value: number): number => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError('The encoded integer must be nonnegative.');
    }
    let payloadByteLength = 1;
    while (value >= 2 ** (8 * payloadByteLength)) {
        payloadByteLength += 1;
    }
    return payloadByteLength + 1;
};

export const screenIndependentPaddedTallyPadKmac = (
    model: IndependentPaddedTallyModel,
    labelByteLength: number,
    queryBudgetBitLength: number,
): IndependentPaddedTallyKmacTheoremScreen => {
    if (
        !Number.isSafeInteger(queryBudgetBitLength) ||
        queryBudgetBitLength < 0 ||
        queryBudgetBitLength > 128
    ) {
        throw new RangeError('The KMAC query-budget exponent is invalid.');
    }
    const rateByteLength = 136;
    const rateBitLength = 8 * rateByteLength;
    const capacityBitLength = 512;
    const keyBitLength = 8 * labelByteLength;
    if (keyBitLength <= rateBitLength) {
        throw new RangeError(
            'The KMAC key does not satisfy the outer-keyed-sponge theorem.',
        );
    }
    const functionNameByteLength = 4;
    const customizationByteLength = 41;
    const encodedFunctionNameByteLength =
        leftEncodeByteLength(8 * functionNameByteLength) +
        functionNameByteLength;
    const encodedCustomizationByteLength =
        leftEncodeByteLength(8 * customizationByteLength) +
        customizationByteLength;
    const cshakePrefixBlockCount = Math.ceil(
        (leftEncodeByteLength(rateByteLength) +
            encodedFunctionNameByteLength +
            encodedCustomizationByteLength) /
            rateByteLength,
    );
    const keyLengthPrefixByteLength = leftEncodeByteLength(keyBitLength);
    const keyBytepadBlockCount = Math.ceil(
        (leftEncodeByteLength(rateByteLength) +
            keyLengthPrefixByteLength +
            labelByteLength) /
            rateByteLength,
    );
    const keyPrefixBitOffsetModuloRate =
        (8 *
            (leftEncodeByteLength(rateByteLength) +
                keyLengthPrefixByteLength)) %
        rateBitLength;
    const derivedKeySecurityBitLength = Math.min(
        keyBitLength - rateBitLength + keyPrefixBitOffsetModuloRate,
        rateBitLength - keyPrefixBitOffsetModuloRate,
    );
    const paddedKeyPrefixBlockCount =
        cshakePrefixBlockCount + keyBytepadBlockCount;
    const constructionEffectiveBlockBudget = 2 ** queryBudgetBitLength;
    const quantumPrimitiveQueryBudget = 2 ** queryBudgetBitLength;
    const spongeDenominator = 2 ** capacityBitLength;
    const keyDenominator = 2 ** derivedKeySecurityBitLength;
    const firstTerm =
        4 *
        Math.sqrt(
            (constructionEffectiveBlockBudget ** 2 *
                quantumPrimitiveQueryBudget) /
                spongeDenominator,
        );
    const secondTerm =
        (3 * constructionEffectiveBlockBudget ** 2) / spongeDenominator;
    const thirdTerm =
        2 *
        Math.sqrt(
            (2 *
                constructionEffectiveBlockBudget *
                quantumPrimitiveQueryBudget ** 2) /
                spongeDenominator,
        );
    const fourthTerm =
        8 *
        Math.sqrt(
            (2 *
                (quantumPrimitiveQueryBudget +
                    constructionEffectiveBlockBudget +
                    paddedKeyPrefixBlockCount) **
                    2) /
                keyDenominator,
        );
    const singleKeyAdvantageUpperBound =
        firstTerm + secondTerm + thirdTerm + fourthTerm;
    const challengedKeyCount = model.kmacCensus.keyCount;
    const completeHybridAdvantageUpperBound = Math.min(
        1,
        challengedKeyCount * singleKeyAdvantageUpperBound,
    );
    return {
        rateBitLength,
        capacityBitLength,
        keyBitLength,
        keyPrefixBitOffsetModuloRate,
        derivedKeySecurityBitLength,
        paddedKeyPrefixBlockCount,
        constructionEffectiveBlockBudget,
        quantumPrimitiveQueryBudget,
        challengedKeyCount,
        singleKeyAdvantageUpperBound,
        completeHybridAdvantageUpperBound,
        singleKeySecurityBitLength: -Math.log2(singleKeyAdvantageUpperBound),
        completeHybridSecurityBitLength: -Math.log2(
            completeHybridAdvantageUpperBound,
        ),
    };
};

class TranscriptReader {
    #offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    get offset(): number {
        return this.#offset;
    }

    readU8(): number {
        return this.readFixed(1)[0] ?? 0;
    }

    readU16(): number {
        const bytes = this.readFixed(2);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    readU32(): number {
        const bytes = this.readFixed(4);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(0, true);
    }

    readFixed(byteLength: number): Uint8Array {
        const end = this.#offset + byteLength;
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            end > this.bytes.byteLength
        ) {
            throw new Error('The padded-tally transcript is truncated.');
        }
        const result = Uint8Array.from(this.bytes.subarray(this.#offset, end));
        this.#offset = end;
        return result;
    }

    skip(byteLength: number): void {
        const end = this.#offset + byteLength;
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            end > this.bytes.byteLength
        ) {
            throw new Error('The padded-tally transcript is truncated.');
        }
        this.#offset = end;
    }

    finish(): void {
        if (this.#offset !== this.bytes.byteLength) {
            throw new Error('The padded-tally transcript has trailing bytes.');
        }
    }
}

const requireMagic = (actual: Uint8Array, expected: string): void => {
    if (new TextDecoder().decode(actual) !== expected) {
        throw new Error('The padded-tally transcript has the wrong magic.');
    }
};

const requireBooleanByte = (value: number): boolean => {
    if (value !== 0 && value !== 1) {
        throw new Error('The padded-tally transcript has a noncanonical flag.');
    }
    return value === 1;
};

type ParsedPaddedTallyHeader = Readonly<{
    targetIdentity: Uint8Array;
    circuitIdentity: Uint8Array;
    participantCount: number;
    participantPosition: number;
    topCount: number;
    allocationNonce: Uint8Array;
}>;

export type ParsedPaddedTallyChunk = ParsedPaddedTallyHeader &
    Readonly<{
        chunkOrdinal: number;
        firstOperation: number;
        operationEnd: number;
        includesInitial: boolean;
        includesTerminal: boolean;
        previousChunkIdentity: Uint8Array;
        payloadByteLength: number;
        relationInventory: PaddedTallyRelationInventory | undefined;
    }>;

export type PaddedTallyRelationInventory = Readonly<{
    initialTokenCount: number;
    constantTokenCount: number;
    linearRowCount: number;
    conjunctionCount: number;
    conjunctionLocalRowCount: number;
    conjunctionMaskTokenCount: number;
    maskedProductSemanticMapCount: number;
    paddedTranslationRowCount: number;
    continuationRowCount: number;
    refreshedDirectTokenCount: number;
    terminalCount: number;
    terminalRowCount: number;
    terminalMaskTokenCount: number;
    terminalSemanticMapCount: number;
}>;

const emptyRelationInventory = (): {
    -readonly [Key in keyof PaddedTallyRelationInventory]: number;
} => ({
    initialTokenCount: 0,
    constantTokenCount: 0,
    linearRowCount: 0,
    conjunctionCount: 0,
    conjunctionLocalRowCount: 0,
    conjunctionMaskTokenCount: 0,
    maskedProductSemanticMapCount: 0,
    paddedTranslationRowCount: 0,
    continuationRowCount: 0,
    refreshedDirectTokenCount: 0,
    terminalCount: 0,
    terminalRowCount: 0,
    terminalMaskTokenCount: 0,
    terminalSemanticMapCount: 0,
});

const readCanonicalToken = (reader: TranscriptReader): void => {
    reader.skip(tokenByteLength - 1);
    requireBooleanByte(reader.readU8());
};

const parseChunkPayload = (
    reader: TranscriptReader,
    model: IndependentPaddedTallyModel,
    descriptor: IndependentChunkDescriptor,
): PaddedTallyRelationInventory => {
    const inventory = emptyRelationInventory();
    if (descriptor.includesInitial) {
        for (
            let tokenOrdinal = 0;
            tokenOrdinal < model.inputWireCount * 4;
            tokenOrdinal += 1
        ) {
            readCanonicalToken(reader);
            inventory.initialTokenCount += 1;
        }
    }
    for (
        let operationIndex = descriptor.firstOperation;
        operationIndex < descriptor.operationEnd;
        operationIndex += 1
    ) {
        const operation = requireArrayItem(
            model.operations,
            operationIndex,
            'serialized operation',
        );
        switch (operation.kind) {
            case 'constant':
                for (
                    let tokenOrdinal = 0;
                    tokenOrdinal < 4;
                    tokenOrdinal += 1
                ) {
                    readCanonicalToken(reader);
                    inventory.constantTokenCount += 1;
                }
                break;
            case 'linear':
                reader.skip(linearPayloadByteLength);
                inventory.linearRowCount += 16;
                break;
            case 'conjunction':
                reader.skip(140 * tokenByteLength);
                inventory.conjunctionCount += 1;
                inventory.conjunctionLocalRowCount += 140;
                for (
                    let tokenOrdinal = 0;
                    tokenOrdinal < 4;
                    tokenOrdinal += 1
                ) {
                    readCanonicalToken(reader);
                    inventory.conjunctionMaskTokenCount += 1;
                }
                if ((reader.readU8() & 0xf0) !== 0) {
                    throw new Error(
                        'The masked-product semantic map is noncanonical.',
                    );
                }
                inventory.maskedProductSemanticMapCount += 1;
                reader.skip(80 * 40);
                inventory.paddedTranslationRowCount += 80;
                reader.skip(2 * 81);
                inventory.continuationRowCount += 2;
                for (
                    let tokenOrdinal = 0;
                    tokenOrdinal < 3;
                    tokenOrdinal += 1
                ) {
                    readCanonicalToken(reader);
                    inventory.refreshedDirectTokenCount += 1;
                }
                break;
            case 'negation':
                break;
        }
    }
    if (descriptor.includesTerminal) {
        for (
            let outputIndex = 0;
            outputIndex < model.outputWires.length;
            outputIndex += 1
        ) {
            reader.skip(16 * tokenByteLength);
            inventory.terminalCount += 1;
            inventory.terminalRowCount += 16;
            for (let tokenOrdinal = 0; tokenOrdinal < 4; tokenOrdinal += 1) {
                readCanonicalToken(reader);
                inventory.terminalMaskTokenCount += 1;
            }
            if ((reader.readU8() & 0xf0) !== 0) {
                throw new Error('The terminal semantic map is noncanonical.');
            }
            inventory.terminalSemanticMapCount += 1;
        }
    }
    reader.finish();
    return inventory;
};

type ParsedPaddedTallyManifestDescriptor = Readonly<{
    firstOperation: number;
    operationEnd: number;
    includesInitial: boolean;
    includesTerminal: boolean;
    chunkByteLength: number;
    chunkIdentity: Uint8Array;
}>;

export type ParsedPaddedTallyManifest = ParsedPaddedTallyHeader &
    Readonly<{
        descriptors: readonly ParsedPaddedTallyManifestDescriptor[];
    }>;

const readCommonHeader = (
    reader: TranscriptReader,
    expectedMagic: string,
): ParsedPaddedTallyHeader => {
    requireMagic(reader.readFixed(4), expectedMagic);
    if (reader.readU16() !== 1) {
        throw new Error('The padded-tally transcript has the wrong version.');
    }
    const targetIdentity = reader.readFixed(identityByteLength);
    const circuitIdentity = reader.readFixed(identityByteLength);
    const participantCount = reader.readU16();
    const participantPosition = reader.readU16();
    const topCount = reader.readU16();
    const allocationNonce = reader.readFixed(allocationNonceByteLength);
    if (
        participantCount !== completionParticipantCount ||
        participantPosition >= participantCount ||
        topCount < 1 ||
        topCount > completionParticipantCount
    ) {
        throw new Error('The padded-tally transcript header is out of range.');
    }
    return {
        targetIdentity,
        circuitIdentity,
        participantCount,
        participantPosition,
        topCount,
        allocationNonce,
    };
};

export const parsePaddedTallyChunk = (
    bytes: Uint8Array,
    model?: IndependentPaddedTallyModel,
): ParsedPaddedTallyChunk => {
    if (bytes.byteLength < chunkHeaderByteLength) {
        throw new Error('The padded-tally chunk omits its header.');
    }
    const reader = new TranscriptReader(bytes);
    const common = readCommonHeader(reader, 'SLPC');
    const chunkOrdinal = reader.readU32();
    const firstOperation = reader.readU32();
    const operationEnd = reader.readU32();
    const includesInitial = requireBooleanByte(reader.readU8());
    const includesTerminal = requireBooleanByte(reader.readU8());
    const previousChunkIdentity = reader.readFixed(identityByteLength);
    if (
        firstOperation > operationEnd ||
        reader.offset !== chunkHeaderByteLength
    ) {
        throw new Error('The padded-tally chunk range is invalid.');
    }
    const payloadByteLength = bytes.byteLength - reader.offset;
    let relationInventory: PaddedTallyRelationInventory | undefined;
    if (model === undefined) {
        reader.skip(payloadByteLength);
        reader.finish();
    } else {
        if (model.topCount !== common.topCount) {
            throw new Error(
                'The independent tally model has the wrong topCount.',
            );
        }
        const descriptor = requireArrayItem(
            model.descriptors,
            chunkOrdinal,
            'chunk descriptor',
        );
        if (
            firstOperation !== descriptor.firstOperation ||
            operationEnd !== descriptor.operationEnd ||
            includesInitial !== descriptor.includesInitial ||
            includesTerminal !== descriptor.includesTerminal ||
            bytes.byteLength !== descriptor.chunkByteLength
        ) {
            throw new Error(
                'The serialized chunk differs from the independent tally model.',
            );
        }
        relationInventory = parseChunkPayload(
            new TranscriptReader(bytes.subarray(reader.offset)),
            model,
            descriptor,
        );
        reader.skip(payloadByteLength);
        reader.finish();
    }
    return {
        ...common,
        chunkOrdinal,
        firstOperation,
        operationEnd,
        includesInitial,
        includesTerminal,
        previousChunkIdentity,
        payloadByteLength,
        relationInventory,
    };
};

export const parsePaddedTallyManifest = (
    bytes: Uint8Array,
    model?: IndependentPaddedTallyModel,
): ParsedPaddedTallyManifest => {
    if (bytes.byteLength < manifestHeaderByteLength) {
        throw new Error('The padded-tally manifest omits its header.');
    }
    const reader = new TranscriptReader(bytes);
    const common = readCommonHeader(reader, 'SLPM');
    const descriptorCount = reader.readU32();
    if (
        descriptorCount < 1 ||
        bytes.byteLength !==
            manifestHeaderByteLength +
                descriptorCount * manifestDescriptorByteLength
    ) {
        throw new Error('The padded-tally manifest length is invalid.');
    }
    const descriptors = Array.from({ length: descriptorCount }, () => {
        const firstOperation = reader.readU32();
        const operationEnd = reader.readU32();
        const includesInitial = requireBooleanByte(reader.readU8());
        const includesTerminal = requireBooleanByte(reader.readU8());
        const chunkByteLength = reader.readU32();
        const chunkIdentity = reader.readFixed(identityByteLength);
        if (
            firstOperation > operationEnd ||
            chunkByteLength < chunkHeaderByteLength
        ) {
            throw new Error('The padded-tally manifest descriptor is invalid.');
        }
        return {
            firstOperation,
            operationEnd,
            includesInitial,
            includesTerminal,
            chunkByteLength,
            chunkIdentity,
        };
    });
    reader.finish();
    if (model !== undefined) {
        if (
            model.topCount !== common.topCount ||
            descriptors.length !== model.descriptors.length ||
            bytes.byteLength !==
                manifestHeaderByteLength +
                    model.descriptors.length * manifestDescriptorByteLength
        ) {
            throw new Error(
                'The manifest differs from the independent tally model.',
            );
        }
        for (const [descriptorOrdinal, descriptor] of descriptors.entries()) {
            const expected = requireArrayItem(
                model.descriptors,
                descriptorOrdinal,
                'manifest descriptor',
            );
            if (
                descriptor.firstOperation !== expected.firstOperation ||
                descriptor.operationEnd !== expected.operationEnd ||
                descriptor.includesInitial !== expected.includesInitial ||
                descriptor.includesTerminal !== expected.includesTerminal ||
                descriptor.chunkByteLength !== expected.chunkByteLength
            ) {
                throw new Error(
                    'A manifest descriptor differs from the independent tally model.',
                );
            }
        }
    }
    return { ...common, descriptors };
};

export const summarizePaddedTallyRelation = (
    chunks: readonly ParsedPaddedTallyChunk[],
): PaddedTallyRelationInventory => {
    const summary = emptyRelationInventory();
    for (const chunk of chunks) {
        if (chunk.relationInventory === undefined) {
            throw new Error(
                'A chunk was not parsed against the independent tally model.',
            );
        }
        for (const key of Object.keys(
            summary,
        ) as (keyof PaddedTallyRelationInventory)[]) {
            summary[key] += chunk.relationInventory[key];
        }
    }
    return summary;
};

export const expectedPaddedTallyRelationInventory = (
    model: IndependentPaddedTallyModel,
): PaddedTallyRelationInventory => ({
    initialTokenCount: 4 * model.inputWireCount,
    constantTokenCount: 4 * model.constantCount,
    linearRowCount: 16 * model.linearCount,
    conjunctionCount: model.conjunctionCount,
    conjunctionLocalRowCount: 140 * model.conjunctionCount,
    conjunctionMaskTokenCount: 4 * model.conjunctionCount,
    maskedProductSemanticMapCount: model.conjunctionCount,
    paddedTranslationRowCount: 80 * model.conjunctionCount,
    continuationRowCount: 2 * model.conjunctionCount,
    refreshedDirectTokenCount: 3 * model.conjunctionCount,
    terminalCount: model.outputWires.length,
    terminalRowCount: 16 * model.outputWires.length,
    terminalMaskTokenCount: 4 * model.outputWires.length,
    terminalSemanticMapCount: model.outputWires.length,
});

export type ParsedPaddedTallyTerminal = Readonly<{
    targetIdentity: Uint8Array;
    outputSchemaIdentity: Uint8Array;
    topCount: number;
    kind: 'no-result' | 'result';
    acceptedBallotAuthorship: readonly boolean[];
    orderedOptionPositions: readonly number[] | undefined;
}>;

export const parsePaddedTallyTerminal = (
    bytes: Uint8Array,
): ParsedPaddedTallyTerminal => {
    const reader = new TranscriptReader(bytes);
    requireMagic(reader.readFixed(4), 'SLPR');
    if (reader.readU16() !== 1) {
        throw new Error('The padded-tally terminal has the wrong version.');
    }
    const targetIdentity = reader.readFixed(identityByteLength);
    const outputSchemaIdentity = reader.readFixed(identityByteLength);
    const topCount = reader.readU16();
    const kindByte = reader.readU8();
    const acceptedBallotAuthorship = Array.from(
        { length: completionParticipantCount },
        () => requireBooleanByte(reader.readU8()),
    );
    const resultCount = reader.readU16();
    const orderedOptionPositions = Array.from({ length: resultCount }, () =>
        reader.readU16(),
    );
    reader.finish();
    if (
        topCount < 1 ||
        topCount > completionParticipantCount ||
        (kindByte !== 1 && kindByte !== 2) ||
        (kindByte === 1 && resultCount !== topCount) ||
        (kindByte === 2 && resultCount !== 0) ||
        new Set(orderedOptionPositions).size !== resultCount ||
        orderedOptionPositions.some(
            (position) => position >= completionParticipantCount,
        )
    ) {
        throw new Error('The padded-tally terminal relation is invalid.');
    }
    return {
        targetIdentity,
        outputSchemaIdentity,
        topCount,
        kind: kindByte === 1 ? 'result' : 'no-result',
        acceptedBallotAuthorship,
        orderedOptionPositions:
            kindByte === 1 ? orderedOptionPositions : undefined,
    };
};
