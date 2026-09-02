const identityByteLength = 64;
const allocationNonceByteLength = 32;
const chunkHeaderByteLength = 250;
const manifestHeaderByteLength = 176;
const manifestDescriptorByteLength = 78;
const completionParticipantCount = 10;
const completionOptionCount = 10;
const scoreBitWidth = 4;
const tokenByteLength = 41;
const initialWirePayloadByteLength = 4 * tokenByteLength;
const constantPayloadByteLength = 4 * tokenByteLength;
const linearPayloadByteLength = 4 * 4 * tokenByteLength;
const conjunctionPayloadByteLength = 9_390;
const terminalPayloadByteLength = 821;
const maximumChunkByteLength = 480_000;
const maximumChunkPayloadByteLength =
    maximumChunkByteLength - chunkHeaderByteLength;
const labelPairEntropyByteLength = 81;

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
}>;

const operationPayloadByteLength = (
    operation: IndependentBooleanOperation,
): number => {
    switch (operation.kind) {
        case 'constant':
            return constantPayloadByteLength;
        case 'linear':
            return linearPayloadByteLength;
        case 'conjunction':
            return conjunctionPayloadByteLength;
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
): Readonly<{
    descriptors: readonly IndependentChunkDescriptor[];
    logicalPayloadByteLength: number;
    labelEntropyByteLength: number;
}> => {
    const operationOffsets: number[] = [];
    let logicalPayloadByteLength =
        inputWireCount * initialWirePayloadByteLength;
    let labelEntropyByteLength =
        inputWireCount * 4 * labelPairEntropyByteLength;
    for (const operation of operations) {
        operationOffsets.push(logicalPayloadByteLength);
        logicalPayloadByteLength += operationPayloadByteLength(operation);
        labelEntropyByteLength +=
            operationLabelPairCount(operation) * labelPairEntropyByteLength;
    }
    const terminalPayloadStart = logicalPayloadByteLength;
    logicalPayloadByteLength += outputCount * terminalPayloadByteLength;
    labelEntropyByteLength += outputCount * 8 * labelPairEntropyByteLength;

    const descriptors: IndependentChunkDescriptor[] = [];
    let firstOperation = 0;
    let logicalPayloadStart = 0;
    let currentPayloadByteLength =
        inputWireCount * initialWirePayloadByteLength;
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
            labelEntropyByteLength: pairCount * labelPairEntropyByteLength,
        });
    };

    for (const [operationIndex, operation] of operations.entries()) {
        const payloadByteLength = operationPayloadByteLength(operation);
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

    const terminalByteLength = outputCount * terminalPayloadByteLength;
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
