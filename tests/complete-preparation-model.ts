import type { IndependentPaddedTallyModel } from './padded-tally-transcript-model.js';

const completionParticipantCount = 10;
const lowSubsetSize = 7;
const terminalSubsetSize = 8;
const sourceBitCount = 40;
const fieldBitWidth = 4;
const moduleAesBlockCount = 3;
const contributionOpeningByteLength = 80;
const pairwiseMasterByteLength = 32;
const subsetCommitmentByteLength = 64;
const preparationPlaintextCanonicalOverheadByteLength = 14;

type CompletionPreparationCensus = Readonly<{
    participantCount: number;
    lowSubsetCount: number;
    terminalSubsetCount: number;
    aggregateSubsetKeyCount: number;
    lowSubsetSlotsPerSender: number;
    terminalSubsetSlotsPerSender: number;
    contributionCount: number;
    contributionOpeningByteLength: number;
    contributionOpeningCorpusByteLength: number;
    commitmentCount: number;
    commitmentCorpusByteLength: number;
    remoteSenderRecipientCount: number;
    openingsPerRemotePlaintext: number;
    remoteOpeningOccurrenceCount: number;
    remoteOpeningCorpusByteLength: number;
    directedPairwiseMasterCount: number;
    remotePairwiseMasterCount: number;
    selfPairwiseMasterCount: number;
    pairwiseMasterCorpusByteLength: number;
    preparationPlaintextByteLength: number;
    preparationPlaintextCorpusByteLength: number;
    heldLowSubsetKeyCountPerParticipant: number;
    heldTerminalSubsetKeyCountPerParticipant: number;
    heldSubsetKeyCountPerParticipant: number;
}>;

type CompletionDerivedStreamCensus = Readonly<{
    topCount: number;
    conjunctionCount: number;
    outputCount: number;
    generationChunkCount: number;
    uniqueMatchedLowSubkeyCount: number;
    uniqueMatchedHighZeroSubkeyCount: number;
    uniqueTerminalZeroSubkeyCount: number;
    uniqueSourceSubkeyCount: number;
    uniqueReceiverBSubkeyCount: number;
    uniquePairwisePadSubkeyCount: number;
    uniqueDerivedSubkeyCount: number;
    maximumSourceDerivedSubkeyInvocationCount: number;
    chunkInventoryDerivedSubkeyInvocationCount: number;
    maximumDerivedSubkeyInvocationCount: number;
    distinctMatchedLowAesBlockCount: number;
    distinctMatchedHighZeroAesBlockCount: number;
    distinctTerminalZeroAesBlockCount: number;
    distinctSourceAesBlockCount: number;
    distinctReceiverBAesBlockCount: number;
    distinctPairwisePadAesBlockCount: number;
    distinctAesBlockCount: number;
    scalarMatchedLowAesInvocationCount: number;
    scalarMatchedHighZeroAesInvocationCount: number;
    scalarTerminalZeroAesInvocationCount: number;
    scalarSourceAesInvocationCount: number;
    scalarReceiverBAesInvocationCount: number;
    scalarPairwisePadAesInvocationCount: number;
    scalarAesInvocationCount: number;
}>;

export type CorruptProjectionCensus = Readonly<{
    corruptParticipantCount: number;
    corruptParticipants: readonly number[];
    hiddenLowSubsetCount: number;
    hiddenTerminalSubsetCount: number;
    hiddenDirectedPairwiseMasterCount: number;
    honestSourceCount: number;
    corruptSourceCount: number;
    hiddenHonestSourceBitCount: number;
    extractableCorruptSourceBitCount: number;
}>;

export type CompletionPreparationModel = Readonly<{
    preparation: CompletionPreparationCensus;
    streams: CompletionDerivedStreamCensus;
}>;

const combinations = (
    elementCount: number,
    selectionCount: number,
): number[][] => {
    if (
        !Number.isSafeInteger(elementCount) ||
        !Number.isSafeInteger(selectionCount) ||
        elementCount < 0 ||
        selectionCount < 0 ||
        selectionCount > elementCount
    ) {
        throw new RangeError('The combination dimensions are invalid.');
    }
    const result: number[][] = [];
    const selection: number[] = [];
    const visit = (firstCandidate: number): void => {
        if (selection.length === selectionCount) {
            result.push([...selection]);
            return;
        }
        const remaining = selectionCount - selection.length;
        for (
            let candidate = firstCandidate;
            candidate <= elementCount - remaining;
            candidate += 1
        ) {
            selection.push(candidate);
            visit(candidate + 1);
            selection.pop();
        }
    };
    visit(0);
    return result;
};

export const completionSubsets = (subsetSize: number): readonly number[] =>
    combinations(completionParticipantCount, subsetSize).map((positions) =>
        positions.reduce((subset, position) => subset | (1 << position), 0),
    );

const subsetContains = (subset: number, position: number): boolean =>
    (subset & (1 << position)) !== 0;

const subsetIsDisjoint = (
    subset: number,
    positions: readonly number[],
): boolean => positions.every((position) => !subsetContains(subset, position));

const countSubsetsContaining = (
    subsets: readonly number[],
    ...positions: readonly number[]
): number =>
    subsets.filter((subset) =>
        positions.every((position) => subsetContains(subset, position)),
    ).length;

const packedReadInvocationCount = (
    itemCount: number,
    itemBitWidth: number,
): number => {
    let invocationCount = 0;
    for (let itemOrdinal = 0; itemOrdinal < itemCount; itemOrdinal += 1) {
        const firstBit = itemOrdinal * itemBitWidth;
        const finalBit = firstBit + itemBitWidth - 1;
        invocationCount +=
            Math.floor(finalBit / 128) - Math.floor(firstBit / 128) + 1;
    }
    return invocationCount;
};

const distinctPackedBlockCount = (
    itemCount: number,
    itemBitWidth: number,
): number => Math.ceil((itemCount * itemBitWidth) / 128);

const sourceSegmentBlockCount = (sourceRank: number): number => {
    const firstBit = sourceRank * sourceBitCount;
    const finalBit = firstBit + sourceBitCount - 1;
    return Math.floor(finalBit / 128) - Math.floor(firstBit / 128) + 1;
};

export const compileCompletionPreparationModel = (
    tally: IndependentPaddedTallyModel,
): CompletionPreparationModel => {
    const lowSubsets = completionSubsets(lowSubsetSize);
    const terminalSubsets = completionSubsets(terminalSubsetSize);
    const lowSubsetSlotsPerSender = countSubsetsContaining(lowSubsets, 0);
    const terminalSubsetSlotsPerSender = countSubsetsContaining(
        terminalSubsets,
        0,
    );
    const openingsPerRemotePlaintext =
        countSubsetsContaining(lowSubsets, 0, 1) +
        countSubsetsContaining(terminalSubsets, 0, 1);
    const remoteSenderRecipientCount =
        completionParticipantCount * (completionParticipantCount - 1);
    const contributionCount =
        completionParticipantCount *
        (lowSubsetSlotsPerSender + terminalSubsetSlotsPerSender);
    const directedPairwiseMasterCount =
        completionParticipantCount * completionParticipantCount;
    const remotePairwiseMasterCount = remoteSenderRecipientCount;
    const selfPairwiseMasterCount = completionParticipantCount;
    const remoteOpeningOccurrenceCount =
        remoteSenderRecipientCount * openingsPerRemotePlaintext;
    const preparationPlaintextByteLength =
        preparationPlaintextCanonicalOverheadByteLength +
        openingsPerRemotePlaintext * contributionOpeningByteLength +
        pairwiseMasterByteLength;

    const sourceBlockCountPerLowSubset = Array.from(
        { length: lowSubsetSize },
        (_, sourceRank) => sourceSegmentBlockCount(sourceRank),
    ).reduce((sum, blockCount) => sum + blockCount, 0);
    const conjunctionCount = tally.conjunctionCount;
    const outputCount = tally.outputWires.length;
    const uniqueMatchedLowSubkeyCount = lowSubsets.length;
    const uniqueMatchedHighZeroSubkeyCount = lowSubsets.length;
    const uniqueTerminalZeroSubkeyCount = terminalSubsets.length;
    const uniqueSourceSubkeyCount = lowSubsets.length * lowSubsetSize;
    const uniqueReceiverBSubkeyCount = lowSubsets.length * lowSubsetSize;
    const uniquePairwisePadSubkeyCount = directedPairwiseMasterCount;
    const uniqueDerivedSubkeyCount =
        uniqueMatchedLowSubkeyCount +
        uniqueMatchedHighZeroSubkeyCount +
        uniqueTerminalZeroSubkeyCount +
        uniqueSourceSubkeyCount +
        uniqueReceiverBSubkeyCount +
        uniquePairwisePadSubkeyCount;
    const maximumSourceDerivedSubkeyInvocationCount =
        completionParticipantCount * lowSubsetSlotsPerSender +
        completionParticipantCount *
            (lowSubsetSlotsPerSender +
                (completionParticipantCount - 1) *
                    countSubsetsContaining(lowSubsets, 0, 1));
    const chunkInventoryDerivedSubkeyInvocationCount =
        tally.descriptors.length *
        completionParticipantCount *
        (2 * lowSubsetSlotsPerSender +
            terminalSubsetSlotsPerSender +
            lowSubsetSlotsPerSender +
            (completionParticipantCount - 1) *
                countSubsetsContaining(lowSubsets, 0, 1) +
            2 * completionParticipantCount);
    const maximumDerivedSubkeyInvocationCount =
        maximumSourceDerivedSubkeyInvocationCount +
        chunkInventoryDerivedSubkeyInvocationCount;

    const distinctMatchedLowAesBlockCount =
        lowSubsets.length * distinctPackedBlockCount(conjunctionCount, 1);
    const distinctMatchedHighZeroAesBlockCount =
        lowSubsets.length *
        distinctPackedBlockCount(conjunctionCount, 3 * fieldBitWidth);
    const distinctTerminalZeroAesBlockCount =
        terminalSubsets.length *
        distinctPackedBlockCount(outputCount, fieldBitWidth);
    const distinctSourceAesBlockCount =
        lowSubsets.length * sourceBlockCountPerLowSubset;
    const distinctReceiverBAesBlockCount =
        uniqueReceiverBSubkeyCount * conjunctionCount * moduleAesBlockCount;
    const distinctPairwisePadAesBlockCount =
        uniquePairwisePadSubkeyCount *
        fieldBitWidth *
        conjunctionCount *
        moduleAesBlockCount;

    const scalarMatchedLowAesInvocationCount =
        completionParticipantCount *
        lowSubsetSlotsPerSender *
        packedReadInvocationCount(conjunctionCount, 1);
    const scalarMatchedHighZeroAesInvocationCount =
        completionParticipantCount *
        lowSubsetSlotsPerSender *
        packedReadInvocationCount(conjunctionCount, 3 * fieldBitWidth);
    const scalarTerminalZeroAesInvocationCount =
        completionParticipantCount *
        terminalSubsetSlotsPerSender *
        packedReadInvocationCount(outputCount, fieldBitWidth);
    const scalarSourceAesInvocationCount =
        distinctSourceAesBlockCount * (1 + lowSubsetSize);
    const scalarReceiverBAesInvocationCount =
        completionParticipantCount *
        (lowSubsetSlotsPerSender +
            lowSubsetSlotsPerSender +
            (completionParticipantCount - 1) *
                countSubsetsContaining(lowSubsets, 0, 1)) *
        conjunctionCount *
        moduleAesBlockCount;
    const scalarPairwisePadAesInvocationCount =
        completionParticipantCount *
        2 *
        completionParticipantCount *
        fieldBitWidth *
        conjunctionCount *
        moduleAesBlockCount;

    return {
        preparation: {
            participantCount: completionParticipantCount,
            lowSubsetCount: lowSubsets.length,
            terminalSubsetCount: terminalSubsets.length,
            aggregateSubsetKeyCount: lowSubsets.length + terminalSubsets.length,
            lowSubsetSlotsPerSender,
            terminalSubsetSlotsPerSender,
            contributionCount,
            contributionOpeningByteLength,
            contributionOpeningCorpusByteLength:
                contributionCount * contributionOpeningByteLength,
            commitmentCount: contributionCount,
            commitmentCorpusByteLength:
                contributionCount * subsetCommitmentByteLength,
            remoteSenderRecipientCount,
            openingsPerRemotePlaintext,
            remoteOpeningOccurrenceCount,
            remoteOpeningCorpusByteLength:
                remoteOpeningOccurrenceCount * contributionOpeningByteLength,
            directedPairwiseMasterCount,
            remotePairwiseMasterCount,
            selfPairwiseMasterCount,
            pairwiseMasterCorpusByteLength:
                directedPairwiseMasterCount * pairwiseMasterByteLength,
            preparationPlaintextByteLength,
            preparationPlaintextCorpusByteLength:
                remoteSenderRecipientCount * preparationPlaintextByteLength,
            heldLowSubsetKeyCountPerParticipant: lowSubsetSlotsPerSender,
            heldTerminalSubsetKeyCountPerParticipant:
                terminalSubsetSlotsPerSender,
            heldSubsetKeyCountPerParticipant:
                lowSubsetSlotsPerSender + terminalSubsetSlotsPerSender,
        },
        streams: {
            topCount: tally.topCount,
            conjunctionCount,
            outputCount,
            generationChunkCount: tally.descriptors.length,
            uniqueMatchedLowSubkeyCount,
            uniqueMatchedHighZeroSubkeyCount,
            uniqueTerminalZeroSubkeyCount,
            uniqueSourceSubkeyCount,
            uniqueReceiverBSubkeyCount,
            uniquePairwisePadSubkeyCount,
            uniqueDerivedSubkeyCount,
            maximumSourceDerivedSubkeyInvocationCount,
            chunkInventoryDerivedSubkeyInvocationCount,
            maximumDerivedSubkeyInvocationCount,
            distinctMatchedLowAesBlockCount,
            distinctMatchedHighZeroAesBlockCount,
            distinctTerminalZeroAesBlockCount,
            distinctSourceAesBlockCount,
            distinctReceiverBAesBlockCount,
            distinctPairwisePadAesBlockCount,
            distinctAesBlockCount:
                distinctMatchedLowAesBlockCount +
                distinctMatchedHighZeroAesBlockCount +
                distinctTerminalZeroAesBlockCount +
                distinctSourceAesBlockCount +
                distinctReceiverBAesBlockCount +
                distinctPairwisePadAesBlockCount,
            scalarMatchedLowAesInvocationCount,
            scalarMatchedHighZeroAesInvocationCount,
            scalarTerminalZeroAesInvocationCount,
            scalarSourceAesInvocationCount,
            scalarReceiverBAesInvocationCount,
            scalarPairwisePadAesInvocationCount,
            scalarAesInvocationCount:
                scalarMatchedLowAesInvocationCount +
                scalarMatchedHighZeroAesInvocationCount +
                scalarTerminalZeroAesInvocationCount +
                scalarSourceAesInvocationCount +
                scalarReceiverBAesInvocationCount +
                scalarPairwisePadAesInvocationCount,
        },
    };
};

export const enumerateCorruptProjectionCensuses = (
    corruptParticipantCount: number,
): readonly CorruptProjectionCensus[] => {
    const lowSubsets = completionSubsets(lowSubsetSize);
    const terminalSubsets = completionSubsets(terminalSubsetSize);
    return combinations(
        completionParticipantCount,
        corruptParticipantCount,
    ).map((corruptParticipants) => {
        const hiddenLowSubsetCount = lowSubsets.filter((subset) =>
            subsetIsDisjoint(subset, corruptParticipants),
        ).length;
        const hiddenTerminalSubsetCount = terminalSubsets.filter((subset) =>
            subsetIsDisjoint(subset, corruptParticipants),
        ).length;
        const honestSourceCount =
            completionParticipantCount - corruptParticipants.length;
        return {
            corruptParticipantCount: corruptParticipants.length,
            corruptParticipants,
            hiddenLowSubsetCount,
            hiddenTerminalSubsetCount,
            hiddenDirectedPairwiseMasterCount:
                honestSourceCount * honestSourceCount,
            honestSourceCount,
            corruptSourceCount: corruptParticipants.length,
            hiddenHonestSourceBitCount: honestSourceCount * sourceBitCount,
            extractableCorruptSourceBitCount:
                corruptParticipants.length * sourceBitCount,
        };
    });
};

export const hiddenSourceSubsetCount = (
    corruptParticipants: readonly number[],
    sourcePosition: number,
): number =>
    completionSubsets(lowSubsetSize).filter(
        (subset) =>
            subsetContains(subset, sourcePosition) &&
            subsetIsDisjoint(subset, corruptParticipants),
    ).length;

const multiplyGaloisField16 = (
    leftOperand: number,
    rightOperand: number,
): number => {
    let left = leftOperand & 0x0f;
    let right = rightOperand & 0x0f;
    let product = 0;
    for (let bit = 0; bit < fieldBitWidth; bit += 1) {
        if ((right & 1) !== 0) product ^= left;
        const highBit = left >>> 3;
        left = (left << 1) & 0x0f;
        if (highBit !== 0) left ^= 0x03;
        right >>>= 1;
    }
    return product & 0x0f;
};

const powerGaloisField16 = (value: number, exponent: number): number => {
    let result = 1;
    let base = value;
    let remainingExponent = exponent;
    while (remainingExponent !== 0) {
        if ((remainingExponent & 1) !== 0) {
            result = multiplyGaloisField16(result, base);
        }
        base = multiplyGaloisField16(base, base);
        remainingExponent >>>= 1;
    }
    return result;
};

const inverseGaloisField16 = (value: number): number => {
    if ((value & 0x0f) === 0) {
        throw new Error('Zero has no inverse in GF(16).');
    }
    return powerGaloisField16(value, 14);
};

export const addFieldPolynomials = (
    left: readonly number[],
    right: readonly number[],
): number[] =>
    Array.from(
        { length: Math.max(left.length, right.length) },
        (_, coefficient) =>
            (left[coefficient] ?? 0) ^ (right[coefficient] ?? 0),
    );

export const multiplyFieldPolynomials = (
    left: readonly number[],
    right: readonly number[],
): number[] => {
    const product = Array.from(
        { length: left.length + right.length - 1 },
        () => 0,
    );
    for (const [leftDegree, leftCoefficient] of left.entries()) {
        for (const [rightDegree, rightCoefficient] of right.entries()) {
            product[leftDegree + rightDegree] ^= multiplyGaloisField16(
                leftCoefficient,
                rightCoefficient,
            );
        }
    }
    return product;
};

export const evaluateFieldPolynomial = (
    coefficients: readonly number[],
    point: number,
): number =>
    coefficients.reduceRight(
        (value, coefficient) =>
            multiplyGaloisField16(value, point) ^ coefficient,
        0,
    );

const normalizedSubsetBasisPolynomial = (subset: number): readonly number[] => {
    const outsidePositions = Array.from(
        { length: completionParticipantCount },
        (_, position) => position,
    ).filter((position) => !subsetContains(subset, position));
    if (
        outsidePositions.length !==
        completionParticipantCount - lowSubsetSize
    ) {
        throw new Error('The normalized basis requires a size-seven subset.');
    }
    let numerator = [1];
    let denominator = 1;
    for (const position of outsidePositions) {
        const coordinate = position + 1;
        numerator = multiplyFieldPolynomials(numerator, [coordinate, 1]);
        denominator = multiplyGaloisField16(denominator, coordinate);
    }
    const inverseDenominator = inverseGaloisField16(denominator);
    return numerator.map((coefficient) =>
        multiplyGaloisField16(coefficient, inverseDenominator),
    );
};

const fixedLengthPolynomialKey = (
    coefficients: readonly number[],
    length: number,
): string =>
    Array.from({ length }, (_, degree) => coefficients[degree] ?? 0)
        .map((coefficient) => coefficient.toString(16))
        .join('');

export const enumerateMatchedMaskHiddenSpan = (
    corruptParticipants: readonly number[],
): Readonly<{
    normalizedVanishingPolynomial: readonly number[];
    wordKeys: ReadonlySet<string>;
}> => {
    if (
        corruptParticipants.length !== 3 ||
        new Set(corruptParticipants).size !== corruptParticipants.length
    ) {
        throw new Error('The matched-mask screen requires one corrupt triple.');
    }
    const corruptSet = new Set(corruptParticipants);
    const honestSubset = Array.from(
        { length: completionParticipantCount },
        (_, position) => position,
    )
        .filter((position) => !corruptSet.has(position))
        .reduce((subset, position) => subset | (1 << position), 0);
    const normalizedVanishingPolynomial =
        normalizedSubsetBasisPolynomial(honestSubset);
    const wordKeys = new Set<string>();
    for (let binaryConstant = 0; binaryConstant <= 1; binaryConstant += 1) {
        for (
            let firstCoefficient = 0;
            firstCoefficient < 16;
            firstCoefficient += 1
        ) {
            for (
                let secondCoefficient = 0;
                secondCoefficient < 16;
                secondCoefficient += 1
            ) {
                for (
                    let thirdCoefficient = 0;
                    thirdCoefficient < 16;
                    thirdCoefficient += 1
                ) {
                    const word = multiplyFieldPolynomials(
                        normalizedVanishingPolynomial,
                        [
                            binaryConstant,
                            firstCoefficient,
                            secondCoefficient,
                            thirdCoefficient,
                        ],
                    );
                    wordKeys.add(fixedLengthPolynomialKey(word, 7));
                }
            }
        }
    }
    return { normalizedVanishingPolynomial, wordKeys };
};

export const matchedMaskWordKey = (coefficients: readonly number[]): string =>
    fixedLengthPolynomialKey(coefficients, 7);
