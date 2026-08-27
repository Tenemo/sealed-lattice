import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const fieldElementByteLength = 40;
const checkpointAuthenticationTagByteLength = 64;
const checkpointDomain =
    'sealed-lattice/v1/preparation/pseudorandom-zero-sharing-cursor-checkpoint';

const binomialCoefficient = (population: number, selection: number): number => {
    let result = 1;
    for (let position = 1; position <= selection; position += 1) {
        result = (result * (population - selection + position)) / position;
    }
    if (!Number.isSafeInteger(result)) {
        throw new Error('The independently derived subset count is unsafe.');
    }
    return result;
};

const varuintByteLength = (value: number): number => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(
            'Varuint model inputs must be nonnegative safe integers.',
        );
    }
    let remaining = value;
    let byteLength = 1;
    while (remaining >= 0x80) {
        remaining = Math.floor(remaining / 0x80);
        byteLength += 1;
    }
    return byteLength;
};

const framedByteLength = (payloadByteLength: number): number =>
    varuintByteLength(payloadByteLength) + payloadByteLength;

const checkpointByteLength = (input: {
    readonly accumulatorByteLength: number;
    readonly chunkIndex: number;
    readonly nextStreamIndex: number;
    readonly participantCount: number;
    readonly participantPosition: number;
    readonly totalFieldCount: number;
}): number =>
    framedByteLength(Buffer.byteLength(checkpointDomain, 'ascii')) +
    varuintByteLength(1) +
    3 * framedByteLength(64) +
    varuintByteLength(input.participantCount) +
    varuintByteLength(input.participantPosition) +
    varuintByteLength(input.totalFieldCount) +
    varuintByteLength(input.chunkIndex) +
    varuintByteLength(input.nextStreamIndex) +
    varuintByteLength(1) +
    framedByteLength(input.accumulatorByteLength) +
    checkpointAuthenticationTagByteLength;

const deriveCompletionZeroSharingMeasurement = () => {
    const participantCount = foundationProfile.participantCount;
    const activeFaultBound = foundationProfile.activeFaultBound;
    const independentLabelSemanticMaskCount = 7_931;
    const outputMaskCount = 41;
    const acceptedAuthorshipBitCount = participantCount;
    const hiddenValueCount =
        independentLabelSemanticMaskCount +
        outputMaskCount +
        acceptedAuthorshipBitCount;
    const hiddenValueProductCount = 2 * hiddenValueCount;
    const conjunctionProductCount = 2_962;
    const zeroSharingCount = hiddenValueProductCount + conjunctionProductCount;
    const authorizedSubsetCountPerParticipant = binomialCoefficient(
        participantCount - 1,
        activeFaultBound,
    );
    const basisStreamCount =
        authorizedSubsetCountPerParticipant * activeFaultBound;
    const fieldElementsPerChunk = Math.floor(
        foundationProfile.streamChunkByteLength / fieldElementByteLength,
    );
    const outputChunkCount = Math.ceil(
        zeroSharingCount / fieldElementsPerChunk,
    );
    const finalChunkFieldCount =
        zeroSharingCount - (outputChunkCount - 1) * fieldElementsPerChunk;
    const outputChunkByteLengths = Object.freeze([
        ...Array.from(
            { length: outputChunkCount - 1 },
            () => fieldElementsPerChunk * fieldElementByteLength,
        ),
        finalChunkFieldCount * fieldElementByteLength,
    ]);
    const checkpointByteLengths: number[] = [];
    for (
        let chunkIndex = 0;
        chunkIndex < outputChunkByteLengths.length;
        chunkIndex += 1
    ) {
        const accumulatorByteLength = outputChunkByteLengths[chunkIndex];
        if (accumulatorByteLength === undefined) {
            throw new Error(
                'The independent output-chunk model is incomplete.',
            );
        }
        for (
            let nextStreamIndex = 1;
            nextStreamIndex <= basisStreamCount;
            nextStreamIndex += 1
        ) {
            checkpointByteLengths.push(
                checkpointByteLength({
                    accumulatorByteLength,
                    chunkIndex,
                    nextStreamIndex,
                    participantCount,
                    participantPosition: 0,
                    totalFieldCount: zeroSharingCount,
                }),
            );
        }
    }
    const cumulativeCheckpointByteLength = checkpointByteLengths.reduce(
        (sum, byteLength) => sum + byteLength,
        0,
    );

    return Object.freeze({
        evidenceClassification:
            'completion-scale scalar WebAssembly zero-sharing development measurement',
        measurementId: 'completion-zero-sharing-cursor',
        expected: Object.freeze({
            acceptedAuthorshipBitCount,
            activeFaultBound,
            authorizedSubsetCountPerParticipant,
            basisPrecomputationFieldMultiplicationCount:
                authorizedSubsetCountPerParticipant *
                (activeFaultBound + activeFaultBound - 1),
            basisStreamCount,
            combinationFieldAdditionCount:
                basisStreamCount * zeroSharingCount - zeroSharingCount,
            combinationFieldMultiplicationCount:
                basisStreamCount * zeroSharingCount,
            conjunctionProductCount,
            cumulativeCheckpointAuthenticatedBodyByteLength:
                cumulativeCheckpointByteLength -
                checkpointByteLengths.length *
                    checkpointAuthenticationTagByteLength,
            cumulativeCheckpointByteLength,
            fieldOutputCount: basisStreamCount * zeroSharingCount,
            hiddenValueCount,
            hiddenValueProductCount,
            independentLabelSemanticMaskCount,
            maximumCheckpointByteLength: Math.max(...checkpointByteLengths),
            minimumCheckpointByteLength: Math.min(...checkpointByteLengths),
            outputChunkByteLengths,
            outputChunkCount,
            outputMaskCount,
            participantCount,
            workCheckpointCount: basisStreamCount * outputChunkCount,
            zeroSharingCount,
        }),
    });
};

export type ZeroSharingWasmMeasurement = ReturnType<
    typeof deriveCompletionZeroSharingMeasurement
>;

const completionZeroSharingMeasurement =
    deriveCompletionZeroSharingMeasurement();

const zeroSharingWasmMeasurementRegistry = Object.freeze({
    [completionZeroSharingMeasurement.measurementId]:
        completionZeroSharingMeasurement,
});

export const resolveZeroSharingWasmMeasurement = (
    measurementId: string,
): ZeroSharingWasmMeasurement => {
    const registeredMeasurementIds = Object.keys(
        zeroSharingWasmMeasurementRegistry,
    );
    if (registeredMeasurementIds.length === 0) {
        throw new Error('The zero-sharing measurement registry is empty.');
    }
    const measurement = (
        zeroSharingWasmMeasurementRegistry as Readonly<
            Record<string, ZeroSharingWasmMeasurement>
        >
    )[measurementId];
    if (measurement === undefined) {
        throw new Error(
            `No zero-sharing WebAssembly measurement matches "${measurementId}". Registered measurements: ${registeredMeasurementIds.join(', ')}.`,
        );
    }
    return measurement;
};
