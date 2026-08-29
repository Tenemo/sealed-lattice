import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const canonicalTupleHeaderByteLength = 8;
const canonicalItemHeaderByteLength = 6;
const variableValueLengthPrefixByteLength = 4;
const hash512ByteLength = 64;
const unsigned16ByteLength = 2;
const unsigned64ByteLength = 8;
const fieldCanonicalByteLength = 3;
const fieldSampleByteLength = 32;
const checkpointTagByteLength = 64;
const checkpointDomain = 'sealed-lattice/v1/direct-mpc/prss-cursor-checkpoint';
const outputDomain = 'sealed-lattice/v1/direct-mpc/prss-cursor-output';

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

const variableValueByteLength = (payloadByteLength: number): number =>
    variableValueLengthPrefixByteLength + payloadByteLength;

const tupleByteLength = (itemByteLengths: readonly number[]): number =>
    canonicalTupleHeaderByteLength +
    itemByteLengths.reduce(
        (sum, byteLength) => sum + canonicalItemHeaderByteLength + byteLength,
        0,
    );

const deriveCompletionDirectMpcMeasurement = () => {
    const participantCount = foundationProfile.participantCount;
    const activeFaultBound = foundationProfile.activeFaultBound;
    const optionCount = foundationProfile.optionCount;
    const scoreBitCount = 4;
    const beaverTripleCount = 9_925;
    const sourceConsistencyMaskCount =
        participantCount * optionCount * scoreBitCount;
    const ordinaryFieldCount =
        3 * beaverTripleCount + sourceConsistencyMaskCount;
    const zeroFieldCount = beaverTripleCount;
    const authorizedSubsetCountPerParticipant = binomialCoefficient(
        participantCount - 1,
        activeFaultBound,
    );
    const ordinaryStreamCount = authorizedSubsetCountPerParticipant;
    const zeroBasisStreamCount =
        authorizedSubsetCountPerParticipant * activeFaultBound;
    const totalStreamCount = ordinaryStreamCount + zeroBasisStreamCount;
    const fieldOutputCount =
        ordinaryStreamCount * ordinaryFieldCount +
        zeroBasisStreamCount * zeroFieldCount;
    const sourceByteLength = fieldOutputCount * fieldSampleByteLength;
    const ordinaryAccumulatorByteLength =
        ordinaryFieldCount * fieldCanonicalByteLength;
    const zeroAccumulatorByteLength = zeroFieldCount * fieldCanonicalByteLength;
    const canonicalAccumulatorByteLength =
        ordinaryAccumulatorByteLength + zeroAccumulatorByteLength;
    const internalAccumulatorByteLength =
        (ordinaryFieldCount + zeroFieldCount) * 4;
    const checkpointBodyByteLength = tupleByteLength([
        variableValueByteLength(Buffer.byteLength(checkpointDomain, 'ascii')),
        unsigned16ByteLength,
        hash512ByteLength,
        hash512ByteLength,
        hash512ByteLength,
        unsigned16ByteLength,
        unsigned16ByteLength,
        unsigned64ByteLength,
        unsigned64ByteLength,
        unsigned64ByteLength,
        variableValueByteLength(ordinaryAccumulatorByteLength),
        variableValueByteLength(zeroAccumulatorByteLength),
    ]);
    const checkpointByteLength = tupleByteLength([
        variableValueByteLength(checkpointBodyByteLength),
        checkpointTagByteLength,
    ]);
    const resultByteLength = tupleByteLength([
        variableValueByteLength(Buffer.byteLength(outputDomain, 'ascii')),
        hash512ByteLength,
        hash512ByteLength,
        hash512ByteLength,
        unsigned16ByteLength,
        unsigned16ByteLength,
        unsigned64ByteLength,
        unsigned64ByteLength,
        variableValueByteLength(ordinaryAccumulatorByteLength),
        variableValueByteLength(zeroAccumulatorByteLength),
    ]);

    return Object.freeze({
        evidenceClassification:
            'completion-scale scalar WebAssembly direct-MPC PRSS development measurement',
        measurementId: 'completion-direct-mpc-prss-cursor',
        expected: Object.freeze({
            accumulationFieldAdditionCount:
                (ordinaryStreamCount - 1) * ordinaryFieldCount +
                (zeroBasisStreamCount - 1) * zeroFieldCount,
            activeFaultBound,
            authorizedSubsetCountPerParticipant,
            basisPrecomputationFieldMultiplicationCount:
                authorizedSubsetCountPerParticipant * (activeFaultBound + 1) +
                authorizedSubsetCountPerParticipant *
                    (2 * activeFaultBound - 1),
            beaverTripleCount,
            canonicalAccumulatorByteLength,
            checkpointByteLength,
            checkpointForegroundTargetMilliseconds: 5_000,
            coldRestoreTargetMilliseconds: 30_000,
            completeContributionTargetMilliseconds: 20 * 60 * 1_000,
            workStepForegroundTargetMilliseconds: 5_000,
            cumulativeCheckpointByteLength:
                checkpointByteLength * totalStreamCount,
            fieldOutputCount,
            internalAccumulatorByteLength,
            maximumXofOutputAllocationByteLength:
                ordinaryFieldCount * fieldSampleByteLength,
            ordinaryBasisModularInverseCount: ordinaryStreamCount,
            ordinaryFieldCount,
            ordinaryStreamCount,
            participantCount,
            participantPosition: 0,
            resultByteLength,
            sourceByteLength,
            sourceConsistencyMaskCount,
            totalStreamCount,
            weightFieldMultiplicationCount: fieldOutputCount,
            zeroBasisStreamCount,
            zeroFieldCount,
        }),
    });
};

export type DirectMpcWasmMeasurement = ReturnType<
    typeof deriveCompletionDirectMpcMeasurement
>;

const completionDirectMpcMeasurement = deriveCompletionDirectMpcMeasurement();

const directMpcWasmMeasurementRegistry = Object.freeze({
    [completionDirectMpcMeasurement.measurementId]:
        completionDirectMpcMeasurement,
});

export const resolveDirectMpcWasmMeasurement = (
    measurementId: string,
): DirectMpcWasmMeasurement => {
    const registeredMeasurementIds = Object.keys(
        directMpcWasmMeasurementRegistry,
    );
    if (registeredMeasurementIds.length === 0) {
        throw new Error('The direct-MPC measurement registry is empty.');
    }
    const measurement = (
        directMpcWasmMeasurementRegistry as Readonly<
            Record<string, DirectMpcWasmMeasurement>
        >
    )[measurementId];
    if (measurement === undefined) {
        throw new Error(
            `No direct-MPC WebAssembly measurement matches "${measurementId}". Registered measurements: ${registeredMeasurementIds.join(', ')}.`,
        );
    }
    return measurement;
};
