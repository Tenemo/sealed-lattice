import { resolveZeroSharingWasmMeasurement } from './zero-sharing-wasm-measurement-registry.js';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const fieldElementByteLength = 40;
const copiedBufferPlanningTargetByteLength = 1_572_864;

export const allRosterZeroSharingCodewordMeasurementId =
    'completion-all-roster-zero-codeword';

const deriveAllRosterZeroSharingCodewordMeasurement = () => {
    const sourceMeasurement = resolveZeroSharingWasmMeasurement(
        'completion-zero-sharing-cursor',
    );
    const participantCount = foundationProfile.participantCount;
    const activeFaultBound = foundationProfile.activeFaultBound;
    const polynomialDegree = 2 * activeFaultBound;
    const basisPointCount = polynomialDegree + 1;
    const comparisonCountPerCodeword = 1 + participantCount - basisPointCount;
    const fieldMultiplicationCountPerCodeword =
        basisPointCount * comparisonCountPerCodeword;
    const fieldAdditionCountPerCodeword =
        (basisPointCount - 1) * comparisonCountPerCodeword;
    const codewordByteLength = participantCount * fieldElementByteLength;
    const planningCodewordCountPerBlock = Math.floor(
        copiedBufferPlanningTargetByteLength / codewordByteLength,
    );
    const absoluteCodewordCountPerBlock = Math.floor(
        foundationProfile.maximumCopiedBufferByteLength / codewordByteLength,
    );
    const verificationBlockByteLengths: number[] = [];
    let remainingCodewordCount = sourceMeasurement.expected.zeroSharingCount;
    while (remainingCodewordCount > 0) {
        const blockCodewordCount = Math.min(
            remainingCodewordCount,
            planningCodewordCountPerBlock,
        );
        verificationBlockByteLengths.push(
            blockCodewordCount * codewordByteLength,
        );
        remainingCodewordCount -= blockCodewordCount;
    }
    const independentlyCheckedCodewordOrdinals = Object.freeze(
        [
            0,
            1,
            2,
            31,
            127,
            1_023,
            4_095,
            8_191,
            16_383,
            26_212,
            26_213,
            26_214,
            26_215,
            30_000,
            sourceMeasurement.expected.zeroSharingCount - 3,
            sourceMeasurement.expected.zeroSharingCount - 2,
            sourceMeasurement.expected.zeroSharingCount - 1,
        ].filter(
            (ordinal, position, ordinals) =>
                ordinal >= 0 &&
                ordinal < sourceMeasurement.expected.zeroSharingCount &&
                ordinals.indexOf(ordinal) === position,
        ),
    );

    return Object.freeze({
        evidenceClassification:
            'completion-scale all-roster scalar WebAssembly zero-codeword development measurement',
        measurementId: allRosterZeroSharingCodewordMeasurementId,
        expected: Object.freeze({
            absoluteCodewordCountPerBlock,
            activeFaultBound,
            basisPointCount,
            basisStreamCountPerParticipant:
                sourceMeasurement.expected.basisStreamCount,
            codewordByteLength,
            comparisonCountPerCodeword,
            copiedBufferPlanningTargetByteLength,
            cumulativeCheckpointByteLengthAllParticipants:
                sourceMeasurement.expected.cumulativeCheckpointByteLength *
                participantCount,
            fieldAdditionCount:
                sourceMeasurement.expected.zeroSharingCount *
                fieldAdditionCountPerCodeword,
            fieldAdditionCountPerCodeword,
            fieldMultiplicationCount:
                sourceMeasurement.expected.zeroSharingCount *
                fieldMultiplicationCountPerCodeword,
            fieldMultiplicationCountPerCodeword,
            independentlyCheckedCodewordOrdinals,
            outputChunkByteLengths:
                sourceMeasurement.expected.outputChunkByteLengths,
            outputChunkCountPerParticipant:
                sourceMeasurement.expected.outputChunkCount,
            participantCount,
            planningCodewordCountPerBlock,
            sourceOutputByteLengthAllParticipants:
                sourceMeasurement.expected.zeroSharingCount *
                fieldElementByteLength *
                participantCount,
            sourceOutputByteLengthPerParticipant:
                sourceMeasurement.expected.zeroSharingCount *
                fieldElementByteLength,
            verificationBlockByteLengths: Object.freeze(
                verificationBlockByteLengths,
            ),
            verificationBlockCount: verificationBlockByteLengths.length,
            workCheckpointCountAllParticipants:
                sourceMeasurement.expected.workCheckpointCount *
                participantCount,
            workCheckpointCountPerParticipant:
                sourceMeasurement.expected.workCheckpointCount,
            zeroSharingCount: sourceMeasurement.expected.zeroSharingCount,
        }),
    });
};

export type ZeroSharingCodewordWasmMeasurement = ReturnType<
    typeof deriveAllRosterZeroSharingCodewordMeasurement
>;

const allRosterZeroSharingCodewordMeasurement =
    deriveAllRosterZeroSharingCodewordMeasurement();

export const resolveZeroSharingCodewordWasmMeasurement = (
    measurementId: string,
): ZeroSharingCodewordWasmMeasurement => {
    if (
        measurementId !== allRosterZeroSharingCodewordMeasurement.measurementId
    ) {
        throw new Error(
            `No all-roster zero-codeword WebAssembly measurement matches "${measurementId}". Registered measurement: ${allRosterZeroSharingCodewordMeasurement.measurementId}.`,
        );
    }
    return allRosterZeroSharingCodewordMeasurement;
};
