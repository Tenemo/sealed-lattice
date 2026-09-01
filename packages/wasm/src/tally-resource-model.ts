const completionProfileParticipantCount = 10;
const sourceWireCount = 1 + 40;
const fieldBitWidth = 4;
const labelByteLength = 48;
const activationChunkHeaderByteLength = 85;
const constantOperationByteLength = fieldBitWidth * labelByteLength;
const exclusiveOrOperationByteLength = fieldBitWidth * 4 * labelByteLength;
const conjunctionOperationByteLength =
    35 * 4 * labelByteLength +
    fieldBitWidth * labelByteLength +
    1 +
    completionProfileParticipantCount * fieldBitWidth * 2 * labelByteLength +
    2 * 2 * labelByteLength +
    (fieldBitWidth - 1) * labelByteLength +
    1;
const outputRekeyByteLength =
    fieldBitWidth * labelByteLength + fieldBitWidth * 4 * labelByteLength + 1;
const initialLabelByteLength =
    completionProfileParticipantCount *
    sourceWireCount *
    fieldBitWidth *
    labelByteLength;

type EmittedTallyPlanCounts = Readonly<{
    operationCount: number;
    constantOperationCount: number;
    exclusiveOrOperationCount: number;
    conjunctionCount: number;
    negationOperationCount: number;
    outputBitCount: number;
    rangeCount: number;
}>;

type TallyScalarWork = Readonly<{
    labelPairsDerivedPerGenerationPass: number;
    labelXofCallsPerGenerationPass: number;
    fourRowTablesGenerated: number;
    garbledRowsEmitted: number;
    selectedGarbledRowsEvaluated: number;
    translationRowsEmitted: number;
    translationRowsOpened: number;
    continuationRowsEmitted: number;
    continuationRowsOpened: number;
    codewordVerifications: number;
    activationGarblingXofCallsPerGenerationPass: number;
    activationGarblingXofCallsPerEvaluation: number;
    referenceWorkerActivationGarblingXofCalls: number;
    subsetAesBlockEncryptionsPerGenerationPass: number;
    referenceWorkerSubsetAesBlockEncryptions: number;
}>;

const requireCount = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError(`${name} must be a nonnegative safe integer.`);
    }
};

const validatePlan = (plan: EmittedTallyPlanCounts): void => {
    for (const [name, value] of Object.entries(plan)) {
        requireCount(value, name);
    }
    if (
        plan.operationCount !==
        plan.constantOperationCount +
            plan.exclusiveOrOperationCount +
            plan.conjunctionCount +
            plan.negationOperationCount
    ) {
        throw new RangeError('The emitted operation counts do not add up.');
    }
};

export const modelParticipantActivationByteLength = (
    plan: EmittedTallyPlanCounts,
): number => {
    validatePlan(plan);
    return (
        plan.rangeCount * activationChunkHeaderByteLength +
        initialLabelByteLength +
        plan.constantOperationCount * constantOperationByteLength +
        plan.exclusiveOrOperationCount * exclusiveOrOperationByteLength +
        plan.conjunctionCount * conjunctionOperationByteLength +
        plan.outputBitCount * outputRekeyByteLength
    );
};

export const modelTallyScalarWork = (
    plan: EmittedTallyPlanCounts,
): TallyScalarWork => {
    validatePlan(plan);
    const fourRowTablesPerParticipant =
        plan.exclusiveOrOperationCount * fieldBitWidth +
        plan.conjunctionCount * 35 +
        plan.outputBitCount * fieldBitWidth;
    const fourRowTablesGenerated =
        completionProfileParticipantCount * fourRowTablesPerParticipant;
    const labelPairsDerivedPerParticipant =
        410 * fieldBitWidth +
        plan.constantOperationCount * fieldBitWidth +
        plan.exclusiveOrOperationCount * 3 * fieldBitWidth +
        plan.conjunctionCount * 51 +
        plan.outputBitCount * 3 * fieldBitWidth;
    const labelPairsDerivedPerGenerationPass =
        completionProfileParticipantCount * labelPairsDerivedPerParticipant;
    const labelXofCallsPerGenerationPass =
        labelPairsDerivedPerGenerationPass * 3;
    const garbledRowsEmitted = fourRowTablesGenerated * 4;
    const translationRowsEmitted =
        plan.conjunctionCount *
        completionProfileParticipantCount *
        completionProfileParticipantCount *
        fieldBitWidth *
        2;
    const translationRowsOpened = translationRowsEmitted / 2;
    const continuationRowsEmitted =
        plan.conjunctionCount * completionProfileParticipantCount * 2;
    const continuationRowsOpened = continuationRowsEmitted / 2;
    const activationGarblingXofCallsPerGenerationPass =
        labelXofCallsPerGenerationPass +
        garbledRowsEmitted +
        translationRowsEmitted +
        continuationRowsEmitted;
    const activationGarblingXofCallsPerEvaluation =
        fourRowTablesGenerated + translationRowsOpened + continuationRowsOpened;
    const sourceShareAesBlockEncryptionsPerParticipant = 40 * (84 + 9 * 56);
    const matchedMaskAesBlockEncryptionsPerParticipant =
        plan.conjunctionCount * 84 * (1 + 3 * fieldBitWidth);
    const outputMaskAesBlockEncryptionsPerParticipant =
        plan.outputBitCount * 36 * fieldBitWidth;
    const subsetAesBlockEncryptionsPerGenerationPass =
        completionProfileParticipantCount *
        (sourceShareAesBlockEncryptionsPerParticipant +
            matchedMaskAesBlockEncryptionsPerParticipant +
            outputMaskAesBlockEncryptionsPerParticipant);
    return {
        labelPairsDerivedPerGenerationPass,
        labelXofCallsPerGenerationPass,
        fourRowTablesGenerated,
        garbledRowsEmitted,
        selectedGarbledRowsEvaluated: fourRowTablesGenerated,
        translationRowsEmitted,
        translationRowsOpened,
        continuationRowsEmitted,
        continuationRowsOpened,
        codewordVerifications: plan.conjunctionCount * 2 + plan.outputBitCount,
        activationGarblingXofCallsPerGenerationPass,
        activationGarblingXofCallsPerEvaluation,
        referenceWorkerActivationGarblingXofCalls:
            2 * activationGarblingXofCallsPerGenerationPass +
            activationGarblingXofCallsPerEvaluation,
        subsetAesBlockEncryptionsPerGenerationPass,
        referenceWorkerSubsetAesBlockEncryptions:
            2 * subsetAesBlockEncryptionsPerGenerationPass,
    };
};
