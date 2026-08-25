type PreparationFieldWasmMeasurement = Readonly<{
    evidenceClassification: string;
    measurementId: string;
    multiplicationCount: number;
    seed: bigint;
    warmupMultiplicationCount: number;
}>;

const reviewedCompletionProfileFieldFloorScreen = Object.freeze({
    evidenceClassification:
        'rounded external-model scalar WebAssembly operation-floor screen',
    measurementId: 'reviewed-completion-profile-field-floor-screen',
    multiplicationCount: 12_500_000,
    seed: 0xd6e8_feb8_6659_fd93n,
    warmupMultiplicationCount: 100_000,
} satisfies PreparationFieldWasmMeasurement);

export const preparationFieldWasmMeasurementRegistry = Object.freeze({
    [reviewedCompletionProfileFieldFloorScreen.measurementId]:
        reviewedCompletionProfileFieldFloorScreen,
});

export const resolvePreparationFieldWasmMeasurement = (
    measurementId: string,
): PreparationFieldWasmMeasurement => {
    const registeredMeasurementIds = Object.keys(
        preparationFieldWasmMeasurementRegistry,
    );
    if (registeredMeasurementIds.length === 0) {
        throw new Error(
            'The preparation-field WebAssembly measurement registry is empty.',
        );
    }

    const measurement = (
        preparationFieldWasmMeasurementRegistry as Readonly<
            Record<string, PreparationFieldWasmMeasurement>
        >
    )[measurementId];
    if (measurement === undefined) {
        throw new Error(
            `No preparation-field WebAssembly measurement matches "${measurementId}". Registered measurements: ${registeredMeasurementIds.join(', ')}.`,
        );
    }
    return measurement;
};
