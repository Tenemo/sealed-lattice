const measurementResultMarker =
    'sealed-lattice-production-desktop-browser-measurement-result:';
const lowercaseKebabCasePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

const requireLowercaseKebabCase = (
    value: string,
    fieldName: string,
): string => {
    if (!lowercaseKebabCasePattern.test(value)) {
        throw new Error(
            `Production desktop-browser measurement ${fieldName} must be lowercase kebab-case.`,
        );
    }
    return value;
};

const requireMeasurementRecord = (value: unknown): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(
            'Production desktop-browser measurement result must be an object.',
        );
    }
    return value as Record<string, unknown>;
};

export const formatProductionDesktopBrowserMeasurementResult = (
    measurement: unknown,
): string => {
    const measurementJson = JSON.stringify(measurement);
    if (measurementJson === undefined) {
        throw new Error(
            'Production desktop-browser measurement result must be JSON-serializable.',
        );
    }
    return `${measurementResultMarker}${measurementJson}`;
};

export const persistProductionDesktopBrowserMeasurementResult = async <
    ValidatedMeasurement,
>(input: {
    caseIdentifier: string;
    commandIdentifier: string;
    outputLogText: string;
    validateMeasurement(
        value: unknown,
        caseIdentifier: string,
    ): ValidatedMeasurement;
    writeMeasurementJson(measurementJson: string): Promise<void>;
}): Promise<
    Readonly<{
        measurement: ValidatedMeasurement;
        measurementJson: string;
    }>
> => {
    const caseIdentifier = requireLowercaseKebabCase(
        input.caseIdentifier,
        'case identifier',
    );
    const commandIdentifier = requireLowercaseKebabCase(
        input.commandIdentifier,
        'command identifier',
    );
    const commandOutputMarker = `[${commandIdentifier}] [stdout] `;
    const selectedResultJson: string[] = [];
    for (const outputLine of input.outputLogText.split(/\r\n|\n|\r/u)) {
        const commandOutputIndex = outputLine.indexOf(commandOutputMarker);
        if (commandOutputIndex === -1) {
            continue;
        }
        const resultMarkerIndex = outputLine.indexOf(
            measurementResultMarker,
            commandOutputIndex + commandOutputMarker.length,
        );
        if (resultMarkerIndex === -1) {
            continue;
        }
        selectedResultJson.push(
            outputLine.slice(
                resultMarkerIndex + measurementResultMarker.length,
            ),
        );
    }
    if (selectedResultJson.length !== 1) {
        throw new Error(
            selectedResultJson.length === 0
                ? `Production desktop-browser measurement ${caseIdentifier} emitted no structured result.`
                : `Production desktop-browser measurement ${caseIdentifier} emitted duplicate structured results.`,
        );
    }
    const measurementJson = selectedResultJson[0];
    let parsedMeasurement: unknown;
    try {
        parsedMeasurement = JSON.parse(measurementJson);
    } catch (error) {
        throw Object.assign(
            new Error(
                `Production desktop-browser measurement ${caseIdentifier} emitted malformed result JSON.`,
            ),
            { cause: error },
        );
    }
    const measurementRecord = requireMeasurementRecord(parsedMeasurement);
    if (measurementRecord.caseIdentifier !== caseIdentifier) {
        throw new Error(
            `Production desktop-browser measurement ${caseIdentifier} emitted a mismatched result case identifier.`,
        );
    }
    const validatedMeasurement = input.validateMeasurement(
        parsedMeasurement,
        caseIdentifier,
    );
    if (JSON.stringify(validatedMeasurement) !== measurementJson) {
        throw new Error(
            `Production desktop-browser measurement ${caseIdentifier} emitted noncanonical or unexpected result data.`,
        );
    }
    await input.writeMeasurementJson(measurementJson);
    return Object.freeze({
        measurement: validatedMeasurement,
        measurementJson,
    });
};
