const caseIdentifierPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

export const requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier = (
    value: unknown,
): string => {
    if (typeof value !== 'string' || !caseIdentifierPattern.test(value)) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement case identifiers must be nonempty lowercase kebab-case strings.',
        );
    }
    return value;
};
