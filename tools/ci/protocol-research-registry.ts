const protocolResearchCases = {
    check: { execution: false, noResult: false },
    'native-result': { execution: true, noResult: false },
    'native-empty': { execution: true, noResult: true },
    'native-invalid-only': { execution: true, noResult: true },
    'native-prefix': { execution: true, noResult: false },
} as const;

export const selectProtocolResearchCase = (arguments_: readonly string[]) => {
    const selectors = arguments_.filter((value) => value !== '--');
    if (selectors.length !== 1) {
        throw new Error('Select exactly one protocol research case.');
    }
    const name = selectors[0];
    if (
        name === undefined ||
        !Object.prototype.hasOwnProperty.call(protocolResearchCases, name)
    ) {
        throw new Error('No protocol research case matches the selector.');
    }
    return {
        name,
        ...protocolResearchCases[name as keyof typeof protocolResearchCases],
    };
};

export const selectPublicCompletionCase = (arguments_: readonly string[]) => {
    const values = arguments_.filter((value) => value !== '--');
    if (
        values.length === 3 &&
        (values[0] === 'certificate-records' ||
            values[0] === 'release-records' ||
            values[0] === 'terminal-records') &&
        values[1]?.trim() &&
        values[2]?.trim()
    ) {
        return {
            name: values[0],
            source: values[1],
            completionDirectory: values[2],
            stage:
                values[0] === 'certificate-records'
                    ? ('certificate' as const)
                    : values[0] === 'release-records'
                      ? ('release' as const)
                      : ('terminal' as const),
        };
    }
    if (
        values.length !== 2 ||
        values[0] !== 'available-records' ||
        !values[1]?.trim()
    ) {
        throw new Error(
            'Select available-records with a passed completion run, or certificate-records/release-records/terminal-records with a passed public target and public-record directory.',
        );
    }
    return {
        name: values[0],
        source: values[1],
        completionDirectory: undefined,
        stage: 'terminal' as const,
    };
};
