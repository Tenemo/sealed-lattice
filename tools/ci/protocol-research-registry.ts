const protocolResearchCases = {
    check: { execution: false, empty: false },
    'native-result': { execution: true, empty: false },
    'native-empty': { execution: true, empty: true },
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
        values.length !== 2 ||
        values[0] !== 'available-records' ||
        !values[1]?.trim()
    ) {
        throw new Error(
            'Select available-records and supply one passed public completion run.',
        );
    }
    return { name: values[0], source: values[1] };
};
