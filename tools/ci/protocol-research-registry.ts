import { completionProfileCounts } from '#tests/supported-profile-model.js';

// The most helpers a participant's worker starts, which native threads
// simulate for an executing case.
const maximumSimulatedHelpers = 8;

// Only the native ceremony cases take a profile; the build check and the
// requested-output and seed-sharing probes cover fixed profiles.
const protocolResearchCases = {
    check: { execution: false, noResult: false, profile: false },
    'native-result': { execution: true, noResult: false, profile: true },
    'native-empty': { execution: true, noResult: true, profile: true },
    'native-invalid-only': { execution: true, noResult: true, profile: true },
    'native-prefix': { execution: true, noResult: false, profile: false },
    'native-seed-sharing': { execution: true, noResult: false, profile: false },
} as const;

type ProtocolResearchSelection = {
    execution: boolean;
    noResult: boolean;
    participantCount: number;
    optionCount: number;
    simulatedHelpers: number;
} & (
    | { name: keyof typeof protocolResearchCases }
    | { name: 'scalar-seed-sharing'; source: string }
);

export const selectProtocolResearchCase = (
    arguments_: readonly string[],
): ProtocolResearchSelection => {
    const values = arguments_.filter((value) => value !== '--');
    if (values[0] === 'scalar-seed-sharing') {
        const source = values[1];
        if (
            values.length !== 2 ||
            source === undefined ||
            !source.trim() ||
            source.startsWith('--')
        )
            throw new Error(
                'Select scalar-seed-sharing with exactly one passed native run and no profile or helper options.',
            );
        return {
            name: 'scalar-seed-sharing',
            source,
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        };
    }
    const option = values.indexOf('--simulated-helpers');
    const helpers = option === -1 ? undefined : values[option + 1];
    if (option !== -1) values.splice(option, 2);
    const [name, ...counts] = values;
    if (
        name === undefined ||
        !Object.prototype.hasOwnProperty.call(protocolResearchCases, name)
    ) {
        throw new Error('No protocol research case matches the selector.');
    }
    const caseName = name as keyof typeof protocolResearchCases;
    const { profile, ...selected } = protocolResearchCases[caseName];
    if (
        option !== -1 &&
        (!selected.execution ||
            name === 'native-seed-sharing' ||
            helpers === undefined ||
            !/^[1-9][0-9]*$/u.test(helpers) ||
            Number(helpers) > maximumSimulatedHelpers ||
            values.includes('--simulated-helpers'))
    ) {
        throw new Error(
            'Only an executing ceremony or requested-output case runs its jobs on simulated helpers, one to ' +
                String(maximumSimulatedHelpers) +
                ' of them, named once.',
        );
    }
    if (
        counts.length !== 0 &&
        (!profile ||
            counts.length !== 2 ||
            counts.some((value) => !/^[1-9][0-9]*$/u.test(value)))
    ) {
        throw new Error(
            'Select exactly one protocol research case, and for a native ceremony case optionally its participant and option counts.',
        );
    }
    const [participantCount, optionCount] =
        name === 'native-seed-sharing'
            ? [4, 2]
            : counts.length === 0
              ? [
                    completionProfileCounts.participantCount,
                    completionProfileCounts.optionCount,
                ]
              : counts.map(Number);
    return {
        name: caseName,
        ...selected,
        participantCount,
        optionCount,
        simulatedHelpers: helpers === undefined ? 0 : Number(helpers),
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
            'Select available-records with a passed native result run, or certificate-records/release-records/terminal-records with a passed native run and a public-record directory.',
        );
    }
    return {
        name: values[0],
        source: values[1],
        completionDirectory: undefined,
        stage: 'terminal' as const,
    };
};
