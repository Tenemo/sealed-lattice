import { completionProfileCounts } from '#tests/supported-profile-model.js';

// The most helpers a participant's worker starts, which native threads
// simulate for an executing case.
const maximumSimulatedHelpers = 8;

export const registrationSessionTest =
    'registration_session_tests::sessions_verify_and_refuse_a_registration_as_its_verifier_does';

// Only the native ceremony cases take a profile; the build check and the
// requested-output probe cover fixed profiles.
const protocolResearchCases = {
    check: { execution: false, noResult: false, profile: false },
    'native-result': { execution: true, noResult: false, profile: true },
    'native-empty': { execution: true, noResult: true, profile: true },
    'native-invalid-only': { execution: true, noResult: true, profile: true },
    'native-requested-output': {
        execution: true,
        noResult: false,
        profile: false,
    },
} as const;

type ProtocolResearchSelection = {
    execution: boolean;
    noResult: boolean;
    participantCount: number;
    optionCount: number;
    simulatedHelpers: number;
} & (
    | { name: keyof typeof protocolResearchCases }
    | { name: 'native-fhe-key-source' }
    | { name: 'registration-session' }
    | { name: 'native-setup-departure' | 'native-selection-fork' }
    | {
          name: 'scalar-fhe-key-source' | 'browser-fhe-key-source';
          source: string;
      }
);

export const selectProtocolResearchCase = (
    commandLineArguments: readonly string[],
): ProtocolResearchSelection => {
    const values = commandLineArguments.filter((value) => value !== '--');
    if (
        values[0] === 'native-setup-departure' ||
        values[0] === 'native-selection-fork'
    ) {
        if (values.length !== 1)
            throw new Error(
                'The setup departure case has a fixed four-participant profile and accepts no overrides.',
            );
        return {
            name: values[0],
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        };
    }
    if (values[0] === 'registration-session') {
        if (values.length !== 1)
            throw new Error(
                'The registration session case accepts no profile, filter or helper options.',
            );
        return {
            name: 'registration-session',
            execution: true,
            noResult: false,
            participantCount: 3,
            optionCount: 2,
            simulatedHelpers: 0,
        };
    }
    if (
        values[0] === 'native-fhe-key-source' ||
        values[0] === 'scalar-fhe-key-source' ||
        values[0] === 'browser-fhe-key-source'
    ) {
        const settings = {
            execution: true,
            noResult: false,
            participantCount: 3,
            optionCount: 2,
            simulatedHelpers: 0,
        };
        if (values[0] === 'native-fhe-key-source') {
            if (values.length !== 1)
                throw new Error(
                    'The native FHE key source screen accepts no additional options.',
                );
            return { name: values[0], ...settings };
        }
        const source = values[1];
        if (values.length !== 2 || !source?.trim() || source.startsWith('--'))
            throw new Error(
                'A scalar or browser FHE key source screen requires exactly one native source.',
            );
        return { name: values[0], source, ...settings };
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
        counts.length === 0
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

export const selectPublicCompletionCase = (
    commandLineArguments: readonly string[],
) => {
    const values = commandLineArguments.filter((value) => value !== '--');
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
