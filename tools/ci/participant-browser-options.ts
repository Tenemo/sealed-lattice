import assert from 'node:assert/strict';

import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

// These select a development cohort, not supported-phone qualification.
export const selectParticipantBrowserOptions = (
    arguments_: readonly string[],
) => {
    const argumentsList = arguments_.filter((value) => value !== '--');
    const counts: string[] = [];
    const switches = new Set<string>();
    const values = new Map<string, string>();
    const flags = new Set([
        '--profile',
        '--memory-pressure',
        '--sequential',
        '--scalar',
        '--setup-departure',
        '--unselected-checkpoint',
        '--publication-faults',
        '--selection-fork',
    ]);
    const valuedOptions = new Set([
        '--foreign-poll',
        '--base-port',
        '--top-count',
    ]);
    for (const argument of argumentsList) {
        if (!argument.startsWith('--')) {
            counts.push(argument);
            continue;
        }
        const separator = argument.indexOf('=');
        const name = separator === -1 ? argument : argument.slice(0, separator);
        assert.ok(
            !switches.has(name) && !values.has(name),
            'A browser option was selected more than once: ' + name,
        );
        if (flags.has(name) && separator === -1) switches.add(name);
        else {
            assert.ok(
                valuedOptions.has(name) && separator !== -1,
                'Unknown browser option or missing value: ' + argument,
            );
            const value = argument.slice(separator + 1);
            assert.ok(
                value.trim(),
                'A browser option has an empty value: ' + name,
            );
            values.set(name, value);
        }
    }
    const mode =
        (
            ['no-result', 'empty', 'rosters', 'plain', 'preparation'] as const
        ).find((value) => value === counts[counts.length - 1]) ?? 'result';
    if (mode !== 'result') counts.pop();
    assert.ok(
        counts.length === 0 ||
            (counts.length === 2 &&
                counts.every((value) => /^[1-9]\d*$/u.test(value))),
        'Optionally select the participant and option counts, then no-result, empty, rosters, plain or preparation.',
    );
    const setupDeparture = switches.has('--setup-departure');
    const unselectedCheckpoint = switches.has('--unselected-checkpoint');
    const selectionFork = switches.has('--selection-fork');
    const [participantCount, optionCount] =
        counts.length === 0
            ? [
                  setupDeparture || unselectedCheckpoint || selectionFork
                      ? 4
                      : 3,
                  2,
              ]
            : counts.map(Number);
    const profile = deriveSupportedProfile(participantCount, optionCount);
    const memoryPressure = switches.has('--memory-pressure');
    const publicationFaults = switches.has('--publication-faults');
    const sequential = switches.has('--sequential');
    const foreignPoll = values.get('--foreign-poll');
    assert.ok(
        !publicationFaults ||
            (mode === 'plain' &&
                !memoryPressure &&
                !setupDeparture &&
                !unselectedCheckpoint &&
                !selectionFork),
        'Publication faults require a plain cohort.',
    );
    assert.ok(
        !(setupDeparture || unselectedCheckpoint || selectionFork) ||
            (participantCount === 4 &&
                optionCount === 2 &&
                mode === 'result' &&
                !memoryPressure &&
                !sequential &&
                foreignPoll === undefined &&
                [setupDeparture, unselectedCheckpoint, selectionFork].filter(
                    Boolean,
                ).length === 1),
        'The fixed setup case requires four participants, two options and no other scenario.',
    );
    assert.ok(
        !memoryPressure || mode === 'plain',
        'Only a plain run applies memory pressure.',
    );
    assert.ok(
        !sequential || mode === 'plain',
        'Only an ordinary plain run selects sequential execution.',
    );
    assert.ok(
        (mode !== 'rosters' && mode !== 'plain' && mode !== 'preparation') ||
            foreignPoll === undefined,
        'Rosters, plain and preparation runs serve no other poll.',
    );
    assert.ok(
        mode !== 'rosters' || profile.maximumCorruptParticipantCount >= 1,
        'Two rosters need a profile that tolerates the corrupt organizer.',
    );
    const basePortArgument = values.get('--base-port');
    const basePort =
        basePortArgument === undefined ? 43_600 : Number(basePortArgument);
    assert.ok(
        /^[1-9]\d*$/u.test(basePortArgument ?? '1') &&
            basePort >= 1024 &&
            basePort + 2 * participantCount + 1 <= 65_535,
        'The base port leaves no room for every origin.',
    );
    const topCountArgument = values.get('--top-count');
    const topCount =
        topCountArgument === undefined
            ? Math.max(1, optionCount - 1)
            : Number(topCountArgument);
    assert.ok(
        /^[1-9]\d*$/u.test(topCountArgument ?? '1') &&
            Number.isSafeInteger(topCount) &&
            topCount >= 1 &&
            topCount <= optionCount,
        'The requested result length must be between one and the option count.',
    );
    return {
        participantCount,
        optionCount,
        mode,
        foreignPoll,
        profiling: switches.has('--profile'),
        scalar: switches.has('--scalar'),
        setupDeparture,
        unselectedCheckpoint,
        selectionFork,
        memoryPressure,
        publicationFaults,
        sequential,
        basePort,
        topCount,
        commandLineArguments: argumentsList,
    };
};
