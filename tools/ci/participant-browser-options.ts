import assert from 'node:assert/strict';
import { parseArgs } from 'node:util';

import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

// The points at which a departing member leaves for good, in stage order:
// each follows the member's earlier work and precedes the named step.
export const participantDepartureBoundaries = [
    'before-confirmation',
    'before-offer',
    'before-selection',
    'before-setup-verification',
    'before-close-response',
    'before-target-vote',
] as const;

export type ParticipantDepartureBoundary =
    (typeof participantDepartureBoundaries)[number];

// Spreads the profile's f tolerated departures over the boundaries, so the
// n - f remaining members complete every later quorum alone. The organizer
// never departs. Members leaving before their offer are eligible authors
// that never offer, so the selection holds the first selected-count eligible
// positions that remain. The members leaving after their offer and before
// their target vote are selected authors; the others come from the positions
// after the eligible ones.
export const scheduleParticipantDepartures = (
    participantCount: number,
    optionCount: number,
) => {
    const {
        maximumCorruptParticipantCount: faults,
        setupContributorCount: selectedCount,
    } = deriveSupportedProfile(participantCount, optionCount);
    const last = participantDepartureBoundaries.length - 1;
    assert.ok(
        faults >= 1 && faults <= participantDepartureBoundaries.length,
        'The profile tolerates no departure to schedule.',
    );
    const boundaries = Array.from(
        { length: faults },
        (_unused, index) =>
            participantDepartureBoundaries[
                faults === 1 ? last : Math.round((index * last) / (faults - 1))
            ],
    );
    const eligibleCount = selectedCount + faults;
    const eligible = Array.from(
        { length: eligibleCount },
        (_unused, position) => position,
    );
    const leavesBeforeOffer = (boundary: ParticipantDepartureBoundary) =>
        boundary === 'before-confirmation' || boundary === 'before-offer';
    // Every other eligible position from the second never offers.
    const unoffered = boundaries
        .filter(leavesBeforeOffer)
        .map((_unused, index) => 2 + 2 * index);
    assert.ok(unoffered.every((position) => position < eligibleCount));
    const selectedPositions = eligible
        .filter((position) => !unoffered.includes(position))
        .slice(0, selectedCount);
    const selectedAuthors = selectedPositions.filter(
        (position) => position !== 0,
    );
    const later = Array.from(
        { length: participantCount - eligibleCount },
        (_unused, index) => eligibleCount + index,
    );
    const unselected = eligible.filter(
        (position) =>
            position !== 0 &&
            !unoffered.includes(position) &&
            !selectedPositions.includes(position),
    );
    const used = new Set([0, ...unoffered]);
    const free = (candidates: readonly number[]) =>
        candidates.filter((position) => !used.has(position));
    const laterOrUnselected = () =>
        free(later).length > 0 ? free(later) : free(unselected);
    const claim = (position: number | undefined) => {
        assert.ok(
            position !== undefined,
            'No member remains to depart at a boundary.',
        );
        used.add(position);
        return position;
    };
    let nextUnoffered = 0;
    const departures = boundaries.map((boundary) => {
        const authors = free(selectedAuthors);
        const others = laterOrUnselected();
        return {
            boundary,
            position: leavesBeforeOffer(boundary)
                ? unoffered[nextUnoffered++]
                : boundary === 'before-selection'
                  ? claim(authors[Math.floor(authors.length / 2)])
                  : boundary === 'before-target-vote'
                    ? claim(authors[authors.length - 1])
                    : claim(
                          boundary === 'before-setup-verification'
                              ? others[0]
                              : others[others.length - 1],
                      ),
        };
    });
    return { departures, selectedPositions };
};

// The runner's options: each switch, and each option with its value, and
// what it selects.
const browserOptions = {
    profile: {
        usage: "Record every operation's CPU samples and summarize them beside the run.",
    },
    'memory-pressure': {
        usage: 'In a plain run, the second contributor first contributes with each WebAssembly memory capped below its need.',
    },
    sequential: {
        usage: "In a plain run, run one participant's browser at a time and report the ordinary workflow's visit bounds.",
    },
    scalar: {
        usage: 'Serve the origins without cross-origin isolation, so every operation uses one scalar worker.',
    },
    'setup-departure': {
        usage: 'The fixed early-departure case: four participants, or seven for two departures, and two options.',
    },
    'unselected-checkpoint': {
        usage: 'The fixed case that activates setup while an eligible contribution stays at its checkpoint.',
    },
    'publication-faults': {
        usage: 'In a plain run, put empty, corrupted and refused publications before the genuine ones.',
    },
    'selection-fork': {
        usage: 'The fixed case in which the corrupt organizer signs competing selections.',
    },
    recovery: {
        usage: "In a plain run, crash the organizer's browser at four durable cuts and record each recovery.",
    },
    departures: {
        usage: "In a concurrent plain run, lose the profile's tolerated members for good, from the roster to the target vote.",
    },
    'foreign-poll': {
        value: '<run directory>',
        usage: "Serve one participant another passed cohort's records of this profile as this poll's.",
    },
    'base-port': {
        value: '<port>',
        usage: 'Start the origins at this port instead of 43600.',
    },
    'top-count': {
        value: '<count>',
        usage: 'Request this many ranked options, from one through the option count.',
    },
} as const satisfies Record<
    string,
    Readonly<{ value?: string; usage: string }>
>;

export const participantBrowserUsage = [
    'Usage: pnpm run research:participant -- [<participants> <options>] [no-result | empty | rosters | plain | preparation] [option...]',
    '',
    'Without counts, a run has three participants and two options, or four participants for a fixed setup case. Without a mode, it closes with a result.',
    '',
    ...Object.entries(browserOptions).map(
        ([name, option]) =>
            `  --${name}${'value' in option ? '=' + option.value : ''}\n      ${option.usage}`,
    ),
].join('\n');

// These select a development cohort, not supported-phone qualification.
export const selectParticipantBrowserOptions = (
    commandLineArguments: readonly string[],
) => {
    const argumentsList = commandLineArguments.filter(
        (value) => value !== '--',
    );
    const parsed = parseArgs({
        args: argumentsList,
        options: Object.fromEntries(
            Object.entries(browserOptions).map(([name, option]) => [
                name,
                { type: 'value' in option ? 'string' : 'boolean' },
            ]),
        ),
        allowPositionals: true,
        strict: true,
        tokens: true,
    });
    const selected = new Set<string>();
    for (const token of parsed.tokens)
        if (token.kind === 'option') {
            assert.ok(
                !selected.has(token.name),
                'A browser option was selected more than once: --' + token.name,
            );
            selected.add(token.name);
        }
    const counts = [...parsed.positionals];
    const switches = new Set<string>();
    const values = new Map<string, string>();
    for (const [name, value] of Object.entries(parsed.values))
        if (typeof value === 'string') {
            assert.ok(
                value.trim(),
                'A browser option has an empty value: --' + name,
            );
            values.set('--' + name, value);
        } else if (value === true) switches.add('--' + name);
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
    const recovery = switches.has('--recovery');
    assert.ok(
        !recovery ||
            (mode === 'plain' &&
                !memoryPressure &&
                !publicationFaults &&
                !setupDeparture &&
                !unselectedCheckpoint &&
                !selectionFork),
        'Recovery measurements require an ordinary plain cohort.',
    );
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
            ((participantCount === 4 ||
                (setupDeparture && participantCount === 7)) &&
                optionCount === 2 &&
                mode === 'result' &&
                !memoryPressure &&
                !sequential &&
                foreignPoll === undefined &&
                [setupDeparture, unselectedCheckpoint, selectionFork].filter(
                    Boolean,
                ).length === 1),
        'The fixed setup case requires four participants (or seven for combined departure), two options and no other scenario.',
    );
    const departures = switches.has('--departures');
    assert.ok(
        !departures ||
            (mode === 'plain' &&
                profile.maximumCorruptParticipantCount >= 1 &&
                !sequential &&
                !recovery &&
                !memoryPressure &&
                !publicationFaults),
        'Departures need a concurrent plain cohort whose profile tolerates one.',
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
        recovery,
        departures,
        basePort,
        topCount,
        commandLineArguments: argumentsList,
    };
};
