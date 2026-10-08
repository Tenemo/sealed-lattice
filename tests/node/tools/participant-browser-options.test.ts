import { describe, expect, it } from 'vitest';

import {
    participantDepartureBoundaries,
    scheduleParticipantDepartures,
    selectParticipantBrowserOptions,
} from '#tools/ci/participant-browser-options.js';

describe('participant browser cohort selection', () => {
    it('selects tolerated departures only for a concurrent plain cohort', () => {
        expect(
            selectParticipantBrowserOptions([
                '20',
                '2',
                'plain',
                '--departures',
                '--scalar',
                '--base-port=45200',
            ]),
        ).toMatchObject({
            participantCount: 20,
            optionCount: 2,
            mode: 'plain',
            departures: true,
            sequential: false,
        });
        expect(
            selectParticipantBrowserOptions(['4', '2', 'plain']),
        ).toMatchObject({ departures: false });
        for (const args of [
            ['--departures'],
            ['3', '2', 'plain', '--departures'],
            ['4', '2', 'no-result', '--departures'],
            ['4', '2', 'preparation', '--departures'],
            ['4', '2', 'plain', '--departures', '--sequential'],
            ['4', '2', 'plain', '--departures', '--recovery'],
            ['4', '2', 'plain', '--departures', '--memory-pressure'],
            ['4', '2', 'plain', '--departures', '--publication-faults'],
            ['4', '2', 'plain', '--departures', '--departures'],
            ['4', '2', 'plain', '--departures=6'],
        ])
            expect(
                () => selectParticipantBrowserOptions(args),
                args.join(' '),
            ).toThrow();
    });

    it('spreads every tolerated departure so that exactly the quorum remains', () => {
        for (let participants = 4; participants <= 20; participants++) {
            // The frozen thresholds, independent of the profile model.
            const faults = Math.floor((participants - 1) / 3);
            const selectedCount = Math.max(faults + 1, 2);
            const eligibleCount = selectedCount + faults;
            const { departures, selectedPositions } =
                scheduleParticipantDepartures(participants, 2);
            expect(departures).toHaveLength(faults);
            const leavers = departures.map(({ position }) => position);
            expect(new Set(leavers).size).toBe(faults);
            expect(
                leavers.every(
                    (position) => position > 0 && position < participants,
                ),
            ).toBe(true);
            // Distinct boundaries in stage order, ending at the target vote.
            const stages = departures.map(({ boundary }) =>
                participantDepartureBoundaries.indexOf(boundary),
            );
            expect(new Set(stages).size).toBe(faults);
            expect(stages).toEqual(
                [...stages].sort((left, right) => left - right),
            );
            expect(stages[stages.length - 1]).toBe(
                participantDepartureBoundaries.length - 1,
            );
            const unoffered = departures
                .filter(
                    ({ boundary }) =>
                        boundary === 'before-confirmation' ||
                        boundary === 'before-offer',
                )
                .map(({ position }) => position);
            expect(selectedPositions).toEqual(
                Array.from({ length: eligibleCount }, (_, position) => position)
                    .filter((position) => !unoffered.includes(position))
                    .slice(0, selectedCount),
            );
            expect(selectedPositions).toHaveLength(selectedCount);
            for (const { boundary, position } of departures)
                expect(selectedPositions.includes(position), boundary).toBe(
                    boundary === 'before-selection' ||
                        boundary === 'before-target-vote',
                );
            expect(
                unoffered.every((position) => position < eligibleCount),
            ).toBe(true);
        }
    });

    it('schedules the largest roster’s six departures across every boundary', () => {
        expect(scheduleParticipantDepartures(20, 2)).toEqual({
            departures: [
                { boundary: 'before-confirmation', position: 2 },
                { boundary: 'before-offer', position: 4 },
                { boundary: 'before-selection', position: 6 },
                { boundary: 'before-setup-verification', position: 13 },
                { boundary: 'before-close-response', position: 19 },
                { boundary: 'before-target-vote', position: 8 },
            ],
            selectedPositions: [0, 1, 3, 5, 6, 7, 8],
        });
        expect(scheduleParticipantDepartures(20, 20)).toEqual(
            scheduleParticipantDepartures(20, 2),
        );
        expect(scheduleParticipantDepartures(4, 2)).toEqual({
            departures: [{ boundary: 'before-target-vote', position: 1 }],
            selectedPositions: [0, 1],
        });
        expect(() => scheduleParticipantDepartures(3, 2)).toThrow();
    });

    it('measures recovery within the ordinary scalar stage schedule', () => {
        expect(
            selectParticipantBrowserOptions([
                '10',
                '10',
                'plain',
                '--scalar',
                '--sequential',
                '--recovery',
            ]),
        ).toMatchObject({
            participantCount: 10,
            optionCount: 10,
            mode: 'plain',
            scalar: true,
            sequential: true,
            recovery: true,
        });
        for (const args of [
            ['--recovery'],
            ['plain', '--recovery', '--publication-faults'],
            ['plain', '--recovery', '--memory-pressure'],
            ['--recovery', '--setup-departure'],
        ])
            expect(() => selectParticipantBrowserOptions(args)).toThrow();
    });
    it('selects the original-credential losing-endorsement case', () => {
        expect(
            selectParticipantBrowserOptions(['--selection-fork', '--scalar']),
        ).toMatchObject({
            participantCount: 4,
            optionCount: 2,
            mode: 'result',
            selectionFork: true,
        });
        for (const args of [
            ['--selection-fork', '--setup-departure'],
            ['--selection-fork', '--unselected-checkpoint'],
            ['3', '2', '--selection-fork'],
            ['--selection-fork', '--sequential'],
        ])
            expect(() => selectParticipantBrowserOptions(args)).toThrow();
    });
    it('preserves the ordinary profile and enables the scalar path explicitly', () => {
        expect(selectParticipantBrowserOptions([])).toMatchObject({
            participantCount: 3,
            optionCount: 2,
            mode: 'result',
            topCount: 1,
            scalar: false,
            sequential: false,
            basePort: 43600,
        });
        const commandLineArguments = [
            '--',
            '4',
            '3',
            'plain',
            '--scalar',
            '--sequential',
            '--profile',
            '--top-count=3',
            '--base-port=44000',
        ];
        expect(
            selectParticipantBrowserOptions(commandLineArguments),
        ).toMatchObject({
            participantCount: 4,
            optionCount: 3,
            mode: 'plain',
            topCount: 3,
            scalar: true,
            sequential: true,
            profiling: true,
            basePort: 44000,
            commandLineArguments: commandLineArguments.slice(1),
        });
    });

    it('accepts one, intermediate and every requested identifier within the selected profile', () => {
        for (const topCount of [1, 2, 3])
            for (const mode of [
                'result',
                'no-result',
                'empty',
                'rosters',
                'plain',
                'preparation',
            ]) {
                const options = selectParticipantBrowserOptions([
                    '4',
                    '3',
                    ...(mode === 'result' ? [] : [mode]),
                    '--top-count=' + String(topCount),
                    '--scalar',
                ]);
                expect(options.topCount).toBe(topCount);
                expect(options.mode).toBe(mode);
                expect(options.scalar).toBe(true);
            }
        // A value may also follow its option as the next argument.
        expect(
            selectParticipantBrowserOptions(['4', '3', '--top-count', '2']),
        ).toMatchObject({ participantCount: 4, optionCount: 3, topCount: 2 });
    });

    it('refuses malformed, duplicate and out-of-profile selections before browser work', () => {
        for (const commandLineArguments of [
            ['2', '2'],
            ['3', '21'],
            ['3', '1'],
            ['21', '2'],
            ['--top-count=0'],
            ['--top-count=3'],
            ['--top-count=-1'],
            ['--top-count=1.5'],
            ['--top-count=01'],
            ['--top-count=NaN'],
            ['--top-count=9007199254740992'],
            ['--top-count='],
            ['--top-count=1', '--top-count=2'],
            ['--top-count'],
            ['--scalar', '--scalar'],
            ['--scalar=true'],
            ['--helpers=0'],
            ['--profile', '--profile'],
            ['--foreign-poll= '],
            ['--base-port=65530'],
            ['--base-port=1023'],
            ['--memory-pressure'],
            ['--publication-faults'],
            ['plain', '--publication-faults', '--memory-pressure'],
            ['--sequential'],
            ['rosters'],
            ['plain', '--foreign-poll=other-run'],
            ['preparation', '--foreign-poll=other-run'],
            ['preparation', '--sequential'],
            ['preparation', '--memory-pressure'],
        ])
            expect(
                () => selectParticipantBrowserOptions(commandLineArguments),
                commandLineArguments.join(' '),
            ).toThrow();
    });

    it('selects publication interference separately from the clean workload', () => {
        expect(
            selectParticipantBrowserOptions([
                '4',
                '2',
                'plain',
                '--scalar',
                '--publication-faults',
            ]),
        ).toMatchObject({
            publicationFaults: true,
            scalar: true,
            mode: 'plain',
        });
    });

    it('selects the original preparation prefix with explicit scalar execution', () => {
        expect(
            selectParticipantBrowserOptions([
                '3',
                '2',
                'preparation',
                '--scalar',
            ]),
        ).toMatchObject({
            participantCount: 3,
            optionCount: 2,
            mode: 'preparation',
            scalar: true,
            sequential: false,
        });
    });

    it('selects the fixed early setup departure without replacing the ordinary baseline', () => {
        expect(
            selectParticipantBrowserOptions(['--setup-departure', '--scalar']),
        ).toMatchObject({
            participantCount: 4,
            optionCount: 2,
            setupDeparture: true,
            mode: 'result',
            scalar: true,
        });
        expect(
            selectParticipantBrowserOptions(['4', '2', '--setup-departure']),
        ).toMatchObject({ setupDeparture: true });
        expect(
            selectParticipantBrowserOptions([
                '7',
                '2',
                '--setup-departure',
                '--scalar',
            ]),
        ).toMatchObject({
            participantCount: 7,
            setupDeparture: true,
            scalar: true,
        });
        expect(selectParticipantBrowserOptions([])).toMatchObject({
            participantCount: 3,
            optionCount: 2,
            setupDeparture: false,
        });
        for (const args of [
            ['3', '2', '--setup-departure'],
            ['6', '2', '--setup-departure'],
            ['8', '2', '--setup-departure'],
            ['4', '3', '--setup-departure'],
            ['4', '2', 'plain', '--setup-departure'],
            ['--setup-departure', '--sequential'],
            ['--setup-departure', '--foreign-poll=old'],
            ['--setup-departure', '--memory-pressure'],
            ['--setup-departure', '--setup-departure'],
        ])
            expect(() => selectParticipantBrowserOptions(args)).toThrow();
    });

    it('selects the original unselected checkpoint case without adding a permanent departure', () => {
        expect(
            selectParticipantBrowserOptions([
                '--unselected-checkpoint',
                '--scalar',
            ]),
        ).toMatchObject({
            participantCount: 4,
            optionCount: 2,
            mode: 'result',
            unselectedCheckpoint: true,
            setupDeparture: false,
        });
        expect(
            selectParticipantBrowserOptions([
                '4',
                '2',
                '--unselected-checkpoint',
            ]),
        ).toMatchObject({ unselectedCheckpoint: true });
        expect(selectParticipantBrowserOptions([])).toMatchObject({
            participantCount: 3,
            unselectedCheckpoint: false,
        });
        for (const args of [
            ['3', '2', '--unselected-checkpoint'],
            ['7', '2', '--unselected-checkpoint'],
            ['4', '3', '--unselected-checkpoint'],
            ['--unselected-checkpoint', '--setup-departure'],
            ['--unselected-checkpoint', '--sequential'],
            ['--unselected-checkpoint', '--memory-pressure'],
            ['--unselected-checkpoint', '--foreign-poll=old'],
            ['4', '2', 'preparation', '--unselected-checkpoint'],
            ['--unselected-checkpoint', '--unselected-checkpoint'],
        ])
            expect(() => selectParticipantBrowserOptions(args)).toThrow();
    });
});
