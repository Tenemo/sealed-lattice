import { describe, expect, it } from 'vitest';

import { selectParticipantBrowserOptions } from '#tools/ci/participant-browser-options.js';

describe('participant browser cohort selection', () => {
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
        const arguments_ = [
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
        expect(selectParticipantBrowserOptions(arguments_)).toMatchObject({
            participantCount: 4,
            optionCount: 3,
            mode: 'plain',
            topCount: 3,
            scalar: true,
            sequential: true,
            profiling: true,
            basePort: 44000,
            commandLineArguments: arguments_.slice(1),
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
    });

    it('refuses malformed, duplicate and out-of-profile selections before browser work', () => {
        for (const arguments_ of [
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
                () => selectParticipantBrowserOptions(arguments_),
                arguments_.join(' '),
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
