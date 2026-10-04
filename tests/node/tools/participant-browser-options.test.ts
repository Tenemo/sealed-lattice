import { describe, expect, it } from 'vitest';

import { selectParticipantBrowserOptions } from '#tools/ci/participant-browser-options.js';

describe('participant browser cohort selection', () => {
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
});
