import { describe, expect, it } from 'vitest';

import { sumProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import {
    selectProtocolResearchCase,
    selectPublicCompletionCase,
} from '#tools/ci/protocol-research-registry.js';
import {
    deriveResearchScenario,
    researchBallotScore,
} from '#tools/ci/protocol-research-scenario.js';

describe('guarded protocol research entry', () => {
    it('requires an explicit public case and a nonempty fixture', () => {
        for (const values of [
            [],
            ['available-records'],
            ['available-records', ''],
            ['unknown', 'fixture'],
            ['certificate-records', 'fixture'],
            ['release-records', 'fixture'],
            ['release-records', 'fixture', ''],
            ['terminal-records', 'fixture', ''],
            ['certificate-records', '', 'records'],
            ['terminal-records', 'fixture', 'records', 'extra'],
        ])
            expect(() => selectPublicCompletionCase(values)).toThrow();
        expect(
            selectPublicCompletionCase(['available-records', 'fixture']),
        ).toEqual({
            name: 'available-records',
            source: 'fixture',
            stage: 'terminal',
            completionDirectory: undefined,
        });
        for (const [name, stage] of [
            ['certificate-records', 'certificate'],
            ['release-records', 'release'],
            ['terminal-records', 'terminal'],
        ]) {
            expect(
                selectPublicCompletionCase(['--', name, 'fixture', 'records']),
            ).toEqual({
                name,
                stage,
                source: 'fixture',
                completionDirectory: 'records',
            });
        }
    });
    it('refuses empty, unknown and ambiguous case selectors', () => {
        for (const values of [
            [],
            ['--'],
            ['unknown'],
            ['native-result', 'native-empty'],
            ['native-invalid-only', 'native-empty'],
            ['invalid-only'],
            ['native-result', '20'],
            ['native-result', '20', '20', '20'],
            ['native-result', '020', '20'],
            ['native-result', '20', '-2'],
            ['native-result', '3.5', '2'],
            ['native-empty', '', '2'],
            ['native-prefix', '3', '2'],
            ['check', '10', '10'],
            ['check', '--simulated-helpers', '3'],
            ['native-result', '--simulated-helpers'],
            ['native-result', '--simulated-helpers', '0'],
            ['native-result', '--simulated-helpers', '9'],
            ['native-result', '--simulated-helpers', '03'],
            ['native-result', '--simulated-helpers', '2.5'],
            [
                'native-result',
                '--simulated-helpers',
                '3',
                '--simulated-helpers',
                '3',
            ],
        ]) {
            expect(() => selectProtocolResearchCase(values)).toThrow();
        }
        expect(selectProtocolResearchCase(['--', 'native-empty'])).toEqual({
            name: 'native-empty',
            execution: true,
            noResult: true,
            participantCount: 10,
            optionCount: 10,
            simulatedHelpers: 0,
        });
        expect(
            selectProtocolResearchCase(['native-invalid-only', '3', '2']),
        ).toEqual({
            name: 'native-invalid-only',
            execution: true,
            noResult: true,
            participantCount: 3,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        expect(
            selectProtocolResearchCase(['--', 'native-result', '20', '20']),
        ).toEqual({
            name: 'native-result',
            execution: true,
            noResult: false,
            participantCount: 20,
            optionCount: 20,
            simulatedHelpers: 0,
        });
        // An executing case may run its jobs on one to eight simulated
        // helpers, named before or after its profile.
        for (const [values, helpers] of [
            [['native-invalid-only', '3', '2', '--simulated-helpers', '1'], 1],
            [['--', 'native-result', '--simulated-helpers', '8', '4', '3'], 8],
        ] as const) {
            expect(selectProtocolResearchCase(values)).toMatchObject({
                execution: true,
                simulatedHelpers: helpers,
            });
        }
        expect(
            selectProtocolResearchCase([
                'native-prefix',
                '--simulated-helpers',
                '3',
            ]).simulatedHelpers,
        ).toBe(3);
        expect(selectProtocolResearchCase(['check']).execution).toBe(false);
        expect(selectProtocolResearchCase(['native-prefix'])).toEqual({
            name: 'native-prefix',
            execution: true,
            noResult: false,
            participantCount: 10,
            optionCount: 10,
            simulatedHelpers: 0,
        });
    });

    it('derives the native ceremony expectations from the thresholds', () => {
        // Totals 21, 30, 39, 28, 17, 16, 35, 24, 23 and 22 over voters 0 and
        // 4 to 7; no two options tie.
        expect(deriveResearchScenario(10, 10)).toMatchObject({
            corrupt: [1, 2, 3],
            accepted: [0, 4, 5, 6, 7],
            omitted: [9],
            invalid: [1, 2],
            conflicting: [3],
            signers: [0, 4, 5, 6, 7, 8, 9],
            identifiers: [2, 6, 1, 3, 7, 8, 9, 0, 4, 5].map(
                (option) => `option-${option}`,
            ),
            releaseThreshold: 4,
            certificateThreshold: 7,
            releaseSubsets: 210,
            departureSets: 176,
        });
        // No corruption: every participant is honest and nobody is omitted.
        expect(deriveResearchScenario(3, 2)).toMatchObject({
            corrupt: [],
            accepted: [0, 1],
            omitted: [],
            invalid: [],
            conflicting: [],
            signers: [0, 1, 2],
            identifiers: ['option-1', 'option-0'],
            releaseSubsets: 3,
            departureSets: 1,
        });
        expect(deriveResearchScenario(4, 3)).toMatchObject({
            accepted: [0, 2, 3],
            omitted: [],
            invalid: [],
            conflicting: [1],
        });
        // Scores repeat every ten options, so ties go to the lower position.
        const largest = deriveResearchScenario(20, 20);
        expect(largest).toMatchObject({
            corrupt: [1, 2, 3, 4, 5, 6],
            accepted: [0, 7, 8, 9, 10, 11, 12, 13],
            omitted: [19],
            invalid: [4, 5],
            conflicting: [6],
            releaseSubsets: 256,
            departureSets: 256,
        });
        expect(largest.identifiers.slice(0, 4)).toEqual([
            'option-6',
            'option-16',
            'option-5',
            'option-15',
        ]);
        for (let position = 0; position < 20; position++)
            for (let option = 0; option < 20; option++) {
                const score = researchBallotScore(position, option);
                expect(score >= 1 && score <= 10).toBe(true);
            }
    });

    it('charges descendants independent of enumeration order without charging unrelated processes', () => {
        const rows = [
            { identifier: 4, parent: 3, bytes: 40 },
            { identifier: 8, parent: 1, bytes: 800 },
            { identifier: 3, parent: 2, bytes: 30 },
            { identifier: 2, parent: 1, bytes: 20 },
        ];
        expect(sumProtocolProcessTree(2, rows)).toBe(90);
        expect(sumProtocolProcessTree(2, [...rows].reverse())).toBe(90);
        expect(sumProtocolProcessTree(5, rows)).toBeUndefined();
    });

    it('charges no process that started before the process of its recorded parent identifier, nor its descendants', () => {
        const rows = [
            { identifier: 2, parent: 1, bytes: 20, started: 500 },
            { identifier: 3, parent: 2, bytes: 30, started: 500 },
            { identifier: 4, parent: 3, bytes: 40, started: 900 },
            // An exited process that had the identifier 2 started these.
            { identifier: 7, parent: 2, bytes: 7000, started: 100 },
            { identifier: 9, parent: 7, bytes: 900, started: 499 },
        ];
        expect(sumProtocolProcessTree(2, rows)).toBe(90);
        expect(sumProtocolProcessTree(2, [...rows].reverse())).toBe(90);
        expect(sumProtocolProcessTree(7, rows)).toBe(7900);
    });
});
