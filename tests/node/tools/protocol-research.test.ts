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
import { parseRegistrationSessionResult } from '#tools/ci/run-registration-session.js';

describe('guarded protocol research entry', () => {
    it('executes only the named original-registration session case', () => {
        expect(
            selectProtocolResearchCase(['registration-session']),
        ).toMatchObject({
            name: 'registration-session',
            execution: true,
            simulatedHelpers: 0,
        });
        for (const args of [
            ['registration-session', '3', '2'],
            ['registration-session', 'unknown'],
            ['registration-session', '--simulated-helpers', '1'],
        ])
            expect(() => selectProtocolResearchCase(args)).toThrow();
        const test =
            'test registration_session_tests::sessions_verify_and_refuse_a_registration_as_its_verifier_does ... ok';
        const summary =
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 1.00s';
        expect(parseRegistrationSessionResult(`${test}\n${summary}\n`)).toEqual(
            { kind: 'registration-session', passed: 1, ignored: 0 },
        );
        for (const output of [
            '',
            summary,
            test,
            `${test}\n${summary.replace('1 passed', '0 passed')}`,
            `${test}\n${summary.replace('0 ignored', '1 ignored')}`,
            `${test}\n${test}\n${summary}`,
        ])
            expect(() => parseRegistrationSessionResult(output)).toThrow();
    });
    it('registers two-case public arithmetic screens without proof/profile overrides', () => {
        expect(selectProtocolResearchCase(['native-public-operator'])).toEqual({
            name: 'native-public-operator',
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const name of [
            'scalar-public-operator',
            'browser-public-operator',
        ])
            expect(
                selectProtocolResearchCase([name, 'native-source']),
            ).toMatchObject({
                name,
                source: 'native-source',
                simulatedHelpers: 0,
            });
        for (const values of [
            ['native-public-operator', 'source'],
            ['native-public-operator', '4', '2'],
            ['native-public-operator', '--simulated-helpers', '1'],
            ['scalar-public-operator'],
            ['browser-public-operator', ''],
            ['scalar-public-operator', 'source', 'extra'],
            ['browser-public-operator', '--unknown'],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
    });
    it('selects opening scalar and browser cases only with one native opening source', () => {
        for (const name of [
            'scalar-opening-share',
            'browser-opening-share',
            'scalar-opening-share-generation',
            'browser-opening-share-generation',
        ]) {
            expect(selectProtocolResearchCase([name, 'source'])).toEqual({
                name,
                source: 'source',
                execution: true,
                noResult: false,
                participantCount: 4,
                optionCount: 2,
                simulatedHelpers: 0,
            });
            for (const arguments_ of [
                [name],
                [name, ''],
                [name, 'source', 'extra'],
                [name, 'source', '--simulated-helpers', '1'],
            ])
                expect(() => selectProtocolResearchCase(arguments_)).toThrow();
        }
    });
    it('requires an explicit public case and a nonempty fixture', () => {
        for (const values of [
            [],
            ['available-records'],
            ['available-records', ''],
            ['unknown', 'fixture'],
            ['available-records', 'fixture', 'extra'],
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

    it('selects only the fixed scalar seed-sharing fixture without profile overrides', () => {
        expect(
            selectProtocolResearchCase(['--', 'native-seed-sharing']),
        ).toEqual({
            name: 'native-seed-sharing',
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const values of [
            ['native-seed-sharing', '4', '2'],
            ['native-seed-sharing', '10', '10'],
            ['native-seed-sharing', '4'],
            ['native-seed-sharing', ''],
            ['native-seed-sharing', '--simulated-helpers', '1'],
            ['native-seed-sharing', 'native-result'],
            ['seed-sharing'],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
    });

    it('keeps deterministic reference comparison separate from fresh opening-share input', () => {
        expect(
            selectProtocolResearchCase([
                'native-opening-share',
                'fresh-run',
                '--compare-reference',
                'old-opening-run',
            ]),
        ).toMatchObject({
            name: 'native-opening-share',
            source: 'fresh-run',
            reference: 'old-opening-run',
        });
        expect(
            selectProtocolResearchCase([
                'native-seed-sharing',
                '--compare-reference',
                'historical-run',
            ]),
        ).toMatchObject({
            name: 'native-seed-sharing',
            reference: 'historical-run',
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        expect(
            selectProtocolResearchCase(['native-opening-share', 'fresh-run']),
        ).toEqual({
            name: 'native-opening-share',
            source: 'fresh-run',
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const values of [
            ['native-seed-sharing', '--compare-reference'],
            ['native-seed-sharing', '--compare-reference', ''],
            [
                'native-seed-sharing',
                '--compare-reference',
                '--simulated-helpers',
            ],
            [
                'native-seed-sharing',
                '--compare-reference',
                'reference',
                'extra',
            ],
            [
                'native-seed-sharing',
                '--compare-reference',
                'reference',
                '--simulated-helpers',
                '1',
            ],
            ['native-result', '--compare-reference', 'reference'],
            ['native-opening-share'],
            ['native-opening-share', ''],
            ['native-opening-share', '--compare-reference'],
            ['native-opening-share', 'fresh', '--simulated-helpers', '1'],
            ['native-opening-share', 'fresh', '4', '2'],
            ['native-opening-share', 'fresh', '--compare-reference'],
            ['native-opening-share', 'fresh', '--compare-reference', ''],
            [
                'native-opening-share',
                'fresh',
                '--compare-reference',
                'old',
                'extra',
            ],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
    });

    it('selects scalar seed-sharing verification only with one native source run', () => {
        expect(
            selectProtocolResearchCase([
                '--',
                'scalar-seed-sharing',
                'logs/2026-10-04/passed-native-run',
            ]),
        ).toEqual({
            name: 'scalar-seed-sharing',
            source: 'logs/2026-10-04/passed-native-run',
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const values of [
            ['scalar-seed-sharing'],
            ['scalar-seed-sharing', ''],
            ['scalar-seed-sharing', '   '],
            ['scalar-seed-sharing', 'source', 'extra'],
            ['scalar-seed-sharing', '4', '2'],
            ['scalar-seed-sharing', 'source', '4', '2'],
            ['scalar-seed-sharing', '--simulated-helpers'],
            ['scalar-seed-sharing', '--simulated-helpers', '1'],
            ['scalar-seed-sharing', 'source', '--simulated-helpers', '1'],
            ['--simulated-helpers', '1', 'scalar-seed-sharing', 'source'],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
        expect(
            selectProtocolResearchCase(['native-seed-sharing']),
        ).not.toHaveProperty('source');
    });

    it('selects external Chrome verification with one pinned native source', () => {
        expect(
            selectProtocolResearchCase(['browser-seed-sharing', 'logs/source']),
        ).toEqual({
            name: 'browser-seed-sharing',
            source: 'logs/source',
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const values of [
            ['browser-seed-sharing'],
            ['browser-seed-sharing', ''],
            ['browser-seed-sharing', 'source', 'extra'],
            ['browser-seed-sharing', '4', '2'],
            ['browser-seed-sharing', 'source', '--simulated-helpers', '1'],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
    });

    it('selects bounded positive generation only from a single native source without helper or profile overrides', () => {
        for (const name of [
            'scalar-seed-sharing-generation',
            'browser-seed-sharing-generation',
        ]) {
            expect(selectProtocolResearchCase([name, 'logs/source'])).toEqual({
                name,
                source: 'logs/source',
                execution: true,
                noResult: false,
                participantCount: 4,
                optionCount: 2,
                simulatedHelpers: 0,
            });
            for (const values of [
                [name],
                [name, ''],
                [name, '4', '2'],
                [name, 'source', 'extra'],
                [name, 'source', '--simulated-helpers', '1'],
            ])
                expect(() => selectProtocolResearchCase(values)).toThrow();
        }
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
