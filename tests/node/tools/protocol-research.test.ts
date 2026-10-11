import { describe, expect, it } from 'vitest';

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
    it('requires only actual response files while retaining original roster positions and all normal responders', () => {
        const departure = deriveResearchScenario(4, 2, true);
        expect(departure.participantCount).toBe(4);
        expect(departure.responseFiles).toEqual([
            'response-0.bin',
            'response-2.bin',
            'response-3.bin',
        ]);
        for (const scenario of [
            deriveResearchScenario(4, 2),
            deriveResearchScenario(4, 2, false, true),
        ])
            expect(scenario.responseFiles).toEqual([
                'response-0.bin',
                'response-1.bin',
                'response-2.bin',
                'response-3.bin',
            ]);
        // Target-signature withholding does not imply an absent close response.
        const normal = deriveResearchScenario(10, 10);
        expect(normal.responseFiles).toEqual(
            Array.from(
                { length: 10 },
                (_, position) => `response-${position}.bin`,
            ),
        );
        expect(normal.responseFiles).toContain('response-1.bin');
        expect(normal.signers).not.toContain(1);
    });
    it('keeps the forked-organizer selection case separate from departures and ballot equivocation', () => {
        expect(
            selectProtocolResearchCase(['native-selection-fork']),
        ).toMatchObject({
            name: 'native-selection-fork',
            participantCount: 4,
            optionCount: 2,
        });
        expect(deriveResearchScenario(4, 2, false, true)).toMatchObject({
            corrupt: [0],
            departed: [],
            selectedAuthors: [0, 2],
            honest: [1, 2, 3],
            accepted: [0, 1, 2, 3],
            signers: [0, 1, 2, 3],
            conflicting: [],
            invalid: [],
            releaseSubsets: 6,
            departureSets: 5,
        });
        expect(() => deriveResearchScenario(4, 2, true, true)).toThrow();
        expect(() =>
            selectProtocolResearchCase(['native-selection-fork', '4', '2']),
        ).toThrow();
    });
    it('fixes the setup departure profile and keeps cooperative corruption separate from honest loss', () => {
        expect(selectProtocolResearchCase(['native-setup-departure'])).toEqual({
            name: 'native-setup-departure',
            execution: true,
            noResult: false,
            participantCount: 4,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const values of [
            ['native-setup-departure', '4', '2'],
            ['native-setup-departure', '--simulated-helpers', '1'],
            ['native-setup-departure', 'extra'],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
        expect(deriveResearchScenario(4, 2, true)).toMatchObject({
            corrupt: [2],
            departed: [1],
            selectedAuthors: [0, 2],
            honest: [0, 1, 3],
            accepted: [0, 2, 3],
            signers: [0, 2, 3],
            invalid: [],
            conflicting: [],
            omitted: [],
            certificateThreshold: 3,
            releaseThreshold: 2,
            releaseSubsets: 3,
            departureSets: 1,
        });
        expect(() => deriveResearchScenario(3, 2, true)).toThrow();
    });
    it('fixes the FHE key source screen and requires one native source for each scalar host', () => {
        expect(
            selectProtocolResearchCase(['native-fhe-key-source']),
        ).toMatchObject({
            name: 'native-fhe-key-source',
            participantCount: 3,
            optionCount: 2,
            simulatedHelpers: 0,
        });
        for (const name of [
            'scalar-fhe-key-source',
            'browser-fhe-key-source',
        ]) {
            expect(selectProtocolResearchCase([name, 'source'])).toMatchObject({
                name,
                source: 'source',
            });
            for (const values of [
                [name],
                [name, ''],
                [name, '--source'],
                [name, 'source', 'extra'],
                [name, 'source', '--simulated-helpers', '1'],
            ])
                expect(() => selectProtocolResearchCase(values)).toThrow();
        }
        for (const values of [
            ['native-fhe-key-source', '3', '2'],
            ['native-fhe-key-source', '--simulated-helpers', '1'],
            ['native-fhe-key-source', 'source'],
        ])
            expect(() => selectProtocolResearchCase(values)).toThrow();
    });
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
            ['native-requested-output', '3', '2'],
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
                'native-requested-output',
                '--simulated-helpers',
                '3',
            ]).simulatedHelpers,
        ).toBe(3);
        expect(selectProtocolResearchCase(['check']).execution).toBe(false);
        expect(selectProtocolResearchCase(['native-requested-output'])).toEqual(
            {
                name: 'native-requested-output',
                execution: true,
                noResult: false,
                participantCount: 10,
                optionCount: 10,
                simulatedHelpers: 0,
            },
        );
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
});
