import { describe, expect, it } from 'vitest';

import { requiredRustHeavyEvidenceTests } from '#tools/ci/heavy-evidence-tests';
import {
    createRequiredRustHeavyEvidenceCargoCommands,
    formatRequiredRustHeavyEvidenceTestList,
    selectedRequiredRustHeavyEvidenceTests,
    shouldListRequiredRustHeavyEvidenceTests,
    unknownRequiredRustHeavyEvidenceOptions,
} from '#tools/ci/run-required-rust-heavy-evidence-tests';

describe('required Rust heavy evidence runner', () => {
    it('selects all required tests by default', () => {
        expect(selectedRequiredRustHeavyEvidenceTests([])).toEqual(
            requiredRustHeavyEvidenceTests,
        );
    });

    it('selects only exact requested required tests in request order', () => {
        const firstRequiredTest = requiredRustHeavyEvidenceTests[0];
        const secondRequiredTest = requiredRustHeavyEvidenceTests[1];

        expect(
            selectedRequiredRustHeavyEvidenceTests([
                secondRequiredTest.testName,
                firstRequiredTest.testName,
            ]),
        ).toEqual([secondRequiredTest, firstRequiredTest]);
    });

    it('rejects unknown required test names and options', () => {
        expect(() =>
            selectedRequiredRustHeavyEvidenceTests([
                'heavy_accepted_setup_not_registered',
            ]),
        ).toThrow(
            'Unknown required Rust heavy evidence test(s): heavy_accepted_setup_not_registered. Use --list to print valid test names.',
        );
        expect(unknownRequiredRustHeavyEvidenceOptions(['--unknown'])).toEqual([
            '--unknown',
        ]);
        expect(() =>
            selectedRequiredRustHeavyEvidenceTests(['--unknown']),
        ).toThrow(
            'Unknown required Rust heavy evidence option(s): --unknown. Use --list to print valid test names.',
        );
    });

    it('prints the required test list without selecting a cargo run', () => {
        expect(shouldListRequiredRustHeavyEvidenceTests(['--list'])).toBe(true);

        const formattedList = formatRequiredRustHeavyEvidenceTestList(
            requiredRustHeavyEvidenceTests.slice(0, 1),
        );

        expect(formattedList).toContain(
            'Required Rust heavy evidence tests (1):',
        );
        expect(formattedList).toContain(
            requiredRustHeavyEvidenceTests[0].testName,
        );
        expect(formattedList).toContain(
            requiredRustHeavyEvidenceTests[0].claimEvidence,
        );
        expect(formattedList).toContain(
            requiredRustHeavyEvidenceTests[0].relativePath,
        );
    });

    it('creates one exact cargo command per selected test with checkpoint resume', () => {
        const selectedTest = requiredRustHeavyEvidenceTests[0];
        const targetDirectory = 'C:/workspace/target/heavy-required-evidence';
        const commands = createRequiredRustHeavyEvidenceCargoCommands(
            [selectedTest],
            {
                baseEnvironment: {
                    EXISTING_VARIABLE: 'preserved',
                },
                targetDirectory,
                testThreadCount: 2,
            },
        );

        expect(commands).toHaveLength(1);
        expect(commands[0]).toMatchObject({
            args: [
                'test',
                '-p',
                'sealed-lattice-kernel',
                selectedTest.testName,
                '--',
                '--ignored',
                '--nocapture',
                '--test-threads',
                '2',
            ],
            command: 'cargo',
            description: `cargo test ${selectedTest.testName} (required heavy evidence)`,
            env: {
                CARGO_INCREMENTAL: '1',
                CARGO_TARGET_DIR: targetDirectory,
                EXISTING_VARIABLE: 'preserved',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            },
            logFileSlug: `cargo-test-required-heavy-evidence-${selectedTest.testName}`,
        });
    });
});
