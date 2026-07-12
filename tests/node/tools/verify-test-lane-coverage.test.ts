import { describe, expect, it } from 'vitest';

import { parseFuzzDurationSeconds } from '#tools/ci/run-foundation-parser-fuzzing';
import { validateFocusedRustLaneSelection } from '#tools/ci/rust-focused-lane-selection';
import {
    aggregateTestScripts,
    canonicalTestLaneDefinitions,
    canonicalTestLaneValues,
    rustTestLanesForInventoryEntry,
    testLaneGroupsForRelativePath,
    testUtilityScripts,
} from '#tools/ci/test-lanes';
import {
    analyzeTypeScriptTestSource,
    parseCargoFuzzBins,
    parseLibtestListOutput,
    validateExternalOracleInventory,
    validateFuzzTargetInventory,
    validateRootTestScripts,
    validateRustTestInventory,
    validateTestLaneCoverage,
} from '#tools/ci/verify-test-lane-coverage';

describe('test lane coverage verification', () => {
    it('classifies the current lane patterns', () => {
        expect(
            testLaneGroupsForRelativePath(
                'packages/protocol/tests/node/election-foundation-thresholds.test.ts',
            ),
        ).toEqual(['node-protocol']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/wasm/tests/node/transcript-core-kernel/core-kernel-and-fixtures.kernel.test.ts',
            ),
        ).toEqual(['node-kernel-fast']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup/setup-package-verification.kernel.test.ts',
            ),
        ).toEqual(['node-kernel-heavy']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/sdk/tests/browser/election-foundation-public-api.browser.test.ts',
            ),
        ).toEqual(['browser']);
        expect(
            testLaneGroupsForRelativePath('tests/node/tools/run-check.test.ts'),
        ).toEqual(['node-fast']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/sdk/tests/browser/public-api.browser.test.ts',
            ),
        ).toEqual(['browser']);
    });

    it('rejects browser tests that are missing the browser suffix', () => {
        expect(
            validateTestLaneCoverage([
                'packages/sdk/tests/browser/election-foundation-public-api.test.ts',
            ]),
        ).toEqual([
            'packages/sdk/tests/browser/election-foundation-public-api.test.ts is not covered by any test lane. Browser tests must use the .browser.test.ts suffix, and kernel tests must use the .kernel.test.ts suffix in a kernel test directory.',
        ]);
    });

    it('finds hidden definitions and rejects empty, focused, and disabled tests', () => {
        expect(
            analyzeTypeScriptTestSource({
                relativePath: 'tools/hidden-tests.ts',
                sourceText:
                    "import { test as verifies } from 'vitest'; verifies('hidden', () => {});",
            }).failures,
        ).toContain(
            'tools/hidden-tests.ts defines Vitest tests outside a recognized test-named file.',
        );
        expect(
            analyzeTypeScriptTestSource({
                relativePath: 'tests/node/empty.test.ts',
                sourceText: 'export {};',
            }).failures,
        ).toContain(
            'tests/node/empty.test.ts is test-named but defines no Vitest tests.',
        );

        const disabledAnalysis = analyzeTypeScriptTestSource({
            relativePath: 'tests/node/disabled.test.ts',
            sourceText:
                "import { describe, it, test } from 'vitest'; describe.only('focused', () => {}); it.skip('skipped', () => {}); test.todo('todo');",
        });
        expect(disabledAnalysis.failures).toHaveLength(3);
        expect(disabledAnalysis.failures.join('\n')).toMatch(/\.only/u);
        expect(disabledAnalysis.failures.join('\n')).toMatch(/\.skip/u);
        expect(disabledAnalysis.failures.join('\n')).toMatch(/\.todo/u);
    });

    it('allows capability skip only in classified browser tests', () => {
        expect(
            analyzeTypeScriptTestSource({
                relativePath:
                    'packages/sdk/tests/browser/capability.browser.test.ts',
                sourceText:
                    "import { describe } from 'vitest'; describe.skipIf(true)('browser', () => {});",
            }).failures,
        ).toEqual([]);
        expect(
            analyzeTypeScriptTestSource({
                relativePath: 'tests/node/capability.test.ts',
                sourceText:
                    "import { describe } from 'vitest'; describe.skipIf(true)('node', () => {});",
            }).failures,
        ).toContain(
            'tests/node/capability.test.ts:1 uses .skipIf outside the classified browser lane.',
        );
    });

    it('parses libtest unit, integration, and doctest inventories', () => {
        expect(
            parseLibtestListOutput(
                'module::unit: test\nintegration_case: test\ncrate::example - compile\n2 tests, 0 benchmarks\n',
            ),
        ).toEqual([
            'crate::example - compile',
            'integration_case',
            'module::unit',
        ]);
    });

    it('classifies every Rust kernel lane and rejects orphaned inventory', () => {
        const entries = [
            {
                ignored: false,
                packageName: 'sealed-lattice-kernel',
                testName: 'foundation::tests::fast_test',
            },
            {
                ignored: true,
                packageName: 'sealed-lattice-kernel',
                testName: 'bgv::tests::heavy_rust_kernel_expensive_relation',
            },
            {
                ignored: true,
                packageName: 'sealed-lattice-kernel',
                testName:
                    'bgv::setup::tests::accepted_setup::proofs::accepted_test',
            },
            {
                ignored: true,
                packageName: 'sealed-lattice-kernel',
                testName:
                    'bgv::setup::tests::private_vss::private_vss_share_envelope_verifier_accepts_foundation_roster_succinct_private_share_proofs',
            },
            {
                ignored: true,
                packageName: 'sealed-lattice-kernel',
                testName:
                    'bgv::evaluator::top_k::tests::level_budget_probe::lagrange_cleared_l1_worst_case',
            },
        ] as const;
        expect(
            entries.map((entry) => rustTestLanesForInventoryEntry(entry)),
        ).toEqual([
            ['rust-kernel-fast'],
            ['rust-kernel-heavy'],
            ['rust-accepted-setup'],
            ['rust-full-profile-evidence'],
            ['rust-measurements'],
        ]);
        expect(
            rustTestLanesForInventoryEntry({
                ignored: true,
                packageName: 'sealed-lattice-kernel',
                testName:
                    'bgv::setup::tests::accepted_setup::heavy_rust_kernel_overlap',
            }),
        ).toEqual(['rust-accepted-setup', 'rust-kernel-heavy']);

        const failures = validateRustTestInventory([
            {
                ignored: true,
                packageName: 'unregistered-rust-package',
                targetName: 'integration',
                testName: 'orphaned_test',
            },
        ]);
        expect(failures).toContain(
            'unregistered-rust-package/integration/orphaned_test is not owned by a Rust test lane.',
        );
        expect(
            failures.some((failure) => failure.includes('stale or missing')),
        ).toBe(true);
    });

    it('rejects missing and undeclared root scripts', () => {
        const validScripts: Record<string, string> = {};
        for (const lane of canonicalTestLaneValues) {
            validScripts[canonicalTestLaneDefinitions[lane].rootScript] =
                'runner';
        }
        for (const script of aggregateTestScripts) {
            validScripts[script] = 'aggregate';
        }
        for (const script of testUtilityScripts) {
            validScripts[script] = 'utility';
        }
        expect(validateRootTestScripts(validScripts)).toEqual([]);

        delete validScripts['test:rust:kernel:measurements'];
        validScripts['test:unregistered'] = 'runner';
        expect(validateRootTestScripts(validScripts)).toEqual(
            expect.arrayContaining([
                'rust-measurements is missing root script test:rust:kernel:measurements.',
                'test:unregistered is an undeclared root test script; register it as a canonical lane or aggregate alias.',
            ]),
        );
    });

    it('rejects missing, unexpected, and redirected fuzz targets', () => {
        expect(
            parseCargoFuzzBins(
                '[[bin]]\nname = "foundation-schema-object"\npath = "fuzz_targets/foundation-schema-object.rs"\n',
            ),
        ).toEqual([
            {
                name: 'foundation-schema-object',
                sourcePath: 'fuzz_targets/foundation-schema-object.rs',
            },
        ]);
        expect(validateFuzzTargetInventory([])[0]).toContain(
            'must declare fuzz target foundation-schema-object exactly once',
        );
        expect(
            validateFuzzTargetInventory([
                { name: 'unexpected', sourcePath: 'fuzz_targets/other.rs' },
            ]).some((failure) => failure.includes('unowned fuzz target')),
        ).toBe(true);
        expect(parseFuzzDurationSeconds([])).toBe(60);
        expect(parseFuzzDurationSeconds(['--', '3600'])).toBe(3600);
        expect(() => parseFuzzDurationSeconds(['0'])).toThrow(
            'positive duration',
        );
        expect(validateExternalOracleInventory([])[0]).toContain(
            'missing from external oracle ownership',
        );
        expect(
            validateExternalOracleInventory([
                'tools/lattigo-oracle/run-lattigo-oracle.ts',
                'tools/other/run-unregistered-oracle.ts',
            ]),
        ).toContain(
            'tools/other/run-unregistered-oracle.ts is an unowned external oracle runner.',
        );
    });

    it('rejects focused filters that select zero or cross-lane tests', () => {
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: 'missing',
                testNames: [],
            }),
        ).toThrow('selects zero tests');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: 'heavy_rust_kernel_',
                testNames: ['bgv::tests::heavy_rust_kernel_expensive_relation'],
            }),
        ).toThrow('test:rust:kernel:heavy');
    });
});
