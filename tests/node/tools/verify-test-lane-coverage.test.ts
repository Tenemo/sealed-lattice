import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseFuzzDurationSeconds } from '#tools/ci/run-foundation-parser-fuzzing';
import { validateFocusedRustLaneSelection } from '#tools/ci/rust-focused-lane-selection';
import { inventoryEntriesFromListedTests } from '#tools/ci/rust-test-inventory';
import {
    aggregateTestScriptCommands,
    aggregateTestScripts,
    browserTestLaneDefinitions,
    canonicalTestLaneDefinitions,
    canonicalTestLaneValues,
    defaultNodeTestLanes,
    rustTestLanesForInventoryEntry,
    testLaneGroupsForRelativePath,
    testUtilityScriptCommands,
    testUtilityScripts,
} from '#tools/ci/test-lanes';
import {
    analyzeTypeScriptTestSource,
    collectOwnedTypeScriptSources,
    parseCargoFuzzBins,
    parseLibtestListOutput,
    validateExternalOracleInventory,
    validateFuzzTargetInventory,
    validateMobileBrowserTestSelectors,
    validateRootTestScripts,
    validateRustTestInventory,
    validateTestLaneCoverage,
} from '#tools/ci/verify-test-lane-coverage';

describe('test lane coverage verification', () => {
    it('classifies the current lane patterns', () => {
        expect(defaultNodeTestLanes).toEqual([
            'fast',
            'protocol',
            'kernel-fast',
        ]);
        expect(browserTestLaneDefinitions.mobile.include).toEqual([
            'packages/sdk/tests/browser/election-foundation-public-api.browser.test.ts',
            'packages/wasm/tests/browser/owned-kernel-worker-channel.browser.test.ts',
            'packages/protocol/tests/browser/browser-action-storage-custody.browser.test.ts',
        ]);
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

    it('cross-checks the exact mobile smoke selectors against discovered browser tests', () => {
        const mobileTests = browserTestLaneDefinitions.mobile.include;
        expect(validateMobileBrowserTestSelectors(mobileTests)).toEqual([]);
        expect(
            validateMobileBrowserTestSelectors(mobileTests.slice(1)),
        ).toEqual([
            `Mobile browser smoke test ${mobileTests[0]} is stale or missing.`,
        ]);
    });

    it('discovers TypeScript tests in unconventional owned directories while excluding private and generated trees', async () => {
        const temporaryRoot = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-test-discovery-'),
        );
        try {
            const ownedTestPath = path.join(
                temporaryRoot,
                'unusual-source',
                'hidden.test.ts',
            );
            const privateTestPath = path.join(
                temporaryRoot,
                'implementation-documentation',
                'private.test.ts',
            );
            const generatedTestPath = path.join(
                temporaryRoot,
                'dist',
                'generated.test.ts',
            );
            for (const filePath of [
                ownedTestPath,
                privateTestPath,
                generatedTestPath,
            ]) {
                await mkdir(path.dirname(filePath), { recursive: true });
                await writeFile(
                    filePath,
                    "import { it } from 'vitest';\n",
                    'utf8',
                );
            }

            const discoveredFiles =
                await collectOwnedTypeScriptSources(temporaryRoot);
            expect(discoveredFiles).toEqual([ownedTestPath]);
        } finally {
            await rm(temporaryRoot, { force: true, recursive: true });
        }
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
                sourceText:
                    "import { describe } from 'vitest'; describe('suite', () => {});",
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

        expect(
            analyzeTypeScriptTestSource({
                relativePath: 'tools/hidden-suite.ts',
                sourceText:
                    "import * as vitest from 'vitest'; vitest.describe('hidden', () => {});",
            }).failures,
        ).toContain(
            'tools/hidden-suite.ts defines Vitest tests outside a recognized test-named file.',
        );
    });

    it('reports every TypeScript parse diagnostic without hiding recovered test ownership', () => {
        const malformedOwnedTest = analyzeTypeScriptTestSource({
            relativePath: 'tests/node/malformed.test.ts',
            sourceText:
                "import { it } from 'vitest';\nit('still discovered', () => {});\nconst firstBrokenValue = ;\nconst secondBrokenValue = ;",
        });

        expect(malformedOwnedTest.definitionCount).toBe(1);
        expect(malformedOwnedTest.failures).toEqual([
            'tests/node/malformed.test.ts:3:26 has TypeScript syntax error TS1109: Expression expected.',
            'tests/node/malformed.test.ts:4:27 has TypeScript syntax error TS1109: Expression expected.',
        ]);

        const malformedHiddenTest = analyzeTypeScriptTestSource({
            relativePath: 'tools/malformed-hidden-tests.ts',
            sourceText:
                "import { test } from 'vitest';\ntest('hidden but recoverable', () => {});\nconst brokenValue = ;",
        });

        expect(malformedHiddenTest.definitionCount).toBe(1);
        expect(malformedHiddenTest.failures).toEqual([
            'tools/malformed-hidden-tests.ts:3:21 has TypeScript syntax error TS1109: Expression expected.',
            'tools/malformed-hidden-tests.ts defines Vitest tests outside a recognized test-named file.',
        ]);
    });

    it('allows runtime browser capability skips and rejects static or unsupported conditional modifiers', () => {
        expect(
            analyzeTypeScriptTestSource({
                relativePath:
                    'packages/sdk/tests/browser/capability.browser.test.ts',
                sourceText:
                    "import { describe, it } from 'vitest'; import { webLocksAvailable } from '#tests/support/browser-capabilities'; describe.skipIf(!webLocksAvailable)('browser', () => { it('works', () => {}); });",
            }).failures,
        ).toEqual([]);
        expect(
            analyzeTypeScriptTestSource({
                relativePath:
                    'packages/sdk/tests/browser/local-capability.browser.test.ts',
                sourceText:
                    "import { describe, it } from 'vitest'; const webLocksAvailable = 'locks' in navigator; describe.skipIf(!webLocksAvailable)('browser', () => { it('works', () => {}); });",
            }).failures,
        ).toContain(
            'packages/sdk/tests/browser/local-capability.browser.test.ts:1 uses .skipIf without the shared webLocksAvailable capability import.',
        );
        expect(
            analyzeTypeScriptTestSource({
                relativePath:
                    'packages/sdk/tests/browser/static-capability.browser.test.ts',
                sourceText:
                    "import { describe, it } from 'vitest'; describe.skipIf(true)('browser', () => { it('works', () => {}); });",
            }).failures,
        ).toContain(
            'packages/sdk/tests/browser/static-capability.browser.test.ts:1 uses .skipIf with a static boolean; only runtime browser-capability conditions are allowed.',
        );
        expect(
            analyzeTypeScriptTestSource({
                relativePath:
                    'packages/sdk/tests/browser/other-capability.browser.test.ts',
                sourceText:
                    "import { describe, it } from 'vitest'; const otherCapability = 'serviceWorker' in navigator; describe.skipIf(otherCapability)('browser', () => { it('works', () => {}); });",
            }).failures,
        ).toContain(
            'packages/sdk/tests/browser/other-capability.browser.test.ts:1 uses .skipIf without the shared webLocksAvailable capability import.',
        );
        expect(
            analyzeTypeScriptTestSource({
                relativePath: 'tests/node/capability.test.ts',
                sourceText:
                    "import { describe, it } from 'vitest'; const capabilityAvailable = true; describe.skipIf(capabilityAvailable)('node', () => { it('works', () => {}); });",
            }).failures,
        ).toContain(
            'tests/node/capability.test.ts:1 uses .skipIf outside the classified browser lane.',
        );
        expect(
            analyzeTypeScriptTestSource({
                relativePath:
                    'packages/sdk/tests/browser/run-if.browser.test.ts',
                sourceText:
                    "import { it } from 'vitest'; const capabilityAvailable = true; it.runIf(capabilityAvailable)('conditional', () => {});",
            }).failures,
        ).toContain(
            'packages/sdk/tests/browser/run-if.browser.test.ts:1 uses .runIf; conditional browser tests must use capability-dependent .skipIf.',
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
        expect(
            inventoryEntriesFromListedTests({
                allTests: ['ordinary', 'ignored'],
                ignoredTests: new Set(['ignored']),
                packageName: 'sealed-lattice-kernel',
                targetName: 'sealed_lattice_kernel',
            }),
        ).toEqual([
            {
                ignored: false,
                packageName: 'sealed-lattice-kernel',
                targetName: 'sealed_lattice_kernel',
                testName: 'ordinary',
            },
            {
                ignored: true,
                packageName: 'sealed-lattice-kernel',
                targetName: 'sealed_lattice_kernel',
                testName: 'ignored',
            },
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
            const definition = canonicalTestLaneDefinitions[lane];
            validScripts[definition.rootScript] = definition.command;
        }
        for (const script of aggregateTestScripts) {
            validScripts[script] = aggregateTestScriptCommands[script];
        }
        for (const script of testUtilityScripts) {
            validScripts[script] = testUtilityScriptCommands[script];
        }
        expect(validateRootTestScripts(validScripts)).toEqual([]);

        delete validScripts['test:rust:kernel:measurements'];
        validScripts['test:node:fast'] = 'tsx ./tools/ci/wrong-runner.ts';
        validScripts['test:unregistered'] = 'runner';
        expect(validateRootTestScripts(validScripts)).toEqual(
            expect.arrayContaining([
                'rust-measurements is missing root script test:rust:kernel:measurements.',
                'test:node:fast runs "tsx ./tools/ci/wrong-runner.ts"; expected "tsx ./tools/ci/run-node-tests.ts fast" for node-fast.',
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
                tests: [],
            }),
        ).toThrow('selects zero tests');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-measurements',
                testFilter: 'heavy_rust_kernel_',
                tests: [
                    {
                        ignored: true,
                        packageName: 'sealed-lattice-kernel',
                        targetName: 'sealed_lattice_kernel',
                        testName:
                            'bgv::tests::heavy_rust_kernel_expensive_relation',
                    },
                ],
            }),
        ).toThrow('test:rust:kernel:heavy');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-kernel-fast',
                testFilter: 'ignored_without_registry_owner',
                tests: [
                    {
                        ignored: true,
                        packageName: 'sealed-lattice-kernel',
                        targetName: 'sealed_lattice_kernel',
                        testName: 'foundation::tests::ignored_without_owner',
                    },
                ],
            }),
        ).toThrow('updated canonical lane registry');
        expect(() =>
            validateFocusedRustLaneSelection({
                lane: 'rust-accepted-setup',
                testFilter: 'overlap',
                tests: [
                    {
                        ignored: true,
                        packageName: 'sealed-lattice-kernel',
                        targetName: 'sealed_lattice_kernel',
                        testName:
                            'bgv::setup::tests::accepted_setup::heavy_rust_kernel_overlap',
                    },
                ],
            }),
        ).toThrow('owned by multiple canonical lanes');
    });
});
