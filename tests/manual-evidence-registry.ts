export type ManualEvidenceCase = Readonly<{
    browserEnvironmentVariable: string;
    identifier: string;
    memoryLimitByteLength: number;
    runnerKind: 'external-chrome' | 'vitest-browser';
    testFile: string;
    testName: string;
}>;

export const manualEvidenceCases: readonly ManualEvidenceCase[] = [
    {
        browserEnvironmentVariable:
            'VITE_SEALED_LATTICE_PADDED_TALLY_TOP_COUNT_1',
        identifier: 'padded-tally-top-count-1',
        memoryLimitByteLength: 6 * 1_024 * 1_024 * 1_024,
        runnerKind: 'vitest-browser',
        testFile:
            'packages/wasm/tests/browser/private-preparation-worker.browser.test.ts',
        testName: 'executes the complete padded tally ceremony at topCount 1',
    },
    {
        browserEnvironmentVariable:
            'VITE_SEALED_LATTICE_PADDED_TALLY_TOP_COUNT_10',
        identifier: 'padded-tally-top-count-10',
        memoryLimitByteLength: 6 * 1_024 * 1_024 * 1_024,
        runnerKind: 'vitest-browser',
        testFile:
            'packages/wasm/tests/browser/private-preparation-worker.browser.test.ts',
        testName: 'executes the complete padded tally ceremony at topCount 10',
    },
    {
        browserEnvironmentVariable:
            'VITE_SEALED_LATTICE_PADDED_TALLY_EMPTY_USABLE_BALLOTS',
        identifier: 'padded-tally-empty-usable-ballots',
        memoryLimitByteLength: 6 * 1_024 * 1_024 * 1_024,
        runnerKind: 'vitest-browser',
        testFile:
            'packages/wasm/tests/browser/private-preparation-worker.browser.test.ts',
        testName:
            'executes the complete padded tally empty-usable-ballot terminal',
    },
    {
        browserEnvironmentVariable:
            'SEALED_LATTICE_EXTERNAL_CHROME_RESOURCE_SCREEN',
        identifier: 'external-chrome-resource-screen',
        memoryLimitByteLength: 6 * 1_024 * 1_024 * 1_024,
        runnerKind: 'external-chrome',
        testFile: 'tools/ci/external-chrome-resource-screen.html',
        testName:
            'screens full-width storage and scalar KMAC work in external Chrome',
    },
    {
        browserEnvironmentVariable:
            'SEALED_LATTICE_EXTERNAL_CHROME_COMPLETE_CEREMONY',
        identifier: 'external-chrome-complete-ceremony',
        memoryLimitByteLength: 6 * 1_024 * 1_024 * 1_024,
        runnerKind: 'external-chrome',
        testFile: 'tools/ci/external-chrome-ceremony.html',
        testName:
            'runs the exact candidate ceremony sequentially in external Chrome',
    },
];

export const resolveManualEvidenceCase = (
    identifier: string,
): ManualEvidenceCase => {
    const evidenceCase = manualEvidenceCases.find(
        (candidate) => candidate.identifier === identifier,
    );
    if (evidenceCase === undefined) {
        throw new Error(`Unknown manual evidence case: ${identifier}.`);
    }
    return evidenceCase;
};
