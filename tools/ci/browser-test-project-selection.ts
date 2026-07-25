export const manualDesktopBrowserProofEvidenceTestGlobs = [
    'packages/wasm/tests/browser/selected-proof-runtime-evidence.manual.browser.test.ts',
] as const;

export const ordinaryDesktopBrowserExcludedTestGlobs = [
    ...manualDesktopBrowserProofEvidenceTestGlobs,
] as const;
