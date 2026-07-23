export const manualDesktopBrowserProofEvidenceTestGlobs = [
    'packages/wasm/tests/browser/selected-proof-runtime-evidence.manual.browser.test.ts',
] as const;

export const proofStorageWidthBrowserEvidenceTestGlobs = [
    'packages/wasm/tests/browser/proof-storage-width-evidence.manual.browser.test.ts',
] as const;

export const ordinaryDesktopBrowserExcludedTestGlobs = [
    ...manualDesktopBrowserProofEvidenceTestGlobs,
    ...proofStorageWidthBrowserEvidenceTestGlobs,
] as const;

export const proofStorageWidthBrowserEvidenceProjectName =
    'chromium-proof-storage-width-evidence';

export const proofStorageWidthBrowserEvidenceWorkspaceProjectName =
    'browser-proof-storage-width-evidence';

export const proofStorageWidthBrowserEvidenceInstanceDefinitions = [
    {
        browser: 'chromium',
        name: proofStorageWidthBrowserEvidenceProjectName,
    },
] as const;
