import type { DesktopBrowserProofEvidenceOwnershipRole } from '#tests/support/desktop-browser-proof-evidence-catalog';

export type { DesktopBrowserProofEvidenceOwnershipRole } from '#tests/support/desktop-browser-proof-evidence-catalog';

export const manualDesktopBrowserProofEvidenceTestGlobs = [
    'packages/wasm/tests/browser/selected-proof-runtime-evidence.manual.browser.test.ts',
] as const;

export const ordinaryDesktopBrowserExcludedTestGlobs = [
    ...manualDesktopBrowserProofEvidenceTestGlobs,
] as const;

export type DesktopBrowserProofEvidenceSessionDefinition = Readonly<{
    browserEngine: 'chromium';
    ownershipRole: DesktopBrowserProofEvidenceOwnershipRole;
    sessionIdentifier: string;
    testProjectLabel: string;
    vitestProjectName: string;
}>;

export const desktopBrowserProofEvidenceSessionDefinitions = Object.freeze([
    {
        browserEngine: 'chromium',
        ownershipRole: 'generation',
        sessionIdentifier: 'chromium-generation',
        testProjectLabel: 'desktop-browser-proof-evidence-chromium-generation',
        vitestProjectName: 'chromium-desktop-proof-evidence-generation',
    },
    {
        browserEngine: 'chromium',
        ownershipRole: 'verification',
        sessionIdentifier: 'chromium-verification',
        testProjectLabel:
            'desktop-browser-proof-evidence-chromium-verification',
        vitestProjectName: 'chromium-desktop-proof-evidence-verification',
    },
] satisfies readonly DesktopBrowserProofEvidenceSessionDefinition[]);
