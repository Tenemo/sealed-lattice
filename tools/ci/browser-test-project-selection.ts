import type { DesktopBrowserProofEvidenceOwnershipRole } from '#tests/support/desktop-browser-proof-evidence-catalog';

export type { DesktopBrowserProofEvidenceOwnershipRole } from '#tests/support/desktop-browser-proof-evidence-catalog';

export const manualDesktopBrowserProofEvidenceTestGlobs = [
    'packages/wasm/tests/browser/selected-proof-runtime-evidence.manual.browser.test.ts',
] as const;

export const ordinaryDesktopBrowserExcludedTestGlobs = [
    ...manualDesktopBrowserProofEvidenceTestGlobs,
] as const;

export type DesktopBrowserProofEvidenceSessionDefinition = Readonly<{
    browserEngine: 'chromium' | 'firefox' | 'webkit';
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
        browserEngine: 'firefox',
        ownershipRole: 'generation',
        sessionIdentifier: 'firefox-generation',
        testProjectLabel: 'desktop-browser-proof-evidence-firefox-generation',
        vitestProjectName: 'firefox-desktop-proof-evidence-generation',
    },
    {
        browserEngine: 'chromium',
        ownershipRole: 'verification',
        sessionIdentifier: 'chromium-verification',
        testProjectLabel:
            'desktop-browser-proof-evidence-chromium-verification',
        vitestProjectName: 'chromium-desktop-proof-evidence-verification',
    },
    {
        browserEngine: 'firefox',
        ownershipRole: 'verification',
        sessionIdentifier: 'firefox-verification',
        testProjectLabel: 'desktop-browser-proof-evidence-firefox-verification',
        vitestProjectName: 'firefox-desktop-proof-evidence-verification',
    },
    {
        browserEngine: 'webkit',
        ownershipRole: 'verification',
        sessionIdentifier: 'webkit-verification',
        testProjectLabel: 'desktop-browser-proof-evidence-webkit-verification',
        vitestProjectName: 'webkit-desktop-proof-evidence-verification',
    },
] satisfies readonly DesktopBrowserProofEvidenceSessionDefinition[]);
