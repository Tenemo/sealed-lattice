import { afterEach, describe, expect, it } from 'vitest';

import { requireDesktopBrowserCommonProofMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-case-identifier';
import {
    runDesktopBrowserCommonProofMeasurementWorker,
    terminateDesktopBrowserCommonProofMeasurementWorkers,
} from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-worker-protocol';
import { formatProductionDesktopBrowserMeasurementResult } from '#packages/protocol/tests/support/production-desktop-browser-measurement-result';

const environment = (
    import.meta as ImportMeta & {
        readonly env: Readonly<Record<string, string | undefined>>;
    }
).env;

afterEach(() => {
    terminateDesktopBrowserCommonProofMeasurementWorkers();
});

describe('Production common-proof desktop-browser measurements', () => {
    it('measures the selected production case in a dedicated module worker', async () => {
        const caseIdentifier =
            requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
                environment.VITE_SEALED_LATTICE_DESKTOP_BROWSER_COMMON_PROOF_MEASUREMENT_CASE_IDENTIFIER,
            );
        const worker = new Worker(
            new URL(
                './production-common-proof.browser.measurement.worker.ts',
                import.meta.url,
            ),
            { type: 'module' },
        );
        const measurement = await runDesktopBrowserCommonProofMeasurementWorker(
            {
                caseIdentifier,
                worker,
            },
        );

        console.info(
            formatProductionDesktopBrowserMeasurementResult(measurement),
        );
        expect(measurement.caseIdentifier).toBe(caseIdentifier);
    });
});
