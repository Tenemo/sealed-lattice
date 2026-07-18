import { afterEach, describe, expect, it } from 'vitest';

import { requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-case-identifier';
import {
    runDesktopBrowserEvaluatorReplayMeasurementWorker,
    terminateDesktopBrowserEvaluatorReplayMeasurementWorkers,
} from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-worker-protocol';
import { formatProductionDesktopBrowserMeasurementResult } from '#packages/protocol/tests/support/production-desktop-browser-measurement-result';

const environment = (
    import.meta as ImportMeta & {
        readonly env: Readonly<Record<string, string | undefined>>;
    }
).env;

afterEach(() => {
    terminateDesktopBrowserEvaluatorReplayMeasurementWorkers();
});

describe('Production evaluator-replay desktop-browser measurements', () => {
    it('measures the selected production case in a dedicated module worker', async () => {
        const caseIdentifier =
            requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
                environment.VITE_SEALED_LATTICE_DESKTOP_BROWSER_EVALUATOR_REPLAY_MEASUREMENT_CASE_IDENTIFIER,
            );
        const worker = new Worker(
            new URL(
                './production-evaluator-replay.browser.measurement.worker.ts',
                import.meta.url,
            ),
            { type: 'module' },
        );
        const measurement =
            await runDesktopBrowserEvaluatorReplayMeasurementWorker({
                caseIdentifier,
                worker,
            });

        console.info(
            formatProductionDesktopBrowserMeasurementResult(measurement),
        );
        expect(measurement.caseIdentifier).toBe(caseIdentifier);
    });
});
