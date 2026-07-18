import { productionEvaluatorReplayMeasurementCases } from './production-evaluator-replay-measurement-cases.js';

import { measureProductionDesktopBrowserEvaluatorReplayCase } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement';
import {
    installDesktopBrowserEvaluatorReplayMeasurementWorkerProtocol,
    type DesktopBrowserEvaluatorReplayMeasurementWorkerScope,
} from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-worker-protocol';

const workerScope =
    globalThis as unknown as DesktopBrowserEvaluatorReplayMeasurementWorkerScope;

installDesktopBrowserEvaluatorReplayMeasurementWorkerProtocol({
    measureCase: (caseIdentifier) =>
        measureProductionDesktopBrowserEvaluatorReplayCase(
            productionEvaluatorReplayMeasurementCases,
            caseIdentifier,
        ),
    workerScope,
});
