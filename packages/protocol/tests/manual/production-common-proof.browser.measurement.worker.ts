import { productionCommonProofMeasurementCases } from './production-common-proof-measurement-cases.js';

import { measureProductionDesktopBrowserCommonProofCase } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';
import {
    installDesktopBrowserCommonProofMeasurementWorkerProtocol,
    type DesktopBrowserCommonProofMeasurementWorkerScope,
} from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-worker-protocol';

const workerScope =
    globalThis as unknown as DesktopBrowserCommonProofMeasurementWorkerScope;

installDesktopBrowserCommonProofMeasurementWorkerProtocol({
    measureCase: (caseIdentifier) =>
        measureProductionDesktopBrowserCommonProofCase(
            productionCommonProofMeasurementCases,
            caseIdentifier,
        ),
    workerScope,
});
