import type { ProductionDesktopBrowserCommonProofMeasurementCase } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';

// Register only complete production family adapters here. The manual lane
// fails closed while this list is empty instead of measuring fixture proofs.
export const productionCommonProofMeasurementCases = Object.freeze(
    [] satisfies readonly ProductionDesktopBrowserCommonProofMeasurementCase[],
);
