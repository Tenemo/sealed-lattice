import type { ProductionDesktopBrowserEvaluatorReplayMeasurementCase } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement';

// Register only an end-to-end production case whose accepted setup, aggregate,
// authenticated store, and board object all come from positive live verification.
// The manual lane fails closed while no such case is available.
export const productionEvaluatorReplayMeasurementCases = Object.freeze(
    [] satisfies readonly ProductionDesktopBrowserEvaluatorReplayMeasurementCase[],
);
