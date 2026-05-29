import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import { emitBrowserBenchmarkLogLine } from '#tests/support/emit-browser-benchmark-log';
import { runMandatoryProfileProofRecordBenchmark } from '#tests/support/mandatory-profile-proof-record-benchmark';

const proofBenchmarkTimeoutMs = 60 * 60_000;

describe('transcript-core kernel in browsers', () => {
    it(
        'generates a mandatory-profile ballot proof record with packed field components through WASM',
        async () => {
            const kernel = await loadTranscriptCoreKernel();
            const { steps } = runMandatoryProfileProofRecordBenchmark({
                kernel,
            });
            expect(steps.length).toBeGreaterThan(0);
            await emitBrowserBenchmarkLogLine(
                JSON.stringify({
                    event: 'mandatory-proof-record-test-steps',
                    steps,
                }),
            );
        },
        proofBenchmarkTimeoutMs,
    );
});
