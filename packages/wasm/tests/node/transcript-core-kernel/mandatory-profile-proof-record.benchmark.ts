// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import { runMandatoryProfileProofRecordBenchmark } from '#tests/support/mandatory-profile-proof-record-benchmark';
import {
    createJsonCheckpointStore,
    shouldResumeFromTestCheckpoints,
} from '#tests/support/node-test-checkpoints';

describe('transcript-core kernel in Node', () => {
    it('generates a mandatory-profile ballot proof record with packed field components through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const { steps } = runMandatoryProfileProofRecordBenchmark({
            checkpoints: createJsonCheckpointStore(),
            kernel,
            resumeFromCheckpoints: shouldResumeFromTestCheckpoints(),
        });
        expect(steps.length).toBeGreaterThan(0);
        console.info(
            JSON.stringify({
                event: 'mandatory-proof-record-test-steps',
                steps,
            }),
        );
    }, 900_000);
});
