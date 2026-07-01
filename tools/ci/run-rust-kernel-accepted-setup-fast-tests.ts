import { runRustKernelAcceptedSetupTests } from './run-rust-kernel-accepted-setup-tests.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

if (isDirectlyInvokedModule(import.meta.url)) {
    void runRustKernelAcceptedSetupTests({
        lane: 'fast',
        scriptName: 'test:rust:kernel:accepted-setup:fast',
    });
}
