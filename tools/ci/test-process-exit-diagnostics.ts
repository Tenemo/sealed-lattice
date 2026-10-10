import type { EventEmitter } from 'node:events';
import { writeSync } from 'node:fs';

import { redactDiagnosticText } from '#tools/ci/run-log-diagnostics.js';

// Reports why a node test process ends on its own. The test runner stops each
// test process from outside once its file finishes, and the process ends
// without a message when its channel to the runner fails, so the runner can
// otherwise report only that the process exited unexpectedly. Its standard
// error reaches the run's output even after the process has ended.
const registered = Symbol.for('sealed-lattice.test-process-exit-diagnostics');
const registry = globalThis as { [registered]?: true };
const report = (text: string) => {
    writeSync(
        2,
        `[test process ${String(process.pid)}] ${redactDiagnosticText(text)}\n`,
    );
};
// The process's typed events omit the channel's failure.
const processEvents: EventEmitter = process;
if (registry[registered] === undefined) {
    registry[registered] = true;
    processEvents.prependListener('error', (error: NodeJS.ErrnoException) => {
        report(
            `Its channel to the test runner failed with ${error.code ?? error.name}: ${error.message}`,
        );
    });
    process.on('disconnect', () => {
        report('Its channel to the test runner closed.');
    });
    process.on('exit', (code) => {
        if (code !== 0)
            report(
                `It is exiting with code ${String(code)}.\n${new Error('Exit').stack ?? ''}`,
            );
    });
}
