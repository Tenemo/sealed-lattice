import { parentPort, workerData } from 'node:worker_threads';

globalThis.self = globalThis;
self.postMessage = (message) => parentPort.postMessage(message);
// A browser worker's close() ends it once its current task returns. Closing
// the helper's port leaves this thread nothing to wait for, so it ends the
// same way. Stopping it with process.exit() instead intermittently crashed
// the whole process when several helpers stopped together.
self.close = () => {
    workerData.port.close();
};
await import(workerData.source);
self.onmessage({ data: 'helper', ports: [workerData.port] });
