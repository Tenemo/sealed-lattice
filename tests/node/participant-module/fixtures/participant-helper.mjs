import { parentPort, workerData } from 'node:worker_threads';

globalThis.self = globalThis;
self.postMessage = (message) => parentPort.postMessage(message);
self.close = () => process.exit(0);
await import(workerData.source);
self.onmessage({ data: 'helper', ports: [workerData.port] });
