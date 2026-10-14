import { MessageChannel, Worker } from 'node:worker_threads';

import { afterEach, beforeEach, vi } from 'vitest';

import { distribution } from '#packages/sdk/tests/node/participant-module/packaged-participant-fixture.js';

export const useHelperWorkers = () => {
    const threads: Worker[] = [];
    const silentPorts: { close: () => void }[] = [];
    const helperPorts = (count: number) =>
        Array.from({ length: count }, () => {
            const channel = new MessageChannel();
            threads.push(
                new Worker(
                    new URL(
                        './fixtures/participant-helper.mjs',
                        import.meta.url,
                    ),
                    {
                        workerData: {
                            source: new URL(
                                'participant-worker.js',
                                distribution,
                            ).href,
                            port: channel.port2,
                        },
                        transferList: [channel.port2],
                    },
                ),
            );
            return channel.port1 as unknown as MessagePort;
        });
    const observedHelperPorts = (count: number) => {
        const starts: ObservedStart[] = [];
        const ports = helperPorts(count).map((port) => {
            const post = port.postMessage.bind(port);
            port.postMessage = (message: unknown) => {
                starts.push(message as ObservedStart);
                post(message);
            };
            return port;
        });
        return {
            ports,
            start: () => {
                const [{ control, arena, layout }] = starts;
                return {
                    control: new Int32Array(control),
                    arena: new Uint8Array(arena),
                    layout,
                };
            },
        };
    };
    beforeEach(() => {
        vi.stubGlobal('crossOriginIsolated', true);
    });
    afterEach(async () => {
        vi.useRealTimers();
        vi.unstubAllGlobals();
        for (const port of silentPorts.splice(0)) port.close();
        await Promise.all(
            threads.splice(0).map((thread) => thread.terminate()),
        );
    });
    return {
        ports: helperPorts,
        observedPorts: observedHelperPorts,
        retainPort: (port: { close: () => void }) => {
            silentPorts.push(port);
        },
    };
};

// Helper ports whose start messages the test reads, so that it sees the
// shared control words and arena the worker hands its helpers.
type ObservedStart = Readonly<{
    control: SharedArrayBuffer;
    arena: SharedArrayBuffer;
    layout: Readonly<{ copiedWord: number }>;
}>;
