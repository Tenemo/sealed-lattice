import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { createNativeOperationGuard } from '#tools/ci/native-operation-guard.js';
import {
    guardProcessTreeMemory,
    readProtocolProcessTree,
} from '#tools/ci/protocol-process-memory.js';
import { runCommandsInSeries } from '#tools/ci/run-command.js';

export const runGuardedFixture = async ({
    root,
    log,
    environment,
    processMemoryLimit,
    command,
    args,
    name,
    handshake,
    parseResult,
    nativeProgressLines,
}: Readonly<{
    root: string;
    log: ActiveLocalRunLog;
    environment: NodeJS.ProcessEnv;
    processMemoryLimit: number;
    command: string;
    args: string[];
    name: string;
    handshake?: boolean;
    parseResult?: (output: string) => Record<string, unknown>;
    nativeProgressLines?: readonly string[];
}>) => {
    assert.ok(freemem() >= 2 * processMemoryLimit);
    const gateDirectory = handshake
        ? await mkdtemp(path.join(root, 'temp/native-fixture-guard-'))
        : undefined;
    const gateFiles =
        gateDirectory === undefined
            ? undefined
            : {
                  startFile: path.join(gateDirectory, 'start'),
                  finishFile: path.join(gateDirectory, 'finish'),
              };
    const controller = new AbortController();
    let peakMemory = 0,
        samples = 0,
        output = '';
    let monitor: Promise<void> | undefined;
    let memoryGuard: { stop: () => Promise<void> } | undefined;
    let nativeGuard: ReturnType<typeof createNativeOperationGuard> | undefined;
    let guardResult:
        | Awaited<
              ReturnType<
                  ReturnType<typeof createNativeOperationGuard>['monitor']
              >
          >
        | undefined;
    const recordSample = (
        phase: 'initial' | 'periodic' | 'final',
        bytes: number,
    ) => {
        samples++;
        peakMemory = Math.max(peakMemory, bytes);
        log.writeEvent({
            eventType: 'bounded-fixture-process-memory',
            details: {
                name,
                phase,
                bytes,
                limit: processMemoryLimit,
            },
        });
    };
    const started = performance.now();
    const exitCode = await runCommandsInSeries(
        [
            {
                command,
                args:
                    gateFiles === undefined
                        ? args
                        : [
                              ...args,
                              '--guard-start',
                              gateFiles.startFile,
                              '--guard-finish',
                              gateFiles.finishFile,
                          ],
                env: environment,
                workingDirectoryPath: root,
                description: name,
                logFileSlug: name,
            },
        ],
        {
            runLog: log,
            outputMode: 'inherit',
            signal: AbortSignal.any([
                controller.signal,
                AbortSignal.timeout(600_000),
            ]),
            observer: {
                onCommandOutput({ chunk, streamName }) {
                    if (streamName === 'stdout') {
                        output += chunk;
                        try {
                            nativeGuard?.observeStdout(chunk);
                        } catch (error) {
                            controller.abort(error);
                        }
                        if (output.length > 1_048_576)
                            controller.abort(
                                new Error(
                                    'Fixture diagnostics exceed their bound.',
                                ),
                            );
                    }
                },
                onCommandStart({ processIdentifier }) {
                    assert.ok(processIdentifier);
                    if (gateFiles !== undefined) {
                        nativeGuard = createNativeOperationGuard({
                            allowedProgressLines: nativeProgressLines,
                            ...gateFiles,
                            memoryLimit: processMemoryLimit,
                            readMemory: () =>
                                readProtocolProcessTree(processIdentifier),
                            recordSample,
                        });
                        monitor = nativeGuard
                            .monitor()
                            .then((result) => {
                                guardResult = result;
                            })
                            .catch((error: unknown) => controller.abort(error));
                        return;
                    }
                    memoryGuard = guardProcessTreeMemory({
                        processIdentifier,
                        memoryLimit: processMemoryLimit,
                        exceededMessage:
                            'Fixture process-tree memory guard exceeded.',
                        onSample: (bytes) => {
                            recordSample('periodic', bytes);
                        },
                        abort: (reason) => {
                            controller.abort(reason);
                        },
                    });
                },
                onCommandExit() {
                    void memoryGuard?.stop();
                    nativeGuard?.stop();
                },
            },
        },
    ).finally(async () => {
        await memoryGuard?.stop();
        await monitor;
        if (gateDirectory !== undefined) {
            const resolved = path.resolve(gateDirectory);
            assert.ok(
                resolved.startsWith(path.resolve(root, 'temp') + path.sep),
            );
            await rm(resolved, { recursive: true });
        }
    });
    assert.equal(
        controller.signal.aborted,
        false,
        String(controller.signal.reason),
    );
    assert.equal(exitCode, 0);
    assert.ok(samples > 0);
    if (handshake) {
        assert.ok(guardResult !== undefined);
        assert.equal(guardResult.samples.initial, 1);
        assert.equal(guardResult.samples.final, 1);
    }
    const reports = parseResult
        ? [parseResult(output)]
        : output
              .trim()
              .split(/\r?\n/u)
              .map((line) => JSON.parse(line) as Record<string, unknown>)
              .filter((record) => typeof record.kind === 'string');
    assert.equal(
        reports.length,
        1,
        'The fixture emitted an ambiguous final report.',
    );
    return {
        result: reports[0],
        peakMemory,
        samples,
        milliseconds: performance.now() - started,
        ...(guardResult === undefined
            ? {}
            : {
                  operationMilliseconds: guardResult.operationMilliseconds,
                  samplesByPhase: guardResult.samples,
                  samplingScope:
                      'Initial sample before work is released, periodic samples while it runs, and a fresh final sample after completion before process exit. Wall time includes coordination; the native operation duration excludes it. Sampled peaks do not bound transient peaks between observations.',
              }),
    };
};
