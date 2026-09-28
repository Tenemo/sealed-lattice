import { spawn } from 'node:child_process';
import { access, mkdir, realpath } from 'node:fs/promises';
import path from 'node:path';

import { killProcessTree } from '#tools/ci/run-command.js';

// Drives an installed release Chrome over its DevTools socket with Runtime
// and Page control, and records CPU samples only when a trace is requested.
// It attaches to the page's workers without enabling any of their domains,
// so that it can read their JavaScript heaps. Network inspection would
// retain payloads and change the storage workload, so it is never enabled.
// Each participant has its own disk-backed profile under the task workspace.
type DevToolsMessage = {
    id?: number;
    method?: string;
    sessionId?: string;
    params?: Record<string, unknown>;
    result?: Record<string, unknown>;
    error?: unknown;
};

// The JavaScript heaps that a page and its workers last reported, together:
// the bytes their objects use and hold, and the bytes of their array
// buffers' and external strings' storage; with the attached sessions, the
// page's and its workers', and how many of them have reported.
type JavaScriptHeaps = Readonly<{
    usedBytes: number;
    totalBytes: number;
    backingBytes: number;
    sessions: number;
    reported: number;
}>;

// The bytes the page's origin last reported storing, all together and in
// its IndexedDB databases, whether it has reported, and why the last request
// failed, if it did.
type OriginStorage = Readonly<{
    usageBytes: number;
    indexedDatabaseBytes: number;
    reported: boolean;
    failure?: string;
}>;

export type ChromeParticipant = Readonly<{
    processIdentifier: number;
    version: string;
    launchArguments: readonly string[];
    evaluate(expression: string): Promise<unknown>;
    // The JavaScript heaps that the page and its current workers last
    // reported; each that has no request outstanding is asked again. A
    // worker answers only between tasks, so one whose code runs without
    // returning to its event loop keeps its last report meanwhile, and one
    // that has not answered yet counts for nothing.
    heaps(): JavaScriptHeaps;
    // The storage the page's origin last reported; the browser is asked
    // again when no request is outstanding.
    storage(): OriginStorage;
    // Runs the action while the browser records the V8 CPU samples of its
    // page and worker threads, and returns the recorded trace events.
    trace<Result>(
        action: () => Promise<Result>,
    ): Promise<Readonly<{ result: Result; events: readonly unknown[] }>>;
    close(): Promise<void>;
    // Ends the browser's process tree at once, as a crash would, without
    // the shutdown work a close lets it finish.
    crash(): Promise<void>;
}>;

const chromeExecutable = () =>
    process.platform === 'win32'
        ? path.join(
              process.env.ProgramFiles ?? 'C:/Program Files',
              'Google/Chrome/Application/chrome.exe',
          )
        : process.platform === 'darwin'
          ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
          : '/usr/bin/google-chrome';

// Launches Chrome for a participant's page, passing V8 the flags when given.
export const launchChromeParticipant = async (
    profileDirectory: string,
    origin: string,
    javaScriptFlags?: string,
): Promise<ChromeParticipant> => {
    const executable = chromeExecutable();
    await access(executable);
    await mkdir(profileDirectory, { recursive: true });
    const profile = await realpath(profileDirectory);
    const workspace = await realpath(path.resolve('temp'));
    if (!profile.startsWith(workspace + path.sep))
        throw new Error('The Chrome profile escapes the task workspace.');
    const launchArguments = [
        '--headless=new',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-extensions',
        '--remote-debugging-port=0',
        '--user-data-dir=' + profile,
        ...(javaScriptFlags === undefined
            ? []
            : ['--js-flags=' + javaScriptFlags]),
        'about:blank',
    ];
    const child = spawn(executable, launchArguments, {
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'pipe'],
    });
    let socket: WebSocket | undefined;
    const pending = new Map<
        number,
        {
            sessionId: string | undefined;
            resolve: (value: Record<string, unknown>) => void;
            reject: (error: Error) => void;
        }
    >();
    let sequence = 0;
    let onLoad: (() => void) | undefined;
    let pageSession = '';
    // The sessions of the page's workers that are still attached.
    const workerSessions = new Set<string>();
    // Each attached session's last reported heap usage, and the sessions
    // whose request for it is outstanding.
    const heapUsages = new Map<string, Record<string, unknown>>();
    const heapRequests = new Set<string>();
    // The origin's last reported storage usage, whether a request for it is
    // outstanding, and why the last request failed.
    let storageUsage: Record<string, unknown> | undefined;
    let storageRequested = false;
    let storageFailure: string | undefined;
    // A crashed page answers none of its requests, so each fails at once.
    let pageCrashed = false;
    // The trace being recorded: its events so far, and what ends it.
    let tracing: { events: unknown[]; complete: () => void } | undefined;
    const send = (
        method: string,
        params: Record<string, unknown> = {},
        sessionId?: string,
    ) =>
        new Promise<Record<string, unknown>>((resolve, reject) => {
            if (socket === undefined) {
                reject(new Error('Chrome is not connected.'));
                return;
            }
            if (pageCrashed && sessionId === pageSession) {
                reject(new Error('The participant page crashed.'));
                return;
            }
            const id = ++sequence;
            pending.set(id, { sessionId, resolve, reject });
            socket.send(
                JSON.stringify({
                    id,
                    method,
                    params,
                    ...(sessionId === undefined ? {} : { sessionId }),
                }),
            );
        });
    const exited = () => child.exitCode !== null || child.signalCode !== null;
    const exit = (onDeadline: () => void, message: string) =>
        new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => {
                onDeadline();
                reject(new Error(message));
            }, 10_000);
            child.once('exit', () => {
                clearTimeout(timer);
                resolve();
            });
        });
    const close = async () => {
        await Promise.race([
            send('Browser.close').catch(() => undefined),
            new Promise((resolve) => setTimeout(resolve, 2000)),
        ]);
        socket?.close();
        if (exited()) return;
        await exit(
            () => child.kill(),
            'Chrome did not close within its deadline.',
        );
    };
    // Taskkill also reports a failure when a process of the tree ends by
    // itself while it runs, so the browser process's exit decides whether
    // the crash happened.
    const crash = async () => {
        socket?.close();
        if (exited()) return;
        const termination = killProcessTree(child, { signal: 'SIGKILL' });
        await exit(
            () => undefined,
            'Chrome did not exit after its termination: ' +
                JSON.stringify(termination),
        );
    };
    try {
        const endpoint = await new Promise<string>((resolve, reject) => {
            let output = '';
            const timer = setTimeout(
                () => reject(new Error('Chrome startup deadline.')),
                30_000,
            );
            child.once('error', (error) => {
                clearTimeout(timer);
                reject(error);
            });
            child.stderr.on('data', (bytes: Buffer) => {
                output += bytes.toString();
                const match = /DevTools listening on (ws:\/\/\S+)/u.exec(
                    output,
                );
                if (match) {
                    clearTimeout(timer);
                    resolve(match[1]);
                }
            });
        });
        const connected = new WebSocket(endpoint);
        socket = connected;
        await new Promise<void>((resolve, reject) => {
            connected.onopen = () => resolve();
            connected.onerror = () =>
                reject(new Error('The Chrome connection failed.'));
        });
        connected.onmessage = ({ data }) => {
            const message = JSON.parse(String(data)) as DevToolsMessage;
            if (message.id !== undefined) {
                const request = pending.get(message.id);
                pending.delete(message.id);
                if (message.error !== undefined)
                    request?.reject(new Error(JSON.stringify(message.error)));
                else request?.resolve(message.result ?? {});
            } else if (
                message.method === 'Page.loadEventFired' &&
                message.sessionId === pageSession
            )
                onLoad?.();
            else if (
                message.method === 'Inspector.targetCrashed' &&
                message.sessionId === pageSession
            ) {
                pageCrashed = true;
                for (const [id, request] of pending)
                    if (request.sessionId === pageSession) {
                        pending.delete(id);
                        request.reject(
                            new Error('The participant page crashed.'),
                        );
                    }
            } else if (
                message.method === 'Target.attachedToTarget' &&
                message.sessionId === pageSession
            ) {
                const { sessionId, targetInfo } = message.params as {
                    sessionId: string;
                    targetInfo: { type: string };
                };
                if (targetInfo.type === 'worker') workerSessions.add(sessionId);
            } else if (message.method === 'Target.detachedFromTarget') {
                // A detached worker answers none of its requests.
                const detached = String(
                    (message.params as { sessionId?: string } | undefined)
                        ?.sessionId,
                );
                workerSessions.delete(detached);
                heapUsages.delete(detached);
                for (const [id, request] of pending)
                    if (request.sessionId === detached) {
                        pending.delete(id);
                        request.reject(new Error('The worker detached.'));
                    }
            } else if (message.method === 'Tracing.dataCollected')
                tracing?.events.push(
                    ...((message.params?.value as unknown[] | undefined) ?? []),
                );
            else if (message.method === 'Tracing.tracingComplete')
                tracing?.complete();
        };
        connected.onclose = () => {
            for (const request of pending.values())
                request.reject(new Error('The Chrome connection closed.'));
            pending.clear();
        };
        const target = await send('Target.createTarget', {
            url: 'about:blank',
        });
        pageSession = String(
            (
                await send('Target.attachToTarget', {
                    targetId: target.targetId,
                    flatten: true,
                })
            ).sessionId,
        );
        await send('Page.enable', {}, pageSession);
        await send('Runtime.enable', {}, pageSession);
        await send(
            'Target.setAutoAttach',
            { autoAttach: true, waitForDebuggerOnStart: false, flatten: true },
            pageSession,
        );
        let timer: ReturnType<typeof setTimeout> | undefined;
        const loaded = new Promise<void>((resolve, reject) => {
            onLoad = resolve;
            timer = setTimeout(
                () => reject(new Error('Chrome navigation deadline.')),
                30_000,
            );
        });
        try {
            await Promise.all([
                loaded,
                send('Page.navigate', { url: origin }, pageSession).then(
                    (value) => {
                        if (value.errorText !== undefined)
                            throw new Error('Chrome could not open the page.');
                    },
                ),
            ]);
        } finally {
            clearTimeout(timer);
            onLoad = undefined;
        }
        const version = String((await send('Browser.getVersion')).product);
        if (child.pid === undefined)
            throw new Error('Chrome has no process identifier.');
        return {
            processIdentifier: child.pid,
            version,
            launchArguments,
            close,
            crash,
            heaps: () => {
                const sessions = [pageSession, ...workerSessions];
                for (const session of sessions) {
                    if (heapRequests.has(session)) continue;
                    heapRequests.add(session);
                    void send('Runtime.getHeapUsage', {}, session)
                        .then(
                            (usage) => {
                                if (
                                    session === pageSession ||
                                    workerSessions.has(session)
                                )
                                    heapUsages.set(session, usage);
                            },
                            () => undefined,
                        )
                        .finally(() => heapRequests.delete(session));
                }
                const usages = [...heapUsages.values()];
                const sum = (field: string) =>
                    usages.reduce(
                        (total, usage) => total + Number(usage[field] ?? 0),
                        0,
                    );
                return {
                    usedBytes: sum('usedSize'),
                    totalBytes: sum('totalSize'),
                    backingBytes: sum('backingStorageSize'),
                    sessions: sessions.length,
                    reported: usages.length,
                };
            },
            storage: () => {
                if (!storageRequested) {
                    storageRequested = true;
                    // Only the page's session serves its origin's storage.
                    void send(
                        'Storage.getUsageAndQuota',
                        { origin },
                        pageSession,
                    )
                        .then(
                            (usage) => {
                                storageUsage = usage;
                                storageFailure = undefined;
                            },
                            (error: unknown) => {
                                storageFailure =
                                    error instanceof Error
                                        ? error.message
                                        : String(error);
                            },
                        )
                        .finally(() => {
                            storageRequested = false;
                        });
                }
                const breakdown =
                    (storageUsage?.usageBreakdown as
                        | readonly { storageType: string; usage: number }[]
                        | undefined) ?? [];
                return {
                    usageBytes: Number(storageUsage?.usage ?? 0),
                    indexedDatabaseBytes: breakdown
                        .filter((entry) => entry.storageType === 'indexeddb')
                        .reduce((total, entry) => total + entry.usage, 0),
                    reported: storageUsage !== undefined,
                    ...(storageFailure === undefined
                        ? {}
                        : { failure: storageFailure }),
                };
            },
            trace: async (action) => {
                if (tracing !== undefined)
                    throw new Error('Chrome is already recording a trace.');
                const events: unknown[] = [];
                const completed = new Promise<void>((resolve) => {
                    tracing = { events, complete: resolve };
                });
                try {
                    await send('Tracing.start', {
                        transferMode: 'ReportEvents',
                        traceConfig: {
                            recordMode: 'recordContinuously',
                            includedCategories: [
                                'disabled-by-default-v8.cpu_profiler',
                            ],
                            excludedCategories: ['*'],
                        },
                    });
                    let result: Awaited<ReturnType<typeof action>>;
                    try {
                        result = await action();
                    } finally {
                        await send('Tracing.end');
                        await completed;
                    }
                    return { result, events };
                } finally {
                    tracing = undefined;
                }
            },
            evaluate: async (expression) => {
                const result = await send(
                    'Runtime.evaluate',
                    { expression, awaitPromise: true, returnByValue: true },
                    pageSession,
                );
                const exception = result.exceptionDetails as
                    | { text?: string; exception?: { description?: string } }
                    | undefined;
                if (exception !== undefined)
                    throw new Error(
                        exception.exception?.description ??
                            exception.text ??
                            'The page evaluation failed.',
                    );
                return (result.result as { value?: unknown }).value;
            },
        };
    } catch (error) {
        await close().catch(() => undefined);
        throw error;
    }
};
