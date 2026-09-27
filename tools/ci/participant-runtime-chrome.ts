import { spawn } from 'node:child_process';
import { access, mkdir, realpath } from 'node:fs/promises';
import path from 'node:path';

import { killProcessTree } from '#tools/ci/run-command.js';

// Drives an installed release Chrome over its DevTools socket with Runtime
// and Page control, and records CPU samples only when a trace is requested.
// Network inspection would retain payloads and change the storage workload,
// so it is never enabled. Each participant has its own disk-backed profile
// under the task workspace.
type DevToolsMessage = {
    id?: number;
    method?: string;
    sessionId?: string;
    params?: Record<string, unknown>;
    result?: Record<string, unknown>;
    error?: unknown;
};

export type ChromeParticipant = Readonly<{
    processIdentifier: number;
    version: string;
    launchArguments: readonly string[];
    evaluate(expression: string): Promise<unknown>;
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

export const launchChromeParticipant = async (
    profileDirectory: string,
    origin: string,
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
            resolve: (value: Record<string, unknown>) => void;
            reject: (error: Error) => void;
        }
    >();
    let sequence = 0;
    let onLoad: (() => void) | undefined;
    let pageSession = '';
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
            const id = ++sequence;
            pending.set(id, { resolve, reject });
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
            else if (message.method === 'Tracing.dataCollected')
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
