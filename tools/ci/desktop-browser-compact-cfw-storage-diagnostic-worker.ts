/// <reference lib="webworker" />

import { runDesktopBrowserCompactCfwStorageDiagnostic } from './desktop-browser-compact-cfw-storage-diagnostic-page.js';

type DiagnosticWorkerRequest = Readonly<{
    browserEngine: 'chromium';
    wasmUrl: string;
}>;

type DiagnosticWorkerResponse =
    | Readonly<{
          evidence: unknown;
          responseKind: 'completed';
      }>
    | Readonly<{
          errorMessage: string;
          errorName: string;
          errorStack?: string;
          responseKind: 'failed';
      }>;

const workerScope = self as unknown as DedicatedWorkerGlobalScope;
let requestAccepted = false;

workerScope.addEventListener('message', (event: MessageEvent<unknown>) => {
    if (requestAccepted) {
        workerScope.postMessage({
            errorMessage:
                'Compact CFW diagnostic worker accepts exactly one request.',
            errorName: 'InvalidState',
            responseKind: 'failed',
        } satisfies DiagnosticWorkerResponse);
        return;
    }
    requestAccepted = true;
    void (async () => {
        const request = event.data as Partial<DiagnosticWorkerRequest>;
        if (
            typeof request !== 'object' ||
            request === null ||
            request.browserEngine !== 'chromium' ||
            typeof request.wasmUrl !== 'string' ||
            request.wasmUrl.length === 0
        ) {
            throw new Error(
                'Compact CFW diagnostic worker received a malformed request.',
            );
        }
        return runDesktopBrowserCompactCfwStorageDiagnostic({
            browserEngine: request.browserEngine,
            wasmUrl: request.wasmUrl,
        });
    })()
        .then((evidence) => {
            workerScope.postMessage({
                evidence,
                responseKind: 'completed',
            } satisfies DiagnosticWorkerResponse);
        })
        .catch((error: unknown) => {
            const normalizedError =
                error instanceof Error ? error : new Error(String(error));
            workerScope.postMessage({
                errorMessage: normalizedError.message,
                errorName: normalizedError.name,
                ...(normalizedError.stack === undefined
                    ? {}
                    : { errorStack: normalizedError.stack }),
                responseKind: 'failed',
            } satisfies DiagnosticWorkerResponse);
        });
});
