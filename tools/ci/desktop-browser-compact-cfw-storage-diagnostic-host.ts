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

export const runDesktopBrowserCompactCfwStorageDiagnostic = async (input: {
    browserEngine: 'chromium';
    wasmUrl: string;
}): Promise<unknown> => {
    const worker = new Worker(
        new URL(
            './desktop-browser-compact-cfw-storage-diagnostic-worker.ts',
            import.meta.url,
        ),
        {
            name: 'sealed-lattice-compact-cfw-storage-diagnostic',
            type: 'module',
        },
    );
    try {
        return await new Promise<unknown>((resolve, reject) => {
            worker.addEventListener(
                'message',
                (event: MessageEvent<DiagnosticWorkerResponse>) => {
                    const response = event.data;
                    if (response.responseKind === 'completed') {
                        resolve(response.evidence);
                        return;
                    }
                    const error = new Error(response.errorMessage);
                    error.name = response.errorName;
                    if (response.errorStack !== undefined) {
                        error.stack = response.errorStack;
                    }
                    reject(error);
                },
                { once: true },
            );
            worker.addEventListener(
                'error',
                (event) => {
                    reject(
                        new Error(
                            `Compact CFW diagnostic worker failed to load: ${event.message}`,
                        ),
                    );
                },
                { once: true },
            );
            worker.postMessage(input);
        });
    } finally {
        worker.terminate();
    }
};
