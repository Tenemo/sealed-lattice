import { afterEach, describe, expect, it } from 'vitest';

import {
    parseProofStorageWidthBrowserMeasurement,
    parseProofStorageWidthBrowserNativeBinding,
    proofStorageWidthBrowserEvidenceConsolePrefix,
    requireProofStorageWidthBrowserNativeMatch,
    serializeProofStorageWidthBrowserMeasurement,
    type ProofStorageWidthBrowserMeasurement,
} from '#tests/support/proof-storage-width-browser-evidence';

type WorkerResponse =
    | Readonly<{
          failureMessage: string;
          messageKind: 'failure';
      }>
    | Readonly<{
          measurement: unknown;
          messageKind: 'measurement';
      }>;

const expectedWasmHashEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_EXPECTED_WASM_SHA256_HEX';
const nativeBindingEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_NATIVE_BINDING';
const databaseNameEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_DATABASE_NAME';

const activeWorkers = new Set<Worker>();

const environment = (): Readonly<Record<string, string | undefined>> =>
    (
        import.meta as ImportMeta & {
            readonly env: Readonly<Record<string, string | undefined>>;
        }
    ).env;

const requiredEnvironmentValue = (fieldName: string): string => {
    const value = environment()[fieldName];
    if (value === undefined || value.length === 0) {
        throw new Error(
            `The strict browser width-evidence runner did not bind ${fieldName}.`,
        );
    }
    return value;
};

const parseWorkerResponse = (value: unknown): WorkerResponse => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(
            'The browser width-evidence worker returned a non-object response.',
        );
    }
    const record = value as Readonly<Record<string, unknown>>;
    if (
        record.messageKind === 'failure' &&
        typeof record.failureMessage === 'string' &&
        record.failureMessage.length > 0
    ) {
        return Object.freeze({
            failureMessage: record.failureMessage,
            messageKind: 'failure',
        });
    }
    if (record.messageKind === 'measurement') {
        return Object.freeze({
            measurement: record.measurement,
            messageKind: 'measurement',
        });
    }
    throw new TypeError(
        'The browser width-evidence worker returned a malformed response.',
    );
};

const runEvidenceWorker = (input: {
    readonly databaseName: string;
    readonly nativeBinding: unknown;
    readonly wasmSha256Hex: string;
}): Promise<ProofStorageWidthBrowserMeasurement> => {
    const worker = new Worker(
        new URL(
            '../support/proof-storage-width-browser-evidence-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    activeWorkers.add(worker);
    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (operation: () => void): void => {
            if (settled) {
                return;
            }
            settled = true;
            activeWorkers.delete(worker);
            worker.terminate();
            operation();
        };
        worker.addEventListener(
            'error',
            (event) =>
                finish(() =>
                    reject(
                        event.error instanceof Error
                            ? event.error
                            : new Error(
                                  'The browser width-evidence worker failed.',
                              ),
                    ),
                ),
            { once: true },
        );
        worker.addEventListener(
            'messageerror',
            () =>
                finish(() =>
                    reject(
                        new Error(
                            'The browser width-evidence worker returned an uncloneable response.',
                        ),
                    ),
                ),
            { once: true },
        );
        worker.addEventListener('message', (event) => {
            try {
                const response = parseWorkerResponse(event.data);
                if (response.messageKind === 'failure') {
                    finish(() => reject(new Error(response.failureMessage)));
                    return;
                }
                const measurement = parseProofStorageWidthBrowserMeasurement(
                    response.measurement,
                );
                finish(() => resolve(measurement));
            } catch (error) {
                finish(() =>
                    reject(
                        error instanceof Error
                            ? error
                            : Object.assign(
                                  new Error(
                                      'The browser width-evidence response could not be processed.',
                                  ),
                                  { cause: error },
                              ),
                    ),
                );
            }
        });
        worker.postMessage({
            command: 'run-proof-storage-width-browser-evidence',
            databaseName: input.databaseName,
            nativeBinding: input.nativeBinding,
            wasmSha256Hex: input.wasmSha256Hex,
        });
    });
};

afterEach(() => {
    for (const worker of activeWorkers) {
        worker.terminate();
    }
    activeWorkers.clear();
});

describe('Proof-storage width release WebAssembly evidence', () => {
    it('recomputes the fixed width-512 proof through bounded IndexedDB custody', async () => {
        const wasmSha256Hex = requiredEnvironmentValue(
            expectedWasmHashEnvironmentVariable,
        );
        if (!/^[0-9a-f]{64}$/u.test(wasmSha256Hex)) {
            throw new Error(
                'The strict browser width-evidence runner bound a malformed WebAssembly hash.',
            );
        }
        const databaseName = requiredEnvironmentValue(
            databaseNameEnvironmentVariable,
        );
        if (databaseName.length > 256) {
            throw new Error(
                'The strict browser width-evidence runner bound an oversized IndexedDB name.',
            );
        }
        let nativeBindingValue: unknown;
        try {
            nativeBindingValue = JSON.parse(
                requiredEnvironmentValue(nativeBindingEnvironmentVariable),
            ) as unknown;
        } catch (error) {
            throw Object.assign(
                new Error(
                    'The strict browser width-evidence runner bound malformed native evidence.',
                ),
                { cause: error },
            );
        }
        const nativeBinding =
            parseProofStorageWidthBrowserNativeBinding(nativeBindingValue);
        const measurement = await runEvidenceWorker({
            databaseName,
            nativeBinding: nativeBindingValue,
            wasmSha256Hex,
        });
        expect(measurement.wasmSha256Hex).toBe(wasmSha256Hex);
        expect(() =>
            requireProofStorageWidthBrowserNativeMatch(
                measurement,
                nativeBinding,
            ),
        ).not.toThrow();
        console.info(
            `${proofStorageWidthBrowserEvidenceConsolePrefix}${JSON.stringify(
                serializeProofStorageWidthBrowserMeasurement(measurement),
            )}`,
        );
    });
});
