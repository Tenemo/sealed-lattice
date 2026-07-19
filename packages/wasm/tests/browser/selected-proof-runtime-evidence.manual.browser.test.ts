import { afterEach, describe, expect, it } from 'vitest';

import {
    desktopBrowserProofMeasurementConsolePrefix,
    parseDesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofExecutionKind,
    type DesktopBrowserProofMeasurementRecord,
} from '#tests/support/desktop-browser-proof-measurement';

const expectedExecutionKinds: Readonly<
    Record<string, DesktopBrowserProofExecutionKind>
> = Object.freeze({
    'aggregate-threshold-share-generation': 'fresh-generation',
    'aggregate-threshold-share-verification': 'verification',
    'ballot-validity-generation': 'fresh-generation',
    'ballot-validity-verification': 'verification',
    'evaluator-key-aggregate-generation': 'fresh-generation',
    'evaluator-key-aggregate-verification': 'verification',
    'evaluator-replay-maximum-stream': 'replay',
    'galois-key-share-batch-generation-fresh': 'fresh-generation',
    'galois-key-share-batch-generation-resumed': 'resumed-generation',
    'galois-key-share-batch-verification': 'verification',
    'vss-share-linkage-generation-fresh': 'fresh-generation',
    'vss-share-linkage-generation-resumed': 'resumed-generation',
    'vss-share-linkage-verification': 'verification',
});

const proofRoundTrips = Object.freeze([
    [
        'aggregate-threshold-share-generation',
        'aggregate-threshold-share-verification',
    ],
    ['ballot-validity-generation', 'ballot-validity-verification'],
    [
        'evaluator-key-aggregate-generation',
        'evaluator-key-aggregate-verification',
    ],
    [
        'galois-key-share-batch-generation-fresh',
        'galois-key-share-batch-verification',
    ],
    ['vss-share-linkage-generation-fresh', 'vss-share-linkage-verification'],
] as const);

const resumedProofPairs = Object.freeze([
    [
        'galois-key-share-batch-generation-fresh',
        'galois-key-share-batch-generation-resumed',
    ],
    [
        'vss-share-linkage-generation-fresh',
        'vss-share-linkage-generation-resumed',
    ],
] as const);

type EvidenceWorkerMessage =
    | Readonly<{
          messageKind: 'complete';
      }>
    | Readonly<{
          failureMessage: string;
          messageKind: 'failure';
      }>
    | Readonly<{
          measurement: unknown;
          messageKind: 'measurement';
      }>;

const activeWorkers = new Set<Worker>();

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const parseWorkerMessage = (value: unknown): EvidenceWorkerMessage => {
    if (!isRecord(value)) {
        throw new TypeError(
            'The desktop proof-evidence worker returned a non-object message.',
        );
    }
    if (value.messageKind === 'complete') {
        return Object.freeze({ messageKind: 'complete' });
    }
    if (
        value.messageKind === 'failure' &&
        typeof value.failureMessage === 'string' &&
        value.failureMessage.length > 0
    ) {
        return Object.freeze({
            failureMessage: value.failureMessage,
            messageKind: 'failure',
        });
    }
    if (value.messageKind === 'measurement') {
        return Object.freeze({
            measurement: value.measurement,
            messageKind: 'measurement',
        });
    }
    throw new TypeError(
        'The desktop proof-evidence worker returned a malformed message.',
    );
};

const expectedProcessedWasmSha256Hex = (): string => {
    const environment = (
        import.meta as ImportMeta & {
            readonly env: Readonly<Record<string, string | undefined>>;
        }
    ).env;
    const value =
        environment[
            'VITE_SEALED_LATTICE_DESKTOP_PROOF_EXPECTED_WASM_SHA256_HEX'
        ];
    if (value === undefined || !/^[0-9a-f]{64}$/u.test(value)) {
        throw new Error(
            'The strict desktop proof-evidence runner did not bind the processed WebAssembly hash.',
        );
    }
    return value;
};

const runEvidenceWorker = (
    wasmSha256Hex: string,
): Promise<readonly DesktopBrowserProofMeasurementRecord[]> => {
    const worker = new Worker(
        new URL(
            '../support/selected-proof-runtime-evidence-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    activeWorkers.add(worker);
    const measurements: DesktopBrowserProofMeasurementRecord[] = [];

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
                                  'The desktop proof-evidence worker failed.',
                              ),
                    ),
                ),
            { once: true },
        );
        worker.addEventListener('messageerror', () =>
            finish(() =>
                reject(
                    new Error(
                        'The desktop proof-evidence worker returned an uncloneable message.',
                    ),
                ),
            ),
        );
        worker.addEventListener('message', (event) => {
            try {
                const message = parseWorkerMessage(event.data);
                if (message.messageKind === 'measurement') {
                    const measurement =
                        parseDesktopBrowserProofMeasurementRecord(
                            message.measurement,
                        );
                    measurements.push(measurement);
                    console.info(
                        `${desktopBrowserProofMeasurementConsolePrefix}${JSON.stringify(measurement)}`,
                    );
                    return;
                }
                if (message.messageKind === 'failure') {
                    finish(() => reject(new Error(message.failureMessage)));
                    return;
                }
                finish(() => resolve(Object.freeze([...measurements])));
            } catch (error) {
                finish(() =>
                    reject(
                        error instanceof Error
                            ? error
                            : Object.assign(
                                  new Error(
                                      'The desktop proof-evidence worker response could not be processed.',
                                  ),
                                  { failureCause: error },
                              ),
                    ),
                );
            }
        });
        worker.postMessage({
            command: 'run-selected-proof-runtime-evidence',
            wasmSha256Hex,
        });
    });
};

const groupMeasurementsByCase = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
): ReadonlyMap<
    string,
    ReadonlyMap<number, DesktopBrowserProofMeasurementRecord>
> => {
    const grouped = new Map<
        string,
        Map<number, DesktopBrowserProofMeasurementRecord>
    >();
    for (const measurement of measurements) {
        let caseMeasurements = grouped.get(measurement.caseIdentifier);
        if (caseMeasurements === undefined) {
            caseMeasurements = new Map();
            grouped.set(measurement.caseIdentifier, caseMeasurements);
        }
        if (caseMeasurements.has(measurement.runOrdinal)) {
            throw new Error(
                `The desktop proof-evidence worker repeated run ${String(measurement.runOrdinal)} for ${measurement.caseIdentifier}.`,
            );
        }
        caseMeasurements.set(measurement.runOrdinal, measurement);
    }
    return grouped;
};

const proofStreamFingerprint = (
    byteLength: number,
    sha512Hex: string,
): string => `${String(byteLength)}:${sha512Hex}`;

const generatedProofFingerprints = (
    measurements: ReadonlyMap<number, DesktopBrowserProofMeasurementRecord>,
): ReadonlySet<string> =>
    new Set(
        [...measurements.values()].map((measurement) =>
            proofStreamFingerprint(
                measurement.canonicalOutputByteLength,
                measurement.outputSha512Hex,
            ),
        ),
    );

const verifiedProofFingerprints = (
    measurements: ReadonlyMap<number, DesktopBrowserProofMeasurementRecord>,
): ReadonlySet<string> =>
    new Set(
        [...measurements.values()].map((measurement) =>
            proofStreamFingerprint(
                measurement.canonicalInputByteLength,
                measurement.canonicalInputSha512Hex,
            ),
        ),
    );

const generationFingerprint = (
    measurement: DesktopBrowserProofMeasurementRecord,
): string =>
    [
        measurement.canonicalInputByteLength,
        measurement.canonicalInputSha512Hex,
        measurement.canonicalOutputByteLength,
        measurement.outputSha512Hex,
    ].join(':');

afterEach(() => {
    for (const worker of activeWorkers) {
        worker.terminate();
    }
    activeWorkers.clear();
});

describe('Selected proof runtime desktop Chromium evidence', () => {
    it('generates, resumes, verifies, and replays the exact selected workload', async () => {
        const wasmSha256Hex = expectedProcessedWasmSha256Hex();
        const measurements = await runEvidenceWorker(wasmSha256Hex);
        const byCaseIdentifier = groupMeasurementsByCase(measurements);

        expect([...byCaseIdentifier.keys()].sort()).toEqual(
            Object.keys(expectedExecutionKinds).sort(),
        );
        expect(new Set(measurements.map(({ suiteId }) => suiteId)).size).toBe(
            1,
        );
        expect(
            new Set(
                measurements.map(
                    ({ wasmSha256Hex: observedHash }) => observedHash,
                ),
            ),
        ).toEqual(new Set([wasmSha256Hex]));

        for (const measurement of measurements) {
            expect(measurement.executionKind).toBe(
                expectedExecutionKinds[measurement.caseIdentifier],
            );
        }
        for (const caseMeasurements of byCaseIdentifier.values()) {
            const orderedRunOrdinals = [...caseMeasurements.keys()].sort(
                (left, right) => left - right,
            );
            expect(orderedRunOrdinals).toEqual(
                orderedRunOrdinals.map((_, runIndex) => runIndex + 1),
            );
        }
        for (const [generationCase, verificationCase] of proofRoundTrips) {
            const generated = byCaseIdentifier.get(generationCase);
            const verified = byCaseIdentifier.get(verificationCase);
            expect(generated).toBeDefined();
            expect(verified).toBeDefined();
            expect(verifiedProofFingerprints(verified ?? new Map())).toEqual(
                generatedProofFingerprints(generated ?? new Map()),
            );
            for (const verification of verified?.values() ?? []) {
                expect(verification.canonicalOutputByteLength).toBe(0);
            }
        }
        for (const [freshCase, resumedCase] of resumedProofPairs) {
            const fresh = byCaseIdentifier.get(freshCase);
            const resumed = byCaseIdentifier.get(resumedCase);
            expect(fresh).toBeDefined();
            expect(resumed).toBeDefined();
            expect(
                new Set(
                    [...(resumed?.values() ?? [])].map(generationFingerprint),
                ),
            ).toEqual(
                new Set(
                    [...(fresh?.values() ?? [])].map(generationFingerprint),
                ),
            );
        }
    });
});
