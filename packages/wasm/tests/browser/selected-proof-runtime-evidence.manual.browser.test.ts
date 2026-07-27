import { afterEach, describe, expect, it } from 'vitest';
import { commands } from 'vitest/browser';

import {
    createDesktopBrowserProofTransportArtifact,
    createDesktopBrowserProofTransportManifest,
    desktopBrowserProofGenerationSessionIdentifiers,
    encodeDesktopBrowserProofTransportBytesAsBase64,
    encodeDesktopBrowserProofTransportManifest,
    parseDesktopBrowserProofTransportManifestAuthenticationBindings,
    readDesktopBrowserProofTransportArtifact,
    readDesktopBrowserProofTransportManifest,
    requireDesktopBrowserProofGenerationSessionIdentifier,
    requireDesktopBrowserProofVerificationSessionIdentifier,
    resolveDesktopBrowserProofTransportArtifactPath,
    resolveDesktopBrowserProofTransportManifestPath,
    type DesktopBrowserProofEvidenceGenerationWorkerStartMessage,
    type DesktopBrowserProofEvidenceVerificationWorkerStartMessage,
    type DesktopBrowserProofGenerationSessionIdentifier,
    type DesktopBrowserProofTransportArtifact,
    type DesktopBrowserProofVerificationSessionIdentifier,
} from '../support/selected-proof-runtime-evidence-transport.js';

import {
    desktopBrowserProofEvidenceCaseExecutionKinds,
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole,
    desktopBrowserProofTransportGenerationCaseIdentifiers,
    resolveDesktopBrowserProofTransportVerificationCaseIdentifier,
    type DesktopBrowserProofEvidenceCaseIdentifier,
    type DesktopBrowserProofEvidenceOwnershipRole,
    type DesktopBrowserProofTransportGenerationCaseIdentifier,
} from '#tests/support/desktop-browser-proof-evidence-catalog';
import {
    desktopBrowserProofMeasurementConsolePrefix,
    parseDesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofMeasurementRecord,
} from '#tests/support/desktop-browser-proof-measurement';

const expectedWasmSha256EnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EXPECTED_WASM_SHA256_HEX';
const evidenceOwnershipRoleEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_ROLE';
const evidenceSessionIdentifierEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_SESSION_IDENTIFIER';
const evidenceTransportDirectoryEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_TRANSPORT_DIRECTORY';
const evidenceManifestAuthenticationEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_MANIFEST_AUTHENTICATION';

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

type EvidenceConfiguration =
    | Readonly<{
          generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
          ownershipRole: 'generation';
          transportDirectoryPath: string;
          wasmSha256Hex: string;
      }>
    | Readonly<{
          manifestAuthentication: ReturnType<
              typeof parseDesktopBrowserProofTransportManifestAuthenticationBindings
          >;
          ownershipRole: 'verification';
          transportDirectoryPath: string;
          verificationSessionIdentifier: DesktopBrowserProofVerificationSessionIdentifier;
          wasmSha256Hex: string;
      }>;

type TransportedProof = Readonly<{
    generationCaseIdentifier: DesktopBrowserProofTransportGenerationCaseIdentifier;
    proofBytes: Uint8Array<ArrayBuffer>;
    runOrdinal: number;
    suiteId: string;
}>;

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
      }>
    | Readonly<{
          messageKind: 'transported-proof';
          transportedProof: TransportedProof;
      }>;

type EvidenceWorkerResult = Readonly<{
    measurements: readonly DesktopBrowserProofMeasurementRecord[];
    transportedProofs: readonly TransportedProof[];
}>;

const activeWorkers = new Set<Worker>();

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (
    record: Readonly<Record<string, unknown>>,
    expectedKeys: readonly string[],
): boolean => {
    const actualKeys = Object.keys(record).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    return (
        actualKeys.length === sortedExpectedKeys.length &&
        actualKeys.every(
            (actualKey, keyIndex) => actualKey === sortedExpectedKeys[keyIndex],
        )
    );
};

const requireTransportedProof = (value: unknown): TransportedProof => {
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'generationCaseIdentifier',
            'proofBytes',
            'runOrdinal',
            'suiteId',
        ]) ||
        !desktopBrowserProofTransportGenerationCaseIdentifiers.includes(
            value.generationCaseIdentifier as DesktopBrowserProofTransportGenerationCaseIdentifier,
        ) ||
        !Number.isSafeInteger(value.runOrdinal) ||
        Number(value.runOrdinal) <= 0 ||
        typeof value.suiteId !== 'string' ||
        !/^[0-9a-f]{128}$/u.test(value.suiteId) ||
        !(value.proofBytes instanceof Uint8Array) ||
        !(value.proofBytes.buffer instanceof ArrayBuffer) ||
        value.proofBytes.byteOffset !== 0 ||
        value.proofBytes.byteLength !== value.proofBytes.buffer.byteLength ||
        value.proofBytes.byteLength === 0
    ) {
        throw new TypeError(
            'The desktop proof-evidence worker returned a malformed transported proof.',
        );
    }
    return Object.freeze({
        generationCaseIdentifier:
            value.generationCaseIdentifier as DesktopBrowserProofTransportGenerationCaseIdentifier,
        proofBytes: value.proofBytes as Uint8Array<ArrayBuffer>,
        runOrdinal: Number(value.runOrdinal),
        suiteId: value.suiteId,
    });
};

const parseWorkerMessage = (value: unknown): EvidenceWorkerMessage => {
    if (!isRecord(value)) {
        throw new TypeError(
            'The desktop proof-evidence worker returned a non-object message.',
        );
    }
    if (
        value.messageKind === 'complete' &&
        hasExactKeys(value, ['messageKind'])
    ) {
        return Object.freeze({ messageKind: 'complete' });
    }
    if (
        value.messageKind === 'failure' &&
        hasExactKeys(value, ['failureMessage', 'messageKind']) &&
        typeof value.failureMessage === 'string' &&
        value.failureMessage.length > 0
    ) {
        return Object.freeze({
            failureMessage: value.failureMessage,
            messageKind: 'failure',
        });
    }
    if (
        value.messageKind === 'measurement' &&
        hasExactKeys(value, ['measurement', 'messageKind'])
    ) {
        return Object.freeze({
            measurement: value.measurement,
            messageKind: 'measurement',
        });
    }
    if (
        value.messageKind === 'transported-proof' &&
        hasExactKeys(value, ['messageKind', 'transportedProof'])
    ) {
        return Object.freeze({
            messageKind: 'transported-proof',
            transportedProof: requireTransportedProof(value.transportedProof),
        });
    }
    throw new TypeError(
        'The desktop proof-evidence worker returned a malformed message.',
    );
};

const browserEnvironment = (): Readonly<Record<string, string | undefined>> =>
    (
        import.meta as ImportMeta & {
            readonly env: Readonly<Record<string, string | undefined>>;
        }
    ).env;

const requireEvidenceConfiguration = (): EvidenceConfiguration => {
    const environment = browserEnvironment();
    const wasmSha256Hex = environment[expectedWasmSha256EnvironmentVariable];
    if (wasmSha256Hex === undefined || !/^[0-9a-f]{64}$/u.test(wasmSha256Hex)) {
        throw new Error(
            'The strict desktop proof-evidence runner did not bind the processed WebAssembly hash.',
        );
    }
    const transportDirectoryPath =
        environment[evidenceTransportDirectoryEnvironmentVariable];
    if (transportDirectoryPath === undefined) {
        throw new Error(
            'The strict desktop proof-evidence runner did not bind its transport directory.',
        );
    }
    const ownershipRole = environment[
        evidenceOwnershipRoleEnvironmentVariable
    ] as DesktopBrowserProofEvidenceOwnershipRole | undefined;
    const sessionIdentifier =
        environment[evidenceSessionIdentifierEnvironmentVariable];
    const manifestAuthentication =
        environment[evidenceManifestAuthenticationEnvironmentVariable];
    if (ownershipRole === 'generation') {
        if (manifestAuthentication !== undefined) {
            throw new Error(
                'The proof-generation session received verification-only manifest authentication.',
            );
        }
        const generationSessionIdentifier =
            requireDesktopBrowserProofGenerationSessionIdentifier(
                sessionIdentifier,
            );
        resolveDesktopBrowserProofTransportManifestPath(
            transportDirectoryPath,
            generationSessionIdentifier,
        );
        return Object.freeze({
            generationSessionIdentifier,
            ownershipRole,
            transportDirectoryPath,
            wasmSha256Hex,
        });
    }
    if (ownershipRole === 'verification') {
        if (manifestAuthentication === undefined) {
            throw new Error(
                'The proof-verification session did not receive authenticated generation manifests.',
            );
        }
        const verificationSessionIdentifier =
            requireDesktopBrowserProofVerificationSessionIdentifier(
                sessionIdentifier,
            );
        return Object.freeze({
            manifestAuthentication:
                parseDesktopBrowserProofTransportManifestAuthenticationBindings(
                    manifestAuthentication,
                ),
            ownershipRole,
            transportDirectoryPath,
            verificationSessionIdentifier,
            wasmSha256Hex,
        });
    }
    throw new Error(
        'The strict desktop proof-evidence runner did not bind a registered ownership role.',
    );
};

const runEvidenceWorker = (
    startMessage:
        | DesktopBrowserProofEvidenceGenerationWorkerStartMessage
        | DesktopBrowserProofEvidenceVerificationWorkerStartMessage,
): Promise<EvidenceWorkerResult> => {
    const worker = new Worker(
        new URL(
            '../support/selected-proof-runtime-evidence-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    activeWorkers.add(worker);
    const measurements: DesktopBrowserProofMeasurementRecord[] = [];
    const transportedProofs: TransportedProof[] = [];

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
                if (message.messageKind === 'transported-proof') {
                    transportedProofs.push(message.transportedProof);
                    return;
                }
                if (message.messageKind === 'failure') {
                    finish(() => reject(new Error(message.failureMessage)));
                    return;
                }
                finish(() =>
                    resolve(
                        Object.freeze({
                            measurements: Object.freeze([...measurements]),
                            transportedProofs: Object.freeze([
                                ...transportedProofs,
                            ]),
                        }),
                    ),
                );
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
        if (startMessage.ownershipRole === 'verification') {
            worker.postMessage(startMessage, [startMessage.proofBytes.buffer]);
        } else {
            worker.postMessage(startMessage);
        }
    });
};

const groupMeasurementsByCase = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
    ownershipRole: DesktopBrowserProofEvidenceOwnershipRole,
): ReadonlyMap<
    DesktopBrowserProofEvidenceCaseIdentifier,
    ReadonlyMap<number, DesktopBrowserProofMeasurementRecord>
> => {
    const expectedCaseIdentifiers =
        desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole[
            ownershipRole
        ];
    const expectedCaseIdentifierSet = new Set(expectedCaseIdentifiers);
    const grouped = new Map<
        DesktopBrowserProofEvidenceCaseIdentifier,
        Map<number, DesktopBrowserProofMeasurementRecord>
    >();
    for (const measurement of measurements) {
        const caseIdentifier =
            measurement.caseIdentifier as DesktopBrowserProofEvidenceCaseIdentifier;
        if (!expectedCaseIdentifierSet.has(caseIdentifier)) {
            throw new Error(
                `The ${ownershipRole} worker returned an unexpected proof case: ${measurement.caseIdentifier}.`,
            );
        }
        if (
            measurement.executionKind !==
            desktopBrowserProofEvidenceCaseExecutionKinds[caseIdentifier]
        ) {
            throw new Error(
                `The ${ownershipRole} worker misclassified ${caseIdentifier}.`,
            );
        }
        let caseMeasurements = grouped.get(caseIdentifier);
        if (caseMeasurements === undefined) {
            caseMeasurements = new Map();
            grouped.set(caseIdentifier, caseMeasurements);
        }
        if (caseMeasurements.has(measurement.runOrdinal)) {
            throw new Error(
                `The desktop proof-evidence worker repeated run ${String(measurement.runOrdinal)} for ${caseIdentifier}.`,
            );
        }
        caseMeasurements.set(measurement.runOrdinal, measurement);
    }
    const missingCaseIdentifiers = expectedCaseIdentifiers.filter(
        (caseIdentifier) => !grouped.has(caseIdentifier),
    );
    if (missingCaseIdentifiers.length > 0) {
        throw new Error(
            `The ${ownershipRole} worker omitted required proof cases: ${missingCaseIdentifiers.join(', ')}.`,
        );
    }
    for (const [caseIdentifier, caseMeasurements] of grouped) {
        const orderedRunOrdinals = [...caseMeasurements.keys()].sort(
            (left, right) => left - right,
        );
        if (
            orderedRunOrdinals.some(
                (runOrdinal, runIndex) => runOrdinal !== runIndex + 1,
            )
        ) {
            throw new Error(
                `The desktop proof-evidence worker returned noncontiguous runs for ${caseIdentifier}.`,
            );
        }
    }
    return grouped;
};

const proofStreamFingerprint = (
    byteLength: number,
    sha512Hex: string,
): string => `${String(byteLength)}:${sha512Hex}`;

const generationFingerprint = (
    measurement: DesktopBrowserProofMeasurementRecord,
): string =>
    [
        measurement.canonicalInputByteLength,
        measurement.canonicalInputSha512Hex,
        measurement.canonicalOutputByteLength,
        measurement.outputSha512Hex,
    ].join(':');

const requireCommonMeasurementBindings = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
    wasmSha256Hex: string,
): string => {
    const suiteIdentifiers = new Set(
        measurements.map((measurement) => measurement.suiteId),
    );
    const wasmHashes = new Set(
        measurements.map((measurement) => measurement.wasmSha256Hex),
    );
    if (suiteIdentifiers.size !== 1 || wasmHashes.size !== 1) {
        throw new Error(
            'The desktop proof-evidence worker did not use one suite and one WebAssembly module.',
        );
    }
    if (!wasmHashes.has(wasmSha256Hex)) {
        throw new Error(
            'The desktop proof-evidence worker did not use the runner-bound WebAssembly module.',
        );
    }
    const suiteId = measurements[0]?.suiteId;
    if (suiteId === undefined) {
        throw new Error(
            'The desktop proof-evidence worker returned no suite-bound measurements.',
        );
    }
    return suiteId;
};

const transportedProofKey = (
    caseIdentifier: DesktopBrowserProofTransportGenerationCaseIdentifier,
    runOrdinal: number,
): string => `${caseIdentifier}:${String(runOrdinal)}`;

const writeTransportArtifact = async (input: {
    artifact: DesktopBrowserProofTransportArtifact;
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    proofBytes: Uint8Array<ArrayBuffer>;
    transportDirectoryPath: string;
}): Promise<void> => {
    const artifactPath = resolveDesktopBrowserProofTransportArtifactPath(
        input.transportDirectoryPath,
        input.artifact,
        input.generationSessionIdentifier,
    );
    await commands.writeFile(
        artifactPath,
        encodeDesktopBrowserProofTransportBytesAsBase64(input.proofBytes),
        'base64',
    );
    const readBackBytes = await readDesktopBrowserProofTransportArtifact({
        artifact: input.artifact,
        generationSessionIdentifier: input.generationSessionIdentifier,
        readFile: (filePath, encoding) => commands.readFile(filePath, encoding),
        transportDirectoryPath: input.transportDirectoryPath,
    });
    if (
        readBackBytes.byteLength !== input.proofBytes.byteLength ||
        readBackBytes.some(
            (byte, byteIndex) => byte !== input.proofBytes[byteIndex],
        )
    ) {
        throw new Error(
            `The desktop proof transport changed bytes while writing ${input.artifact.fileName}.`,
        );
    }
};

const runGenerationSession = async (
    configuration: Extract<
        EvidenceConfiguration,
        { ownershipRole: 'generation' }
    >,
): Promise<void> => {
    const result = await runEvidenceWorker({
        caseIdentifiers:
            desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole.generation,
        command: 'generate-selected-proof-runtime-evidence',
        generationSessionIdentifier: configuration.generationSessionIdentifier,
        ownershipRole: 'generation',
        wasmSha256Hex: configuration.wasmSha256Hex,
    });
    const measurementsByCase = groupMeasurementsByCase(
        result.measurements,
        'generation',
    );
    const suiteId = requireCommonMeasurementBindings(
        result.measurements,
        configuration.wasmSha256Hex,
    );

    for (const [
        freshCaseIdentifier,
        resumedCaseIdentifier,
    ] of resumedProofPairs) {
        const freshMeasurements = measurementsByCase.get(freshCaseIdentifier);
        const resumedMeasurements = measurementsByCase.get(
            resumedCaseIdentifier,
        );
        expect(freshMeasurements).toBeDefined();
        expect(resumedMeasurements).toBeDefined();
        expect(
            new Set(
                [...(resumedMeasurements?.values() ?? [])].map(
                    generationFingerprint,
                ),
            ),
        ).toEqual(
            new Set(
                [...(freshMeasurements?.values() ?? [])].map(
                    generationFingerprint,
                ),
            ),
        );
    }

    const transportedProofsByRun = new Map<string, TransportedProof>();
    for (const transportedProof of result.transportedProofs) {
        if (transportedProof.suiteId !== suiteId) {
            throw new Error(
                'The desktop proof-evidence worker transported a proof for a different suite.',
            );
        }
        const proofKey = transportedProofKey(
            transportedProof.generationCaseIdentifier,
            transportedProof.runOrdinal,
        );
        if (transportedProofsByRun.has(proofKey)) {
            throw new Error(
                `The desktop proof-evidence worker transported ${proofKey} more than once.`,
            );
        }
        transportedProofsByRun.set(proofKey, transportedProof);
    }

    const artifacts: DesktopBrowserProofTransportArtifact[] = [];
    for (const generationCaseIdentifier of desktopBrowserProofTransportGenerationCaseIdentifiers) {
        const caseMeasurements = measurementsByCase.get(
            generationCaseIdentifier,
        );
        if (caseMeasurements === undefined) {
            throw new Error(
                `The generation worker omitted ${generationCaseIdentifier}.`,
            );
        }
        for (const measurement of caseMeasurements.values()) {
            const proofKey = transportedProofKey(
                generationCaseIdentifier,
                measurement.runOrdinal,
            );
            const transportedProof = transportedProofsByRun.get(proofKey);
            if (transportedProof === undefined) {
                throw new Error(
                    `The generation worker did not transport canonical proof bytes for ${proofKey}.`,
                );
            }
            const artifact = createDesktopBrowserProofTransportArtifact({
                generationCaseIdentifier,
                generationSessionIdentifier:
                    configuration.generationSessionIdentifier,
                proofBytes: transportedProof.proofBytes,
                runOrdinal: transportedProof.runOrdinal,
            });
            if (
                proofStreamFingerprint(
                    artifact.canonicalProofByteLength,
                    artifact.canonicalProofSha512Hex,
                ) !==
                proofStreamFingerprint(
                    measurement.canonicalOutputByteLength,
                    measurement.outputSha512Hex,
                )
            ) {
                throw new Error(
                    `The generation measurement does not bind the transported proof bytes for ${proofKey}.`,
                );
            }
            await writeTransportArtifact({
                artifact,
                generationSessionIdentifier:
                    configuration.generationSessionIdentifier,
                proofBytes: transportedProof.proofBytes,
                transportDirectoryPath: configuration.transportDirectoryPath,
            });
            artifacts.push(artifact);
            transportedProofsByRun.delete(proofKey);
        }
    }
    if (transportedProofsByRun.size > 0) {
        throw new Error(
            `The generation worker transported unmeasured proof bytes: ${[...transportedProofsByRun.keys()].join(', ')}.`,
        );
    }

    const manifest = createDesktopBrowserProofTransportManifest({
        artifacts,
        generationSessionIdentifier: configuration.generationSessionIdentifier,
        suiteId,
        wasmSha256Hex: configuration.wasmSha256Hex,
    });
    const manifestPath = resolveDesktopBrowserProofTransportManifestPath(
        configuration.transportDirectoryPath,
        configuration.generationSessionIdentifier,
    );
    await commands.writeFile(
        manifestPath,
        encodeDesktopBrowserProofTransportManifest(manifest),
        'utf8',
    );
    await readDesktopBrowserProofTransportManifest({
        expectedSuiteId: suiteId,
        expectedWasmSha256Hex: configuration.wasmSha256Hex,
        generationSessionIdentifier: configuration.generationSessionIdentifier,
        readFile: (filePath, encoding) => commands.readFile(filePath, encoding),
        transportDirectoryPath: configuration.transportDirectoryPath,
    });
};

const runVerificationSession = async (
    configuration: Extract<
        EvidenceConfiguration,
        { ownershipRole: 'verification' }
    >,
): Promise<void> => {
    const measurements: DesktopBrowserProofMeasurementRecord[] = [];
    const nextRunOrdinalByVerificationCase = new Map<string, number>();
    let suiteId: string | undefined;

    for (const generationSessionIdentifier of desktopBrowserProofGenerationSessionIdentifiers) {
        const authenticatedManifest =
            await readDesktopBrowserProofTransportManifest({
                expectedManifestSha512Hex:
                    configuration.manifestAuthentication[
                        generationSessionIdentifier
                    ],
                ...(suiteId === undefined ? {} : { expectedSuiteId: suiteId }),
                expectedWasmSha256Hex: configuration.wasmSha256Hex,
                generationSessionIdentifier,
                readFile: (filePath, encoding) =>
                    commands.readFile(filePath, encoding),
                transportDirectoryPath: configuration.transportDirectoryPath,
            });
        suiteId ??= authenticatedManifest.manifest.suiteId;

        for (const artifact of authenticatedManifest.manifest.artifacts) {
            const verificationCaseIdentifier =
                resolveDesktopBrowserProofTransportVerificationCaseIdentifier(
                    artifact.generationCaseIdentifier,
                );
            if (verificationCaseIdentifier === undefined) {
                throw new Error(
                    `The transport catalog did not assign a verifier to ${artifact.generationCaseIdentifier}.`,
                );
            }
            const verificationRunOrdinal =
                (nextRunOrdinalByVerificationCase.get(
                    verificationCaseIdentifier,
                ) ?? 0) + 1;
            nextRunOrdinalByVerificationCase.set(
                verificationCaseIdentifier,
                verificationRunOrdinal,
            );
            const proofBytes = await readDesktopBrowserProofTransportArtifact({
                artifact,
                generationSessionIdentifier,
                readFile: (filePath, encoding) =>
                    commands.readFile(filePath, encoding),
                transportDirectoryPath: configuration.transportDirectoryPath,
            });
            const result = await runEvidenceWorker({
                canonicalProofByteLength: artifact.canonicalProofByteLength,
                canonicalProofSha512Hex: artifact.canonicalProofSha512Hex,
                command: 'verify-selected-proof-runtime-evidence',
                generationCaseIdentifier: artifact.generationCaseIdentifier,
                generationRunOrdinal: artifact.runOrdinal,
                generationSessionIdentifier,
                ownershipRole: 'verification',
                proofBytes,
                suiteId: authenticatedManifest.manifest.suiteId,
                verificationCaseIdentifier,
                verificationRunOrdinal,
                verificationSessionIdentifier:
                    configuration.verificationSessionIdentifier,
                wasmSha256Hex: configuration.wasmSha256Hex,
            });
            if (
                result.transportedProofs.length !== 0 ||
                result.measurements.length !== 1
            ) {
                throw new Error(
                    `The fresh verification worker did not return exactly one measurement for ${artifact.fileName}.`,
                );
            }
            const measurement = result.measurements[0];
            if (
                measurement === undefined ||
                measurement.caseIdentifier !== verificationCaseIdentifier ||
                measurement.runOrdinal !== verificationRunOrdinal ||
                measurement.suiteId !==
                    authenticatedManifest.manifest.suiteId ||
                measurement.wasmSha256Hex !== configuration.wasmSha256Hex ||
                measurement.executionKind !== 'verification' ||
                measurement.canonicalInputByteLength !==
                    artifact.canonicalProofByteLength ||
                measurement.canonicalInputSha512Hex !==
                    artifact.canonicalProofSha512Hex ||
                measurement.canonicalOutputByteLength !== 0
            ) {
                throw new Error(
                    `The fresh verification measurement did not bind the transported bytes for ${artifact.fileName}.`,
                );
            }
            measurements.push(measurement);
        }
    }

    groupMeasurementsByCase(measurements, 'verification');
    requireCommonMeasurementBindings(measurements, configuration.wasmSha256Hex);
};

afterEach(() => {
    for (const worker of activeWorkers) {
        worker.terminate();
    }
    activeWorkers.clear();
});

describe('Selected proof runtime desktop-browser evidence', () => {
    it('owns one role-specific generation or fresh-verification session', async () => {
        const configuration = requireEvidenceConfiguration();
        expect(configuration.ownershipRole).toMatch(
            /^(?:generation|verification)$/u,
        );
        if (configuration.ownershipRole === 'generation') {
            await runGenerationSession(configuration);
            return;
        }
        await runVerificationSession(configuration);
    });
});
