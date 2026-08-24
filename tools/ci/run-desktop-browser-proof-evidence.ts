import { createHash } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { normalizeTranscriptCoreKernelBytesForHash } from '../../packages/wasm/src/transcript-core-bridge.js';
import {
    parseDesktopBrowserProofDeterministicParityBinding,
    readDesktopBrowserProofTransportManifest,
    requireDesktopBrowserProofGenerationSessionIdentifier,
    serializeDesktopBrowserProofTransportManifestAuthenticationBindings,
    type DesktopBrowserProofGenerationSessionIdentifier,
} from '../../packages/wasm/tests/support/selected-proof-runtime-evidence-transport.js';
import {
    desktopBrowserProofCancellationCoverageRequirement,
    desktopBrowserProofDeterministicParityCaseIdentifier,
    desktopBrowserProofEvidenceCaseExecutionKinds as requiredCaseExecutionKinds,
    desktopBrowserProofEvidenceCaseIdentifiers as requiredCaseIdentifiers,
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole as requiredCaseIdentifiersByOwnershipRole,
    desktopBrowserProofGenerationRepetitionRequirement,
    desktopBrowserProofRefusalReuseRequirement,
    desktopBrowserProofTransportCasePairs as transportedProofCasePairs,
} from '../../tests/support/desktop-browser-proof-evidence-catalog.js';
import {
    parseDesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofCancellationBoundaryKind,
    type DesktopBrowserProofExecutionKind,
    type DesktopBrowserProofMeasurementRecord,
} from '../../tests/support/desktop-browser-proof-measurement.js';

import {
    desktopBrowserProofEvidenceSessionDefinitions,
    type DesktopBrowserProofEvidenceSessionDefinition,
} from './browser-test-project-selection.js';
import {
    desktopBrowserProductionNetworkAccountingAuthorityEvent,
    parseDesktopBrowserProductionNetworkAccountingAuthority,
    projectDesktopBrowserNetworkEvidence,
    type DesktopBrowserNetworkProjection,
} from './desktop-browser-network-projection.js';
import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { createProcessMemoryGuard } from './process-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
} from './run-command.js';

const laneLabel = 'Desktop-browser proof evidence';
const browserEvidenceTestFile =
    'packages/wasm/tests/browser/selected-proof-runtime-evidence.manual.browser.test.ts';
const processedWasmKernelPath = path.resolve(
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const publicSdkWasmKernelPath = path.resolve(
    'packages',
    'sdk',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const expectedWasmSha256EnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EXPECTED_WASM_SHA256_HEX';
const evidenceOwnershipRoleEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_ROLE';
const evidenceTransportDirectoryEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_TRANSPORT_DIRECTORY';
const evidenceSessionIdentifierEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_SESSION_IDENTIFIER';
const evidenceManifestAuthenticationEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EVIDENCE_MANIFEST_AUTHENTICATION';

const absoluteResourceBounds = Object.freeze({
    copiedBufferByteLength: 8_388_608,
    externalScratchByteLength: 1_073_741_824,
    liveBufferByteLength: 2_097_152,
    liveBufferCount: 2,
    proofByteLength: 268_435_456,
    transportStreamByteLength: 4_294_967_291,
    wasmLinearMemoryByteLength: 671_088_640,
});

const selectedProofEvidenceGate = Object.freeze({
    proofByteLength: 5_242_880,
});

const softPlanningTargets = Object.freeze({
    browserProcessIncreaseByteLength: 671_088_640,
    copiedBufferByteLength: 1_572_864,
    externalScratchByteLength: 268_435_456,
    wasmLinearMemoryByteLength: 402_653_184,
});

type JsonRecord = Readonly<Record<string, unknown>>;

const requireProductionNetworkAccountingAuthority = (
    testEvents: readonly JsonRecord[],
) => {
    const authorityEvents = testEvents.filter(
        (event) =>
            event.event ===
            desktopBrowserProductionNetworkAccountingAuthorityEvent,
    );
    if (authorityEvents.length !== 1) {
        throw new Error(
            `Desktop-browser network evidence requires exactly one ${desktopBrowserProductionNetworkAccountingAuthorityEvent} record.`,
        );
    }
    return parseDesktopBrowserProductionNetworkAccountingAuthority(
        authorityEvents[0],
    );
};

type DesktopBrowserProofCancellationBoundary = Readonly<{
    boundaryIdentifier: string;
    boundaryKind: DesktopBrowserProofCancellationBoundaryKind;
    boundaryOrdinal: number;
}>;

export const deriveDesktopBrowserProofCancellationBoundaryCatalogSha512Hex = (
    boundaries: readonly DesktopBrowserProofCancellationBoundary[],
): string => {
    const canonicalBoundaries = boundaries.map((boundary) => {
        if (
            !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(boundary.boundaryIdentifier) ||
            !['safe-boundary', 'storage-yield'].includes(
                boundary.boundaryKind,
            ) ||
            !Number.isSafeInteger(boundary.boundaryOrdinal) ||
            boundary.boundaryOrdinal <= 0
        ) {
            throw new TypeError(
                'The cancellation boundary catalog contains a malformed entry.',
            );
        }
        return {
            boundaryIdentifier: boundary.boundaryIdentifier,
            boundaryKind: boundary.boundaryKind,
            boundaryOrdinal: boundary.boundaryOrdinal,
        };
    });
    if (
        canonicalBoundaries.length === 0 ||
        new Set(
            canonicalBoundaries.map(
                ({ boundaryIdentifier }) => boundaryIdentifier,
            ),
        ).size !== canonicalBoundaries.length
    ) {
        throw new TypeError(
            'The cancellation boundary catalog must be nonempty and use unique identifiers.',
        );
    }
    return createHash('sha512')
        .update(JSON.stringify(canonicalBoundaries))
        .digest('hex');
};

export type DesktopBrowserProofEvidenceSessionEvents = Readonly<{
    sessionIdentifier: string;
    testEvents: readonly JsonRecord[];
}>;

type ValidatedDesktopBrowserProofEvidenceSession = Readonly<{
    measurements: readonly DesktopBrowserProofMeasurementRecord[];
    session: DesktopBrowserProofEvidenceSessionDefinition;
}>;

export type DesktopBrowserProofEvidenceNetworkSessionProjection = Readonly<{
    browserEngine: DesktopBrowserProofEvidenceSessionDefinition['browserEngine'];
    projection: DesktopBrowserNetworkProjection;
    sessionIdentifier: string;
}>;

const requirePositiveMeasuredBytes = (
    value: number,
    fieldName: string,
    caseIdentifier: string,
): void => {
    if (value === 0) {
        throw new Error(
            `Desktop-browser proof evidence reported zero ${fieldName} for ${caseIdentifier}.`,
        );
    }
};

const requireAtMostAbsoluteBound = (
    value: number,
    bound: number,
    fieldName: string,
    caseIdentifier: string,
): void => {
    if (value > bound) {
        throw new Error(
            `Desktop-browser proof evidence exceeded the absolute ${fieldName} bound for ${caseIdentifier}: ${String(value)} > ${String(bound)} bytes.`,
        );
    }
};

const requireSelectedProofWithinEvidenceGate = (
    proofByteLength: number,
    caseIdentifier: string,
): void => {
    if (proofByteLength > selectedProofEvidenceGate.proofByteLength) {
        throw new Error(
            `Desktop-browser proof evidence exceeded the selected proof evidence-selection bound for ${caseIdentifier}: ${String(proofByteLength)} > ${String(selectedProofEvidenceGate.proofByteLength)} bytes.`,
        );
    }
};

const validateMeasurementResourceBounds = (
    measurement: DesktopBrowserProofMeasurementRecord,
): void => {
    requirePositiveMeasuredBytes(
        measurement.canonicalInputByteLength,
        'canonical input',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.copiedBufferPeakByteLength,
        absoluteResourceBounds.copiedBufferByteLength,
        'single copied-buffer',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.externalScratchPeakByteLength,
        absoluteResourceBounds.externalScratchByteLength,
        'external-scratch peak',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.wasmLinearMemoryPeakByteLength,
        absoluteResourceBounds.wasmLinearMemoryByteLength,
        'WebAssembly linear-memory peak',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.resourceAccounting.simultaneousLiveBufferPeakByteLength,
        absoluteResourceBounds.liveBufferByteLength,
        'simultaneous live-buffer peak',
        measurement.caseIdentifier,
    );
    if (
        measurement.resourceAccounting.simultaneousLiveBufferPeakCount >
        absoluteResourceBounds.liveBufferCount
    ) {
        throw new Error(
            `Desktop-browser proof evidence exceeded the absolute simultaneous live-buffer count for ${measurement.caseIdentifier}: ${String(measurement.resourceAccounting.simultaneousLiveBufferPeakCount)} > ${String(absoluteResourceBounds.liveBufferCount)}.`,
        );
    }

    if (
        measurement.executionKind === 'fresh-generation' ||
        measurement.executionKind === 'resumed-generation' ||
        measurement.executionKind === 'worker-reuse-generation' ||
        measurement.executionKind === 'deterministic-parity'
    ) {
        requirePositiveMeasuredBytes(
            measurement.canonicalOutputByteLength,
            'canonical proof output',
            measurement.caseIdentifier,
        );
        requireAtMostAbsoluteBound(
            measurement.canonicalOutputByteLength,
            absoluteResourceBounds.proofByteLength,
            'proof-stream',
            measurement.caseIdentifier,
        );
        requireSelectedProofWithinEvidenceGate(
            measurement.canonicalOutputByteLength,
            measurement.caseIdentifier,
        );
        return;
    }
    if (
        measurement.executionKind === 'cancelled-generation' ||
        measurement.executionKind === 'refused-generation'
    ) {
        if (measurement.canonicalOutputByteLength !== 0) {
            throw new Error(
                `Desktop-browser ${measurement.executionKind} evidence emitted a canonical proof for ${measurement.caseIdentifier}.`,
            );
        }
        return;
    }
    if (measurement.executionKind === 'verification') {
        if (measurement.canonicalOutputByteLength !== 0) {
            throw new Error(
                `Desktop-browser proof verification reported a canonical output artifact for ${measurement.caseIdentifier}.`,
            );
        }
        requireAtMostAbsoluteBound(
            measurement.canonicalInputByteLength,
            absoluteResourceBounds.proofByteLength,
            'proof-stream',
            measurement.caseIdentifier,
        );
        requireSelectedProofWithinEvidenceGate(
            measurement.canonicalInputByteLength,
            measurement.caseIdentifier,
        );
        return;
    }
    requirePositiveMeasuredBytes(
        measurement.canonicalOutputByteLength,
        'canonical replay output',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.canonicalInputByteLength,
        absoluteResourceBounds.transportStreamByteLength,
        'transport-stream',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.canonicalOutputByteLength,
        absoluteResourceBounds.transportStreamByteLength,
        'transport-stream',
        measurement.caseIdentifier,
    );
};

const readJsonLines = async (
    filePath: string,
): Promise<readonly JsonRecord[]> => {
    const text = await readFile(filePath, 'utf8');
    return text
        .split(/\r?\n/u)
        .filter((line) => line.length > 0)
        .map((line, lineIndex) => {
            const value = JSON.parse(line) as unknown;
            if (
                typeof value !== 'object' ||
                value === null ||
                Array.isArray(value)
            ) {
                throw new Error(
                    `${filePath} line ${String(lineIndex + 1)} is not a JSON object.`,
                );
            }
            return value as JsonRecord;
        });
};

const optionalSafeInteger = (
    record: JsonRecord,
    fieldName: string,
): number | undefined => {
    const value = record[fieldName];
    return Number.isSafeInteger(value) && Number(value) >= 0
        ? Number(value)
        : undefined;
};

const maximumObservedValue = (
    records: readonly JsonRecord[],
    fieldName: string,
): number | undefined => {
    const observations = records.flatMap((record) => {
        const value = optionalSafeInteger(record, fieldName);
        return value === undefined ? [] : [value];
    });
    return observations.length === 0 ? undefined : Math.max(...observations);
};

const nearestBaselineValue = (
    records: readonly JsonRecord[],
    fieldName: string,
    startedAtUnixMilliseconds: number,
): number | undefined => {
    return records
        .filter(
            (record) =>
                optionalSafeInteger(record, 'recordedAtUnixMilliseconds') !==
                    undefined &&
                Number(record.recordedAtUnixMilliseconds) <=
                    startedAtUnixMilliseconds,
        )
        .sort(
            (left, right) =>
                Number(right.recordedAtUnixMilliseconds) -
                Number(left.recordedAtUnixMilliseconds),
        )
        .map((record) => optionalSafeInteger(record, fieldName))
        .find((value) => value !== undefined);
};

const optionalIncrease = (
    peak: number | undefined,
    baseline: number | undefined,
): number | undefined =>
    peak === undefined || baseline === undefined
        ? undefined
        : Math.max(0, peak - baseline);

const planningVariance = (value: number, target: number) =>
    Object.freeze({
        overageByteLength: Math.max(0, value - target),
        ratio: value / target,
        targetByteLength: target,
        valueByteLength: value,
    });

const validateDesktopBrowserProofMeasurementEventsForRequiredCases = (
    testEvents: readonly JsonRecord[],
    requiredCaseIdentifiersForSession: readonly string[],
    expectedBindings?: Readonly<{
        wasmSha256Hex: string;
    }>,
): readonly DesktopBrowserProofMeasurementRecord[] => {
    const requiredCaseIdentifierSet = new Set(
        requiredCaseIdentifiersForSession,
    );
    const measurementEvents = testEvents.filter(
        (event) => event.event === 'desktop-browser-proof-measurement',
    );
    for (const measurementEvent of measurementEvents) {
        if (measurementEvent.browser !== true) {
            throw new Error(
                'Desktop-browser proof evidence included a non-browser measurement.',
            );
        }
    }
    const measurements = measurementEvents.map((event) =>
        parseDesktopBrowserProofMeasurementRecord(event),
    );
    const measurementsByCaseIdentifier = new Map<
        string,
        Map<number, DesktopBrowserProofMeasurementRecord>
    >();
    for (const measurement of measurements) {
        const expectedExecutionKind = (
            requiredCaseExecutionKinds as Readonly<
                Partial<Record<string, DesktopBrowserProofExecutionKind>>
            >
        )[measurement.caseIdentifier];
        if (
            expectedExecutionKind === undefined ||
            !requiredCaseIdentifierSet.has(measurement.caseIdentifier)
        ) {
            throw new Error(
                `Desktop-browser proof evidence reported an unexpected case: ${measurement.caseIdentifier}.`,
            );
        }
        let caseMeasurements = measurementsByCaseIdentifier.get(
            measurement.caseIdentifier,
        );
        if (caseMeasurements === undefined) {
            caseMeasurements = new Map();
            measurementsByCaseIdentifier.set(
                measurement.caseIdentifier,
                caseMeasurements,
            );
        }
        if (caseMeasurements.has(measurement.runOrdinal)) {
            throw new Error(
                `Desktop-browser proof evidence reported the same run ordinal more than once for ${measurement.caseIdentifier}: ${String(measurement.runOrdinal)}.`,
            );
        }
        if (measurement.executionKind !== expectedExecutionKind) {
            throw new Error(
                `Desktop-browser proof evidence reported ${measurement.caseIdentifier} as ${measurement.executionKind}, expected ${expectedExecutionKind}.`,
            );
        }
        validateMeasurementResourceBounds(measurement);
        caseMeasurements.set(measurement.runOrdinal, measurement);
    }
    const missingCaseIdentifiers = requiredCaseIdentifiersForSession.filter(
        (caseIdentifier) => !measurementsByCaseIdentifier.has(caseIdentifier),
    );
    if (missingCaseIdentifiers.length > 0) {
        throw new Error(
            `Desktop-browser proof evidence omitted required cases: ${missingCaseIdentifiers.join(', ')}.`,
        );
    }
    for (const [
        caseIdentifier,
        caseMeasurements,
    ] of measurementsByCaseIdentifier) {
        const orderedRunOrdinals = [...caseMeasurements.keys()].sort(
            (left, right) => left - right,
        );
        if (
            orderedRunOrdinals.some(
                (runOrdinal, runIndex) => runOrdinal !== runIndex + 1,
            )
        ) {
            throw new Error(
                `Desktop-browser proof-evidence run ordinals must be contiguous from one for ${caseIdentifier}.`,
            );
        }
    }
    const observedSuiteIdentifiers = new Set(
        measurements.map((measurement) => measurement.suiteId),
    );
    const observedWasmHashes = new Set(
        measurements.map((measurement) => measurement.wasmSha256Hex),
    );
    if (observedSuiteIdentifiers.size !== 1 || observedWasmHashes.size !== 1) {
        throw new Error(
            'Desktop-browser proof evidence did not use one exact suite and one exact processed WebAssembly module.',
        );
    }
    if (
        expectedBindings !== undefined &&
        !observedWasmHashes.has(expectedBindings.wasmSha256Hex)
    ) {
        throw new Error(
            'Desktop-browser proof evidence did not use the normalized processed WebAssembly module produced by this build.',
        );
    }
    return measurements;
};

export const validateDesktopBrowserProofMeasurementEvents = (
    testEvents: readonly JsonRecord[],
    expectedBindings?: Readonly<{
        wasmSha256Hex: string;
    }>,
): readonly DesktopBrowserProofMeasurementRecord[] => {
    const measurements =
        validateDesktopBrowserProofMeasurementEventsForRequiredCases(
            testEvents,
            requiredCaseIdentifiers,
            expectedBindings,
        );
    validateGenerationSessionContract(
        measurements.filter(
            ({ executionKind }) => executionKind !== 'verification',
        ),
    );
    validateFreshVerificationWorkers(
        measurements.filter(
            ({ executionKind }) => executionKind === 'verification',
        ),
    );
    return measurements;
};

const proofStreamFingerprint = (
    byteLength: number,
    sha512Hex: string,
): string => `${String(byteLength)}:${sha512Hex}`;

const generatedProofFingerprints = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
    caseIdentifier: string,
): readonly string[] =>
    measurements
        .filter((measurement) => measurement.caseIdentifier === caseIdentifier)
        .map((measurement) =>
            proofStreamFingerprint(
                measurement.canonicalOutputByteLength,
                measurement.outputSha512Hex,
            ),
        )
        .sort();

const verifiedProofFingerprints = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
    caseIdentifier: string,
): readonly string[] =>
    measurements
        .filter((measurement) => measurement.caseIdentifier === caseIdentifier)
        .map((measurement) =>
            proofStreamFingerprint(
                measurement.canonicalInputByteLength,
                measurement.canonicalInputSha512Hex,
            ),
        )
        .sort();

const equalFingerprintLists = (
    left: readonly string[],
    right: readonly string[],
): boolean =>
    left.length === right.length &&
    left.every((value, valueIndex) => value === right[valueIndex]);

const measurementsForCase = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
    caseIdentifier: string,
): readonly DesktopBrowserProofMeasurementRecord[] =>
    measurements.filter(
        (measurement) => measurement.caseIdentifier === caseIdentifier,
    );

const requireExactlyOneMeasurement = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
    caseIdentifier: string,
): DesktopBrowserProofMeasurementRecord => {
    const matchingMeasurements = measurementsForCase(
        measurements,
        caseIdentifier,
    );
    if (matchingMeasurements.length !== 1) {
        throw new Error(
            `Desktop-browser proof evidence requires exactly one ${caseIdentifier} measurement.`,
        );
    }
    const measurement = matchingMeasurements[0];
    if (measurement === undefined) {
        throw new Error(
            `Desktop-browser proof evidence omitted ${caseIdentifier}.`,
        );
    }
    return measurement;
};

const requireCancellationDeclaration = (
    measurement: DesktopBrowserProofMeasurementRecord,
): Readonly<{
    catalogSha512Hex: string;
    safeBoundaryCount: number;
    storageYieldBoundaryCount: number;
}> => {
    if (
        measurement.cancellationBoundaryCatalogSha512Hex === undefined ||
        measurement.declaredSafeBoundaryCount === undefined ||
        measurement.declaredStorageYieldBoundaryCount === undefined
    ) {
        throw new Error(
            `Desktop-browser proof evidence omitted the cancellation boundary declaration for ${measurement.caseIdentifier}.`,
        );
    }
    return Object.freeze({
        catalogSha512Hex: measurement.cancellationBoundaryCatalogSha512Hex,
        safeBoundaryCount: measurement.declaredSafeBoundaryCount,
        storageYieldBoundaryCount:
            measurement.declaredStorageYieldBoundaryCount,
    });
};

const validateGenerationSessionContract = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
): void => {
    const repetitionRequirement =
        desktopBrowserProofGenerationRepetitionRequirement;
    const cancellationRequirement =
        desktopBrowserProofCancellationCoverageRequirement;
    if (
        cancellationRequirement.declarationCaseIdentifier !==
        repetitionRequirement.caseIdentifier
    ) {
        throw new Error(
            'The proof-evidence catalog assigned cancellation declarations to a different generation case.',
        );
    }
    const repeatedMeasurements = measurementsForCase(
        measurements,
        repetitionRequirement.caseIdentifier,
    );
    const coldRunCount = repeatedMeasurements.filter(
        ({ browserCacheState }) => browserCacheState === 'cold',
    ).length;
    const warmRunCount = repeatedMeasurements.filter(
        ({ browserCacheState }) => browserCacheState === 'warm',
    ).length;
    if (
        coldRunCount < repetitionRequirement.minimumColdRunCount ||
        warmRunCount < repetitionRequirement.minimumWarmRunCount
    ) {
        throw new Error(
            `Desktop-browser proof evidence requires at least ${String(repetitionRequirement.minimumColdRunCount)} cold and ${String(repetitionRequirement.minimumWarmRunCount)} warm ${repetitionRequirement.caseIdentifier} runs.`,
        );
    }
    const declarations = repeatedMeasurements.map(
        requireCancellationDeclaration,
    );
    const declarationFingerprints = new Set(
        declarations.map(
            (declaration) =>
                `${declaration.catalogSha512Hex}:${String(declaration.safeBoundaryCount)}:${String(declaration.storageYieldBoundaryCount)}`,
        ),
    );
    if (declarationFingerprints.size !== 1) {
        throw new Error(
            'Desktop-browser proof generation runs declared different cancellation boundary catalogs.',
        );
    }
    const declaration = declarations[0];
    if (declaration === undefined) {
        throw new Error(
            'Desktop-browser proof evidence omitted its cancellation boundary declaration source.',
        );
    }
    const cancellationMeasurements = measurementsForCase(
        measurements,
        cancellationRequirement.cancellationCaseIdentifier,
    );
    const declaredBoundaryCount =
        declaration.safeBoundaryCount + declaration.storageYieldBoundaryCount;
    if (
        declaredBoundaryCount === 0 ||
        cancellationMeasurements.length !== declaredBoundaryCount
    ) {
        throw new Error(
            'Desktop-browser proof evidence did not cancel at every declared storage yield and safe boundary.',
        );
    }
    const cancellationBoundaries = [...cancellationMeasurements]
        .sort((left, right) => left.runOrdinal - right.runOrdinal)
        .map((measurement) => {
            const measurementDeclaration =
                requireCancellationDeclaration(measurement);
            if (
                measurementDeclaration.catalogSha512Hex !==
                    declaration.catalogSha512Hex ||
                measurementDeclaration.safeBoundaryCount !==
                    declaration.safeBoundaryCount ||
                measurementDeclaration.storageYieldBoundaryCount !==
                    declaration.storageYieldBoundaryCount ||
                measurement.cancellationBoundaryIdentifier === undefined ||
                measurement.cancellationBoundaryKind === undefined ||
                measurement.cancellationBoundaryOrdinal === undefined
            ) {
                throw new Error(
                    'Desktop-browser proof cancellation evidence does not match its declared boundary catalog.',
                );
            }
            return Object.freeze({
                boundaryIdentifier: measurement.cancellationBoundaryIdentifier,
                boundaryKind: measurement.cancellationBoundaryKind,
                boundaryOrdinal: measurement.cancellationBoundaryOrdinal,
            });
        });
    for (const [boundaryKind, expectedCount] of [
        ['safe-boundary', declaration.safeBoundaryCount],
        ['storage-yield', declaration.storageYieldBoundaryCount],
    ] as const) {
        const observedOrdinals = cancellationBoundaries
            .filter((boundary) => boundary.boundaryKind === boundaryKind)
            .map((boundary) => boundary.boundaryOrdinal)
            .sort((left, right) => left - right);
        if (
            observedOrdinals.length !== expectedCount ||
            observedOrdinals.some(
                (ordinal, ordinalIndex) => ordinal !== ordinalIndex + 1,
            )
        ) {
            throw new Error(
                `Desktop-browser proof evidence omitted or repeated a ${boundaryKind} cancellation ordinal.`,
            );
        }
    }
    if (
        deriveDesktopBrowserProofCancellationBoundaryCatalogSha512Hex(
            cancellationBoundaries,
        ) !== declaration.catalogSha512Hex
    ) {
        throw new Error(
            'Desktop-browser proof cancellation evidence does not match its catalog digest.',
        );
    }

    const cancellationReuseMeasurement = requireExactlyOneMeasurement(
        measurements,
        cancellationRequirement.reuseCaseIdentifier,
    );
    const reusedCancellationMeasurement = cancellationMeasurements.find(
        (measurement) =>
            measurement.runOrdinal === cancellationReuseMeasurement.runOrdinal,
    );
    if (
        reusedCancellationMeasurement === undefined ||
        cancellationReuseMeasurement.workerInstanceIdentifier !==
            reusedCancellationMeasurement.workerInstanceIdentifier ||
        cancellationReuseMeasurement.workerOperationOrdinal !==
            reusedCancellationMeasurement.workerOperationOrdinal + 1
    ) {
        throw new Error(
            'Desktop-browser proof evidence did not reuse the same worker immediately after cancellation.',
        );
    }

    const refusalRequirement = desktopBrowserProofRefusalReuseRequirement;
    const refusalMeasurement = requireExactlyOneMeasurement(
        measurements,
        refusalRequirement.refusalCaseIdentifier,
    );
    const refusalReuseMeasurement = requireExactlyOneMeasurement(
        measurements,
        refusalRequirement.reuseCaseIdentifier,
    );
    if (
        refusalMeasurement.refusalReasonIdentifier === undefined ||
        refusalReuseMeasurement.workerInstanceIdentifier !==
            refusalMeasurement.workerInstanceIdentifier ||
        refusalReuseMeasurement.workerOperationOrdinal !==
            refusalMeasurement.workerOperationOrdinal + 1
    ) {
        throw new Error(
            'Desktop-browser proof evidence did not reuse the same worker immediately after refusal.',
        );
    }

    const parityMeasurement = requireExactlyOneMeasurement(
        measurements,
        desktopBrowserProofDeterministicParityCaseIdentifier,
    );
    parseDesktopBrowserProofDeterministicParityBinding({
        deterministicCoinBindingSha512Hex:
            parityMeasurement.deterministicCoinBindingSha512Hex,
        nativeProofByteLength: parityMeasurement.nativeReferenceByteLength,
        nativeProofSha512Hex: parityMeasurement.nativeReferenceSha512Hex,
        wasmProofByteLength: parityMeasurement.canonicalOutputByteLength,
        wasmProofSha512Hex: parityMeasurement.outputSha512Hex,
    });
};

const validateFreshVerificationWorkers = (
    measurements: readonly DesktopBrowserProofMeasurementRecord[],
): void => {
    const workerInstanceIdentifiers = measurements.map(
        ({ workerInstanceIdentifier }) => workerInstanceIdentifier,
    );
    if (
        new Set(workerInstanceIdentifiers).size !==
            workerInstanceIdentifiers.length ||
        measurements.some(
            ({ workerOperationOrdinal }) => workerOperationOrdinal !== 1,
        )
    ) {
        throw new Error(
            'Desktop-browser proof verification did not use one fresh worker instance per transported proof.',
        );
    }
};

export const validateDesktopBrowserProofEvidenceOwnershipMatrix = (
    sessionEventSets: readonly DesktopBrowserProofEvidenceSessionEvents[],
    expectedBindings?: Readonly<{
        wasmSha256Hex: string;
    }>,
): readonly ValidatedDesktopBrowserProofEvidenceSession[] => {
    const sessionDefinitionsByIdentifier = new Map(
        desktopBrowserProofEvidenceSessionDefinitions.map((session) => [
            session.sessionIdentifier,
            session,
        ]),
    );
    const validatedSessionsByIdentifier = new Map<
        string,
        ValidatedDesktopBrowserProofEvidenceSession
    >();

    for (const sessionEventSet of sessionEventSets) {
        const session = sessionDefinitionsByIdentifier.get(
            sessionEventSet.sessionIdentifier,
        );
        if (session === undefined) {
            throw new Error(
                `Desktop-browser proof evidence reported an unexpected ownership session: ${sessionEventSet.sessionIdentifier}.`,
            );
        }
        if (validatedSessionsByIdentifier.has(session.sessionIdentifier)) {
            throw new Error(
                `Desktop-browser proof evidence repeated ownership session ${session.sessionIdentifier}.`,
            );
        }
        const measurements =
            validateDesktopBrowserProofMeasurementEventsForRequiredCases(
                sessionEventSet.testEvents,
                requiredCaseIdentifiersByOwnershipRole[session.ownershipRole],
                expectedBindings,
            );
        if (session.ownershipRole === 'generation') {
            validateGenerationSessionContract(measurements);
        } else {
            validateFreshVerificationWorkers(measurements);
        }
        validatedSessionsByIdentifier.set(session.sessionIdentifier, {
            measurements,
            session,
        });
    }

    const missingSessionIdentifiers =
        desktopBrowserProofEvidenceSessionDefinitions
            .map((session) => session.sessionIdentifier)
            .filter(
                (sessionIdentifier) =>
                    !validatedSessionsByIdentifier.has(sessionIdentifier),
            );
    if (missingSessionIdentifiers.length > 0) {
        throw new Error(
            `Desktop-browser proof evidence omitted required ownership sessions: ${missingSessionIdentifiers.join(', ')}.`,
        );
    }

    const validatedSessions = desktopBrowserProofEvidenceSessionDefinitions.map(
        (session) => {
            const validatedSession = validatedSessionsByIdentifier.get(
                session.sessionIdentifier,
            );
            if (validatedSession === undefined) {
                throw new Error(
                    `Desktop-browser proof evidence did not validate ownership session ${session.sessionIdentifier}.`,
                );
            }
            return validatedSession;
        },
    );
    const observedSuiteIdentifiers = new Set(
        validatedSessions.flatMap(({ measurements }) =>
            measurements.map((measurement) => measurement.suiteId),
        ),
    );
    const observedWasmHashes = new Set(
        validatedSessions.flatMap(({ measurements }) =>
            measurements.map((measurement) => measurement.wasmSha256Hex),
        ),
    );
    if (observedSuiteIdentifiers.size !== 1 || observedWasmHashes.size !== 1) {
        throw new Error(
            'Desktop-browser proof-evidence ownership sessions did not use one exact suite and one exact processed WebAssembly module.',
        );
    }

    const generationSessions = validatedSessions.filter(
        ({ session }) => session.ownershipRole === 'generation',
    );
    const verificationSessions = validatedSessions.filter(
        ({ session }) => session.ownershipRole === 'verification',
    );
    for (const [
        generationCaseIdentifier,
        verificationCaseIdentifier,
    ] of transportedProofCasePairs) {
        const transportedFingerprints = generationSessions
            .flatMap(({ measurements }) =>
                generatedProofFingerprints(
                    measurements,
                    generationCaseIdentifier,
                ),
            )
            .sort();
        for (const verificationSession of verificationSessions) {
            const observedVerificationFingerprints = verifiedProofFingerprints(
                verificationSession.measurements,
                verificationCaseIdentifier,
            );
            if (
                !equalFingerprintLists(
                    observedVerificationFingerprints,
                    transportedFingerprints,
                )
            ) {
                throw new Error(
                    `Desktop-browser proof-evidence ownership session ${verificationSession.session.sessionIdentifier} did not freshly verify exactly the transported bytes for ${generationCaseIdentifier}.`,
                );
            }
        }
    }

    return validatedSessions;
};

export const projectDesktopBrowserProofEvidenceNetworkSessions = (
    sessionEventSets: readonly DesktopBrowserProofEvidenceSessionEvents[],
    expectedBindings?: Readonly<{
        wasmSha256Hex: string;
    }>,
): readonly DesktopBrowserProofEvidenceNetworkSessionProjection[] => {
    const validatedSessions =
        validateDesktopBrowserProofEvidenceOwnershipMatrix(
            sessionEventSets,
            expectedBindings,
        );
    const eventSetsBySessionIdentifier = new Map(
        sessionEventSets.map((sessionEventSet) => [
            sessionEventSet.sessionIdentifier,
            sessionEventSet,
        ]),
    );
    const networkSessionProjections = validatedSessions
        .filter(({ session }) => session.ownershipRole === 'generation')
        .map(({ measurements, session }) => {
            const sessionEventSet = eventSetsBySessionIdentifier.get(
                session.sessionIdentifier,
            );
            if (sessionEventSet === undefined) {
                throw new Error(
                    `Desktop-browser network projection lost ownership session ${session.sessionIdentifier}.`,
                );
            }
            return Object.freeze({
                browserEngine: session.browserEngine,
                projection: projectDesktopBrowserNetworkEvidence({
                    evidenceEvents: sessionEventSet.testEvents,
                    measurements,
                    productionAccountingAuthority:
                        requireProductionNetworkAccountingAuthority(
                            sessionEventSet.testEvents,
                        ),
                }),
                sessionIdentifier: session.sessionIdentifier,
            });
        });
    return Object.freeze(networkSessionProjections);
};

const deriveProcessedWasmSha256Hex = async (): Promise<string> => {
    const [producerBytes, publicSdkBytes] = await Promise.all([
        readFile(processedWasmKernelPath),
        readFile(publicSdkWasmKernelPath),
    ]);
    if (!producerBytes.equals(publicSdkBytes)) {
        throw new Error(
            'The public SDK WebAssembly module differs from the processed producer artifact.',
        );
    }
    return createHash('sha256')
        .update(normalizeTranscriptCoreKernelBytesForHash(producerBytes))
        .digest('hex');
};

const recordResourceWindows = async (input: {
    expectedWasmSha256Hex: string;
    processMemoryDiagnosticPath: string;
    runLog: ActiveLocalRunLog;
    session: DesktopBrowserProofEvidenceSessionDefinition;
    testEventPath: string;
}): Promise<readonly JsonRecord[]> => {
    const [testEvents, memoryEvents] = await Promise.all([
        readJsonLines(input.testEventPath),
        readJsonLines(input.processMemoryDiagnosticPath),
    ]);
    const measurements =
        validateDesktopBrowserProofMeasurementEventsForRequiredCases(
            testEvents,
            requiredCaseIdentifiersByOwnershipRole[input.session.ownershipRole],
            { wasmSha256Hex: input.expectedWasmSha256Hex },
        );

    for (const measurement of measurements) {
        const windowSamples = memoryEvents.filter((event) => {
            if (event.eventType !== 'resource-sample') {
                return false;
            }
            const recordedAtUnixMilliseconds = optionalSafeInteger(
                event,
                'recordedAtUnixMilliseconds',
            );
            return (
                recordedAtUnixMilliseconds !== undefined &&
                recordedAtUnixMilliseconds >=
                    measurement.startedAtUnixMilliseconds &&
                recordedAtUnixMilliseconds <=
                    measurement.finishedAtUnixMilliseconds
            );
        });
        const processTreeBaselineByteLength = nearestBaselineValue(
            memoryEvents,
            'processTreeResidentMemoryBytes',
            measurement.startedAtUnixMilliseconds,
        );
        const processTreePeakByteLength = maximumObservedValue(
            windowSamples,
            'processTreeResidentMemoryBytes',
        );
        const backendBaselineByteLength = nearestBaselineValue(
            memoryEvents,
            'backendCurrentMemoryBytes',
            measurement.startedAtUnixMilliseconds,
        );
        const backendPeakByteLength = maximumObservedValue(
            windowSamples,
            'backendCurrentMemoryBytes',
        );
        const processTreePeakIncreaseByteLength = optionalIncrease(
            processTreePeakByteLength,
            processTreeBaselineByteLength,
        );
        const measuredProofByteLength =
            measurement.executionKind === 'fresh-generation' ||
            measurement.executionKind === 'resumed-generation'
                ? measurement.canonicalOutputByteLength
                : measurement.executionKind === 'verification'
                  ? measurement.canonicalInputByteLength
                  : undefined;
        input.runLog.writeEvent({
            details: {
                browserEngine: input.session.browserEngine,
                caseIdentifier: measurement.caseIdentifier,
                executionKind: measurement.executionKind,
                ownershipRole: input.session.ownershipRole,
                physicalBrowserMeasurements: {
                    browserProcessResidentMemoryEndByteLength:
                        measurement.browserProcessResidentMemoryEndByteLength,
                    browserProcessResidentMemoryPeakByteLength:
                        measurement.browserProcessResidentMemoryPeakByteLength,
                    browserProcessResidentMemoryStartByteLength:
                        measurement.browserProcessResidentMemoryStartByteLength,
                    javascriptHeapEndByteLength:
                        measurement.javascriptHeapEndByteLength,
                    javascriptHeapPeakByteLength:
                        measurement.javascriptHeapPeakByteLength,
                    javascriptHeapStartByteLength:
                        measurement.javascriptHeapStartByteLength,
                    resourceAccounting: measurement.resourceAccounting,
                    wasmLinearMemoryEndPageCount:
                        measurement.wasmLinearMemoryEndPageCount,
                    wasmLinearMemoryPeakPageCount:
                        measurement.wasmLinearMemoryPeakPageCount,
                    wasmLinearMemoryStartPageCount:
                        measurement.wasmLinearMemoryStartPageCount,
                },
                resourceSampleCount: windowSamples.length,
                sessionIdentifier: input.session.sessionIdentifier,
                softPlanningVariances: {
                    copiedBuffer: planningVariance(
                        measurement.copiedBufferPeakByteLength,
                        softPlanningTargets.copiedBufferByteLength,
                    ),
                    externalScratch: planningVariance(
                        measurement.externalScratchPeakByteLength,
                        softPlanningTargets.externalScratchByteLength,
                    ),
                    wasmLinearMemory: planningVariance(
                        measurement.wasmLinearMemoryPeakByteLength,
                        softPlanningTargets.wasmLinearMemoryByteLength,
                    ),
                    ...(processTreePeakIncreaseByteLength === undefined
                        ? {}
                        : {
                              browserProcessIncrease: planningVariance(
                                  processTreePeakIncreaseByteLength,
                                  softPlanningTargets.browserProcessIncreaseByteLength,
                              ),
                          }),
                },
                ...(measuredProofByteLength === undefined
                    ? {}
                    : {
                          selectedProofEvidenceGate: {
                              maximumProofByteLength:
                                  selectedProofEvidenceGate.proofByteLength,
                              measuredProofByteLength,
                          },
                      }),
                suiteId: measurement.suiteId,
                wasmSha256Hex: measurement.wasmSha256Hex,
                ...(backendBaselineByteLength === undefined
                    ? {}
                    : { backendBaselineByteLength }),
                ...(backendPeakByteLength === undefined
                    ? {}
                    : { backendPeakByteLength }),
                ...(optionalIncrease(
                    backendPeakByteLength,
                    backendBaselineByteLength,
                ) === undefined
                    ? {}
                    : {
                          backendPeakIncreaseByteLength: optionalIncrease(
                              backendPeakByteLength,
                              backendBaselineByteLength,
                          ),
                      }),
                ...(processTreeBaselineByteLength === undefined
                    ? {}
                    : { processTreeBaselineByteLength }),
                ...(processTreePeakByteLength === undefined
                    ? {}
                    : { processTreePeakByteLength }),
                ...(processTreePeakIncreaseByteLength === undefined
                    ? {}
                    : {
                          processTreePeakIncreaseByteLength,
                      }),
            },
            eventType: 'desktop-browser-proof-resource-window',
        });
    }
    return testEvents;
};

export const runDesktopBrowserProofEvidence = async (): Promise<void> => {
    const rawArguments = process.argv
        .slice(2)
        .filter((argument) => argument !== '--');
    if (rawArguments.length > 0) {
        throw new Error(
            'The desktop-browser proof-evidence runner accepts no arguments.',
        );
    }
    await runWithLocalRunLog(
        {
            commandLineArguments: process.argv.slice(2),
            lanes: [laneLabel],
            scriptName: 'test:browser:proof-evidence',
        },
        async (runLog) => {
            const packageManagerRunner = resolvePackageManagerRunner();
            const processMemoryGuard = createProcessMemoryGuard({
                insufficientFreeMemoryRunDescription:
                    'Desktop-browser proof evidence',
            });
            const commandEnvironment: NodeJS.ProcessEnv = { ...process.env };
            for (const laneOwnedEnvironmentVariable of [
                evidenceOwnershipRoleEnvironmentVariable,
                evidenceTransportDirectoryEnvironmentVariable,
                evidenceSessionIdentifierEnvironmentVariable,
                evidenceManifestAuthenticationEnvironmentVariable,
            ]) {
                delete commandEnvironment[laneOwnedEnvironmentVariable];
            }
            const buildCommand = createPackageManagerCommand(
                'build the processed release WebAssembly workspace',
                ['run', 'build'],
                {
                    env: commandEnvironment,
                    logFileSlug: 'build-desktop-browser-proof-evidence',
                    packageManagerRunner,
                },
            );
            let exitCode = await runCommandsInSeries([buildCommand], {
                outputMode: 'inherit',
                runLog,
            });
            if (exitCode !== 0) {
                process.exitCode = exitCode;
                return;
            }

            const expectedWasmSha256Hex = await deriveProcessedWasmSha256Hex();
            commandEnvironment[expectedWasmSha256EnvironmentVariable] =
                expectedWasmSha256Hex;
            const transportDirectoryPath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'desktop-browser-proof-evidence-transport',
            );
            await mkdir(transportDirectoryPath, { recursive: true });

            await withLocalHeavyLaneLease({
                action: async () => {
                    exitCode = await runCommandsInSeries(
                        [processMemoryGuard.buildVerificationCommand()],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) {
                        return;
                    }
                    const sessionEventSets: DesktopBrowserProofEvidenceSessionEvents[] =
                        [];
                    const authenticatedGenerationManifestDigests = new Map<
                        DesktopBrowserProofGenerationSessionIdentifier,
                        string
                    >();
                    for (const session of desktopBrowserProofEvidenceSessionDefinitions) {
                        const manifestAuthentication =
                            session.ownershipRole === 'verification'
                                ? serializeDesktopBrowserProofTransportManifestAuthenticationBindings(
                                      {
                                          'chromium-generation': (() => {
                                              const digest =
                                                  authenticatedGenerationManifestDigests.get(
                                                      'chromium-generation',
                                                  );
                                              if (digest === undefined) {
                                                  throw new Error(
                                                      'The Chromium generation session did not authenticate its transport manifest.',
                                                  );
                                              }
                                              return digest;
                                          })(),
                                      },
                                  )
                                : undefined;
                        const sessionCommandEnvironment: NodeJS.ProcessEnv = {
                            ...commandEnvironment,
                            [evidenceOwnershipRoleEnvironmentVariable]:
                                session.ownershipRole,
                            [evidenceSessionIdentifierEnvironmentVariable]:
                                session.sessionIdentifier,
                            [evidenceTransportDirectoryEnvironmentVariable]:
                                transportDirectoryPath,
                            ...(manifestAuthentication === undefined
                                ? {}
                                : {
                                      [evidenceManifestAuthenticationEnvironmentVariable]:
                                          manifestAuthentication,
                                  }),
                            SEALED_LATTICE_TEST_PROJECT_LABEL:
                                session.testProjectLabel,
                        };
                        const processMemoryDiagnosticPath = path.join(
                            runLog.runDirectoryPath,
                            'resources',
                            `process-memory-guard-desktop-browser-proof-evidence-${session.sessionIdentifier}.jsonl`,
                        );
                        const testEventPath = path.join(
                            runLog.runDirectoryPath,
                            'tests',
                            `${session.testProjectLabel}.jsonl`,
                        );
                        const browserCommand = createPackageManagerCommand(
                            `run the manual desktop ${session.browserEngine} proof-evidence ${session.ownershipRole} session`,
                            [
                                'exec',
                                'vitest',
                                '--project',
                                session.vitestProjectName,
                                '--run',
                                browserEvidenceTestFile,
                            ],
                            {
                                env: sessionCommandEnvironment,
                                logFileSlug: `vitest-desktop-browser-proof-evidence-${session.sessionIdentifier}`,
                                packageManagerRunner,
                            },
                        );
                        exitCode = await runCommandsInSeries(
                            [
                                processMemoryGuard.guardCommand(
                                    browserCommand,
                                    {
                                        diagnosticsPath:
                                            processMemoryDiagnosticPath,
                                    },
                                ),
                            ],
                            { outputMode: 'inherit', runLog },
                        );
                        if (exitCode !== 0) {
                            return;
                        }
                        const testEvents = await recordResourceWindows({
                            expectedWasmSha256Hex,
                            processMemoryDiagnosticPath,
                            runLog,
                            session,
                            testEventPath,
                        });
                        sessionEventSets.push({
                            sessionIdentifier: session.sessionIdentifier,
                            testEvents,
                        });
                        if (session.ownershipRole === 'generation') {
                            const generationSessionIdentifier =
                                requireDesktopBrowserProofGenerationSessionIdentifier(
                                    session.sessionIdentifier,
                                );
                            const generationMeasurements =
                                validateDesktopBrowserProofMeasurementEventsForRequiredCases(
                                    testEvents,
                                    requiredCaseIdentifiersByOwnershipRole.generation,
                                    {
                                        wasmSha256Hex: expectedWasmSha256Hex,
                                    },
                                );
                            const generationSuiteId =
                                generationMeasurements[0]?.suiteId;
                            if (generationSuiteId === undefined) {
                                throw new Error(
                                    `The ${session.browserEngine} generation session produced no suite-bound measurements.`,
                                );
                            }
                            const authenticatedManifest =
                                await readDesktopBrowserProofTransportManifest({
                                    expectedSuiteId: generationSuiteId,
                                    expectedWasmSha256Hex,
                                    generationSessionIdentifier,
                                    readFile: async (filePath, encoding) =>
                                        readFile(filePath, encoding),
                                    transportDirectoryPath,
                                });
                            authenticatedGenerationManifestDigests.set(
                                generationSessionIdentifier,
                                authenticatedManifest.manifestSha512Hex,
                            );
                        }
                    }
                    const networkSessionProjections =
                        projectDesktopBrowserProofEvidenceNetworkSessions(
                            sessionEventSets,
                            { wasmSha256Hex: expectedWasmSha256Hex },
                        );
                    for (const networkSessionProjection of networkSessionProjections) {
                        runLog.writeEvent({
                            details: networkSessionProjection,
                            eventType:
                                'desktop-browser-proof-network-projection',
                        });
                    }
                },
                laneLabel,
                runLog,
            });
            process.exitCode = exitCode;
        },
    );
};

if (import.meta.main) {
    void runDesktopBrowserProofEvidence();
}
