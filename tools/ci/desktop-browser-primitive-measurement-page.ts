import {
    openIndexedDbUntrustedStorageAdapter,
    type IndexedDbUntrustedStorageAdapter,
} from "../../packages/protocol/src/runtime/indexed-db-untrusted-storage-adapter.js";
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAuthenticatedRepairProtection,
    type UntrustedStorageExclusiveCapacityReservation,
} from "../../packages/protocol/src/runtime/untrusted-storage-transaction-store.js";

import {
    desktopBrowserBoundaryCopyIterationCount,
    primitiveMeasurementCaseCatalog,
    requireCompletePrimitiveMeasurementCatalog,
    validatePrimitiveMeasurementRecord,
    type DesktopBrowserAuthenticatedStorageMeasurement,
    type DesktopBrowserBoundaryCopyMeasurement,
    type DesktopBrowserFocusedPrimitiveMeasurementEvidence,
    type DesktopBrowserPrimitiveCaseMeasurement,
    type DesktopBrowserPrimitiveMeasurementEvidence,
    type PrimitiveMeasurementRecord,
} from "./primitive-measurement-evidence.js";

type PrimitiveMeasurementWasmExports = Readonly<{
    memory: WebAssembly.Memory;
    sealed_lattice_allocate(length: number): number;
    sealed_lattice_deallocate(pointer: number, length: number): void;
    sealed_lattice_primitive_measurement_with_length(
        caseIdentifier: number,
        outputLengthPointer: number,
        outputStatusPointer: number,
    ): number;
}>;

const wasm32UsizeByteLength = 4;
const browserStorageIterationCount = 4;
const browserStorageReadPassCount = 2;
const browserStorageMaximumDeletionBatchRecordCount = 64;
const browserBoundaryCopyWarmupIterationCount = 8;
const logicalRecordPrefix = "primitive-measurement/";
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const requireNumberExport = (
    exports: WebAssembly.Exports,
    exportName: keyof PrimitiveMeasurementWasmExports,
): ((...arguments_: number[]) => number | void) => {
    const candidate = exports[exportName];
    if (typeof candidate !== "function") {
        throw new Error(
            `Primitive-measurement WASM export ${exportName} is absent.`,
        );
    }
    return candidate as (...arguments_: number[]) => number | void;
};

const instantiateMeasurementKernel = async (
    wasmBytes: ArrayBuffer,
): Promise<PrimitiveMeasurementWasmExports> => {
    const instantiated = await WebAssembly.instantiate(wasmBytes, {
        env: {
            sealed_lattice_primitive_measurement_now_milliseconds: () =>
                performance.now(),
        },
    });
    const exports = instantiated.instance.exports;
    if (!(exports.memory instanceof WebAssembly.Memory)) {
        throw new Error("Primitive-measurement WASM memory export is absent.");
    }
    return Object.freeze({
        memory: exports.memory,
        sealed_lattice_allocate: requireNumberExport(
            exports,
            "sealed_lattice_allocate",
        ) as (length: number) => number,
        sealed_lattice_deallocate: requireNumberExport(
            exports,
            "sealed_lattice_deallocate",
        ),
        sealed_lattice_primitive_measurement_with_length: requireNumberExport(
            exports,
            "sealed_lattice_primitive_measurement_with_length",
        ) as (caseIdentifier: number, outputLengthPointer: number) => number,
    });
};

const runPrimitiveCase = async (
    wasmBytes: ArrayBuffer,
    caseIdentifier: number,
): Promise<DesktopBrowserPrimitiveCaseMeasurement> => {
    const kernel = await instantiateMeasurementKernel(wasmBytes);
    const wasmMemoryByteLengthBefore = kernel.memory.buffer.byteLength;
    const outputLengthPointer = kernel.sealed_lattice_allocate(
        wasm32UsizeByteLength,
    );
    if (outputLengthPointer === 0) {
        throw new Error(
            "Primitive-measurement WASM refused its output-length allocation.",
        );
    }
    const outputStatusPointer = kernel.sealed_lattice_allocate(
        wasm32UsizeByteLength,
    );
    if (outputStatusPointer === 0) {
        kernel.sealed_lattice_deallocate(
            outputLengthPointer,
            wasm32UsizeByteLength,
        );
        throw new Error(
            "Primitive-measurement WASM refused its output-status allocation.",
        );
    }
    let outputPointer = 0;
    let outputLength = 0;
    const startedAt = performance.now();
    try {
        outputPointer = kernel.sealed_lattice_primitive_measurement_with_length(
            caseIdentifier,
            outputLengthPointer,
            outputStatusPointer,
        );
        const outputView = new DataView(kernel.memory.buffer);
        outputLength = outputView.getUint32(outputLengthPointer, true);
        const outputStatus = outputView.getUint32(outputStatusPointer, true);
        if (
            outputPointer === 0 ||
            outputLength === 0 ||
            outputLength > 65_536
        ) {
            throw new Error(
                `Primitive-measurement WASM case ${String(caseIdentifier)} returned an invalid result extent (pointer ${String(outputPointer)}, length ${String(outputLength)}, status ${String(outputStatus)}, memory ${String(kernel.memory.buffer.byteLength)} bytes).`,
            );
        }
        const resultBytes = new Uint8Array(
            kernel.memory.buffer,
            outputPointer,
            outputLength,
        ).slice();
        if (outputStatus === 1) {
            const refusal = textDecoder.decode(resultBytes);
            resultBytes.fill(0);
            throw new Error(
                `Primitive-measurement WASM case ${String(caseIdentifier)} refused: ${refusal}`,
            );
        }
        if (outputStatus !== 0) {
            resultBytes.fill(0);
            throw new Error(
                `Primitive-measurement WASM case ${String(caseIdentifier)} returned unsupported status ${String(outputStatus)}.`,
            );
        }
        const record = validatePrimitiveMeasurementRecord(
            JSON.parse(textDecoder.decode(resultBytes)) as unknown,
            "wasm32-unknown-unknown",
        );
        resultBytes.fill(0);
        return Object.freeze({
            record,
            wallElapsedMilliseconds: performance.now() - startedAt,
            wasmMemoryByteLengthAfter: kernel.memory.buffer.byteLength,
            wasmMemoryByteLengthBefore,
        });
    } finally {
        if (outputPointer !== 0 && outputLength !== 0) {
            kernel.sealed_lattice_deallocate(outputPointer, outputLength);
        }
        kernel.sealed_lattice_deallocate(
            outputLengthPointer,
            wasm32UsizeByteLength,
        );
        kernel.sealed_lattice_deallocate(
            outputStatusPointer,
            wasm32UsizeByteLength,
        );
    }
};

const makePatternedRecord = (
    byteLength: number,
    recordOrdinal: number,
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(new ArrayBuffer(byteLength));
    for (
        let byteOrdinal = 0;
        byteOrdinal < bytes.byteLength;
        byteOrdinal += 1
    ) {
        bytes[byteOrdinal] =
            (byteOrdinal * 37 + recordOrdinal * 17 + 11) & 0xff;
    }
    return bytes;
};

const assertPatternedRecord = (
    bytes: Uint8Array,
    recordOrdinal: number,
): void => {
    for (
        let byteOrdinal = 0;
        byteOrdinal < bytes.byteLength;
        byteOrdinal += 1
    ) {
        const expected = (byteOrdinal * 37 + recordOrdinal * 17 + 11) & 0xff;
        if (bytes[byteOrdinal] !== expected) {
            throw new Error(
                `Authenticated browser storage changed record ${String(recordOrdinal)} at byte ${String(byteOrdinal)}.`,
            );
        }
    }
};

const copyToArrayBufferView = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
    const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
    copy.set(bytes);
    return copy;
};

const createRepairProtection =
    async (): Promise<UntrustedStorageAuthenticatedRepairProtection> => {
        const authenticationKey = await crypto.subtle.generateKey(
            { length: 256, name: "AES-GCM" },
            false,
            ["decrypt", "encrypt"],
        );
        const repairIdentity = crypto.getRandomValues(new Uint8Array(64));
        return Object.freeze({
            deriveDigest: async (bytes: Uint8Array) =>
                new Uint8Array(
                    await crypto.subtle.digest(
                        "SHA-512",
                        copyToArrayBufferView(bytes),
                    ),
                ),
            open: async (sealedBytes: Uint8Array) => {
                if (sealedBytes.byteLength < 28) {
                    throw new Error(
                        "Primitive-measurement repair head is truncated.",
                    );
                }
                return new Uint8Array(
                    await crypto.subtle.decrypt(
                        {
                            iv: copyToArrayBufferView(
                                sealedBytes.subarray(0, 12),
                            ),
                            name: "AES-GCM",
                        },
                        authenticationKey,
                        copyToArrayBufferView(sealedBytes.subarray(12)),
                    ),
                );
            },
            repairIdentity,
            seal: async (plaintext: Uint8Array) => {
                const nonce = crypto.getRandomValues(new Uint8Array(12));
                const ciphertext = new Uint8Array(
                    await crypto.subtle.encrypt(
                        { iv: nonce, name: "AES-GCM" },
                        authenticationKey,
                        copyToArrayBufferView(plaintext),
                    ),
                );
                const sealedBytes = new Uint8Array(
                    nonce.byteLength + ciphertext.byteLength,
                );
                sealedBytes.set(nonce);
                sealedBytes.set(ciphertext, nonce.byteLength);
                return sealedBytes;
            },
        });
    };

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener("success", () => resolve(), { once: true });
        request.addEventListener(
            "error",
            () =>
                reject(
                    request.error ??
                        new Error(
                            "Primitive-measurement IndexedDB deletion failed.",
                        ),
                ),
            { once: true },
        );
        request.addEventListener(
            "blocked",
            () =>
                reject(
                    new Error(
                        "Primitive-measurement IndexedDB deletion was blocked by a leaked connection.",
                    ),
                ),
            { once: true },
        );
    });

const copyStorageEstimate = async (): Promise<
    Readonly<{ quota?: number; usage?: number }>
> => {
    const estimate = await navigator.storage.estimate();
    return Object.freeze({
        ...(estimate.quota === undefined ? {} : { quota: estimate.quota }),
        ...(estimate.usage === undefined ? {} : { usage: estimate.usage }),
    });
};

const describeMeasurementFailure = (failure: unknown): string =>
    failure instanceof Error
        ? `${failure.name}: ${failure.message}`
        : String(failure);

export const deriveDesktopBrowserAuthenticatedStorageConfiguration = (
    recordByteLength: number,
) =>
    Object.freeze({
        reservation: Object.freeze({
            initialLogicalRecordKeyPrefixes: [logicalRecordPrefix],
            maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength: 1_048_576,
            maximumAdditionalOwnedRecordCount: browserStorageIterationCount * 2,
            maximumAdditionalStoredValueByteLength:
                recordByteLength * browserStorageIterationCount + 1_048_576,
            maximumDeletionBatchRecordCount:
                browserStorageMaximumDeletionBatchRecordCount,
        }),
        storeLimits: Object.freeze({
            maximumActiveTransactionCount: 1,
            maximumLeaseByteLength: recordByteLength,
            maximumLeaseCountPerTransaction:
                browserStorageMaximumDeletionBatchRecordCount,
            maximumOwnedRecordCount: 64,
            maximumStoredValueByteLength: 64 * 1_048_576,
            maximumTransactionByteLength: recordByteLength,
            maximumTransactionLifetimeMilliseconds: 60_000,
        }),
    });

export const runDesktopBrowserAuthenticatedStorageMeasurement = async (
    recordByteLength: number,
): Promise<DesktopBrowserAuthenticatedStorageMeasurement> => {
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    const databaseName = `sealed-lattice-primitive-measurement-${Array.from(
        randomBytes,
        (byte) => byte.toString(16).padStart(2, "0"),
    ).join("")}`;
    randomBytes.fill(0);
    const storageEstimateBefore = await copyStorageEstimate();
    let adapter: IndexedDbUntrustedStorageAdapter | undefined;
    let reservation: UntrustedStorageExclusiveCapacityReservation | undefined;
    let primaryFailure: unknown;
    let measurement: DesktopBrowserAuthenticatedStorageMeasurement | undefined;
    try {
        adapter = await openIndexedDbUntrustedStorageAdapter({ databaseName });
        const configuration =
            deriveDesktopBrowserAuthenticatedStorageConfiguration(
                recordByteLength,
            );
        const opened = await openUntrustedStorageTransactionStore({
            adapter,
            authenticatedRepairProtection: await createRepairProtection(),
            limits: configuration.storeLimits,
            namespace: "primitive-measurement",
        });
        reservation = await opened.store.reserveExclusiveCapacity(
            configuration.reservation,
        );

        let writeElapsedMilliseconds = 0;
        for (
            let recordOrdinal = 0;
            recordOrdinal < browserStorageIterationCount;
            recordOrdinal += 1
        ) {
            const logicalRecordKey = `${logicalRecordPrefix}${String(
                recordOrdinal,
            ).padStart(4, "0")}`;
            const recordBytes = makePatternedRecord(
                recordByteLength,
                recordOrdinal,
            );
            const startedAt = performance.now();
            const transaction = await opened.store.beginTransaction({
                lifetimeMilliseconds: 60_000,
            });
            try {
                const lease = await transaction.issueWriteLease({
                    declaredByteLength: recordByteLength,
                    logicalRecordKey,
                });
                await lease.write(recordBytes);
                await lease.seal(({ bytes, logicalRecordKey: observedKey }) => {
                    if (observedKey !== logicalRecordKey) {
                        throw new Error(
                            "Authenticated browser storage changed a logical record key.",
                        );
                    }
                    assertPatternedRecord(bytes, recordOrdinal);
                });
                await transaction.commit();
            } catch (error) {
                await transaction.closeAfterFailure();
                throw error;
            } finally {
                writeElapsedMilliseconds += performance.now() - startedAt;
                recordBytes.fill(0);
            }
        }

        let readElapsedMilliseconds = 0;
        for (
            let readPassOrdinal = 0;
            readPassOrdinal < browserStorageReadPassCount;
            readPassOrdinal += 1
        ) {
            for (
                let recordOrdinal = 0;
                recordOrdinal < browserStorageIterationCount;
                recordOrdinal += 1
            ) {
                const logicalRecordKey = `${logicalRecordPrefix}${String(
                    recordOrdinal,
                ).padStart(4, "0")}`;
                const startedAt = performance.now();
                const storedBytes = await opened.store.readAuthenticated({
                    authenticate: ({
                        bytes,
                        logicalRecordKey: observedKey,
                    }) => {
                        if (observedKey !== logicalRecordKey) {
                            throw new Error(
                                "Authenticated browser storage read the wrong logical key.",
                            );
                        }
                        assertPatternedRecord(bytes, recordOrdinal);
                    },
                    logicalRecordKey,
                });
                readElapsedMilliseconds += performance.now() - startedAt;
                if (storedBytes === undefined) {
                    throw new Error(
                        "Authenticated browser storage lost a measured record.",
                    );
                }
                assertPatternedRecord(storedBytes, recordOrdinal);
                storedBytes.fill(0);
            }
        }

        const cleanupStartedAt = performance.now();
        const deletedRecordCount =
            await reservation.deleteAuthenticatedLogicalRecords(
                logicalRecordPrefix,
            );
        const cleanupElapsedMilliseconds = performance.now() - cleanupStartedAt;
        if (deletedRecordCount !== browserStorageIterationCount) {
            throw new Error(
                "Authenticated browser storage deleted the wrong measured record count.",
            );
        }
        const physicalAccounting = reservation.copyPhysicalStorageAccounting();
        const storageEstimateAfter = await copyStorageEstimate();
        measurement = Object.freeze({
            cleanupElapsedMilliseconds,
            iterationCount: browserStorageIterationCount,
            physicalAccounting,
            readElapsedMilliseconds,
            readPassCount: browserStorageReadPassCount,
            recordByteLength,
            storageEstimateAfter,
            storageEstimateBefore,
            writeElapsedMilliseconds,
        });
    } catch (error) {
        primaryFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    if (reservation !== undefined) {
        try {
            await reservation.release();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (adapter !== undefined) {
        try {
            await adapter.close();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    try {
        await deleteDatabase(databaseName);
    } catch (error) {
        cleanupFailures.push(error);
    }
    if (primaryFailure !== undefined || cleanupFailures.length !== 0) {
        const failureDescriptions = [
            ...(primaryFailure === undefined
                ? []
                : [`primary=${describeMeasurementFailure(primaryFailure)}`]),
            ...cleanupFailures.map(
                (failure, failureOrdinal) =>
                    `cleanup[${String(failureOrdinal)}]=${describeMeasurementFailure(failure)}`,
            ),
        ];
        throw new Error(
            `Primitive-measurement browser storage or its cleanup failed: ${failureDescriptions.join("; ")}.`,
        );
    }
    if (measurement === undefined) {
        throw new Error(
            "Primitive-measurement browser storage completed without evidence.",
        );
    }
    return measurement;
};

export const runDesktopBrowserBoundaryCopyMeasurement = async (
    wasmBytes: ArrayBuffer,
    byteLength: number,
): Promise<DesktopBrowserBoundaryCopyMeasurement> => {
    const kernel = await instantiateMeasurementKernel(wasmBytes);
    const wasmMemoryByteLengthBefore = kernel.memory.buffer.byteLength;
    const pointer = kernel.sealed_lattice_allocate(byteLength);
    if (pointer === 0) {
        throw new Error(
            "Primitive-measurement WASM refused the boundary-copy allocation.",
        );
    }
    const source = makePatternedRecord(byteLength, 91);
    let checksum = 0x811c_9dc5;
    try {
        const destination = new Uint8Array(
            kernel.memory.buffer,
            pointer,
            byteLength,
        );
        for (
            let iterationOrdinal = 0;
            iterationOrdinal < browserBoundaryCopyWarmupIterationCount;
            iterationOrdinal += 1
        ) {
            destination.set(source);
            const copied = destination.slice();
            assertPatternedRecord(copied, 91);
            copied.fill(0);
        }

        const copyIntoStartedAt = performance.now();
        for (
            let iterationOrdinal = 0;
            iterationOrdinal < desktopBrowserBoundaryCopyIterationCount;
            iterationOrdinal += 1
        ) {
            destination.set(source);
            checksum =
                Math.imul(
                    (checksum ^
                        (destination[iterationOrdinal % byteLength] ?? 0) ^
                        iterationOrdinal) >>>
                        0,
                    0x0100_0193,
                ) >>> 0;
        }
        const copyIntoWasmElapsedMilliseconds =
            performance.now() - copyIntoStartedAt;

        const copyFromStartedAt = performance.now();
        for (
            let iterationOrdinal = 0;
            iterationOrdinal < desktopBrowserBoundaryCopyIterationCount;
            iterationOrdinal += 1
        ) {
            const copied = destination.slice();
            assertPatternedRecord(copied, 91);
            checksum =
                Math.imul(
                    (checksum ^
                        (copied[iterationOrdinal % byteLength] ?? 0) ^
                        iterationOrdinal ^
                        0x8000_0000) >>>
                        0,
                    0x0100_0193,
                ) >>> 0;
            copied.fill(0);
        }
        const copyFromWasmElapsedMilliseconds =
            performance.now() - copyFromStartedAt;
        return Object.freeze({
            byteLengthPerCopy: byteLength,
            checksumHex: checksum.toString(16).padStart(8, "0"),
            copyFromWasmElapsedMilliseconds,
            copyIntoWasmElapsedMilliseconds,
            iterationCount: desktopBrowserBoundaryCopyIterationCount,
            wasmMemoryByteLengthAfter: kernel.memory.buffer.byteLength,
            wasmMemoryByteLengthBefore,
        });
    } finally {
        source.fill(0);
        kernel.sealed_lattice_deallocate(pointer, byteLength);
    }
};

const dimensionValue = (
    record: PrimitiveMeasurementRecord,
    dimensionName: string,
): number => {
    const dimension = record.dimensions.find(
        (candidate) => candidate.name === dimensionName,
    );
    if (dimension === undefined) {
        throw new Error(
            `Primitive measurement ${record.caseName} lacks ${dimensionName}.`,
        );
    }
    return dimension.value;
};

export const runDesktopBrowserPrimitiveMeasurements = async (input: {
    browserEngine: "chromium" | "firefox";
    wasmUrl: string;
}): Promise<DesktopBrowserPrimitiveMeasurementEvidence> => {
    const response = await fetch(input.wasmUrl, { cache: "no-store" });
    if (!response.ok) {
        throw new Error(
            `Primitive-measurement WASM fetch failed with ${String(response.status)}.`,
        );
    }
    const wasmBytes = await response.arrayBuffer();
    if (wasmBytes.byteLength === 0) {
        throw new Error("Primitive-measurement WASM artifact is empty.");
    }
    const primitiveCases: DesktopBrowserPrimitiveCaseMeasurement[] = [];
    for (const catalogEntry of primitiveMeasurementCaseCatalog) {
        primitiveCases.push(
            await runPrimitiveCase(wasmBytes, catalogEntry.caseIdentifier),
        );
    }
    requireCompletePrimitiveMeasurementCatalog(
        primitiveCases.map((measurement) => measurement.record),
    );
    const authenticatedScratchRecord = primitiveCases.find(
        (measurement) => measurement.record.caseIdentifier === 6,
    );
    if (authenticatedScratchRecord === undefined) {
        throw new Error(
            "Primitive-measurement authenticated scratch-record case is absent.",
        );
    }
    const recordByteLength = dimensionValue(
        authenticatedScratchRecord.record,
        "canonicalEnvelopeByteLength",
    );
    const boundaryCopies = await runDesktopBrowserBoundaryCopyMeasurement(
        wasmBytes,
        recordByteLength,
    );
    const storage =
        await runDesktopBrowserAuthenticatedStorageMeasurement(
            recordByteLength,
        );
    return Object.freeze({
        boundaryCopies,
        browserEngine: input.browserEngine,
        browserUserAgent: navigator.userAgent,
        primitiveCases: Object.freeze(primitiveCases),
        schemaVersion: 1,
        storage,
    });
};

export const runDesktopBrowserFocusedPrimitiveMeasurements = async (input: {
    browserEngine: "chromium" | "firefox";
    caseIdentifiers: readonly number[];
    wasmUrl: string;
}): Promise<readonly DesktopBrowserFocusedPrimitiveMeasurementEvidence[]> => {
    if (
        input.caseIdentifiers.length === 0 ||
        new Set(input.caseIdentifiers).size !== input.caseIdentifiers.length ||
        primitiveMeasurementCaseCatalog
            .filter((entry) =>
                input.caseIdentifiers.includes(entry.caseIdentifier),
            )
            .some(
                (entry, entryIndex) =>
                    entry.caseIdentifier !== input.caseIdentifiers[entryIndex],
            ) ||
        input.caseIdentifiers.some(
            (caseIdentifier) =>
                !primitiveMeasurementCaseCatalog.some(
                    (entry) => entry.caseIdentifier === caseIdentifier,
                ),
        )
    ) {
        throw new Error(
            "Focused primitive-measurement case set is empty, duplicated, unsupported, or noncanonical.",
        );
    }
    const response = await fetch(input.wasmUrl, { cache: "no-store" });
    if (!response.ok) {
        throw new Error(
            `Primitive-measurement WASM fetch failed with ${String(response.status)}.`,
        );
    }
    const wasmBytes = await response.arrayBuffer();
    if (wasmBytes.byteLength === 0) {
        throw new Error("Primitive-measurement WASM artifact is empty.");
    }
    const evidence: DesktopBrowserFocusedPrimitiveMeasurementEvidence[] = [];
    for (const caseIdentifier of input.caseIdentifiers) {
        const primitiveCase = await runPrimitiveCase(wasmBytes, caseIdentifier);
        if (primitiveCase.record.caseIdentifier !== caseIdentifier) {
            throw new Error(
                `Focused primitive-measurement WASM returned case ${String(primitiveCase.record.caseIdentifier)} instead of case ${String(caseIdentifier)}.`,
            );
        }
        evidence.push(
            Object.freeze({
                browserEngine: input.browserEngine,
                browserUserAgent: navigator.userAgent,
                primitiveCase,
                schemaVersion: 1,
            }),
        );
    }
    return Object.freeze(evidence);
};
