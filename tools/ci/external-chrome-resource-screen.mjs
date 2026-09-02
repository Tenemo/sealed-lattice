const databaseName = 'sealed-lattice-external-chrome-resource-screen';
const objectStoreName = 'chunks';
const shake256OutputByteLength = 64;
const reclaimSettleLimitMilliseconds = 30_000;
const reclaimPollIntervalMilliseconds = 250;
const stableEstimateSampleCount = 4;

/**
 * @typedef {{
 *   beginDigest: () => void,
 *   finishDigest: () => Uint8Array,
 *   memory: WebAssembly.Memory,
 *   runKmac: (family: number, invocationCount: number) => number,
 *   updateDigest: (bytes: ArrayBuffer) => void,
 * }} ResourceKernel
 */

/**
 * @typedef {{
 *   chunkCount: number,
 *   chunkPayloadByteLength: number,
 *   corpusByteLength: number,
 *   expectedShake256Hex: string,
 *   finalChunkByteLength: number,
 *   kmacHistogram: readonly {
 *     phase: 'selected-evaluation',
 *     family: 'continuation-row' | 'joint-row' | 'local-row',
 *     keyByteLength: number,
 *     messageByteLength: number,
 *     outputByteLength: number,
 *     invocationCount: number,
 *   }[],
 * }} ResourceScreenConfiguration
 */

const statusElement = document.querySelector('#status');

const setStatus = (value) => {
    if (statusElement !== null) statusElement.textContent = value;
};

const transactionCompletion = (transaction) =>
    new Promise((resolve, reject) => {
        transaction.addEventListener('complete', () => resolve(), {
            once: true,
        });
        transaction.addEventListener(
            'abort',
            () => reject(new Error('The IndexedDB transaction aborted.')),
            { once: true },
        );
        transaction.addEventListener(
            'error',
            () => reject(new Error('The IndexedDB transaction failed.')),
            { once: true },
        );
    });

const openDatabase = () =>
    new Promise((resolve, reject) => {
        const request = indexedDB.open(databaseName, 1);
        request.addEventListener(
            'upgradeneeded',
            () => {
                request.result.createObjectStore(objectStoreName);
            },
            { once: true },
        );
        request.addEventListener('success', () => resolve(request.result), {
            once: true,
        });
        request.addEventListener(
            'error',
            () => reject(new Error('The resource database failed to open.')),
            { once: true },
        );
    });

const deleteDatabase = () =>
    new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'blocked',
            () => reject(new Error('The resource database deletion blocked.')),
            { once: true },
        );
        request.addEventListener(
            'error',
            () => reject(new Error('The resource database deletion failed.')),
            { once: true },
        );
    });

const storageEstimate = async () => {
    const estimate = await navigator.storage.estimate();
    if (
        !Number.isSafeInteger(estimate.quota) ||
        !Number.isSafeInteger(estimate.usage) ||
        estimate.quota < 0 ||
        estimate.usage < 0
    ) {
        throw new Error('Chrome returned an incomplete storage estimate.');
    }
    const detailedEstimate = /** @type {StorageEstimate & {
        usageDetails?: Record<string, unknown>
    }} */ (estimate);
    return {
        quota: estimate.quota,
        usage: estimate.usage,
        usageDetails: Object.fromEntries(
            Object.entries(detailedEstimate.usageDetails ?? {}).filter(
                ([, value]) => typeof value === 'number',
            ),
        ),
    };
};

const writeChunk = async (database, ordinal, bytes) => {
    const transaction = database.transaction(objectStoreName, 'readwrite', {
        durability: 'strict',
    });
    const completion = transactionCompletion(transaction);
    transaction.objectStore(objectStoreName).put(bytes, ordinal);
    await completion;
};

const clearDatabase = async (database) => {
    const transaction = database.transaction(objectStoreName, 'readwrite', {
        durability: 'strict',
    });
    const completion = transactionCompletion(transaction);
    transaction.objectStore(objectStoreName).clear();
    await completion;
};

const readChunk = async (database, ordinal) => {
    const transaction = database.transaction(objectStoreName, 'readonly');
    const completion = transactionCompletion(transaction);
    const request = transaction.objectStore(objectStoreName).get(ordinal);
    const result = await new Promise((resolve, reject) => {
        request.addEventListener('success', () => resolve(request.result), {
            once: true,
        });
        request.addEventListener(
            'error',
            () =>
                reject(new Error('A retained resource chunk failed to read.')),
            { once: true },
        );
    });
    await completion;
    if (!(result instanceof ArrayBuffer)) {
        throw new Error('A retained resource chunk is not an ArrayBuffer.');
    }
    return result;
};

/** @param {Uint8Array} bytes */
const bytesToHex = (bytes) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** @returns {Promise<ResourceKernel>} */
const instantiateResourceKernel = async () => {
    const response = await fetch('/resource-screen-kernel.wasm', {
        cache: 'no-store',
    });
    if (!response.ok) {
        throw new Error('The resource-screen kernel failed to download.');
    }
    const source = await WebAssembly.instantiate(await response.arrayBuffer());
    const exports = source.instance.exports;
    const memory = exports.memory;
    const allocate = exports.sealed_lattice_allocate;
    const deallocate = exports.sealed_lattice_deallocate;
    const runKmac = exports.sealed_lattice_resource_screen_padded_kmac;
    const initializeShake =
        exports.sealed_lattice_resource_screen_shake256_initialize;
    const updateShake = exports.sealed_lattice_resource_screen_shake256_update;
    const finalizeShake =
        exports.sealed_lattice_resource_screen_shake256_finalize;
    if (
        !(memory instanceof WebAssembly.Memory) ||
        typeof allocate !== 'function' ||
        typeof deallocate !== 'function' ||
        typeof runKmac !== 'function' ||
        typeof initializeShake !== 'function' ||
        typeof updateShake !== 'function' ||
        typeof finalizeShake !== 'function'
    ) {
        throw new Error('The resource-screen kernel exports are incomplete.');
    }

    /** @param {ArrayBuffer} bytes */
    const updateDigest = (bytes) => {
        const pointer = allocate(bytes.byteLength) >>> 0;
        if (pointer === 0) {
            throw new Error('The resource-screen kernel allocation failed.');
        }
        try {
            new Uint8Array(memory.buffer, pointer, bytes.byteLength).set(
                new Uint8Array(bytes),
            );
            if (updateShake(pointer, bytes.byteLength) !== 1) {
                throw new Error('The resource-screen SHAKE update failed.');
            }
        } finally {
            deallocate(pointer, bytes.byteLength);
        }
    };

    /** @returns {Uint8Array} */
    const finishDigest = () => {
        const pointer = allocate(shake256OutputByteLength) >>> 0;
        if (pointer === 0) {
            throw new Error('The SHAKE output allocation failed.');
        }
        try {
            if (finalizeShake(pointer, shake256OutputByteLength) !== 1) {
                throw new Error(
                    'The resource-screen SHAKE finalization failed.',
                );
            }
            return Uint8Array.from(
                new Uint8Array(
                    memory.buffer,
                    pointer,
                    shake256OutputByteLength,
                ),
            );
        } finally {
            deallocate(pointer, shake256OutputByteLength);
        }
    };

    return {
        beginDigest: () => {
            if (initializeShake() !== 1) {
                throw new Error(
                    'The resource-screen SHAKE initialization failed.',
                );
            }
        },
        finishDigest,
        memory,
        runKmac,
        updateDigest,
    };
};

const waitForReclaim = async (baselineUsage) => {
    const startedAt = performance.now();
    let estimate = await storageEstimate();
    while (
        estimate.usage > baselineUsage &&
        performance.now() - startedAt < reclaimSettleLimitMilliseconds
    ) {
        await new Promise((resolve) =>
            setTimeout(resolve, reclaimPollIntervalMilliseconds),
        );
        estimate = await storageEstimate();
    }
    return estimate;
};

const waitForStableStorageEstimate = async () => {
    const startedAt = performance.now();
    let estimate = await storageEstimate();
    let stableSamples = 0;
    while (performance.now() - startedAt < reclaimSettleLimitMilliseconds) {
        await new Promise((resolve) =>
            setTimeout(resolve, reclaimPollIntervalMilliseconds),
        );
        const nextEstimate = await storageEstimate();
        stableSamples =
            nextEstimate.usage === estimate.usage ? stableSamples + 1 : 0;
        estimate = nextEstimate;
        if (stableSamples >= stableEstimateSampleCount) return estimate;
    }
    return estimate;
};

const calibrateIndexedDbBaseline = async () => {
    const database = await openDatabase();
    database.close();
    await deleteDatabase();
    return waitForStableStorageEstimate();
};

/**
 * @param {ResourceScreenConfiguration} configuration
 * @param {ResourceKernel} kernel
 */
const runStorageScreen = async (configuration, kernel) => {
    const startedAt = performance.now();
    const initialEstimate = await storageEstimate();
    const estimateBefore = await calibrateIndexedDbBaseline();
    const persistedBefore = await navigator.storage.persisted();
    if (
        estimateBefore.quota - estimateBefore.usage <
        configuration.corpusByteLength
    ) {
        throw new Error('Chrome quota does not admit the synthetic corpus.');
    }
    const database = await openDatabase();
    const writeStartedAt = performance.now();
    try {
        for (
            let chunkOrdinal = 0;
            chunkOrdinal < configuration.chunkCount;
            chunkOrdinal += 1
        ) {
            setStatus(
                `Writing chunk ${String(chunkOrdinal + 1)} of ${String(configuration.chunkCount)}`,
            );
            const response = await fetch(
                `/synthetic-chunk/${String(chunkOrdinal)}`,
                { cache: 'no-store' },
            );
            if (!response.ok) {
                throw new Error(
                    `Synthetic chunk ${String(chunkOrdinal)} failed.`,
                );
            }
            const bytes = await response.arrayBuffer();
            const expectedLength =
                chunkOrdinal + 1 === configuration.chunkCount
                    ? configuration.finalChunkByteLength
                    : configuration.chunkPayloadByteLength;
            if (bytes.byteLength !== expectedLength) {
                throw new Error(
                    `Synthetic chunk ${String(chunkOrdinal)} has the wrong length.`,
                );
            }
            await writeChunk(database, chunkOrdinal, bytes);
        }
        const writeFinishedAt = performance.now();
        const estimateAfterWrite = await waitForStableStorageEstimate();

        kernel.beginDigest();
        const readStartedAt = performance.now();
        for (
            let chunkOrdinal = 0;
            chunkOrdinal < configuration.chunkCount;
            chunkOrdinal += 1
        ) {
            setStatus(
                `Reading chunk ${String(chunkOrdinal + 1)} of ${String(configuration.chunkCount)}`,
            );
            kernel.updateDigest(await readChunk(database, chunkOrdinal));
        }
        const digestHex = bytesToHex(kernel.finishDigest());
        const readFinishedAt = performance.now();
        if (digestHex !== configuration.expectedShake256Hex) {
            throw new Error('The retained corpus SHAKE256 digest disagrees.');
        }

        const clearStartedAt = performance.now();
        await clearDatabase(database);
        const estimateAfterClear = await waitForReclaim(estimateBefore.usage);
        const clearFinishedAt = performance.now();
        database.close();
        const deleteStartedAt = performance.now();
        await deleteDatabase();
        const estimateAfterDelete = await waitForReclaim(estimateBefore.usage);
        const databases = await indexedDB.databases();
        const databasePresentAfterDelete = databases.some(
            (entry) => entry.name === databaseName,
        );
        const finishedAt = performance.now();
        return {
            chunkCount: configuration.chunkCount,
            chunkPayloadByteLength: configuration.chunkPayloadByteLength,
            clearAndReclaimMilliseconds: clearFinishedAt - clearStartedAt,
            corpusByteLength: configuration.corpusByteLength,
            databasePresentAfterDelete,
            deleteAndReclaimMilliseconds: finishedAt - deleteStartedAt,
            expectedShake256Hex: configuration.expectedShake256Hex,
            fetchAndStoreMilliseconds: writeFinishedAt - writeStartedAt,
            finalChunkByteLength: configuration.finalChunkByteLength,
            initialUsage: initialEstimate.usage,
            persistedBefore,
            quotaAfterWrite: estimateAfterWrite.quota,
            quotaBefore: estimateBefore.quota,
            readAndDigestMilliseconds: readFinishedAt - readStartedAt,
            shake256Hex: digestHex,
            totalForegroundMilliseconds: finishedAt - startedAt,
            usageAfterClear: estimateAfterClear.usage,
            usageDetailsAfterClear: estimateAfterClear.usageDetails,
            usageAfterDelete: estimateAfterDelete.usage,
            usageDetailsAfterDelete: estimateAfterDelete.usageDetails,
            usageAfterWrite: estimateAfterWrite.usage,
            usageDetailsAfterWrite: estimateAfterWrite.usageDetails,
            usageBefore: estimateBefore.usage,
            usageDetailsBefore: estimateBefore.usageDetails,
        };
    } catch (error) {
        database.close();
        throw error;
    }
};

/**
 * @param {ResourceScreenConfiguration} configuration
 * @param {ResourceKernel} kernel
 */
const runWorkScreen = (configuration, kernel) => {
    setStatus('Running scalar KMAC screen');
    const startedAt = performance.now();
    const familyCodes = {
        'local-row': 1,
        'joint-row': 2,
        'continuation-row': 3,
    };
    const expectedShapes = {
        'local-row': [40, 223, 41],
        'joint-row': [40, 223, 40],
        'continuation-row': [40, 230, 81],
    };
    let checksum = 0;
    let invocationCount = 0;
    let inputByteLength = 0;
    let outputByteLength = 0;
    const histogram = configuration.kmacHistogram.map((entry) => {
        const expectedShape = expectedShapes[entry.family];
        const familyCode = familyCodes[entry.family];
        if (
            entry.phase !== 'selected-evaluation' ||
            expectedShape === undefined ||
            familyCode === undefined ||
            entry.keyByteLength !== expectedShape[0] ||
            entry.messageByteLength !== expectedShape[1] ||
            entry.outputByteLength !== expectedShape[2] ||
            !Number.isSafeInteger(entry.invocationCount) ||
            entry.invocationCount < 1 ||
            entry.invocationCount > 0xffff_ffff
        ) {
            throw new Error('The generated KMAC histogram is malformed.');
        }
        const familyStartedAt = performance.now();
        const familyChecksum =
            kernel.runKmac(familyCode, entry.invocationCount) >>> 0;
        const familyFinishedAt = performance.now();
        if (familyChecksum === 0xffff_ffff) {
            throw new Error('The scalar kernel refused a KMAC family.');
        }
        checksum = (checksum ^ familyChecksum) >>> 0;
        invocationCount += entry.invocationCount;
        inputByteLength += entry.invocationCount * entry.messageByteLength;
        outputByteLength += entry.invocationCount * entry.outputByteLength;
        return {
            ...entry,
            checksum: familyChecksum,
            elapsedMilliseconds: familyFinishedAt - familyStartedAt,
        };
    });
    const finishedAt = performance.now();
    return {
        checksum,
        histogram,
        inputByteLength,
        invocationCount,
        outputByteLength,
        totalForegroundMilliseconds: finishedAt - startedAt,
        wasmMemoryByteLength: kernel.memory.buffer.byteLength,
    };
};

/** @param {ResourceScreenConfiguration} configuration */
globalThis.runExternalChromeResourceScreen = async (configuration) => {
    setStatus('Loading scalar WebAssembly');
    const kernel = await instantiateResourceKernel();
    const storage = await runStorageScreen(configuration, kernel);
    const work = runWorkScreen(configuration, kernel);
    setStatus('Complete');
    return { storage, work };
};
