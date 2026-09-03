/// <reference types="vite/client" />

import { afterEach, describe, expect, it } from 'vitest';

import {
    actionSignatureKeyGenerationRandomnessByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import {
    instantiateConstructionKernelCommandRuntime,
    type KernelResourceMeasurement,
} from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import { actionSignatureCarrierByteLength } from '../../src/preparation-parent-runtime.js';
import { PrivatePreparationDurableState } from '../../src/private-preparation-durable-state.js';
import { PrivatePreparationWorkerClient } from '../../src/private-preparation-worker-client.js';
import type {
    PrivatePreparationActionContext,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PaddedTallyEvaluationStep,
    PublishedFinalityPackage,
    PublishedPaddedTallyChunk,
    PublishedPreparationPackage,
    PublishedSourcePackage,
    TallyEvaluationProgress,
} from '../../src/private-preparation-worker-protocol.js';
import { openRosterRuntime } from '../../src/roster-runtime.js';
import {
    abstentionSourceBodyByteLength,
    submittedSourceBodyByteLength,
} from '../../src/source-runtime.js';

import { compileFullTallyResourceModel } from '#tests/full-tally-resource-model.js';
import {
    compileIndependentLocalRecordCensus,
    enumerateFullTallyLocalRecordSeals,
    localRecordContextKey,
    parseIndependentLocalRecordContext,
} from '#tests/local-record-context-model.js';
import { resolveManualEvidenceCase } from '#tests/manual-evidence-registry.js';
import {
    compileIndependentPaddedTallyModel,
    expectedPaddedTallyRelationInventory,
    parsePaddedTallyChunk,
    parsePaddedTallyManifest,
    parsePaddedTallyTerminal,
    summarizePaddedTallyRelation,
    type ParsedPaddedTallyChunk,
} from '#tests/padded-tally-transcript-model.js';

const participantCount = 10;
const preparationAttempt = 7;
const runtimeIdentity = new Uint8Array(64).fill(0x11);
const candidateBuildIdentity = new Uint8Array(64).fill(0x22);
const actionProposalIdentity = new Uint8Array(64).fill(0x33);
const actionDefinitionIdentity = new Uint8Array(64).fill(0x34);
const predecessorIdentity = new Uint8Array(64).fill(0x44);
const manualEvidenceEnvironment = import.meta.env;
const topCountOneEvidenceCase = resolveManualEvidenceCase(
    'padded-tally-top-count-1',
);
const topCountTenEvidenceCase = resolveManualEvidenceCase(
    'padded-tally-top-count-10',
);
const emptyUsableBallotEvidenceCase = resolveManualEvidenceCase(
    'padded-tally-empty-usable-ballots',
);
const kernelUrl = new URL(
    '/packages/wasm/dist/sealed-lattice-kernel.wasm',
    window.location.origin,
);
let workerKernelObjectUrlPromise: Promise<string> | undefined;
const resolveWorkerKernelUrl = (): Promise<string> => {
    workerKernelObjectUrlPromise ??= (async () => {
        const response = await fetch(kernelUrl, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(
                `Failed to preload the worker kernel: HTTP ${String(response.status)}.`,
            );
        }
        return URL.createObjectURL(
            new Blob([await response.arrayBuffer()], {
                type: 'application/wasm',
            }),
        );
    })();
    return workerKernelObjectUrlPromise;
};
const ordinaryWorkerUrl = new URL(
    './fixtures/private-preparation-test-worker.ts',
    import.meta.url,
);
const crashWorkerUrl = new URL(
    './fixtures/private-preparation-crash-worker.ts',
    import.meta.url,
);
const sourceCrashWorkerUrl = new URL(
    './fixtures/private-preparation-source-crash-worker.ts',
    import.meta.url,
);
const tallyGenerationInitializationCrashWorkerUrl = new URL(
    './fixtures/private-preparation-tally-generation-initialization-crash-worker.ts',
    import.meta.url,
);
const tallyChunkCrashWorkerUrl = new URL(
    './fixtures/private-preparation-tally-chunk-crash-worker.ts',
    import.meta.url,
);
const tallyPublicationCrashWorkerUrl = new URL(
    './fixtures/private-preparation-tally-publication-crash-worker.ts',
    import.meta.url,
);
const tallyEvaluationInitializationCrashWorkerUrl = new URL(
    './fixtures/private-preparation-tally-evaluation-initialization-crash-worker.ts',
    import.meta.url,
);
const tallyEvaluationStepCrashWorkerUrl = new URL(
    './fixtures/private-preparation-tally-evaluation-step-crash-worker.ts',
    import.meta.url,
);
const tallyTerminalCrashWorkerUrl = new URL(
    './fixtures/private-preparation-tally-terminal-crash-worker.ts',
    import.meta.url,
);
const openClients = new Set<PrivatePreparationWorkerClient>();
const databaseNames = new Set<string>();
const visitCountsByRunIdentity = new Map<string, number[]>();
const visitStartsByClient = new Map<
    PrivatePreparationWorkerClient,
    Readonly<{ runIdentity: string; startedAtMilliseconds: number }>
>();
const longestVisitMillisecondsByRunIdentity = new Map<string, number>();
const relayReadByteLengthByDatabase = new Map<string, number>();
const relayWriteByteLengthByDatabase = new Map<string, number>();

const actionContext = (
    participantPosition: number,
): PrivatePreparationActionContext => ({
    actionProposalIdentity,
    actionDefinitionIdentity,
    predecessorIdentity,
    participantPosition,
});

const databaseName = (
    runIdentity: string,
    participantPosition: number,
): string =>
    `sealed-lattice-worker-${runIdentity}-${String(participantPosition)}`;

const deleteDatabase = (name: string): Promise<void> =>
    new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(name);
        request.addEventListener('success', () => resolve());
        request.addEventListener('error', () =>
            reject(new Error(`Failed to delete test database ${name}.`)),
        );
        request.addEventListener('blocked', () =>
            reject(new Error(`Test database ${name} remained open.`)),
        );
    });

const openDatabase = (name: string): Promise<IDBDatabase> =>
    new Promise((resolve, reject) => {
        const request = indexedDB.open(name);
        request.addEventListener('success', () => resolve(request.result));
        request.addEventListener('error', () =>
            reject(new Error(`Failed to open test database ${name}.`)),
        );
    });

const transactionCompletion = (transaction: IDBTransaction): Promise<void> =>
    new Promise((resolve, reject) => {
        transaction.addEventListener('complete', () => resolve());
        transaction.addEventListener('abort', () =>
            reject(new Error('The test database transaction was aborted.')),
        );
        transaction.addEventListener('error', () =>
            reject(new Error('The test database transaction failed.')),
        );
    });

const relayChunkStoreName = 'chunks';

const openRelayDatabase = (name: string): Promise<IDBDatabase> =>
    new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 1);
        request.addEventListener('upgradeneeded', () => {
            if (
                !request.result.objectStoreNames.contains(relayChunkStoreName)
            ) {
                request.result.createObjectStore(relayChunkStoreName, {
                    keyPath: 'id',
                });
            }
        });
        request.addEventListener('success', () => resolve(request.result));
        request.addEventListener('error', () =>
            reject(new Error(`Failed to open relay database ${name}.`)),
        );
    });

const relayChunkIdentifier = (
    chunkOrdinal: number,
    participantPosition: number,
): string => `${String(chunkOrdinal)}.${String(participantPosition)}`;

const persistRelayChunk = async (
    name: string,
    chunkOrdinal: number,
    participantPosition: number,
    chunk: Uint8Array,
): Promise<void> => {
    const database = await openRelayDatabase(name);
    try {
        const transaction = database.transaction(
            relayChunkStoreName,
            'readwrite',
            { durability: 'strict' },
        );
        transaction.objectStore(relayChunkStoreName).put({
            id: relayChunkIdentifier(chunkOrdinal, participantPosition),
            bytes: Uint8Array.from(chunk),
        });
        await transactionCompletion(transaction);
        relayWriteByteLengthByDatabase.set(
            name,
            (relayWriteByteLengthByDatabase.get(name) ?? 0) + chunk.byteLength,
        );
    } finally {
        database.close();
    }
};

const readRelayChunkSet = async (
    name: string,
    chunkOrdinal: number,
): Promise<Uint8Array[]> => {
    const database = await openRelayDatabase(name);
    try {
        const transaction = database.transaction(
            relayChunkStoreName,
            'readonly',
        );
        const requests = Array.from(
            { length: participantCount },
            (_, participantPosition) =>
                transaction
                    .objectStore(relayChunkStoreName)
                    .get(
                        relayChunkIdentifier(chunkOrdinal, participantPosition),
                    ),
        );
        const records = await Promise.all(
            requests.map(
                (request) =>
                    new Promise<unknown>((resolve, reject) => {
                        request.addEventListener('success', () =>
                            resolve(request.result),
                        );
                        request.addEventListener('error', () =>
                            reject(
                                new Error(
                                    'Failed to read a retained relay chunk.',
                                ),
                            ),
                        );
                    }),
            ),
        );
        await transactionCompletion(transaction);
        const chunks = records.map((record, participantPosition) => {
            if (
                typeof record !== 'object' ||
                record === null ||
                !('id' in record) ||
                record.id !==
                    relayChunkIdentifier(chunkOrdinal, participantPosition) ||
                !('bytes' in record) ||
                !(record.bytes instanceof Uint8Array)
            ) {
                throw new Error('The retained relay chunk is malformed.');
            }
            return Uint8Array.from(record.bytes);
        });
        relayReadByteLengthByDatabase.set(
            name,
            (relayReadByteLengthByDatabase.get(name) ?? 0) +
                chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0),
        );
        return chunks;
    } finally {
        database.close();
    }
};

const readRawStateRecord = async (
    name: string,
    storeName: 'activations' | 'evaluations',
    identifier: string,
): Promise<unknown> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction(storeName, 'readonly');
        const request = transaction.objectStore(storeName).get(identifier);
        const result = await new Promise<unknown>((resolve, reject) => {
            request.addEventListener('success', () => resolve(request.result));
            request.addEventListener('error', () =>
                reject(new Error(`Failed to read raw ${storeName} state.`)),
            );
        });
        await transactionCompletion(transaction);
        return result;
    } finally {
        database.close();
    }
};

const restoreRawStateRecord = async (
    name: string,
    storeName: 'activations' | 'evaluations',
    record: unknown,
): Promise<void> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction(storeName, 'readwrite', {
            durability: 'strict',
        });
        transaction.objectStore(storeName).put(record);
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const deleteRawStateRecord = async (
    name: string,
    storeName: 'activations' | 'evaluations',
    identifier: string,
): Promise<void> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction(storeName, 'readwrite', {
            durability: 'strict',
        });
        transaction.objectStore(storeName).delete(identifier);
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const readRawActivationRecord = (
    name: string,
    identifier: string,
): Promise<unknown> => readRawStateRecord(name, 'activations', identifier);

const restoreRawActivationRecord = (
    name: string,
    record: unknown,
): Promise<void> => restoreRawStateRecord(name, 'activations', record);

const deleteRawActivationRecord = (
    name: string,
    identifier: string,
): Promise<void> => deleteRawStateRecord(name, 'activations', identifier);

const readRawEvaluationRecord = (
    name: string,
    identifier: string,
): Promise<unknown> => readRawStateRecord(name, 'evaluations', identifier);

const restoreRawEvaluationRecord = (
    name: string,
    record: unknown,
): Promise<void> => restoreRawStateRecord(name, 'evaluations', record);

const deleteRawEvaluationRecord = (
    name: string,
    identifier: string,
): Promise<void> => deleteRawStateRecord(name, 'evaluations', identifier);

type RawDurableStoreName =
    | 'root'
    | 'actions'
    | 'preparations'
    | 'slots'
    | 'sources'
    | 'finalities'
    | 'activations'
    | 'evaluations';

const readRawStoreSnapshot = async (
    name: string,
    storeNames: readonly RawDurableStoreName[],
): Promise<readonly (readonly unknown[])[]> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction(storeNames, 'readonly');
        const records = await Promise.all(
            storeNames.map(
                (storeName) =>
                    new Promise<unknown[]>((resolve, reject) => {
                        const request = transaction
                            .objectStore(storeName)
                            .getAll();
                        request.addEventListener('success', () =>
                            resolve(request.result as unknown[]),
                        );
                        request.addEventListener('error', () =>
                            reject(
                                new Error(
                                    `Failed to snapshot raw ${storeName} state.`,
                                ),
                            ),
                        );
                    }),
            ),
        );
        await transactionCompletion(transaction);
        return records;
    } finally {
        database.close();
    }
};

const restoreRawStoreSnapshot = async (
    name: string,
    storeNames: readonly RawDurableStoreName[],
    records: readonly (readonly unknown[])[],
): Promise<void> => {
    if (storeNames.length !== records.length || storeNames.length === 0) {
        throw new Error('The raw durable snapshot is inconsistent.');
    }
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction(storeNames, 'readwrite', {
            durability: 'strict',
        });
        for (let index = 0; index < storeNames.length; index += 1) {
            const storeName = storeNames[index];
            const storeRecords = records[index];
            if (storeName === undefined || storeRecords === undefined) {
                transaction.abort();
                throw new Error('The raw durable snapshot changed shape.');
            }
            const store = transaction.objectStore(storeName);
            store.clear();
            for (const record of storeRecords) {
                store.put(record);
            }
        }
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const copyRawProtectedRecordWithIdentifier = (
    record: unknown,
    identifier: string,
): unknown => {
    if (
        typeof record !== 'object' ||
        record === null ||
        !('id' in record) ||
        typeof record.id !== 'string' ||
        !('context' in record) ||
        !(record.context instanceof ArrayBuffer) ||
        !('nonce' in record) ||
        !(record.nonce instanceof ArrayBuffer) ||
        !('ciphertext' in record) ||
        !(record.ciphertext instanceof ArrayBuffer)
    ) {
        throw new Error('The raw protected-record fixture is malformed.');
    }
    return {
        id: identifier,
        context: record.context.slice(0),
        nonce: record.nonce.slice(0),
        ciphertext: record.ciphertext.slice(0),
    };
};

const protectedRecordByteLength = (record: unknown): number => {
    if (
        typeof record !== 'object' ||
        record === null ||
        !('id' in record) ||
        typeof record.id !== 'string' ||
        !('context' in record) ||
        !(record.context instanceof ArrayBuffer) ||
        !('nonce' in record) ||
        !(record.nonce instanceof ArrayBuffer) ||
        !('ciphertext' in record) ||
        !(record.ciphertext instanceof ArrayBuffer)
    ) {
        throw new Error('The protected record measurement is malformed.');
    }
    parseIndependentLocalRecordContext(new Uint8Array(record.context));
    return (
        new TextEncoder().encode(record.id).byteLength +
        record.context.byteLength +
        record.nonce.byteLength +
        record.ciphertext.byteLength
    );
};

const protectedStoreNames = [
    'actions',
    'preparations',
    'slots',
    'sources',
    'finalities',
    'activations',
    'evaluations',
] as const;

const measureProtectedDatabase = async (
    name: string,
): Promise<
    Readonly<{
        byteLength: number;
        recordCount: number;
        contextKeys: readonly string[];
    }>
> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction(
            protectedStoreNames,
            'readonly',
        );
        const records = await Promise.all(
            protectedStoreNames.map(
                (storeName) =>
                    new Promise<unknown[]>((resolve, reject) => {
                        const request = transaction
                            .objectStore(storeName)
                            .getAll();
                        request.addEventListener('success', () =>
                            resolve(request.result as unknown[]),
                        );
                        request.addEventListener('error', () =>
                            reject(
                                new Error(
                                    'Failed to measure protected records.',
                                ),
                            ),
                        );
                    }),
            ),
        );
        await transactionCompletion(transaction);
        let byteLength = 0;
        let recordCount = 0;
        const contextKeys: string[] = [];
        for (const record of records.flat()) {
            byteLength += protectedRecordByteLength(record);
            recordCount += 1;
            if (
                typeof record !== 'object' ||
                record === null ||
                !('context' in record) ||
                !(record.context instanceof ArrayBuffer)
            ) {
                throw new Error('The protected record context is malformed.');
            }
            contextKeys.push(
                localRecordContextKey(new Uint8Array(record.context)),
            );
        }
        return { byteLength, recordCount, contextKeys };
    } finally {
        database.close();
    }
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const activationIdentifier = (participantPosition: number): string =>
    `padded-tally-generation.${bytesToHex(runtimeIdentity)}.${bytesToHex(
        actionProposalIdentity,
    )}.${String(participantPosition)}`;

const evaluationIdentifier = (participantPosition: number): string =>
    `padded-tally-evaluation.${bytesToHex(runtimeIdentity)}.${bytesToHex(
        actionProposalIdentity,
    )}.${String(participantPosition)}`;

const recordVisit = (
    runIdentity: string,
    participantPosition: number,
): void => {
    const visitCounts =
        visitCountsByRunIdentity.get(runIdentity) ??
        Array.from({ length: participantCount }, () => 0);
    visitCounts[participantPosition] =
        (visitCounts[participantPosition] ?? 0) + 1;
    visitCountsByRunIdentity.set(runIdentity, visitCounts);
};

const openClient = async (
    runIdentity: string,
    participantPosition: number,
): Promise<PrivatePreparationWorkerClient> => {
    const startedAtMilliseconds = performance.now();
    recordVisit(runIdentity, participantPosition);
    const name = databaseName(runIdentity, participantPosition);
    databaseNames.add(name);
    const client = await PrivatePreparationWorkerClient.create(
        ordinaryWorkerUrl,
        {
            databaseName: name,
            kernelUrl: await resolveWorkerKernelUrl(),
            kernelOptions: { allowUnpinnedKernel: true },
            runtimeIdentity,
            candidateBuildIdentity,
        },
    );
    openClients.add(client);
    visitStartsByClient.set(client, { runIdentity, startedAtMilliseconds });
    return client;
};

const closeClient = (client: PrivatePreparationWorkerClient): void => {
    const visit = visitStartsByClient.get(client);
    if (visit !== undefined) {
        longestVisitMillisecondsByRunIdentity.set(
            visit.runIdentity,
            Math.max(
                longestVisitMillisecondsByRunIdentity.get(visit.runIdentity) ??
                    0,
                performance.now() - visit.startedAtMilliseconds,
            ),
        );
        visitStartsByClient.delete(client);
    }
    client.close();
    openClients.delete(client);
};

type CompletionRosterFixture = Readonly<{
    canonicalRosterBytes: Uint8Array;
    rosterIdentity: Uint8Array;
    credentials: readonly Readonly<{
        signingSecretKey: Uint8Array;
        mailboxDecapsulationKey: Uint8Array;
    }>[];
}>;

const createCompletionRosterFixture =
    async (): Promise<CompletionRosterFixture> => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            {
                allowUnpinnedKernel: true,
            },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const mailboxRuntime = openPairEncryptionRuntime(kernel);
        const rosterRuntime = openRosterRuntime(kernel);
        const credentials: Array<{
            signingSecretKey: Uint8Array;
            mailboxDecapsulationKey: Uint8Array;
        }> = [];
        const publicKeys = Array.from({ length: participantCount }, () => {
            const signing = signatureRuntime.generateKeyPair(
                crypto.getRandomValues(
                    new Uint8Array(
                        actionSignatureKeyGenerationRandomnessByteLength,
                    ),
                ),
            );
            const mailbox = mailboxRuntime.generateKeyPair(
                crypto.getRandomValues(
                    new Uint8Array(
                        pairEncryptionKeyGenerationRandomnessByteLength,
                    ),
                ),
            );
            credentials.push({
                signingSecretKey: signing.secretKey,
                mailboxDecapsulationKey: mailbox.decryptionKey,
            });
            return {
                signingVerificationKey: signing.verificationKey,
                mailboxEncapsulationKey: mailbox.encryptionKey,
            };
        });
        const roster = rosterRuntime.encode(publicKeys);
        return {
            canonicalRosterBytes: roster.canonicalBytes,
            rosterIdentity: roster.rosterIdentity,
            credentials,
        };
    };

const publishPreparationPackages = async (
    runIdentity: string,
    roster: CompletionRosterFixture,
): Promise<PublishedPreparationPackage[]> => {
    const packages: PublishedPreparationPackage[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const credential = roster.credentials[participantPosition];
        if (credential === undefined) {
            throw new Error('The roster fixture omitted a credential.');
        }
        const client = await openClient(runIdentity, participantPosition);
        packages.push(
            await client.createPreparationPackage(
                actionContext(participantPosition),
                roster.canonicalRosterBytes,
                credential.signingSecretKey,
                credential.mailboxDecapsulationKey,
                preparationAttempt,
            ),
        );
        closeClient(client);
    }
    return packages;
};

const remoteBodyIndex = (
    senderPosition: number,
    recipientPosition: number,
): number =>
    recipientPosition < senderPosition
        ? recipientPosition
        : recipientPosition - 1;

type CompletePreparationContinuation = (input: {
    canonicalRosterBytes: Uint8Array;
    client: PrivatePreparationWorkerClient;
    participantPosition: number;
    preparationParents: readonly Readonly<{
        body: Uint8Array;
        signature: Uint8Array;
    }>[];
}) => Promise<void>;

const createCompletePreparation = async (
    runIdentity: string,
    afterPrivateConsumption?: CompletePreparationContinuation,
): Promise<
    Readonly<{
        canonicalRosterBytes: Uint8Array;
        preparationPackages: readonly PublishedPreparationPackage[];
        preparationParents: readonly Readonly<{
            body: Uint8Array;
            signature: Uint8Array;
        }>[];
    }>
> => {
    const roster = await createCompletionRosterFixture();
    const canonicalRosterBytes = roster.canonicalRosterBytes;
    const preparationPackages = await publishPreparationPackages(
        runIdentity,
        roster,
    );
    const preparationParents = preparationPackages.map((entry) => ({
        body: entry.parentBody,
        signature: entry.parentSignature,
    }));
    for (
        let recipientPosition = 0;
        recipientPosition < participantCount;
        recipientPosition += 1
    ) {
        const client = await openClient(runIdentity, recipientPosition);
        for (
            let senderPosition = 0;
            senderPosition < participantCount;
            senderPosition += 1
        ) {
            if (senderPosition === recipientPosition) {
                continue;
            }
            const privateBody =
                preparationPackages[senderPosition]?.privateBodies[
                    remoteBodyIndex(senderPosition, recipientPosition)
                ];
            const parent = preparationPackages[senderPosition];
            if (privateBody === undefined || parent === undefined) {
                throw new Error('The preparation fixture is incomplete.');
            }
            const consumption = await client.consumePrivatePreparation(
                actionContext(recipientPosition),
                canonicalRosterBytes,
                preparationAttempt,
                parent.parentBody,
                parent.parentSignature,
                privateBody,
            );
            if (consumption.status !== 'resolved') {
                throw new Error('A preparation delivery did not resolve.');
            }
        }
        await afterPrivateConsumption?.({
            canonicalRosterBytes,
            client,
            participantPosition: recipientPosition,
            preparationParents,
        });
        closeClient(client);
    }
    return {
        canonicalRosterBytes,
        preparationPackages,
        preparationParents,
    };
};

const rawRequest = <Result>(
    worker: Worker,
    request: PrivatePreparationWorkerRequest,
): Promise<Result> =>
    new Promise((resolve, reject) => {
        const onMessage = (
            event: MessageEvent<PrivatePreparationWorkerResponse>,
        ): void => {
            const response = event.data;
            if (
                typeof response !== 'object' ||
                response === null ||
                !('requestId' in response) ||
                response.requestId !== request.requestId
            ) {
                return;
            }
            worker.removeEventListener('message', onMessage);
            if (response.ok) {
                resolve(response.result as Result);
            } else {
                reject(new Error(response.error.message));
            }
        };
        worker.addEventListener('message', onMessage);
        worker.postMessage(request);
    });

type TallyGenerationInitializationInput = Extract<
    PrivatePreparationWorkerRequest,
    { operation: 'initialize-padded-tally-generation' }
>['input'];

const crashWorkerAtBoundary = async (
    runIdentity: string,
    participantPosition: number,
    workerUrl: URL,
    boundaryName: string,
    request: PrivatePreparationWorkerRequest,
): Promise<void> => {
    const startedAtMilliseconds = performance.now();
    recordVisit(runIdentity, participantPosition);
    const worker = new Worker(workerUrl, { type: 'module' });
    try {
        await rawRequest(worker, {
            requestId: 1,
            operation: 'initialize',
            input: {
                databaseName: databaseName(runIdentity, participantPosition),
                kernelUrl: await resolveWorkerKernelUrl(),
                kernelOptions: { allowUnpinnedKernel: true },
                runtimeIdentity,
                candidateBuildIdentity,
            },
        });
        const boundary = new Promise<void>((resolve, reject) => {
            worker.addEventListener(
                'message',
                (event: MessageEvent<unknown>) => {
                    const data = event.data;
                    if (
                        typeof data === 'object' &&
                        data !== null &&
                        'testBoundary' in data &&
                        data.testBoundary === boundaryName
                    ) {
                        resolve();
                        return;
                    }
                    if (
                        typeof data === 'object' &&
                        data !== null &&
                        'requestId' in data &&
                        data.requestId === 2
                    ) {
                        const description =
                            'error' in data
                                ? JSON.stringify(data.error)
                                : 'the operation returned before its crash hook';
                        reject(
                            new Error(
                                `${boundaryName} was not reached: ${description}`,
                            ),
                        );
                    }
                },
            );
        });
        worker.postMessage(request);
        await boundary;
    } finally {
        worker.terminate();
        longestVisitMillisecondsByRunIdentity.set(
            runIdentity,
            Math.max(
                longestVisitMillisecondsByRunIdentity.get(runIdentity) ?? 0,
                performance.now() - startedAtMilliseconds,
            ),
        );
    }
};

type CeremonyBallot = Readonly<{
    declaration: 'abstain' | 'submit';
    scoreEncodings: Uint8Array;
}>;

type CompleteCeremonyMode = 'empty-usable-ballots' | 'result';

const ceremonyBallots = (mode: CompleteCeremonyMode): CeremonyBallot[] =>
    Array.from({ length: participantCount }, (_, participantPosition) => {
        if (mode === 'empty-usable-ballots') {
            return {
                declaration: 'submit' as const,
                scoreEncodings: new Uint8Array(participantCount).fill(
                    participantPosition % 2 === 0 ? 0 : 15,
                ),
            };
        }
        if (participantPosition >= 8) {
            return {
                declaration: 'abstain' as const,
                scoreEncodings: new Uint8Array(participantCount),
            };
        }
        if (participantPosition === 6) {
            return {
                declaration: 'submit' as const,
                scoreEncodings: new Uint8Array(participantCount),
            };
        }
        if (participantPosition === 7) {
            return {
                declaration: 'submit' as const,
                scoreEncodings: new Uint8Array(participantCount).fill(15),
            };
        }
        return {
            declaration: 'submit' as const,
            scoreEncodings: Uint8Array.from(
                { length: participantCount },
                (_optionIndex, optionPosition) =>
                    ((optionPosition + 3 * participantPosition) %
                        participantCount) +
                    1,
            ),
        };
    });

const evaluateCeremonyBallotsDirectly = (
    ballots: readonly CeremonyBallot[],
    topCount: number,
): Readonly<{
    acceptedBallotAuthorshipBitmap: number;
    orderedOptionPositions: readonly number[] | undefined;
}> => {
    const aggregateScores = Array.from({ length: participantCount }, () => 0);
    let acceptedBallotAuthorshipBitmap = 0;
    for (const [participantPosition, ballot] of ballots.entries()) {
        const accepted =
            ballot.declaration === 'submit' &&
            ballot.scoreEncodings.every((score) => score >= 1 && score <= 10);
        if (!accepted) continue;
        acceptedBallotAuthorshipBitmap |= 1 << participantPosition;
        for (const [optionPosition, score] of ballot.scoreEncodings.entries()) {
            aggregateScores[optionPosition] =
                (aggregateScores[optionPosition] ?? 0) + score;
        }
    }
    const orderedOptionPositions =
        acceptedBallotAuthorshipBitmap === 0
            ? undefined
            : Array.from(
                  { length: participantCount },
                  (_, position) => position,
              )
                  .sort(
                      (left, right) =>
                          (aggregateScores[right] ?? 0) -
                              (aggregateScores[left] ?? 0) || left - right,
                  )
                  .slice(0, topCount);
    return {
        acceptedBallotAuthorshipBitmap,
        orderedOptionPositions,
    };
};

const expectCompletePaddedTallyCeremony = async (
    topCount: number,
    mode: CompleteCeremonyMode = 'result',
): Promise<void> => {
    const repairPath = topCount === 1 && mode === 'result';
    const independentModel = compileIndependentPaddedTallyModel(topCount);
    const expectedRelationInventory =
        expectedPaddedTallyRelationInventory(independentModel);
    const runIdentity = crypto.randomUUID();
    const relayDatabaseName = `sealed-lattice-relay-${runIdentity}`;
    databaseNames.add(relayDatabaseName);
    const storageBefore = await navigator.storage.estimate();
    let maximumActivationRecordByteLength = 0;
    let maximumEvaluationRecordByteLength = 0;
    const ballots = ceremonyBallots(mode);
    const sourcePackages: PublishedSourcePackage[] = [];
    const { canonicalRosterBytes, preparationPackages, preparationParents } =
        await createCompletePreparation(
            runIdentity,
            async ({
                canonicalRosterBytes: callbackRosterBytes,
                client,
                participantPosition,
                preparationParents: callbackPreparationParents,
            }) => {
                const ballot = ballots[participantPosition];
                if (ballot === undefined) {
                    throw new Error(
                        'The ceremony ballot fixture is incomplete.',
                    );
                }
                sourcePackages.push(
                    await client.createSourcePackage(
                        actionContext(participantPosition),
                        callbackRosterBytes,
                        preparationAttempt,
                        callbackPreparationParents,
                        ballot.declaration === 'abstain'
                            ? { declaration: 'abstain' }
                            : {
                                  declaration: 'submit',
                                  scoreEncodings: ballot.scoreEncodings,
                              },
                    ),
                );
            },
        );
    const sources = sourcePackages.map((source, participantPosition) => ({
        declaration:
            ballots[participantPosition]?.declaration ?? ('abstain' as const),
        body: source.sourceBody,
        signature: source.sourceSignature,
    }));
    const finalities: PublishedFinalityPackage[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const client = await openClient(runIdentity, participantPosition);
        try {
            finalities.push(
                await client.createFinalitySignature(
                    actionContext(participantPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sources,
                    topCount,
                ),
            );
        } finally {
            closeClient(client);
        }
    }
    const expectedSourceSubmissionBitmap = ballots.reduce(
        (bitmap, ballot, participantPosition) =>
            ballot.declaration === 'submit'
                ? bitmap | (1 << participantPosition)
                : bitmap,
        0,
    );
    expect(
        finalities.every(
            (finality) =>
                finality.targetKind === 'computation' &&
                finality.topCount === topCount &&
                finality.sourceSubmissionBitmap ===
                    expectedSourceSubmissionBitmap,
        ),
    ).toBe(true);
    const finalitySignatures = finalities
        .slice(0, 8)
        .map((finality, signerPosition) => ({
            signerPosition,
            signature: finality.finalitySignature,
        }));
    const pendingManifests: Array<Uint8Array | undefined> = Array.from(
        { length: participantCount },
        () => undefined,
    );
    const pendingActivationSignatures: Array<Uint8Array | undefined> =
        Array.from({ length: participantCount }, () => undefined);
    const parsedChunksByParticipant: ParsedPaddedTallyChunk[][] = Array.from(
        { length: participantCount },
        () => [],
    );
    const chunkIdentitiesByParticipant: Uint8Array[][] = Array.from(
        { length: participantCount },
        () => [],
    );
    let canonicalTargetIdentity: Uint8Array | undefined;
    let canonicalCircuitIdentity: Uint8Array | undefined;
    let plan:
        | Awaited<
              ReturnType<
                  PrivatePreparationWorkerClient['initializePaddedTallyGeneration']
              >
          >['plan']
        | undefined;
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const client = await openClient(runIdentity, participantPosition);
        try {
            const initialization = await client.initializePaddedTallyGeneration(
                actionContext(participantPosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                sources,
                finalitySignatures,
                topCount,
            );
            plan ??= initialization.plan;
            expect(initialization.plan).toEqual(plan);
            expect({
                participantCount: initialization.plan.participantCount,
                optionCount: initialization.plan.optionCount,
                topCount: initialization.plan.topCount,
                inputWireCount: initialization.plan.inputWireCount,
                operationCount: initialization.plan.operationCount,
                constantCount: initialization.plan.constantCount,
                linearCount: initialization.plan.linearCount,
                conjunctionCount: initialization.plan.conjunctionCount,
                negationCount: initialization.plan.negationCount,
                outputCount: initialization.plan.outputCount,
                wireCount: initialization.plan.wireCount,
                logicalPayloadByteLength:
                    initialization.plan.logicalPayloadByteLength,
                labelEntropyByteLength:
                    initialization.plan.labelEntropyByteLength,
                manifestByteLength: initialization.plan.manifestByteLength,
                maximumLiveWireCount: initialization.plan.maximumLiveWireCount,
                chunks: initialization.plan.chunks.map((chunk) => ({
                    chunkByteLength: chunk.chunkByteLength,
                    labelEntropyByteLength: chunk.labelEntropyByteLength,
                    liveWireCountAfterChunk: chunk.liveWireCountAfterChunk,
                })),
            }).toEqual({
                participantCount,
                optionCount: participantCount,
                topCount,
                inputWireCount: independentModel.inputWireCount,
                operationCount: independentModel.operations.length,
                constantCount: independentModel.constantCount,
                linearCount: independentModel.linearCount,
                conjunctionCount: independentModel.conjunctionCount,
                negationCount: independentModel.negationCount,
                outputCount: independentModel.outputWires.length,
                wireCount:
                    independentModel.inputWireCount +
                    independentModel.operations.length,
                logicalPayloadByteLength:
                    independentModel.logicalPayloadByteLength,
                labelEntropyByteLength: independentModel.labelEntropyByteLength,
                manifestByteLength:
                    176 + 78 * independentModel.descriptors.length,
                maximumLiveWireCount: independentModel.maximumLiveWireCount,
                chunks: independentModel.descriptors.map(
                    (descriptor, chunkIndex) => ({
                        chunkByteLength: descriptor.chunkByteLength,
                        labelEntropyByteLength:
                            descriptor.labelEntropyByteLength,
                        liveWireCountAfterChunk:
                            independentModel.liveWireCountsAfterChunks[
                                chunkIndex
                            ],
                    }),
                ),
            });
            for (
                let chunkOrdinal = 0;
                chunkOrdinal < initialization.plan.chunks.length;
                chunkOrdinal += 1
            ) {
                const generated = await client.createPaddedTallyChunk(
                    actionContext(participantPosition),
                    chunkOrdinal,
                );
                if (participantPosition === 0) {
                    const retainedActivation = await readRawActivationRecord(
                        databaseName(runIdentity, participantPosition),
                        activationIdentifier(participantPosition),
                    );
                    if (retainedActivation === undefined) {
                        throw new Error(
                            'The activation resource checkpoint is absent.',
                        );
                    }
                    maximumActivationRecordByteLength = Math.max(
                        maximumActivationRecordByteLength,
                        protectedRecordByteLength(retainedActivation),
                    );
                }
                expect(generated.chunkOrdinal).toBe(chunkOrdinal);
                const parsedChunk = parsePaddedTallyChunk(
                    generated.chunk,
                    independentModel,
                );
                const parsedParticipantChunks =
                    parsedChunksByParticipant[participantPosition];
                const participantChunkIdentities =
                    chunkIdentitiesByParticipant[participantPosition];
                if (
                    parsedParticipantChunks === undefined ||
                    participantChunkIdentities === undefined
                ) {
                    throw new Error(
                        'The independent transcript inventory is incomplete.',
                    );
                }
                canonicalTargetIdentity ??= parsedChunk.targetIdentity;
                canonicalCircuitIdentity ??= parsedChunk.circuitIdentity;
                expect(parsedChunk.targetIdentity).toEqual(
                    canonicalTargetIdentity,
                );
                expect(parsedChunk.circuitIdentity).toEqual(
                    canonicalCircuitIdentity,
                );
                expect(parsedChunk.participantCount).toBe(participantCount);
                expect(parsedChunk.participantPosition).toBe(
                    participantPosition,
                );
                expect(parsedChunk.topCount).toBe(topCount);
                expect(parsedChunk.chunkOrdinal).toBe(chunkOrdinal);
                expect(generated.chunk).toHaveLength(
                    initialization.plan.chunks[chunkOrdinal]?.chunkByteLength,
                );
                expect(parsedChunk.includesInitial).toBe(chunkOrdinal === 0);
                expect(parsedChunk.includesTerminal).toBe(
                    chunkOrdinal + 1 === initialization.plan.chunks.length,
                );
                const previousParsedChunk =
                    parsedParticipantChunks[parsedParticipantChunks.length - 1];
                const previousChunkIdentity =
                    participantChunkIdentities[
                        participantChunkIdentities.length - 1
                    ];
                expect(parsedChunk.firstOperation).toBe(
                    previousParsedChunk?.operationEnd ?? 0,
                );
                expect(parsedChunk.previousChunkIdentity).toEqual(
                    previousChunkIdentity ?? new Uint8Array(64),
                );
                expect(parsedChunk.allocationNonce).toEqual(
                    parsedParticipantChunks[0]?.allocationNonce ??
                        parsedChunk.allocationNonce,
                );
                parsedParticipantChunks.push(parsedChunk);
                participantChunkIdentities.push(generated.chunkIdentity);
                await persistRelayChunk(
                    relayDatabaseName,
                    chunkOrdinal,
                    participantPosition,
                    generated.chunk,
                );
                if (generated.status === 'complete') {
                    expect(chunkOrdinal + 1).toBe(
                        initialization.plan.chunks.length,
                    );
                    pendingManifests[participantPosition] = generated.manifest;
                    pendingActivationSignatures[participantPosition] =
                        generated.activationSignature;
                    const parsedManifest = parsePaddedTallyManifest(
                        generated.manifest,
                        independentModel,
                    );
                    expect(parsedManifest.targetIdentity).toEqual(
                        canonicalTargetIdentity,
                    );
                    expect(parsedManifest.circuitIdentity).toEqual(
                        canonicalCircuitIdentity,
                    );
                    expect(parsedManifest.participantCount).toBe(
                        participantCount,
                    );
                    expect(parsedManifest.participantPosition).toBe(
                        participantPosition,
                    );
                    expect(parsedManifest.topCount).toBe(topCount);
                    expect(parsedManifest.allocationNonce).toEqual(
                        parsedParticipantChunks[0]?.allocationNonce,
                    );
                    expect(parsedManifest.descriptors).toHaveLength(
                        initialization.plan.chunks.length,
                    );
                    for (const [
                        descriptorOrdinal,
                        descriptor,
                    ] of parsedManifest.descriptors.entries()) {
                        const parsed =
                            parsedParticipantChunks[descriptorOrdinal];
                        const identity =
                            participantChunkIdentities[descriptorOrdinal];
                        if (parsed === undefined || identity === undefined) {
                            throw new Error(
                                'The independent descriptor inventory is incomplete.',
                            );
                        }
                        expect(descriptor).toEqual({
                            firstOperation: parsed.firstOperation,
                            operationEnd: parsed.operationEnd,
                            includesInitial: parsed.includesInitial,
                            includesTerminal: parsed.includesTerminal,
                            chunkByteLength:
                                initialization.plan.chunks[descriptorOrdinal]
                                    ?.chunkByteLength,
                            chunkIdentity: identity,
                        });
                    }
                } else {
                    expect(chunkOrdinal + 1).toBeLessThan(
                        initialization.plan.chunks.length,
                    );
                }
            }
        } finally {
            closeClient(client);
        }
    }
    if (
        plan === undefined ||
        pendingManifests.some((manifest) => manifest === undefined) ||
        pendingActivationSignatures.some((signature) => signature === undefined)
    ) {
        throw new Error('The complete activation inventory is absent.');
    }
    for (const participantChunks of parsedChunksByParticipant) {
        expect(summarizePaddedTallyRelation(participantChunks)).toEqual(
            expectedRelationInventory,
        );
    }
    const manifests = pendingManifests.map((manifest) => {
        if (manifest === undefined) {
            throw new Error('A complete participant manifest is absent.');
        }
        return manifest;
    });
    const activationSignatures = pendingActivationSignatures.map(
        (signature) => {
            if (signature === undefined) {
                throw new Error(
                    'A complete participant activation signature is absent.',
                );
            }
            return signature;
        },
    );
    type EvaluatedTallyTerminal = Extract<
        TallyEvaluationProgress,
        { batchIdentity: Uint8Array }
    >;
    let acceptedTerminal: EvaluatedTallyTerminal | undefined;
    let kernelResources: KernelResourceMeasurement = {
        maximumRequestByteLength: 0,
        maximumResponseByteLength: 0,
        wasmMemoryByteLength: 0,
    };
    const observeKernelResources = (
        resources: KernelResourceMeasurement,
    ): void => {
        kernelResources = {
            maximumRequestByteLength: Math.max(
                kernelResources.maximumRequestByteLength,
                resources.maximumRequestByteLength,
            ),
            maximumResponseByteLength: Math.max(
                kernelResources.maximumResponseByteLength,
                resources.maximumResponseByteLength,
            ),
            wasmMemoryByteLength: Math.max(
                kernelResources.wasmMemoryByteLength,
                resources.wasmMemoryByteLength,
            ),
        };
    };
    const direct = evaluateCeremonyBallotsDirectly(ballots, topCount);
    const acceptTerminal = (
        terminal: PaddedTallyEvaluationStep,
    ): EvaluatedTallyTerminal => {
        if (terminal.kind === 'pending' || !('batchIdentity' in terminal)) {
            throw new Error(
                'The complete ceremony did not return an evaluated terminal.',
            );
        }
        observeKernelResources(terminal.resources);
        expect(terminal.acceptedBallotAuthorshipBitmap).toBe(
            direct.acceptedBallotAuthorshipBitmap,
        );
        if (direct.orderedOptionPositions === undefined) {
            if (
                terminal.kind !== 'no-result' ||
                terminal.terminalPath !== 'evaluated'
            ) {
                throw new Error(
                    'The empty usable-ballot circuit returned the wrong terminal.',
                );
            }
        } else {
            if (terminal.kind !== 'result') {
                throw new Error(
                    'The usable-ballot circuit did not return a result.',
                );
            }
            expect(terminal.orderedOptionPositions).toEqual(
                direct.orderedOptionPositions,
            );
        }
        return terminal;
    };
    const assertSameTerminal = (
        restored: TallyEvaluationProgress,
        expected: EvaluatedTallyTerminal,
    ): void => {
        if (!('batchIdentity' in restored) || restored.kind !== expected.kind) {
            throw new Error('The restored terminal changed evaluated kind.');
        }
        expect(restored.acceptedBallotAuthorshipBitmap).toBe(
            expected.acceptedBallotAuthorshipBitmap,
        );
        if (expected.kind === 'result') {
            if (restored.kind !== 'result') {
                throw new Error('The restored result changed kind.');
            }
            expect(restored.orderedOptionPositions).toEqual(
                expected.orderedOptionPositions,
            );
        } else if (
            restored.kind !== 'no-result' ||
            restored.terminalPath !== 'evaluated'
        ) {
            throw new Error('The restored no-result changed path.');
        }
        expect(restored.batchIdentity).toEqual(expected.batchIdentity);
        expect(restored.terminalBody).toEqual(expected.terminalBody);
        expect(restored.terminalIdentity).toEqual(expected.terminalIdentity);
    };
    if (repairPath) {
        await crashWorkerAtBoundary(
            runIdentity,
            0,
            tallyEvaluationInitializationCrashWorkerUrl,
            'tally-evaluation-durably-initialized',
            {
                requestId: 2,
                operation: 'initialize-padded-tally-evaluation',
                input: {
                    ...actionContext(0),
                    canonicalRosterBytes,
                    finalitySignatures,
                    manifests,
                    activationSignatures,
                },
            },
        );
        const firstChunks = await readRelayChunkSet(relayDatabaseName, 0);
        await crashWorkerAtBoundary(
            runIdentity,
            0,
            tallyEvaluationStepCrashWorkerUrl,
            'tally-evaluation-step-durably-persisted',
            {
                requestId: 2,
                operation: 'evaluate-padded-tally-chunk',
                input: {
                    ...actionContext(0),
                    expectedChunkOrdinal: 0,
                    chunks: firstChunks,
                },
            },
        );
        const replayedFirstChunks = await readRelayChunkSet(
            relayDatabaseName,
            0,
        );
        const evaluator = await openClient(runIdentity, 0);
        try {
            const initialization =
                await evaluator.initializePaddedTallyEvaluation(
                    actionContext(0),
                    canonicalRosterBytes,
                    finalitySignatures,
                    manifests,
                    activationSignatures,
                );
            expect(initialization.status).toBe('already-initialized');
            expect(initialization.plan).toEqual(plan);
            const firstReplay = await evaluator.evaluatePaddedTallyChunk(
                actionContext(0),
                0,
                replayedFirstChunks,
            );
            expect(firstReplay.kind).toBe('pending');
            await expect(
                evaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    0,
                    replayedFirstChunks.slice(0, 9),
                ),
            ).rejects.toThrow();
            const alternateFirstChunks = replayedFirstChunks.map((chunk) =>
                Uint8Array.from(chunk),
            );
            const alternateFirstChunk = alternateFirstChunks[4];
            if (alternateFirstChunk === undefined) {
                throw new Error('The replay corruption fixture is absent.');
            }
            alternateFirstChunk[250] ^= 1;
            await expect(
                evaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    0,
                    alternateFirstChunks,
                ),
            ).rejects.toMatchObject({ name: 'Conflict' });
            const evaluationRecordAfterFirst = await readRawEvaluationRecord(
                databaseName(runIdentity, 0),
                evaluationIdentifier(0),
            );
            if (evaluationRecordAfterFirst === undefined) {
                throw new Error('The first evaluation checkpoint is absent.');
            }
            const evaluationRollbackStoreNames = [
                'root',
                'actions',
                'evaluations',
            ] as const;
            const firstEvaluationRollbackSubset = await readRawStoreSnapshot(
                databaseName(runIdentity, 0),
                evaluationRollbackStoreNames,
            );
            const secondChunks = await readRelayChunkSet(relayDatabaseName, 1);
            const second = await evaluator.evaluatePaddedTallyChunk(
                actionContext(0),
                1,
                secondChunks,
            );
            expect(second.kind).toBe('pending');
            const evaluationRecordAfterSecond = await readRawEvaluationRecord(
                databaseName(runIdentity, 0),
                evaluationIdentifier(0),
            );
            if (evaluationRecordAfterSecond === undefined) {
                throw new Error('The second evaluation checkpoint is absent.');
            }
            const secondEvaluationRollbackSubset = await readRawStoreSnapshot(
                databaseName(runIdentity, 0),
                evaluationRollbackStoreNames,
            );
            await restoreRawEvaluationRecord(
                databaseName(runIdentity, 0),
                evaluationRecordAfterFirst,
            );
            await expect(
                evaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    1,
                    secondChunks,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            await restoreRawEvaluationRecord(
                databaseName(runIdentity, 0),
                evaluationRecordAfterSecond,
            );
            await restoreRawStoreSnapshot(
                databaseName(runIdentity, 0),
                evaluationRollbackStoreNames,
                firstEvaluationRollbackSubset,
            );
            await expect(
                evaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    1,
                    secondChunks,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            await restoreRawStoreSnapshot(
                databaseName(runIdentity, 0),
                evaluationRollbackStoreNames,
                secondEvaluationRollbackSubset,
            );
            for (
                let chunkOrdinal = 2;
                chunkOrdinal < plan.chunks.length - 1;
                chunkOrdinal += 1
            ) {
                const pending = await evaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    chunkOrdinal,
                    await readRelayChunkSet(relayDatabaseName, chunkOrdinal),
                );
                expect(pending.kind).toBe('pending');
            }
        } finally {
            closeClient(evaluator);
        }
        const lastChunkOrdinal = plan.chunks.length - 1;
        const lastChunks = await readRelayChunkSet(
            relayDatabaseName,
            lastChunkOrdinal,
        );
        await crashWorkerAtBoundary(
            runIdentity,
            0,
            tallyTerminalCrashWorkerUrl,
            'tally-terminal-durably-persisted',
            {
                requestId: 2,
                operation: 'evaluate-padded-tally-chunk',
                input: {
                    ...actionContext(0),
                    expectedChunkOrdinal: lastChunkOrdinal,
                    chunks: lastChunks,
                },
            },
        );
        const terminalRecord = await readRawEvaluationRecord(
            databaseName(runIdentity, 0),
            evaluationIdentifier(0),
        );
        if (terminalRecord === undefined) {
            throw new Error('The crash-restored terminal is absent.');
        }
        const replayedLastChunks = await readRelayChunkSet(
            relayDatabaseName,
            lastChunkOrdinal,
        );
        const restoredEvaluator = await openClient(runIdentity, 0);
        try {
            acceptedTerminal = acceptTerminal(
                await restoredEvaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    lastChunkOrdinal,
                    replayedLastChunks,
                ),
            );
            const alternateLastChunks = replayedLastChunks.map((chunk) =>
                Uint8Array.from(chunk),
            );
            const alternateLastChunk = alternateLastChunks[6];
            if (alternateLastChunk === undefined) {
                throw new Error('The terminal replay fixture is absent.');
            }
            alternateLastChunk[250] ^= 1;
            await expect(
                restoredEvaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    lastChunkOrdinal,
                    alternateLastChunks,
                ),
            ).rejects.toMatchObject({ name: 'Conflict' });
            assertSameTerminal(
                await restoredEvaluator.readTallyResult(actionContext(0)),
                acceptedTerminal,
            );
            await deleteRawEvaluationRecord(
                databaseName(runIdentity, 0),
                evaluationIdentifier(0),
            );
            await expect(
                restoredEvaluator.readTallyResult(actionContext(0)),
            ).rejects.toMatchObject({ name: 'StateLost' });
            await restoreRawEvaluationRecord(
                databaseName(runIdentity, 0),
                terminalRecord,
            );
            assertSameTerminal(
                await restoredEvaluator.readTallyResult(actionContext(0)),
                acceptedTerminal,
            );
        } finally {
            closeClient(restoredEvaluator);
        }
    } else {
        const evaluator = await openClient(runIdentity, 0);
        try {
            const corruptManifests = manifests.map((manifest) =>
                Uint8Array.from(manifest),
            );
            const corruptManifest = corruptManifests[2];
            if (corruptManifest === undefined) {
                throw new Error('The manifest corruption fixture is absent.');
            }
            corruptManifest[corruptManifest.byteLength - 1] ^= 1;
            await expect(
                evaluator.initializePaddedTallyEvaluation(
                    actionContext(0),
                    canonicalRosterBytes,
                    finalitySignatures,
                    corruptManifests,
                    activationSignatures,
                ),
            ).rejects.toThrow();
            const initialization =
                await evaluator.initializePaddedTallyEvaluation(
                    actionContext(0),
                    canonicalRosterBytes,
                    finalitySignatures,
                    manifests,
                    activationSignatures,
                );
            expect(initialization.plan).toEqual(plan);
            for (
                let chunkOrdinal = 0;
                chunkOrdinal < plan.chunks.length;
                chunkOrdinal += 1
            ) {
                const chunks = await readRelayChunkSet(
                    relayDatabaseName,
                    chunkOrdinal,
                );
                if (chunkOrdinal === 0) {
                    await expect(
                        evaluator.evaluatePaddedTallyChunk(
                            actionContext(0),
                            chunkOrdinal,
                            chunks.slice(0, 9),
                        ),
                    ).rejects.toThrow();
                    const maliciousChunks = chunks.map((chunk) =>
                        Uint8Array.from(chunk),
                    );
                    for (const participantPosition of [0, 1, 2]) {
                        const maliciousChunk =
                            maliciousChunks[participantPosition];
                        if (maliciousChunk === undefined) {
                            throw new Error(
                                'The three-party corruption fixture is incomplete.',
                            );
                        }
                        maliciousChunk[250] ^= 1;
                    }
                    await expect(
                        evaluator.evaluatePaddedTallyChunk(
                            actionContext(0),
                            chunkOrdinal,
                            maliciousChunks,
                        ),
                    ).rejects.toThrow();
                }
                const evaluated = await evaluator.evaluatePaddedTallyChunk(
                    actionContext(0),
                    chunkOrdinal,
                    chunks,
                );
                await expect(
                    evaluator.evaluatePaddedTallyChunk(
                        actionContext(0),
                        chunkOrdinal,
                        chunks,
                    ),
                ).resolves.toEqual(evaluated);
                if (chunkOrdinal + 1 === plan.chunks.length) {
                    acceptedTerminal = acceptTerminal(evaluated);
                }
            }
            if (acceptedTerminal === undefined) {
                throw new Error('The accepted terminal fixture is absent.');
            }
            assertSameTerminal(
                await evaluator.readTallyResult(actionContext(0)),
                acceptedTerminal,
            );
        } finally {
            closeClient(evaluator);
        }
    }
    if (acceptedTerminal === undefined) {
        throw new Error('The accepted terminal fixture is absent.');
    }
    for (
        let participantPosition = 1;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const evaluator = await openClient(runIdentity, participantPosition);
        try {
            const initialization =
                await evaluator.initializePaddedTallyEvaluation(
                    actionContext(participantPosition),
                    canonicalRosterBytes,
                    finalitySignatures,
                    manifests,
                    activationSignatures,
                );
            expect(initialization.plan).toEqual(plan);
            let participantTerminal: PaddedTallyEvaluationStep | undefined;
            for (
                let chunkOrdinal = 0;
                chunkOrdinal < plan.chunks.length;
                chunkOrdinal += 1
            ) {
                const progress = await evaluator.evaluatePaddedTallyChunk(
                    actionContext(participantPosition),
                    chunkOrdinal,
                    await readRelayChunkSet(relayDatabaseName, chunkOrdinal),
                );
                if (participantPosition === 1) {
                    const retainedEvaluation = await readRawEvaluationRecord(
                        databaseName(runIdentity, participantPosition),
                        evaluationIdentifier(participantPosition),
                    );
                    if (retainedEvaluation === undefined) {
                        throw new Error(
                            'The evaluation resource checkpoint is absent.',
                        );
                    }
                    maximumEvaluationRecordByteLength = Math.max(
                        maximumEvaluationRecordByteLength,
                        protectedRecordByteLength(retainedEvaluation),
                    );
                }
                if (chunkOrdinal + 1 === plan.chunks.length) {
                    participantTerminal = progress;
                } else {
                    expect(progress.kind).toBe('pending');
                }
            }
            if (participantTerminal === undefined) {
                throw new Error(
                    'A sequential participant omitted result retrieval.',
                );
            }
            assertSameTerminal(
                acceptTerminal(participantTerminal),
                acceptedTerminal,
            );
            assertSameTerminal(
                await evaluator.readTallyResult(
                    actionContext(participantPosition),
                ),
                acceptedTerminal,
            );
        } finally {
            closeClient(evaluator);
        }
    }
    if (canonicalTargetIdentity === undefined) {
        throw new Error('The independent target identity is absent.');
    }
    const parsedTerminal = parsePaddedTallyTerminal(
        acceptedTerminal.terminalBody,
    );
    expect(parsedTerminal.targetIdentity).toEqual(canonicalTargetIdentity);
    expect(parsedTerminal.topCount).toBe(topCount);
    expect(parsedTerminal.kind).toBe(acceptedTerminal.kind);
    expect(
        parsedTerminal.acceptedBallotAuthorship.reduce(
            (bitmap, accepted, participantPosition) =>
                accepted ? bitmap | (1 << participantPosition) : bitmap,
            0,
        ),
    ).toBe(acceptedTerminal.acceptedBallotAuthorshipBitmap);
    expect(parsedTerminal.orderedOptionPositions).toEqual(
        direct.orderedOptionPositions,
    );
    const protectedDatabaseMeasurements = await Promise.all(
        Array.from({ length: participantCount }, (_, participantPosition) =>
            measureProtectedDatabase(
                databaseName(runIdentity, participantPosition),
            ),
        ),
    );
    const totalProtectedRecordByteLength = protectedDatabaseMeasurements.reduce(
        (sum, measurement) => sum + measurement.byteLength,
        0,
    );
    const protectedRecordCount = protectedDatabaseMeasurements.reduce(
        (sum, measurement) => sum + measurement.recordCount,
        0,
    );
    const protectedRecordContextKeys = protectedDatabaseMeasurements.flatMap(
        (measurement) => measurement.contextKeys,
    );
    expect(protectedRecordCount).toBe(150);
    expect(new Set(protectedRecordContextKeys).size).toBe(protectedRecordCount);
    const preparationUploadByteLength = preparationPackages.reduce(
        (sum, preparationPackage) =>
            sum +
            preparationPackage.parentBody.byteLength +
            preparationPackage.parentSignature.byteLength +
            preparationPackage.privateBodies.reduce(
                (privateSum, body) => privateSum + body.byteLength,
                0,
            ),
        0,
    );
    const preparationParentInventoryByteLength = preparationParents.reduce(
        (sum, parent) =>
            sum + parent.body.byteLength + parent.signature.byteLength,
        0,
    );
    const sourceInventoryByteLength = sourcePackages.reduce(
        (sum, source) =>
            sum +
            source.sourceBody.byteLength +
            source.sourceSignature.byteLength,
        0,
    );
    const finalityTargetBody = finalities[0]?.targetBody;
    if (finalityTargetBody === undefined) {
        throw new Error('The resource ledger omitted the finality target.');
    }
    const finalitySignatureInventoryByteLength = finalities.reduce(
        (sum, finality) => sum + finality.finalitySignature.byteLength,
        0,
    );
    const emittedFinalityUploadByteLength = finalities.reduce(
        (sum, finality) =>
            sum +
            finality.targetBody.byteLength +
            finality.finalitySignature.byteLength,
        0,
    );
    const quorumFinalityInventoryByteLength = finalitySignatures.reduce(
        (sum, signature) => sum + signature.signature.byteLength,
        0,
    );
    const activationInventoryByteLength =
        manifests.reduce((sum, manifest) => sum + manifest.byteLength, 0) +
        activationSignatures.reduce(
            (sum, signature) => sum + signature.byteLength,
            0,
        );
    const activationChunkCorpusByteLength =
        participantCount *
        plan.chunks.reduce(
            (sum, chunkPlan) => sum + chunkPlan.chunkByteLength,
            0,
        );
    const activationUploadByteLength =
        activationChunkCorpusByteLength + activationInventoryByteLength;
    const emittedUploadByteLength =
        preparationUploadByteLength +
        sourceInventoryByteLength +
        emittedFinalityUploadByteLength +
        activationUploadByteLength +
        acceptedTerminal.terminalBody.byteLength;
    const deduplicatedPublicCorpusByteLength =
        preparationUploadByteLength +
        sourceInventoryByteLength +
        finalityTargetBody.byteLength +
        finalitySignatureInventoryByteLength +
        activationUploadByteLength +
        acceptedTerminal.terminalBody.byteLength;
    const maximumPrivatePreparationRecipientByteLength = Math.max(
        ...Array.from({ length: participantCount }, (_, recipientPosition) =>
            preparationPackages.reduce(
                (sum, preparationPackage, senderPosition) =>
                    senderPosition === recipientPosition
                        ? sum
                        : sum +
                          preparationPackage.parentBody.byteLength +
                          preparationPackage.parentSignature.byteLength +
                          (preparationPackage.privateBodies[
                              remoteBodyIndex(senderPosition, recipientPosition)
                          ]?.byteLength ?? 0),
                0,
            ),
        ),
    );
    const activationVerificationInventoryByteLength =
        canonicalRosterBytes.byteLength +
        quorumFinalityInventoryByteLength +
        activationInventoryByteLength;
    const cleanVerifiedDownloadByteLength =
        5 * canonicalRosterBytes.byteLength +
        maximumPrivatePreparationRecipientByteLength +
        2 * preparationParentInventoryByteLength +
        2 * sourceInventoryByteLength +
        2 * quorumFinalityInventoryByteLength +
        activationInventoryByteLength +
        activationChunkCorpusByteLength;
    const independentResourceModel = compileFullTallyResourceModel(
        topCount,
        ballots.filter((ballot) => ballot.declaration === 'submit').length,
    );
    const localRecordCensus = compileIndependentLocalRecordCensus(
        enumerateFullTallyLocalRecordSeals(independentModel),
    );
    const inventoryGenerations = await Promise.all(
        Array.from({ length: participantCount }, async (_, position) => {
            const rootSnapshot = await readRawStoreSnapshot(
                databaseName(runIdentity, position),
                ['root'],
            );
            const root = rootSnapshot[0]?.[0];
            if (
                typeof root !== 'object' ||
                root === null ||
                !('generation' in root) ||
                typeof root.generation !== 'bigint'
            ) {
                throw new Error(
                    'The retained root inventory generation is malformed.',
                );
            }
            return root.generation;
        }),
    );
    const expectedInventoryGeneration = BigInt(
        localRecordCensus.inventoryCommitCount / participantCount,
    );
    expect(inventoryGenerations).toEqual(
        Array.from(
            { length: participantCount },
            () => expectedInventoryGeneration,
        ),
    );
    expect(independentResourceModel).toMatchObject({
        activationChunkCorpusByteLength,
        activationInventoryByteLength,
        cleanVerifiedDownloadByteLength,
        maximumPrivatePreparationRecipientByteLength,
        preparationParentInventoryByteLength,
        sourceInventoryByteLength,
    });
    expect(kernelResources.maximumRequestByteLength).toBe(
        independentResourceModel.maximumChunkEvaluationRequestByteLength,
    );
    const relayWriteByteLength =
        relayWriteByteLengthByDatabase.get(relayDatabaseName) ?? 0;
    const relayReadByteLength =
        relayReadByteLengthByDatabase.get(relayDatabaseName) ?? 0;
    expect(relayWriteByteLength).toBe(activationChunkCorpusByteLength);
    const baselineRelayReadByteLength =
        participantCount * activationChunkCorpusByteLength;
    const relayRefetchByteLength =
        relayReadByteLength - baselineRelayReadByteLength;
    expect(relayRefetchByteLength).toBeGreaterThanOrEqual(0);
    const maximumChunkSetByteLength =
        participantCount *
        Math.max(...plan.chunks.map((chunk) => chunk.chunkByteLength));
    const accountedJavaScriptWasmOverlapByteLength =
        maximumChunkSetByteLength +
        kernelResources.maximumRequestByteLength +
        kernelResources.maximumResponseByteLength +
        kernelResources.wasmMemoryByteLength;
    const generationKmacCallCountPerParticipant =
        independentModel.kmacCensus.generationCallCount / participantCount;
    if (!Number.isSafeInteger(generationKmacCallCountPerParticipant)) {
        throw new Error(
            'The independent KMAC generation census is not participant symmetric.',
        );
    }
    const evaluationKmacCallCount =
        independentModel.kmacCensus.selectedEvaluationCallCount;
    const storageAfter = await navigator.storage.estimate();
    const visitCounts = visitCountsByRunIdentity.get(runIdentity);
    expect(visitCounts).toBeDefined();
    expect(Math.max(...(visitCounts ?? []))).toBeLessThanOrEqual(10);
    if (repairPath) {
        expect(visitCounts?.[0]).toBe(9);
        expect(visitCounts?.slice(1)).toEqual(
            Array.from({ length: participantCount - 1 }, () => 5),
        );
    } else {
        expect(visitCounts).toEqual(
            Array.from({ length: participantCount }, () => 5),
        );
    }
    console.info(
        JSON.stringify({
            evidence: 'complete-padded-tally-ceremony',
            path: repairPath ? 'repair' : 'ordinary',
            terminalKind: acceptedTerminal.kind,
            topCount,
            chunkCount: plan.chunks.length,
            logicalPayloadByteLength: plan.logicalPayloadByteLength,
            labelEntropyByteLength: plan.labelEntropyByteLength,
            manifestByteLength: plan.manifestByteLength,
            visits: visitCounts,
            longestForegroundIntervalMilliseconds:
                longestVisitMillisecondsByRunIdentity.get(runIdentity) ?? null,
            resourcesFromEmittedObjects: {
                activationChunkCorpusByteLength,
                activationInventoryByteLength,
                accountedJavaScriptWasmOverlapByteLength,
                cleanVerifiedDownloadByteLength,
                deduplicatedPublicCorpusByteLength,
                emittedUploadByteLength,
                evaluationKmacCallCount,
                generationKmacCallCountPerParticipant,
                kmacAssumptionCensus: independentModel.kmacCensus,
                maximumActivationRecordByteLength,
                maximumChunkSetByteLength,
                maximumEvaluationRecordByteLength,
                maximumPrivatePreparationRecipientByteLength,
                protectedRecordByteLength: totalProtectedRecordByteLength,
                protectedRecordCount,
                relayReadByteLength,
                relayRefetchByteLength,
                relayWriteByteLength,
                repairVerifiedDownloadByteLength:
                    cleanVerifiedDownloadByteLength +
                    activationVerificationInventoryByteLength +
                    relayRefetchByteLength,
            },
            storageUsageBefore: storageBefore.usage ?? null,
            storageUsageAfter: storageAfter.usage ?? null,
            kernelResources,
        }),
    );
};

afterEach(async () => {
    for (const client of [...openClients]) {
        closeClient(client);
    }
    openClients.clear();
    for (const name of databaseNames) {
        await deleteDatabase(name);
    }
    databaseNames.clear();
    visitCountsByRunIdentity.clear();
    visitStartsByClient.clear();
    longestVisitMillisecondsByRunIdentity.clear();
    relayReadByteLengthByDatabase.clear();
    relayWriteByteLengthByDatabase.clear();
    const workerKernelObjectUrl = await workerKernelObjectUrlPromise?.catch(
        () => undefined,
    );
    workerKernelObjectUrlPromise = undefined;
    if (workerKernelObjectUrl !== undefined) {
        URL.revokeObjectURL(workerKernelObjectUrl);
    }
});

describe('private preparation worker in Chromium', () => {
    it('accepts pregranted worker storage and refuses ungranted storage without a window requester', async () => {
        const originalStorage = Object.getOwnPropertyDescriptor(
            navigator,
            'storage',
        );
        const durableDatabaseName = `sealed-lattice-persistent-storage-${crypto.randomUUID()}`;
        databaseNames.add(durableDatabaseName);
        try {
            Object.defineProperty(navigator, 'storage', {
                configurable: true,
                value: { persisted: () => Promise.resolve(true) },
            });
            const durableState = await PrivatePreparationDurableState.open(
                durableDatabaseName,
                true,
            );
            durableState.close();

            Object.defineProperty(navigator, 'storage', {
                configurable: true,
                value: { persisted: () => Promise.resolve(false) },
            });
            await expect(
                PrivatePreparationDurableState.open(
                    `${durableDatabaseName}-ungranted`,
                    true,
                ),
            ).rejects.toMatchObject({ code: 'MissingPersistence' });
        } finally {
            if (originalStorage === undefined) {
                Reflect.deleteProperty(navigator, 'storage');
            } else {
                Object.defineProperty(navigator, 'storage', originalStorage);
            }
        }
    });

    it(
        'persists one exact package, opens only after durable consumption, and burns a crash-interrupted slot',
        { timeout: 300_000 },
        async () => {
            const runIdentity = crypto.randomUUID();
            const roster = await createCompletionRosterFixture();
            const canonicalRosterBytes = roster.canonicalRosterBytes;
            expect(roster.rosterIdentity).toHaveLength(64);
            const preparationPackages = await publishPreparationPackages(
                runIdentity,
                roster,
            );

            const firstSenderPosition = 2;
            const firstRecipientPosition = 8;
            const firstPackage = preparationPackages[firstSenderPosition];
            const firstCredential = roster.credentials[firstSenderPosition];
            const wrongCredential = roster.credentials[firstSenderPosition + 1];
            if (
                firstPackage === undefined ||
                firstCredential === undefined ||
                wrongCredential === undefined
            ) {
                throw new Error('The preparation fixture is incomplete.');
            }
            const firstSender = await openClient(
                runIdentity,
                firstSenderPosition,
            );
            await expect(
                firstSender.createPreparationPackage(
                    actionContext(firstSenderPosition),
                    canonicalRosterBytes,
                    wrongCredential.signingSecretKey,
                    wrongCredential.mailboxDecapsulationKey,
                    preparationAttempt,
                ),
            ).rejects.toThrow();
            const replayedPackage = await firstSender.createPreparationPackage(
                actionContext(firstSenderPosition),
                canonicalRosterBytes,
                firstCredential.signingSecretKey,
                firstCredential.mailboxDecapsulationKey,
                preparationAttempt,
            );
            expect(replayedPackage).toEqual(firstPackage);
            closeClient(firstSender);

            const firstRecipient = await openClient(
                runIdentity,
                firstRecipientPosition,
            );
            const firstPrivateBody =
                firstPackage.privateBodies[
                    remoteBodyIndex(firstSenderPosition, firstRecipientPosition)
                ];
            expect(firstPrivateBody).toBeInstanceOf(Uint8Array);
            if (firstPrivateBody === undefined) {
                throw new Error('The sender omitted the recipient body.');
            }
            await expect(
                firstRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: firstSenderPosition,
                status: 'resolved',
            });
            await expect(
                firstRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: firstSenderPosition,
                status: 'already-resolved',
            });
            const mutatedBody = Uint8Array.from(firstPrivateBody);
            mutatedBody[mutatedBody.byteLength - 1] ^= 1;
            await expect(
                firstRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    mutatedBody,
                ),
            ).rejects.toThrow();
            closeClient(firstRecipient);

            const restoredRecipient = await openClient(
                runIdentity,
                firstRecipientPosition,
            );
            await expect(
                restoredRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: firstSenderPosition,
                status: 'already-resolved',
            });
            closeClient(restoredRecipient);

            const firstRecipientDatabaseName = databaseName(
                runIdentity,
                firstRecipientPosition,
            );
            const retainedSlotSnapshot = await readRawStoreSnapshot(
                firstRecipientDatabaseName,
                ['slots'],
            );
            await restoreRawStoreSnapshot(
                firstRecipientDatabaseName,
                ['slots'],
                [[]],
            );
            const deletedSlotRecipient = await openClient(
                runIdentity,
                firstRecipientPosition,
            );
            await expect(
                deletedSlotRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(deletedSlotRecipient);
            await restoreRawStoreSnapshot(
                firstRecipientDatabaseName,
                ['slots'],
                retainedSlotSnapshot,
            );
            const retainedSlotRecords = retainedSlotSnapshot[0];
            const retainedSlotRecord = retainedSlotRecords?.[0];
            if (
                retainedSlotRecords === undefined ||
                retainedSlotRecord === undefined
            ) {
                throw new Error('The retained slot fixture is empty.');
            }
            await restoreRawStoreSnapshot(
                firstRecipientDatabaseName,
                ['slots'],
                [
                    [
                        ...retainedSlotRecords,
                        copyRawProtectedRecordWithIdentifier(
                            retainedSlotRecord,
                            'unexpected-protected-slot',
                        ),
                    ],
                ],
            );
            const insertedSlotRecipient = await openClient(
                runIdentity,
                firstRecipientPosition,
            );
            await expect(
                insertedSlotRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(insertedSlotRecipient);
            await restoreRawStoreSnapshot(
                firstRecipientDatabaseName,
                ['slots'],
                retainedSlotSnapshot,
            );

            const crashSenderPosition = 3;
            const crashRecipientPosition = 9;
            const crashPackage = preparationPackages[crashSenderPosition];
            if (crashPackage === undefined) {
                throw new Error('The crash preparation fixture is incomplete.');
            }
            const crashPrivateBody =
                crashPackage.privateBodies[
                    remoteBodyIndex(crashSenderPosition, crashRecipientPosition)
                ];
            if (crashPrivateBody === undefined) {
                throw new Error('The crash sender omitted the recipient body.');
            }

            const crashWorker = new Worker(crashWorkerUrl, { type: 'module' });
            await rawRequest(crashWorker, {
                requestId: 1,
                operation: 'initialize',
                input: {
                    databaseName: databaseName(
                        runIdentity,
                        crashRecipientPosition,
                    ),
                    kernelUrl: await resolveWorkerKernelUrl(),
                    kernelOptions: { allowUnpinnedKernel: true },
                    runtimeIdentity,
                    candidateBuildIdentity,
                },
            });
            const durableBoundary = new Promise<void>((resolve) => {
                crashWorker.addEventListener(
                    'message',
                    (event: MessageEvent<unknown>) => {
                        const data = event.data;
                        if (
                            typeof data === 'object' &&
                            data !== null &&
                            'testBoundary' in data &&
                            data.testBoundary === 'durably-consumed'
                        ) {
                            resolve();
                        }
                    },
                );
            });
            crashWorker.postMessage({
                requestId: 2,
                operation: 'consume-private-preparation',
                input: {
                    ...actionContext(crashRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    parentBody: crashPackage.parentBody,
                    parentSignature: crashPackage.parentSignature,
                    privateBody: crashPrivateBody,
                },
            } satisfies PrivatePreparationWorkerRequest);
            await durableBoundary;
            crashWorker.terminate();

            const recoveredRecipient = await openClient(
                runIdentity,
                crashRecipientPosition,
            );
            await expect(
                recoveredRecipient.consumePrivatePreparation(
                    actionContext(crashRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    crashPackage.parentBody,
                    crashPackage.parentSignature,
                    crashPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: crashSenderPosition,
                status: 'burned',
            });
            closeClient(recoveredRecipient);
        },
    );

    it(
        'executes and restores complete preparation, source, and finality',
        { timeout: 600_000 },
        async () => {
            const runIdentity = crypto.randomUUID();
            const submittedScores = Uint8Array.of(
                1,
                10,
                3,
                9,
                5,
                8,
                7,
                6,
                4,
                2,
            );
            const roster = await createCompletionRosterFixture();
            const canonicalRosterBytes = roster.canonicalRosterBytes;
            const preparationPackages = await publishPreparationPackages(
                runIdentity,
                roster,
            );
            const preparationParents = preparationPackages.map((entry) => ({
                body: entry.parentBody,
                signature: entry.parentSignature,
            }));

            for (
                let recipientPosition = 0;
                recipientPosition < participantCount;
                recipientPosition += 1
            ) {
                const client = await openClient(runIdentity, recipientPosition);
                for (
                    let senderPosition = 0;
                    senderPosition < participantCount;
                    senderPosition += 1
                ) {
                    if (senderPosition === recipientPosition) {
                        continue;
                    }
                    const senderPackage = preparationPackages[senderPosition];
                    const privateBody =
                        senderPackage?.privateBodies[
                            remoteBodyIndex(senderPosition, recipientPosition)
                        ];
                    if (
                        senderPackage === undefined ||
                        privateBody === undefined
                    ) {
                        throw new Error(
                            'The complete preparation fixture is incomplete.',
                        );
                    }
                    await expect(
                        client.consumePrivatePreparation(
                            actionContext(recipientPosition),
                            canonicalRosterBytes,
                            preparationAttempt,
                            senderPackage.parentBody,
                            senderPackage.parentSignature,
                            privateBody,
                        ),
                    ).resolves.toEqual({
                        senderPosition,
                        status: 'resolved',
                    });
                }
                closeClient(client);
            }

            const sourcePosition = 0;
            const crashWorker = new Worker(sourceCrashWorkerUrl, {
                type: 'module',
            });
            await rawRequest(crashWorker, {
                requestId: 1,
                operation: 'initialize',
                input: {
                    databaseName: databaseName(runIdentity, sourcePosition),
                    kernelUrl: await resolveWorkerKernelUrl(),
                    kernelOptions: { allowUnpinnedKernel: true },
                    runtimeIdentity,
                    candidateBuildIdentity,
                },
            });
            const sourceBoundary = new Promise<void>((resolve) => {
                crashWorker.addEventListener(
                    'message',
                    (event: MessageEvent<unknown>) => {
                        const data = event.data;
                        if (
                            typeof data === 'object' &&
                            data !== null &&
                            'testBoundary' in data &&
                            data.testBoundary === 'source-durably-bound'
                        ) {
                            resolve();
                        }
                    },
                );
            });
            crashWorker.postMessage({
                requestId: 2,
                operation: 'create-source-package',
                input: {
                    ...actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    choice: {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                },
            } satisfies PrivatePreparationWorkerRequest);
            await sourceBoundary;
            crashWorker.terminate();

            const sourceRollbackStoreNames = [
                'root',
                'actions',
                'sources',
            ] as const;
            const boundSourceRollbackSubset = await readRawStoreSnapshot(
                databaseName(runIdentity, sourcePosition),
                sourceRollbackStoreNames,
            );

            const recoveredSource = await openClient(
                runIdentity,
                sourcePosition,
            );
            const submitted = await recoveredSource.createSourcePackage(
                actionContext(sourcePosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                {
                    declaration: 'submit',
                    scoreEncodings: submittedScores,
                },
            );
            expect(submitted.sourceBody).toHaveLength(
                submittedSourceBodyByteLength,
            );
            await expect(
                recoveredSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                ),
            ).resolves.toEqual(submitted);
            await expect(
                recoveredSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: new Uint8Array(10),
                    },
                ),
            ).rejects.toThrow();
            closeClient(recoveredSource);

            const publishedSourceRollbackSubset = await readRawStoreSnapshot(
                databaseName(runIdentity, sourcePosition),
                sourceRollbackStoreNames,
            );
            await restoreRawStoreSnapshot(
                databaseName(runIdentity, sourcePosition),
                sourceRollbackStoreNames,
                boundSourceRollbackSubset,
            );
            const rolledBackSource = await openClient(
                runIdentity,
                sourcePosition,
            );
            await expect(
                rolledBackSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(rolledBackSource);
            await restoreRawStoreSnapshot(
                databaseName(runIdentity, sourcePosition),
                sourceRollbackStoreNames,
                publishedSourceRollbackSubset,
            );

            const restoredSource = await openClient(
                runIdentity,
                sourcePosition,
            );
            await expect(
                restoredSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                ),
            ).resolves.toEqual(submitted);
            closeClient(restoredSource);

            const abstainingPosition = 1;
            const abstainingSource = await openClient(
                runIdentity,
                abstainingPosition,
            );
            const abstention = await abstainingSource.createSourcePackage(
                actionContext(abstainingPosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                { declaration: 'abstain' },
            );
            expect(abstention.sourceBody).toHaveLength(
                abstentionSourceBodyByteLength,
            );
            closeClient(abstainingSource);

            const malformedPosition = 2;
            const malformedSource = await openClient(
                runIdentity,
                malformedPosition,
            );
            const mutatedParents = preparationParents.map((parent) => ({
                body: Uint8Array.from(parent.body),
                signature: Uint8Array.from(parent.signature),
            }));
            const mutatedParent = mutatedParents[3];
            if (mutatedParent === undefined) {
                throw new Error('The mutation fixture omitted a parent.');
            }
            mutatedParent.body[mutatedParent.body.byteLength - 1] ^= 1;
            await expect(
                malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    mutatedParents,
                    { declaration: 'abstain' },
                ),
            ).rejects.toThrow();
            await expect(
                malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    canonicalRosterBytes,
                    preparationAttempt + 1,
                    preparationParents,
                    { declaration: 'abstain' },
                ),
            ).rejects.toThrow();
            const recoveredAbstention =
                await malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    { declaration: 'abstain' },
                );
            expect(recoveredAbstention.sourceBody).toHaveLength(
                abstentionSourceBodyByteLength,
            );
            expect(recoveredAbstention.sourceSignature).toHaveLength(
                actionSignatureCarrierByteLength,
            );
            closeClient(malformedSource);

            const sourcePackages: (PublishedSourcePackage | undefined)[] =
                Array.from({ length: participantCount });
            const sourceDeclarations = Array.from(
                { length: participantCount },
                () => 'abstain' as const,
            ) as ('abstain' | 'submit')[];
            sourcePackages[0] = submitted;
            sourceDeclarations[0] = 'submit';
            sourcePackages[1] = abstention;
            sourcePackages[2] = recoveredAbstention;
            const unusableScores = [
                new Uint8Array(10),
                new Uint8Array(10).fill(15),
            ];
            for (
                let participantPosition = 3;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const unusable = unusableScores[participantPosition - 3];
                const choice =
                    unusable === undefined
                        ? ({ declaration: 'abstain' } as const)
                        : ({
                              declaration: 'submit',
                              scoreEncodings: unusable,
                          } as const);
                sourceDeclarations[participantPosition] = choice.declaration;
                sourcePackages[participantPosition] =
                    await client.createSourcePackage(
                        actionContext(participantPosition),
                        canonicalRosterBytes,
                        preparationAttempt,
                        preparationParents,
                        choice,
                    );
                closeClient(client);
            }
            const sourceCarriers = sourcePackages.map((source, position) => {
                if (source === undefined) {
                    throw new Error(
                        'The finalized source roster is incomplete.',
                    );
                }
                return {
                    declaration: sourceDeclarations[position] ?? 'abstain',
                    body: source.sourceBody,
                    signature: source.sourceSignature,
                };
            });

            const topCount = 1;
            const finalityPackages: PublishedFinalityPackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const finality = await client.createFinalitySignature(
                    actionContext(participantPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    topCount,
                );
                finalityPackages.push(finality);
                closeClient(client);
            }
            const finalityTargetIdentity = finalityPackages[0]?.targetIdentity;
            if (finalityTargetIdentity === undefined) {
                throw new Error('The finality roster is empty.');
            }
            expect(
                finalityPackages.every(
                    (entry) =>
                        entry.targetKind === 'computation' &&
                        entry.topCount === topCount &&
                        entry.sourceSubmissionBitmap === 0b0000_0001_1001 &&
                        entry.targetIdentity.every(
                            (byte, index) =>
                                byte === finalityTargetIdentity[index],
                        ),
                ),
            ).toBe(true);
            const conflictingFinality = await openClient(runIdentity, 9);
            await expect(
                conflictingFinality.createFinalitySignature(
                    actionContext(9),
                    canonicalRosterBytes,
                    preparationAttempt,
                    [...sourceCarriers].reverse(),
                    topCount,
                ),
            ).rejects.toThrow();
            await expect(
                conflictingFinality.createFinalitySignature(
                    actionContext(9),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    topCount + 1,
                ),
            ).rejects.toThrow();
            await expect(
                conflictingFinality.createFinalitySignature(
                    {
                        ...actionContext(9),
                        actionDefinitionIdentity: new Uint8Array(64).fill(0xee),
                    },
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    topCount,
                ),
            ).rejects.toThrow();
            closeClient(conflictingFinality);

            const activationPosition = 0;
            const finalitySignatures = finalityPackages
                .slice(0, 8)
                .map((finality, signerPosition) => ({
                    signerPosition,
                    signature: finality.finalitySignature,
                }));
            const activationInput: TallyGenerationInitializationInput = {
                ...actionContext(activationPosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                sources: sourceCarriers,
                finalitySignatures,
                topCount,
            };
            await crashWorkerAtBoundary(
                runIdentity,
                activationPosition,
                tallyGenerationInitializationCrashWorkerUrl,
                'tally-generation-durably-initialized',
                {
                    requestId: 2,
                    operation: 'initialize-padded-tally-generation',
                    input: activationInput,
                },
            );
            const allocatedGenerationRecord = await readRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            if (allocatedGenerationRecord === undefined) {
                throw new Error(
                    'The generation initialization crash omitted its durable checkpoint.',
                );
            }
            const rollbackSubsetStoreNames = [
                'root',
                'actions',
                'activations',
            ] as const;
            const allocatedRollbackSubset = await readRawStoreSnapshot(
                databaseName(runIdentity, activationPosition),
                rollbackSubsetStoreNames,
            );
            const activationClient = await openClient(
                runIdentity,
                activationPosition,
            );
            const initialization =
                await activationClient.initializePaddedTallyGeneration(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                );
            expect(initialization.status).toBe('already-initialized');
            expect(initialization.plan.topCount).toBe(topCount);
            expect(initialization.plan.inputWireCount).toBe(410);
            expect(initialization.plan.outputCount).toBe(15);
            expect(initialization.plan.chunks).toHaveLength(45);
            await expect(
                activationClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    1,
                ),
            ).rejects.toMatchObject({ name: 'Conflict' });
            await expect(
                activationClient.initializePaddedTallyGeneration(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures.slice(0, 7),
                    topCount,
                ),
            ).rejects.toThrow();
            closeClient(activationClient);

            await crashWorkerAtBoundary(
                runIdentity,
                activationPosition,
                tallyChunkCrashWorkerUrl,
                'tally-chunk-durably-persisted',
                {
                    requestId: 2,
                    operation: 'create-padded-tally-chunk',
                    input: {
                        ...actionContext(activationPosition),
                        expectedChunkOrdinal: 0,
                    },
                },
            );
            const persistedChunkRecord = await readRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            if (persistedChunkRecord === undefined) {
                throw new Error(
                    'The chunk crash boundary omitted retained chunk state.',
                );
            }
            const persistedRollbackSubset = await readRawStoreSnapshot(
                databaseName(runIdentity, activationPosition),
                rollbackSubsetStoreNames,
            );
            const restoredChunkClient = await openClient(
                runIdentity,
                activationPosition,
            );
            const chunk: PublishedPaddedTallyChunk =
                await restoredChunkClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    0,
                );
            expect(chunk.status).toBe('pending');
            expect(chunk.chunkOrdinal).toBe(0);
            expect(chunk.chunk).toHaveLength(
                initialization.plan.chunks[0]?.chunkByteLength,
            );
            expect(chunk.chunkIdentity).toHaveLength(64);
            await expect(
                restoredChunkClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    0,
                ),
            ).resolves.toEqual(chunk);
            await expect(
                restoredChunkClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    2,
                ),
            ).rejects.toMatchObject({ name: 'Conflict' });
            closeClient(restoredChunkClient);

            await restoreRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                allocatedGenerationRecord,
            );
            const rollbackClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                rollbackClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    0,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(rollbackClient);
            await restoreRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                persistedChunkRecord,
            );

            await restoreRawStoreSnapshot(
                databaseName(runIdentity, activationPosition),
                rollbackSubsetStoreNames,
                allocatedRollbackSubset,
            );
            const coordinatedRollbackClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                coordinatedRollbackClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    0,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(coordinatedRollbackClient);
            await restoreRawStoreSnapshot(
                databaseName(runIdentity, activationPosition),
                rollbackSubsetStoreNames,
                persistedRollbackSubset,
            );

            const lastChunkOrdinal = initialization.plan.chunks.length - 1;
            const publicationPreparationClient = await openClient(
                runIdentity,
                activationPosition,
            );
            for (
                let chunkOrdinal = 1;
                chunkOrdinal < lastChunkOrdinal;
                chunkOrdinal += 1
            ) {
                const pending =
                    await publicationPreparationClient.createPaddedTallyChunk(
                        actionContext(activationPosition),
                        chunkOrdinal,
                    );
                expect(pending.status).toBe('pending');
            }
            closeClient(publicationPreparationClient);
            const prePublicationRecord = await readRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            if (prePublicationRecord === undefined) {
                throw new Error(
                    'The pre-publication tally checkpoint is absent.',
                );
            }
            await crashWorkerAtBoundary(
                runIdentity,
                activationPosition,
                tallyPublicationCrashWorkerUrl,
                'tally-activation-durably-published',
                {
                    requestId: 2,
                    operation: 'create-padded-tally-chunk',
                    input: {
                        ...actionContext(activationPosition),
                        expectedChunkOrdinal: lastChunkOrdinal,
                    },
                },
            );
            const publishedGenerationRecord = await readRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            if (publishedGenerationRecord === undefined) {
                throw new Error(
                    'The publication crash omitted the completed activation.',
                );
            }
            const publishedActivationClient = await openClient(
                runIdentity,
                activationPosition,
            );
            const published =
                await publishedActivationClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    lastChunkOrdinal,
                );
            if (published.status !== 'complete') {
                throw new Error(
                    'The crash-restored activation remained incomplete.',
                );
            }
            expect(published.manifest).toHaveLength(
                initialization.plan.manifestByteLength,
            );
            await expect(
                publishedActivationClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    lastChunkOrdinal,
                ),
            ).resolves.toEqual(published);
            closeClient(publishedActivationClient);
            await restoreRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                prePublicationRecord,
            );
            const publicationRollbackClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                publicationRollbackClient.createPaddedTallyChunk(
                    actionContext(activationPosition),
                    lastChunkOrdinal,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(publicationRollbackClient);
            await restoreRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                publishedGenerationRecord,
            );

            await deleteRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            const stateLossClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                stateLossClient.initializePaddedTallyGeneration(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(stateLossClient);

            const computationResultClient = await openClient(runIdentity, 0);
            await expect(
                computationResultClient.readTallyResult(actionContext(0)),
            ).rejects.toThrow();
            closeClient(computationResultClient);
        },
    );

    it(
        'finalizes an all-abstain roster without an activation wave',
        { timeout: 300_000 },
        async () => {
            const runIdentity = crypto.randomUUID();
            const { canonicalRosterBytes, preparationParents } =
                await createCompletePreparation(runIdentity);
            const sources: PublishedSourcePackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                sources.push(
                    await client.createSourcePackage(
                        actionContext(participantPosition),
                        canonicalRosterBytes,
                        preparationAttempt,
                        preparationParents,
                        { declaration: 'abstain' },
                    ),
                );
                closeClient(client);
            }
            const sourceCarriers = sources.map((source) => ({
                declaration: 'abstain' as const,
                body: source.sourceBody,
                signature: source.sourceSignature,
            }));
            const topCount = 10;
            const finalities: PublishedFinalityPackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                finalities.push(
                    await client.createFinalitySignature(
                        actionContext(participantPosition),
                        canonicalRosterBytes,
                        preparationAttempt,
                        sourceCarriers,
                        topCount,
                    ),
                );
                closeClient(client);
            }
            expect(
                finalities.every(
                    (finality) =>
                        finality.targetKind === 'no-result' &&
                        finality.topCount === topCount &&
                        finality.sourceSubmissionBitmap === 0,
                ),
            ).toBe(true);
            const certificate = finalities
                .slice(0, 8)
                .map((finality, signerPosition) => ({
                    signerPosition,
                    signature: finality.finalitySignature,
                }));
            const resultClient = await openClient(runIdentity, 0);
            await expect(
                resultClient.readTallyResult(actionContext(0)),
            ).rejects.toThrow();
            await expect(
                resultClient.finalizeNoResult(
                    actionContext(0),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    certificate.slice(0, 7),
                    topCount,
                ),
            ).rejects.toThrow();
            await expect(
                resultClient.finalizeNoResult(
                    actionContext(0),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    certificate,
                    topCount,
                ),
            ).resolves.toMatchObject({
                kind: 'no-result',
                acceptedBallotAuthorshipBitmap: 0,
            });
            closeClient(resultClient);
            const restoredResultClient = await openClient(runIdentity, 0);
            await expect(
                restoredResultClient.readTallyResult(actionContext(0)),
            ).resolves.toMatchObject({
                kind: 'no-result',
                acceptedBallotAuthorshipBitmap: 0,
            });
            closeClient(restoredResultClient);
            const measurements = await Promise.all(
                Array.from(
                    { length: participantCount },
                    (_, participantPosition) =>
                        measureProtectedDatabase(
                            databaseName(runIdentity, participantPosition),
                        ),
                ),
            );
            const contextKeys = measurements.flatMap(
                (measurement) => measurement.contextKeys,
            );
            expect(
                measurements.reduce(
                    (sum, measurement) => sum + measurement.recordCount,
                    0,
                ),
            ).toBe(131);
            expect(new Set(contextKeys).size).toBe(131);
        },
    );

    it.skipIf(
        manualEvidenceEnvironment[
            topCountOneEvidenceCase.browserEnvironmentVariable
        ] !== '1',
    )(topCountOneEvidenceCase.testName, { timeout: 3_600_000 }, async () =>
        expectCompletePaddedTallyCeremony(1),
    );

    it.skipIf(
        manualEvidenceEnvironment[
            topCountTenEvidenceCase.browserEnvironmentVariable
        ] !== '1',
    )(topCountTenEvidenceCase.testName, { timeout: 7_200_000 }, async () =>
        expectCompletePaddedTallyCeremony(10),
    );

    it.skipIf(
        manualEvidenceEnvironment[
            emptyUsableBallotEvidenceCase.browserEnvironmentVariable
        ] !== '1',
    )(
        emptyUsableBallotEvidenceCase.testName,
        { timeout: 3_600_000 },
        async () =>
            expectCompletePaddedTallyCeremony(1, 'empty-usable-ballots'),
    );
});
