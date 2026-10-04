import { readParticipantLimits } from '#packages/sdk/src/participant/worker/bounds.js';
import {
    fromHexadecimal,
    hexadecimal,
} from '#packages/sdk/src/participant/worker/bytes.js';
import { instantiateParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import {
    authenticateRoot,
    dataKind,
    readDataKind,
} from '#packages/sdk/src/participant/worker/root.js';
import {
    openParticipantDatabase,
    readParticipantValue,
} from '#packages/sdk/src/participant/worker/storage.js';

export { mutateParticipantPadding } from './participant-padding-corruption.js';

export type SourceCustodyObservation = Readonly<{
    generation: number;
    dataKeyBytes: number;
    sourceReferences: number;
    sourceRecords: number;
}>;

type SourceCustodyRequest = Readonly<{
    namespace: string;
    runtimeIdentity: string;
    moduleDigest: string;
    mutation?: 'missing' | 'damaged';
}>;

// Bundled only by the guarded preparation harness. Root plaintext and keys
// stay inside the browser; mutations run only in its isolated profile copies.
export const inspectParticipantSourceCustody = async (
    request: SourceCustodyRequest,
): Promise<SourceCustodyObservation> => {
    if (
        !/^[0-9a-f]{128}$/u.test(request.runtimeIdentity) ||
        !/^[0-9a-f]{128}$/u.test(request.moduleDigest) ||
        (request.mutation !== undefined &&
            !['missing', 'damaged'].includes(request.mutation))
    )
        throw new Error('Invalid source custody fixture request.');
    const response = await fetch('/sdk/participant.wasm');
    if (!response.ok) throw new Error('The participant module is unavailable.');
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (
        hexadecimal(
            new Uint8Array(await crypto.subtle.digest('SHA-512', bytes)),
        ) !== request.moduleDigest
    )
        throw new Error('The source custody fixture received another module.');
    const { kernel, handlers } = await instantiateParticipantKernel(
        await WebAssembly.compile(bytes),
        noParallelHelpers,
    );
    if (kernel.worker_reserve(0, 0) !== 0)
        throw new Error('The source custody fixture memory plan was refused.');
    const database = await openParticipantDatabase(request.namespace);
    const privateBytes: Uint8Array[] = [];
    try {
        const context = {
            namespace: request.namespace,
            database,
            kernel,
            handlers,
            parallel: noParallelHelpers,
            runtime: fromHexadecimal(request.runtimeIdentity),
            limits: readParticipantLimits(kernel),
            separateEvaluation: false,
        };
        const root = await authenticateRoot(context);
        privateBytes.push(root.plaintext, root.manifest.dataKeys);
        const references = root.manifest.references.filter(
            (reference) => reference.kind === dataKind.sourceCapsule,
        );
        const keys = await new Promise<IDBValidKey[]>((resolve, reject) => {
            const reading = database
                .transaction('data')
                .objectStore('data')
                .getAllKeys();
            reading.onsuccess = () => resolve(reading.result);
            reading.onerror = () =>
                reject(
                    reading.error ??
                        new Error('Source record inventory read failed.'),
                );
        });
        const sourceKeys = keys.filter(
            (key) => Array.isArray(key) && key[0] === dataKind.sourceCapsule,
        );
        const observation = {
            generation: root.head.generation,
            dataKeyBytes: root.manifest.dataKeys.length,
            sourceReferences: references.length,
            sourceRecords: sourceKeys.length,
        };
        if (request.mutation !== undefined) {
            if (
                root.head.generation >= 12 ||
                references.length !== 1 ||
                sourceKeys.length !== 1 ||
                references[0].offset !== 0
            )
                throw new Error(
                    'The source capsule mutation requires one original pre-setup capsule.',
                );
            const capsule = await readDataKind(
                context,
                root.manifest,
                dataKind.sourceCapsule,
            );
            privateBytes.push(capsule);
            const original = capsule.slice();
            privateBytes.push(original);
            if (request.mutation === 'damaged')
                capsule[capsule.length - 1] ^= 1;
            const key = [dataKind.sourceCapsule, 0];
            await new Promise<void>((resolve, reject) => {
                const transaction = database.transaction('data', 'readwrite', {
                    durability: 'strict',
                });
                transaction.oncomplete = () => resolve();
                transaction.onabort = () =>
                    reject(
                        transaction.error ??
                            new Error('Source mutation transaction aborted.'),
                    );
                const store = transaction.objectStore('data');
                if (request.mutation === 'missing') store.delete(key);
                else store.put(new Blob([new Uint8Array(capsule)]), key);
            });
            const retained = await readParticipantValue(database, 'data', key);
            if (request.mutation === 'missing') {
                if (retained !== undefined)
                    throw new Error(
                        'The source capsule deletion did not persist.',
                    );
            } else {
                if (
                    !(retained instanceof Blob) ||
                    retained.size !== capsule.length
                )
                    throw new Error(
                        'The source capsule mutation changed its framing.',
                    );
                const actual = new Uint8Array(await retained.arrayBuffer());
                privateBytes.push(actual);
                if (
                    actual.some((value, index) => value !== capsule[index]) ||
                    actual.every((value, index) => value === original[index])
                )
                    throw new Error(
                        'The source capsule damage did not persist.',
                    );
            }
        }
        return observation;
    } finally {
        privateBytes.forEach((value) => value.fill(0));
        database.close();
    }
};
