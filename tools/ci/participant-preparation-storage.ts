import { readParticipantLimits } from '#packages/sdk/src/participant/worker/bounds.js';
import {
    fromHexadecimal,
    hexadecimal,
} from '#packages/sdk/src/participant/worker/bytes.js';
import {
    contributionRecords,
    resumeParticipant,
} from '#packages/sdk/src/participant/worker/contribution.js';
import { restoreEnrollment } from '#packages/sdk/src/participant/worker/enrollment.js';
import { instantiateParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import {
    authenticateRoot,
    dataKind,
    readDataKind,
} from '#packages/sdk/src/participant/worker/root.js';
import { retainedProfile } from '#packages/sdk/src/participant/worker/roster.js';
import {
    openParticipantDatabase,
    readParticipantValue,
    snapshotParticipant,
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

export type CheckpointCustodyObservation = Readonly<{
    generation: number;
    phase: number | null;
    position: number;
    ownJournalSha512: string | null;
    headerSha512: string | null;
    recordInventorySha512: string;
    contributionRecords: number;
    checkpointRecords: number;
    endorsement: 'intent' | 'signed' | null;
    damagedRecord?: Readonly<{
        index: number;
        bytes: number;
        beforeSha512: string;
        afterSha512: string;
    }>;
}>;

// Authenticate original root, credential, profile and every declared own
// record before reporting opaque diagnostic identities. No private bytes or
// keys leave this fixture, and only an isolated copy requests the mutation.
export const inspectParticipantCheckpointCustody = async (
    request: Omit<SourceCustodyRequest, 'mutation'> &
        Readonly<{ damageCheckpoint?: boolean }>,
): Promise<CheckpointCustodyObservation> => {
    if (
        !/^[0-9a-f]{128}$/u.test(request.runtimeIdentity) ||
        !/^[0-9a-f]{128}$/u.test(request.moduleDigest)
    )
        throw new Error('Invalid checkpoint custody fixture request.');
    const digest = async (bytes: Uint8Array) =>
        hexadecimal(
            new Uint8Array(
                await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
            ),
        );
    const response = await fetch('/sdk/participant.wasm');
    if (!response.ok) throw new Error('The participant module is unavailable.');
    const moduleBytes = new Uint8Array(await response.arrayBuffer());
    if ((await digest(moduleBytes)) !== request.moduleDigest)
        throw new Error('The checkpoint fixture received another module.');
    const { kernel, handlers } = await instantiateParticipantKernel(
        await WebAssembly.compile(moduleBytes),
        noParallelHelpers,
    );
    if (kernel.worker_reserve(0, 0) !== 0)
        throw new Error('The checkpoint fixture memory plan was refused.');
    const database = await openParticipantDatabase(request.namespace);
    const privateBytes: Uint8Array[] = [];
    try {
        const initial = {
            namespace: request.namespace,
            database,
            kernel,
            handlers,
            parallel: noParallelHelpers,
            runtime: fromHexadecimal(request.runtimeIdentity),
            limits: readParticipantLimits(kernel),
            separateEvaluation: false,
        };
        const root = await authenticateRoot(initial);
        privateBytes.push(root.plaintext, root.manifest.dataKeys);
        const context = await retainedProfile(
            initial,
            root,
            await restoreEnrollment(initial, root, false),
        );
        const session = await resumeParticipant(context, root);
        const own = session.preparation.contribution;
        if (own !== undefined) privateBytes.push(own);
        const state = session.state;
        if (state !== undefined) {
            privateBytes.push(
                state.header,
                state.seed,
                state.coins,
                ...state.publicRecords.map((record) => record.key),
                ...state.privateRecords.map((record) => record.key),
                ...state.signingRecords.map((record) => record.key),
            );
        }
        const snapshot = await snapshotParticipant(database);
        const records: {
            store: string;
            coordinate: IDBValidKey;
            bytes: number;
            sha512: string;
        }[] = [];
        for (const record of contributionRecords(session)) {
            if (
                record.store !== 'contribution' &&
                record.store !== 'checkpoint'
            )
                throw new Error(
                    'The own checkpoint inventory names another store.',
                );
            const blob = await readParticipantValue(
                database,
                record.store,
                record.key,
            );
            if (!(blob instanceof Blob))
                throw new Error(
                    'An authenticated checkpoint record disappeared.',
                );
            const bytes = new Uint8Array(await blob.arrayBuffer());
            records.push({
                store: record.store,
                coordinate: record.key,
                bytes: bytes.length,
                sha512: await digest(bytes),
            });
            bytes.fill(0);
        }
        const observation: CheckpointCustodyObservation = {
            generation: root.head.generation,
            phase: state?.phase ?? null,
            position: context.position,
            ownJournalSha512: own === undefined ? null : await digest(own),
            headerSha512:
                state === undefined ? null : await digest(state.header),
            recordInventorySha512: await digest(
                new TextEncoder().encode(JSON.stringify(records)),
            ),
            contributionRecords: snapshot.counts.contribution,
            checkpointRecords: snapshot.counts.checkpoint,
            endorsement: session.preparation.endorsement?.stage ?? null,
        };
        if (!request.damageCheckpoint) return observation;
        if (
            root.head.generation !== 4 ||
            state?.phase !== 5 ||
            state.privateRecords.length === 0
        )
            throw new Error(
                'Checkpoint damage requires the original retained phase-five state.',
            );
        const index = state.privateRecords.length - 1;
        const record = await readParticipantValue(
            database,
            'checkpoint',
            index,
        );
        if (!(record instanceof Blob) || record.size === 0)
            throw new Error('The required checkpoint record is unavailable.');
        const changed = new Uint8Array(await record.arrayBuffer());
        privateBytes.push(changed);
        const beforeSha512 = await digest(changed);
        changed[changed.length - 1] ^= 1;
        await new Promise<void>((resolve, reject) => {
            const transaction = database.transaction(
                'checkpoint',
                'readwrite',
                { durability: 'strict' },
            );
            transaction.oncomplete = () => resolve();
            transaction.onabort = () =>
                reject(
                    transaction.error ??
                        new Error('Checkpoint damage was not committed.'),
                );
            transaction
                .objectStore('checkpoint')
                .put(new Blob([new Uint8Array(changed)]), index);
        });
        const reopened = await readParticipantValue(
            database,
            'checkpoint',
            index,
        );
        if (!(reopened instanceof Blob) || reopened.size !== changed.length)
            throw new Error('Checkpoint damage changed the record framing.');
        const actual = new Uint8Array(await reopened.arrayBuffer());
        privateBytes.push(actual);
        const afterSha512 = await digest(actual);
        if (
            afterSha512 === beforeSha512 ||
            afterSha512 !== (await digest(changed))
        )
            throw new Error('Checkpoint damage did not survive readback.');
        return {
            ...observation,
            damagedRecord: {
                index,
                bytes: changed.length,
                beforeSha512,
                afterSha512,
            },
        };
    } finally {
        privateBytes.forEach((bytes) => bytes.fill(0));
        database.close();
    }
};

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
