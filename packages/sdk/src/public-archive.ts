import {
    FoundationKernelCommandError,
    isProtocolHash,
} from '@sealed-lattice/wasm';
import type {
    ArchiveAcknowledgement,
    ArchivePolicy,
    ArchiveRecord,
    ArchiveReference,
    ProtocolHash,
    PublicArchiveRuntime,
} from '@sealed-lattice/wasm';

export type { ArchiveRecord, ArchiveReference } from '@sealed-lattice/wasm';

/** This store contains public bytes only. Every read is checked again. */
export type PublicArchiveStore = Readonly<{
    get(identity: ProtocolHash): Promise<Uint8Array | undefined>;
    put(identity: ProtocolHash, bytes: Uint8Array): Promise<void>;
}>;

export type PublicArchiveOptions = Readonly<{
    context: ProtocolHash;
    faultBound: number;
    replicas: readonly Readonly<{
        baseUrl: string;
        verificationKey: Uint8Array;
    }>[];
    maximumRecords: number;
    maximumTotalBytes: number;
}>;

export type PublicArchive = Readonly<{
    encodeRecord(
        purpose: string,
        dependencies: readonly ArchiveReference[],
        payload: Uint8Array,
    ): Readonly<{ reference: ArchiveReference; bytes: Uint8Array }>;
    readRecord(reference: ArchiveReference, bytes: Uint8Array): ArchiveRecord;
    publish(
        root: ArchiveReference,
        source: PublicArchiveStore,
        signal?: AbortSignal,
    ): Promise<readonly number[]>;
    retrieve(
        root: ArchiveReference,
        destination: PublicArchiveStore,
        signal?: AbortSignal,
    ): Promise<Readonly<{ recordCount: number; byteLength: number }>>;
    /** Hints only: neither a complete inventory nor an absence or order claim. */
    discover(signal?: AbortSignal): AsyncIterable<readonly ArchiveReference[]>;
}>;

const maximumRecordBytes = 1_572_864;
const firstSuccessful = <Value>(
    operations: readonly Promise<Value>[],
): Promise<Value> =>
    new Promise((resolve, reject) => {
        let remaining = operations.length;
        if (remaining === 0)
            reject(new Error('No archive replica is configured.'));
        for (const operation of operations) {
            void operation.then(resolve, (error: unknown) => {
                remaining--;
                if (remaining === 0)
                    reject(
                        error instanceof Error
                            ? error
                            : new Error('Archive retrieval failed.'),
                    );
            });
        }
    });
const isReference = (value: unknown): value is ArchiveReference => {
    if (value === null || typeof value !== 'object') return false;
    const reference = value as Record<string, unknown>;
    return (
        isProtocolHash(reference.identity) &&
        typeof reference.byteLength === 'number' &&
        Number.isSafeInteger(reference.byteLength) &&
        reference.byteLength > 0 &&
        reference.byteLength <= maximumRecordBytes
    );
};

const readResponse = async (
    response: Response,
    maximum: number,
): Promise<Uint8Array> => {
    if (response.ok && response.body === null && maximum === 0)
        return new Uint8Array();
    if (!response.ok || response.body === null) {
        await response.body?.cancel();
        throw new Error('Archive response is unavailable.');
    }
    const reader = response.body.getReader();
    const bytes = new Uint8Array(maximum);
    let offset = 0;
    try {
        for (;;) {
            const chunk = await reader.read();
            if (chunk.done) return bytes.subarray(0, offset);
            if (chunk.value.byteLength > maximum - offset)
                throw new RangeError('Archive response exceeds its bound.');
            bytes.set(chunk.value, offset);
            offset += chunk.value.byteLength;
        }
    } finally {
        await reader.cancel();
        reader.releaseLock();
    }
};

export const openPublicArchive = (
    runtime: PublicArchiveRuntime,
    options: PublicArchiveOptions,
): PublicArchive => {
    if (
        !isProtocolHash(options.context) ||
        !Number.isSafeInteger(options.maximumRecords) ||
        options.maximumRecords < 1 ||
        options.maximumRecords > 65_536 ||
        !Number.isSafeInteger(options.maximumTotalBytes) ||
        options.maximumTotalBytes < 1 ||
        options.maximumTotalBytes > 4_294_967_291 ||
        options.replicas.length > 32
    )
        throw new RangeError(
            'Archive configuration exceeds its supported bounds.',
        );
    const context = options.context;
    const maximumRecords = options.maximumRecords;
    const maximumTotalBytes = options.maximumTotalBytes;
    const replicas = options.replicas.map((replica) => {
        const url = new URL(replica.baseUrl);
        if (
            url.username ||
            url.password ||
            url.search ||
            url.hash ||
            (url.protocol !== 'https:' &&
                !(
                    url.protocol === 'http:' &&
                    (url.hostname === '127.0.0.1' ||
                        url.hostname === 'localhost')
                ))
        )
            throw new TypeError(
                'Archive replicas require HTTPS or loopback HTTP.',
            );
        if (!url.pathname.endsWith('/')) url.pathname += '/';
        return {
            baseUrl: url.href,
            verificationKey: Uint8Array.from(replica.verificationKey),
        };
    });
    if (
        new Set(replicas.map((replica) => replica.baseUrl)).size !==
        replicas.length
    )
        throw new TypeError('Archive replica endpoints must be distinct.');
    const policy: ArchivePolicy = {
        faultBound: options.faultBound,
        verificationKeys: replicas.map((replica) => replica.verificationKey),
    };
    // This checks the configured key population and fault bound. It does not
    // assert that these keys represent physically independent fault domains.
    runtime.archiveReceiptMessage(policy, context, {
        identity: context,
        byteLength: 1,
    });
    const endpoint = (position: number, suffix: string): string =>
        new URL(suffix, replicas[position].baseUrl).href;
    const checked = (
        reference: ArchiveReference,
        bytes: Uint8Array,
    ): ArchiveRecord => runtime.readArchiveRecord(context, reference, bytes);

    const walk = async (
        root: ArchiveReference,
        load: (reference: ArchiveReference) => Promise<ArchiveRecord>,
        signal?: AbortSignal,
    ): Promise<{ recordCount: number; byteLength: number }> => {
        const pending: ArchiveReference[] = [];
        const lengths = new Map<string, number>();
        let byteLength = 0;
        const add = (reference: ArchiveReference): void => {
            if (!isReference(reference))
                throw new TypeError('Invalid archive reference.');
            const prior = lengths.get(reference.identity);
            if (prior !== undefined) {
                if (prior !== reference.byteLength)
                    throw new Error('Conflicting archive reference lengths.');
                return;
            }
            if (
                lengths.size >= maximumRecords ||
                reference.byteLength > maximumTotalBytes - byteLength
            )
                throw new RangeError(
                    'Archive closure exceeds its configured bound.',
                );
            lengths.set(reference.identity, reference.byteLength);
            byteLength += reference.byteLength;
            pending.push({ ...reference });
        };
        add(root);
        for (let index = 0; index < pending.length; index++) {
            signal?.throwIfAborted();
            const record = await load(pending[index]);
            for (const dependency of record.dependencies) add(dependency);
        }
        return { recordCount: lengths.size, byteLength };
    };

    return {
        encodeRecord: (purpose, dependencies, payload) =>
            runtime.encodeArchiveRecord({
                context,
                purpose,
                dependencies,
                payload,
            }),
        readRecord: checked,
        publish: async (rootInput, source, signal) => {
            const root = {
                identity: rootInput.identity,
                byteLength: rootInput.byteLength,
            };
            const controller = new AbortController();
            const combined =
                signal === undefined
                    ? controller.signal
                    : AbortSignal.any([signal, controller.signal]);
            const attempt = async (
                position: number,
            ): Promise<ArchiveAcknowledgement> => {
                await walk(
                    root,
                    async (reference) => {
                        const bytes = await source.get(reference.identity);
                        if (bytes === undefined)
                            throw new Error(
                                'Required public archive source bytes are missing.',
                            );
                        const record = checked(reference, bytes);
                        const response = await fetch(
                            endpoint(position, 'records/' + reference.identity),
                            {
                                method: 'PUT',
                                body: Uint8Array.from(bytes),
                                signal: combined,
                                credentials: 'omit',
                                redirect: 'error',
                            },
                        );
                        await readResponse(response, 0);
                        return record;
                    },
                    combined,
                );
                const response = await fetch(endpoint(position, 'retain'), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ context, root }),
                    signal: combined,
                    credentials: 'omit',
                    redirect: 'error',
                });
                return {
                    replicaPosition: position,
                    signature: await readResponse(response, 3309),
                };
            };
            // Do not wait for an unavailable replica after an authenticated
            // quorum. Every attempt has its own complete-closure transfer.
            const acknowledgements: ArchiveAcknowledgement[] = [];
            const failures: unknown[] = [];
            return await new Promise<readonly number[]>((resolve, reject) => {
                let settled = 0;
                for (let position = 0; position < replicas.length; position++) {
                    void attempt(position)
                        .then((acknowledgement) => {
                            acknowledgements.push(acknowledgement);
                            try {
                                resolve(
                                    runtime.authenticateArchiveAcknowledgements(
                                        policy,
                                        context,
                                        root,
                                        acknowledgements,
                                    ),
                                );
                            } catch (error) {
                                if (
                                    !(
                                        error instanceof
                                        FoundationKernelCommandError
                                    )
                                )
                                    throw error;
                            }
                        })
                        .catch((error: unknown) => {
                            failures.push(error);
                        })
                        .finally(() => {
                            settled++;
                            if (settled === replicas.length)
                                reject(
                                    (failures[0] instanceof Error
                                        ? failures[0]
                                        : undefined) ??
                                        new Error(
                                            'Insufficient authenticated archive acknowledgements.',
                                        ),
                                );
                        });
                }
            }).finally(() => controller.abort());
        },
        retrieve: async (root, destination, signal) =>
            walk(
                root,
                async (reference) => {
                    const cached = await destination.get(reference.identity);
                    if (cached !== undefined) {
                        try {
                            return checked(reference, cached);
                        } catch (error) {
                            if (!(
                                error instanceof FoundationKernelCommandError ||
                                error instanceof RangeError
                            ))
                                throw error;
                        }
                    }
                    const controller = new AbortController();
                    const combined =
                        signal === undefined
                            ? controller.signal
                            : AbortSignal.any([signal, controller.signal]);
                    try {
                        const recovered = await firstSuccessful(
                            replicas.map(async (_replica, position) => {
                                const response = await fetch(
                                    endpoint(
                                        position,
                                        'records/' + reference.identity,
                                    ),
                                    {
                                        signal: combined,
                                        credentials: 'omit',
                                        redirect: 'error',
                                    },
                                );
                                const bytes = await readResponse(
                                    response,
                                    reference.byteLength,
                                );
                                return {
                                    bytes,
                                    record: checked(reference, bytes),
                                };
                            }),
                        );
                        await destination.put(
                            reference.identity,
                            recovered.bytes,
                        );
                        return recovered.record;
                    } finally {
                        controller.abort();
                    }
                },
                signal,
            ),
        discover: async function* (signal) {
            const controller = new AbortController();
            const combined =
                signal === undefined
                    ? controller.signal
                    : AbortSignal.any([signal, controller.signal]);
            const page = (position: number, after: string, seen: number) =>
                (async () => {
                    const bytes = await readResponse(
                        await fetch(
                            endpoint(
                                position,
                                'discovery/' + context + '?after=' + after,
                            ),
                            {
                                signal: combined,
                                credentials: 'omit',
                                redirect: 'error',
                            },
                        ),
                        maximumRecordBytes,
                    );
                    const value: unknown = JSON.parse(
                        new TextDecoder('utf-8', { fatal: true }).decode(bytes),
                    );
                    if (
                        !Array.isArray(value) ||
                        value.length > maximumRecords - seen ||
                        !value.every(isReference)
                    )
                        throw new Error('Malformed archive discovery reply.');
                    let previous = after;
                    for (const reference of value) {
                        if (reference.identity <= previous)
                            throw new Error(
                                'Archive discovery cursor did not advance.',
                            );
                        previous = reference.identity;
                    }
                    return {
                        position,
                        roots: value,
                        after: previous,
                        seen: seen + value.length,
                    };
                })().catch(() => ({
                    position,
                    roots: [] as ArchiveReference[],
                    after,
                    seen,
                }));
            const pending = new Map(
                replicas.map((_replica, position) => [
                    position,
                    page(position, '', 0),
                ]),
            );
            try {
                while (pending.size > 0) {
                    const reply = await Promise.race(pending.values());
                    pending.delete(reply.position);
                    signal?.throwIfAborted();
                    if (reply.roots.length > 0) {
                        yield reply.roots;
                        pending.set(
                            reply.position,
                            page(reply.position, reply.after, reply.seen),
                        );
                    }
                }
            } finally {
                controller.abort();
            }
        },
    };
};
