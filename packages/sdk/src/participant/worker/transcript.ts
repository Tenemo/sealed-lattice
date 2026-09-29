import {
    maximumFoundationCopiedBufferByteLength,
    openPinnedFoundationCeremonyRuntime,
} from '@sealed-lattice/wasm';
import type { ArchiveReference } from '@sealed-lattice/wasm';

import { openPublicArchive } from '../../public-archive.js';
import type { PublicArchive } from '../../public-archive.js';
import {
    createTranscriptFileEncoder,
    encodeTranscriptIndex,
    openTranscript,
    transcriptIndexPurpose,
} from '../../transcript-archive.js';
import type {
    TranscriptFile,
    TranscriptSink,
} from '../../transcript-archive.js';

import { fromHexadecimal } from './bytes.js';
import { describe, PublicInputFailure } from './context.js';
import { networkMilliseconds, readBounded } from './public.js';

// The archive the application's SDK configures: the replicas' base URLs and
// hexadecimal verification keys, the fault bound, and the foundation kernel
// that encodes and checks archive records with the digest the SDK's build
// recorded. The worker fetches the kernel itself, as it does the module.
export type WorkerArchive = Readonly<{
    faultBound: number;
    replicas: readonly Readonly<{ baseUrl: string; verificationKey: string }>[];
    kernel: string;
    kernelSha256: string;
}>;

// The format's largest retrieval; a larger transcript is archived in parts.
const retrievalLimits = {
    maximumRecords: 65_536,
    maximumTotalBytes: 4_294_967_291,
};

// Archive failures are public input: the replicas are untrusted, and the
// participant stays pending.
const publicly = async <Value>(operation: () => Promise<Value>) => {
    try {
        return await operation();
    } catch (error) {
        if (error instanceof PublicInputFailure) throw error;
        throw new PublicInputFailure(
            'The archive is unavailable: ' + describe(error),
        );
    }
};

const withDeadline = (signal: AbortSignal | undefined) =>
    signal === undefined
        ? AbortSignal.timeout(networkMilliseconds)
        : AbortSignal.any([signal, AbortSignal.timeout(networkMilliseconds)]);

/**
 * The archive client for the poll's records, whose every record request has
 * the network deadline, and one client for each replica alone, which sends a
 * record to that replica without waiting for another.
 */
type OpenedArchive = Readonly<{
    faultBound: number;
    archive: PublicArchive;
    replicas: readonly PublicArchive[];
}>;

export const openArchive = (configuration: WorkerArchive, poll: string) =>
    publicly(async (): Promise<OpenedArchive> => {
        const runtime = await openPinnedFoundationCeremonyRuntime(
            new Uint8Array(
                await readBounded(
                    configuration.kernel,
                    maximumFoundationCopiedBufferByteLength,
                ),
            ).buffer,
            configuration.kernelSha256,
        );
        const replicas = configuration.replicas.map((replica) => ({
            baseUrl: replica.baseUrl,
            verificationKey: fromHexadecimal(replica.verificationKey),
        }));
        const archive = openPublicArchive(runtime, {
            context: poll,
            faultBound: configuration.faultBound,
            replicas,
            ...retrievalLimits,
        });
        return {
            faultBound: configuration.faultBound,
            archive: {
                ...archive,
                fetch: (reference, signal) =>
                    archive.fetch(reference, withDeadline(signal)),
            },
            replicas: replicas.map((replica) =>
                openPublicArchive(runtime, {
                    context: poll,
                    faultBound: 0,
                    replicas: [replica],
                    ...retrievalLimits,
                }),
            ),
        };
    });

// What archiving reports: the transcript's index, how many parts it lists,
// and its record count and bytes.
export type ArchivedTranscript = Readonly<{
    transcript: ArchiveReference;
    parts: number;
    records: number;
    byteLength: number;
}>;

/**
 * Records every public record a visit reads to its end under its name and
 * sends each record of the transcript to the replicas as it is produced. A
 * replica that fails to take a record, or does not answer within the network
 * deadline, can no longer hold the transcript and is sent nothing more, and
 * more replicas than the fault bound must take every record. Once the visit
 * reaches its outcome, the parts and then the index are acknowledged. A
 * record the visit reads twice must have the same bytes both times.
 */
export const createTranscriptRecorder = (opened: OpenedArchive) => {
    const started = performance.now();
    const holding = new Set(opened.replicas.keys());
    const sent = new Set<string>();
    const sink: TranscriptSink = (record) =>
        publicly(async () => {
            if (sent.has(record.reference.identity)) return;
            const controller = new AbortController();
            const signal = AbortSignal.any([
                controller.signal,
                AbortSignal.timeout(networkMilliseconds),
            ]);
            // Keep enough complete candidates that even b lying holders can
            // withhold their acknowledgement without blocking b+1 honest
            // ones. Extra slow replicas need not delay every recording visit.
            const desired = Math.min(holding.size, 2 * opened.faultBound + 1);
            const held = new Set<number>();
            let settled = 0;
            try {
                await new Promise<void>((resolve) => {
                    for (const position of holding) {
                        void opened.replicas[position]
                            .store(record, signal)
                            .then(
                                () => {
                                    held.add(position);
                                },
                                () => undefined,
                            )
                            .finally(() => {
                                settled++;
                                if (
                                    held.size >= desired ||
                                    settled === holding.size
                                )
                                    resolve();
                            });
                    }
                });
            } finally {
                controller.abort();
            }
            for (const position of holding)
                if (!held.has(position)) holding.delete(position);
            if (holding.size <= opened.faultBound)
                throw new PublicInputFailure(
                    'Too few archive replicas hold the transcript.',
                );
            sent.add(record.reference.identity);
        });
    const files = new Map<string, TranscriptFile>();
    const remember = (file: TranscriptFile) => {
        const previous = files.get(file.route);
        if (
            previous !== undefined &&
            previous.reference.identity !== file.reference.identity
        )
            throw new PublicInputFailure(
                'A public record changed during the visit.',
            );
        files.set(file.route, file);
    };
    return {
        // The caller obtains this index only from its authenticated root,
        // retained after successful setup verification over recorded bytes.
        // No chunk payload or protocol verdict is taken from an archive hint.
        reuse: (index: ArchiveReference) =>
            publicly(async () => {
                const transcript = await openTranscript(opened.archive, index);
                for (const file of transcript.files()) remember(file);
            }),
        // Archiving never stops the participant, so every failure to encode
        // or send a record is public input.
        open: (name: string) => {
            let encoder: ReturnType<typeof createTranscriptFileEncoder>;
            try {
                encoder = createTranscriptFileEncoder(
                    opened.archive,
                    name,
                    sink,
                );
            } catch (error) {
                throw new PublicInputFailure(
                    'The archive cannot hold a record: ' + describe(error),
                );
            }
            return {
                write: (bytes: Uint8Array) =>
                    publicly(() => encoder.write(bytes)),
                finish: () =>
                    publicly(async () => {
                        const file = await encoder.finish();
                        remember(file);
                    }),
            };
        },
        // Each part is acknowledged before the index that lists it. A replica
        // may take as long to check a closure as this visit took to read and
        // verify the whole transcript.
        archive: () =>
            publicly(async (): Promise<ArchivedTranscript> => {
                const encoded = await encodeTranscriptIndex(
                    opened.archive,
                    [...files.values()],
                    new Uint8Array(),
                    retrievalLimits,
                    sink,
                );
                const deadline = Math.max(
                    networkMilliseconds,
                    performance.now() - started,
                );
                for (const root of [
                    ...encoded.parts.map((part) => part.root),
                    encoded.index,
                ])
                    await opened.archive.retain(
                        root,
                        AbortSignal.timeout(deadline),
                    );
                return {
                    transcript: encoded.index,
                    parts: encoded.parts.length,
                    records: encoded.records,
                    byteLength: encoded.byteLength,
                };
            }),
    };
};

/**
 * The indexes among the roots the replicas report for the poll within the
 * network deadline: hints, never an inventory. A root no replica serves is
 * not a transcript.
 */
export const discoverTranscripts = (opened: OpenedArchive) =>
    publicly(async () => {
        const deadline = AbortSignal.timeout(networkMilliseconds);
        const seen = new Set<string>();
        const indexes: ArchiveReference[] = [];
        try {
            for await (const roots of opened.archive.discover(deadline))
                for (const root of roots) {
                    if (seen.has(root.identity)) continue;
                    seen.add(root.identity);
                    const fetched = await opened.archive
                        .fetch(root, deadline)
                        .catch((error: unknown) => {
                            if (deadline.aborted) throw error;
                            return undefined;
                        });
                    if (fetched?.record.purpose === transcriptIndexPurpose)
                        indexes.push(root);
                }
        } catch (error) {
            if (!deadline.aborted) throw error;
        }
        return indexes;
    });

/**
 * Serves a visit's public reads from an archived transcript. Only the
 * transcript's own failures are public input; a failure of the verifier that
 * consumes the bytes keeps its meaning.
 */
export const openTranscriptSource = async (
    opened: OpenedArchive,
    index: ArchiveReference,
) => {
    const transcript = await publicly(() =>
        openTranscript(opened.archive, index),
    );
    return {
        read: async (
            name: string,
            maximum: number,
            accept: (bytes: Uint8Array) => void | Promise<void>,
        ): Promise<number> => {
            const length = transcript.length(name);
            if (length === undefined)
                throw new PublicInputFailure('A public record is unavailable.');
            if (length > BigInt(maximum))
                throw new PublicInputFailure(
                    'A public record exceeds its bound.',
                );
            let consumer: { error: unknown } | undefined;
            try {
                return Number(
                    await transcript.read(name, async (bytes) => {
                        try {
                            await accept(bytes);
                        } catch (error) {
                            consumer = { error };
                            throw error;
                        }
                    }),
                );
            } catch (error) {
                if (consumer !== undefined) throw consumer.error;
                if (error instanceof PublicInputFailure) throw error;
                throw new PublicInputFailure(
                    'The archive is unavailable: ' + describe(error),
                );
            }
        },
    };
};
