import {
    candidateChunkBytes,
    candidatePageEntries,
    decodeCandidateManifest,
    encodeCandidateManifest,
    encodeCandidatePage,
    encodeCandidateReceipt,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';

// In-memory transport only: it never authenticates a protocol record. Tests
// may alter these public bytes independently of the owning verifier.
export const participantRelayFixture = () => {
    const chunks = new Map<string, Uint8Array>();
    const manifests = new Map<string, Uint8Array>();
    const lists = new Map<string, string[]>();
    let serial = 0;
    const identifier = () => (++serial).toString(16).padStart(32, '0');
    const putChunk = (bytes: Uint8Array) => {
        const id = identifier();
        chunks.set(id, bytes.slice());
        return id;
    };
    const append = (key: string, bytes: Uint8Array) => {
        decodeCandidateManifest(bytes);
        const id = identifier();
        manifests.set(id, bytes.slice());
        const entries = lists.get(key) ?? [];
        const index = entries.length;
        entries.push(id);
        lists.set(key, entries);
        return { id, index };
    };
    const publish = (key: string, files: ReadonlyMap<string, Uint8Array>) =>
        append(
            key,
            encodeCandidateManifest({
                files: [...files].map(([name, bytes]) => ({
                    name,
                    length: bytes.length,
                    chunks: Array.from(
                        {
                            length: Math.ceil(
                                bytes.length / candidateChunkBytes,
                            ),
                        },
                        (_, index) =>
                            putChunk(
                                bytes.subarray(
                                    index * candidateChunkBytes,
                                    (index + 1) * candidateChunkBytes,
                                ),
                            ),
                    ),
                })),
            }),
        );
    const response = (bytes: Uint8Array | undefined) =>
        bytes === undefined
            ? new Response(null, { status: 404 })
            : new Response(new Uint8Array(bytes));
    const fetch = async (request: string, options: RequestInit = {}) => {
        const url = new URL(request);
        if (options.method === 'POST') {
            const bytes = new Uint8Array(
                await (options.body as Blob).arrayBuffer(),
            );
            if (url.pathname === '/chunks') {
                if (bytes.length > candidateChunkBytes)
                    return new Response(null, { status: 413 });
                return response(
                    Uint8Array.from(putChunk(bytes).match(/../gu)!, (byte) =>
                        parseInt(byte, 16),
                    ),
                );
            }
            if (url.pathname.startsWith('/candidates/'))
                return response(
                    encodeCandidateReceipt(
                        append(
                            url.pathname.slice('/candidates/'.length),
                            bytes,
                        ),
                    ),
                );
        }
        if (url.pathname.startsWith('/candidates/')) {
            const entries =
                lists.get(url.pathname.slice('/candidates/'.length)) ?? [];
            const offset = Number(url.searchParams.get('offset'));
            return response(
                encodeCandidatePage({
                    total: entries.length,
                    ids: entries.slice(offset, offset + candidatePageEntries),
                }),
            );
        }
        if (url.pathname.startsWith('/candidate/'))
            return response(
                manifests.get(url.pathname.slice('/candidate/'.length)),
            );
        if (url.pathname.startsWith('/chunk/'))
            return response(chunks.get(url.pathname.slice('/chunk/'.length)));
        return new Response(null, { status: 404 });
    };
    return { chunks, manifests, lists, publish, fetch };
};
