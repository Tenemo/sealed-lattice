import {
    candidateChunkBytes,
    candidateManifestBytes,
    encodeCandidatePage,
    encodeCandidateReceipt,
    isCandidateLocator,
    isCandidateKey,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import type {
    participantRelayStore,
    StoredParticipantCandidate,
} from '#tools/ci/participant-relay-record.js';

type Store = ReturnType<typeof participantRelayStore>;
// The parts of a Node HTTP request and response the relay uses, which the
// in-process test transport also supplies.
type CandidateRequest = AsyncIterable<Uint8Array> &
    Readonly<{ method?: string }>;
type CandidateResponse = {
    setHeader: (name: string, value: string) => unknown;
    writeHead: (status: number) => { end: () => unknown };
    end: (bytes?: Uint8Array) => unknown;
};
type Views = Readonly<{
    accept?: (key: string, bytes: Uint8Array) => Promise<boolean>;
    published?: (candidate: StoredParticipantCandidate) => Promise<void>;
    manifest?: (
        candidate: StoredParticipantCandidate,
    ) => Promise<Uint8Array | undefined>;
    chunk?: (
        locator: string,
        bytes: Uint8Array,
    ) => Promise<Uint8Array | undefined>;
    page?: (key: string, offset: number) => ReturnType<Store['page']>;
}>;

const readBody = async (request: CandidateRequest, maximum: number) => {
    const parts: Uint8Array[] = [];
    let length = 0;
    for await (const bytes of request) {
        length += bytes.length;
        if (length > maximum)
            throw new RangeError('Publication exceeds its bound.');
        parts.push(bytes);
    }
    return Buffer.concat(parts, length);
};

// Storage and bounded framing only. Views let the development harness model
// a malicious relay; no server verdict supplies authentication or acceptance.
export const serveParticipantCandidates = async (
    store: Store,
    request: CandidateRequest,
    response: CandidateResponse,
    url: URL,
    views: Views = {},
) => {
    const pathname = url.pathname;
    if (!(
        pathname === '/chunks' ||
        pathname.startsWith('/chunk/') ||
        pathname.startsWith('/candidate/') ||
        pathname.startsWith('/candidates/')
    ))
        return false;
    response.setHeader('Access-Control-Allow-Origin', '*');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', 'application/octet-stream');
    const send = (bytes: Uint8Array | undefined) => {
        response.writeHead(bytes === undefined ? 404 : 200);
        response.end(bytes);
    };
    try {
        if (
            pathname === '/chunks' &&
            request.method === 'POST' &&
            url.search === ''
        ) {
            const locator = await store.putChunk(
                await readBody(request, candidateChunkBytes),
            );
            send(Buffer.from(locator, 'hex'));
            return true;
        }
        if (pathname.startsWith('/candidates/')) {
            const key = pathname.slice('/candidates/'.length);
            if (!isCandidateKey(key))
                throw new RangeError('Invalid candidate key.');
            if (request.method === 'POST' && url.search === '') {
                const bytes = await readBody(request, candidateManifestBytes);
                if (
                    views.accept !== undefined &&
                    !(await views.accept(key, bytes))
                ) {
                    response.writeHead(503).end();
                    return true;
                }
                const receipt = await store.append(key, bytes);
                await views.published?.(await store.candidate(receipt.locator));
                send(encodeCandidateReceipt(receipt));
                return true;
            }
            const offset = url.searchParams.get('offset');
            if (
                request.method === 'GET' &&
                offset !== null &&
                /^(0|[1-9]\d*)$/u.test(offset) &&
                Number.isSafeInteger(Number(offset)) &&
                [...url.searchParams].length === 1
            ) {
                send(
                    encodeCandidatePage(
                        await (views.page ?? store.page)(key, Number(offset)),
                    ),
                );
                return true;
            }
        }
        for (const prefix of ['/candidate/', '/chunk/']) {
            if (!pathname.startsWith(prefix)) continue;
            const locator = pathname.slice(prefix.length);
            if (
                request.method !== 'GET' ||
                url.search !== '' ||
                !isCandidateLocator(locator)
            )
                break;
            if (prefix === '/candidate/') {
                const candidate = await store.candidate(locator);
                send(
                    views.manifest === undefined
                        ? candidate.bytes
                        : await views.manifest(candidate),
                );
            } else {
                const bytes = await store.chunk(locator);
                send(
                    views.chunk === undefined
                        ? bytes
                        : await views.chunk(locator, bytes),
                );
            }
            return true;
        }
        response.writeHead(400).end();
    } catch (error) {
        if (error instanceof RangeError) response.writeHead(400).end();
        else if (
            error !== null &&
            typeof error === 'object' &&
            'code' in error &&
            error.code === 'ENOENT'
        )
            response.writeHead(404).end();
        else throw error;
    }
    return true;
};
