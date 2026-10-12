import type { IncomingMessage, ServerResponse } from 'node:http';

export type ParticipantTransfer = {
    requests: number;
    sentPayloadBytes: number;
    receivedPayloadBytes: number;
    incompleteExchanges: number;
    unknownRequestLengths: number;
};

export const emptyParticipantTransfer = (): ParticipantTransfer => ({
    requests: 0,
    sentPayloadBytes: 0,
    receivedPayloadBytes: 0,
    incompleteExchanges: 0,
    unknownRequestLengths: 0,
});

// These local hosts send bounded responses with end(). Count payloads without
// capturing bodies or enabling browser network inspection. Upload lengths
// come from the browser's Content-Length; aborted exchanges stay explicit.
// HTTP headers, TLS and link-layer overhead are outside these counters.
export const observeParticipantTransfer = (
    request: IncomingMessage,
    response: ServerResponse,
    totals: ParticipantTransfer,
) => {
    totals.requests++;
    const length = request.headers['content-length'];
    if (
        typeof length === 'string' &&
        /^\d+$/u.test(length) &&
        Number.isSafeInteger(Number(length))
    )
        totals.sentPayloadBytes += Number(length);
    else if (
        request.method !== 'GET' &&
        request.method !== 'HEAD' &&
        request.method !== 'OPTIONS'
    )
        totals.unknownRequestLengths++;
    const end = response.end.bind(response);
    response.end = (
        body?: unknown,
        encoding?: BufferEncoding | (() => void),
        callback?: () => void,
    ) => {
        if (
            request.method === 'HEAD' ||
            response.statusCode === 204 ||
            response.statusCode === 304
        ) {
            // These responses carry no payload even if end receives one.
        } else if (typeof body === 'string')
            totals.receivedPayloadBytes += Buffer.byteLength(
                body,
                typeof encoding === 'string' ? encoding : undefined,
            );
        else if (body instanceof Uint8Array)
            totals.receivedPayloadBytes += body.byteLength;
        return typeof encoding === 'string'
            ? end(body, encoding, callback)
            : end(body, encoding);
    };
    response.once('close', () => {
        if (!response.writableFinished) totals.incompleteExchanges++;
    });
};
