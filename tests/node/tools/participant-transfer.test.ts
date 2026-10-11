import { createServer } from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import {
    emptyParticipantTransfer,
    observeParticipantTransfer,
} from '#tools/ci/participant-transfer.js';

describe('participant HTTP payload measurements', () => {
    const servers: ReturnType<typeof createServer>[] = [];
    afterEach(async () => {
        for (const server of servers.splice(0)) {
            server.closeAllConnections();
            await new Promise<void>((resolve, reject) =>
                server.close((error) =>
                    error === undefined ? resolve() : reject(error),
                ),
            );
        }
    });
    it('counts binary uploads and UTF-8 or binary replies without counting header-only bodies', async () => {
        const totals = emptyParticipantTransfer();
        const server = createServer((request, response) => {
            observeParticipantTransfer(request, response, totals);
            request.resume();
            request.on('end', () => {
                if (request.method === 'HEAD') response.end('not transmitted');
                else if (request.url === '/empty')
                    response.writeHead(204).end();
                else if (request.url === '/text') response.end('ą漢');
                else response.end(Buffer.from([0, 0xff, 7]));
            });
        });
        servers.push(server);
        await new Promise<void>((resolve) =>
            server.listen(0, '127.0.0.1', resolve),
        );
        const address = server.address();
        if (address === null || typeof address === 'string')
            throw new Error('No test port.');
        const base = `http://127.0.0.1:${String(address.port)}`;
        for (const [route, length] of [
            ['/text', 17],
            ['/binary', 1024],
            ['/empty', 0],
        ] as const) {
            const response = await fetch(base + route, {
                method: 'POST',
                body: new Uint8Array(length),
            });
            await response.arrayBuffer();
        }
        await fetch(base, { method: 'HEAD' });
        expect(totals).toEqual({
            requests: 4,
            sentPayloadBytes: 1041,
            receivedPayloadBytes: 8,
            incompleteExchanges: 0,
            unknownRequestLengths: 0,
        });
    });
});
