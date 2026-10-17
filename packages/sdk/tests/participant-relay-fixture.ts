import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';

import { onTestFinished } from 'vitest';

import {
    candidateChunkBytes,
    candidatePageEntries,
    encodeCandidateManifest,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import { serveParticipantCandidates } from '#tools/ci/participant-candidate-http.js';
import { participantRelayStore } from '#tools/ci/participant-relay-record.js';

// The harness relay's own request handling and storage in a temporary
// directory, so a test is refused what the relay refuses. It never
// authenticates a protocol record; tests may alter these public bytes
// independently of the owning verifier.
export const participantRelayFixture = () => {
    const repository = realpathSync(path.resolve('.'));
    const scratch = path.join(repository, 'temp/test-relay-fixtures');
    mkdirSync(scratch, { recursive: true });
    const resolvedScratch = realpathSync(scratch);
    if (!resolvedScratch.startsWith(repository + path.sep))
        throw new Error('Relay fixtures escaped the repository.');
    const directory = mkdtempSync(
        path.join(resolvedScratch, 'participant-relay-'),
    );
    onTestFinished(() => {
        const resolved = realpathSync(directory);
        if (!resolved.startsWith(resolvedScratch + path.sep))
            throw new Error('Relay fixture escaped its scratch directory.');
        rmSync(resolved, { recursive: true, force: true });
    });
    const store = participantRelayStore(directory);
    const publish = async (
        key: string,
        files: ReadonlyMap<string, Uint8Array>,
    ) => {
        const entries = [];
        for (const [name, bytes] of files) {
            const chunks = [];
            for (
                let offset = 0;
                offset < bytes.length;
                offset += candidateChunkBytes
            )
                chunks.push(
                    await store.putChunk(
                        bytes.subarray(offset, offset + candidateChunkBytes),
                    ),
                );
            entries.push({ name, length: bytes.length, chunks });
        }
        return store.append(key, encodeCandidateManifest({ files: entries }));
    };
    // The file names of each manifest published under the key, in order.
    const published = async (key: string) => {
        const names: string[][] = [];
        for (let offset = 0; ; offset += candidatePageEntries) {
            const page = await store.page(key, offset);
            for (const locator of page.locators)
                names.push(
                    (await store.candidate(locator)).manifest.files.map(
                        ({ name }) => name,
                    ),
                );
            if (offset + candidatePageEntries >= page.total) return names;
        }
    };
    const fetch = async (request: string, options: RequestInit = {}) => {
        const body =
            options.body instanceof Blob
                ? new Uint8Array(await options.body.arrayBuffer())
                : new Uint8Array();
        let status = 200;
        let bytes: Uint8Array | undefined;
        const response = {
            setHeader: () => undefined,
            writeHead: (value: number) => {
                status = value;
                return response;
            },
            end: (value?: Uint8Array) => {
                bytes = value;
            },
        };
        const served = await serveParticipantCandidates(
            store,
            Object.assign(Readable.from(body.length > 0 ? [body] : []), {
                method: options.method ?? 'GET',
            }),
            response,
            new URL(request),
        );
        return served && status === 200 && bytes !== undefined
            ? new Response(new Uint8Array(bytes))
            : new Response(null, { status: served ? status : 404 });
    };
    return { publish, published, fetch };
};
