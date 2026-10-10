import { PublicInputFailure } from '../shared/failures.js';

import {
    candidateChunkBytes,
    candidateIdentifierBytes,
    candidateManifestBytes,
    candidatePageEntries,
    decodeCandidateManifest,
    decodeCandidatePage,
    fillsDiscoveryPage,
    isCandidateId,
    isCandidateKey,
    type CandidateManifest,
} from './candidate-codec.js';
import { readBounded } from './relay.js';
import type { PublicRelay } from './relay.js';

// Candidates on the relay: each logical key's append-only discovery list of
// candidate locators, their manifests and their files' immutable chunks.

// A view only correlates one untrusted manifest and its immutable transport
// locators. It carries no author, byte-identity or proof verification result.
export type CandidateView = Readonly<{
    id: string;
    manifest: () => Promise<CandidateManifest>;
}>;

const publicCandidate = (relay: PublicRelay, id: string): CandidateView => {
    if (!isCandidateId(id))
        throw new PublicInputFailure('Malformed candidate locator.');
    let loaded: Promise<CandidateManifest> | undefined;
    return {
        id,
        manifest: () =>
            (loaded ??= (async () => {
                const bytes = await readBounded(
                    relay.base + 'candidate/' + id,
                    candidateManifestBytes,
                );
                try {
                    return decodeCandidateManifest(bytes);
                } catch {
                    throw new PublicInputFailure(
                        'Malformed candidate manifest.',
                    );
                }
            })()),
    };
};

// One page of a key's candidate discovery list, from the offset.
export const readCandidatePage = async (
    relay: PublicRelay,
    key: string,
    offset: number,
) =>
    decodeCandidatePage(
        await readBounded(
            relay.base + 'candidates/' + key + '?offset=' + String(offset),
            12 + candidatePageEntries * candidateIdentifierBytes,
        ),
    );

// Freeze a finite discovery prefix for this operation. Yield each locator before
// fetching its manifest, so a malformed candidate cannot monopolize a round
// of a caller's fair scan across authors. A later operation sees later appends.
export async function* readCandidates(relay: PublicRelay, key: string) {
    if (!isCandidateKey(key)) throw new Error('Invalid candidate key.');
    let offset = 0;
    let end: number | undefined;
    for (;;) {
        let page;
        try {
            page = await readCandidatePage(relay, key, offset);
        } catch (error) {
            if (
                error instanceof PublicInputFailure ||
                error instanceof RangeError
            )
                return;
            throw error;
        }
        end ??= page.total;
        if (
            page.total < end ||
            !fillsDiscoveryPage(
                page.ids.length,
                page.total,
                offset,
                candidatePageEntries,
            )
        )
            return;
        for (const id of page.ids.slice(0, end - offset))
            yield publicCandidate(relay, id);
        offset += page.ids.length;
        if (offset >= end) return;
    }
}

export const findCandidate = async <Value>(
    relay: PublicRelay,
    key: string,
    consume: (candidate: CandidateView) => Promise<Value>,
): Promise<Value> => {
    for await (const candidate of readCandidates(relay, key)) {
        try {
            return await consume(candidate);
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    throw new PublicInputFailure(
        'No valid complete candidate is available: ' + key,
    );
};

// The discovery lists of the roster positions below the count that the
// filter includes, by position.
export const candidateLists = (
    relay: PublicRelay,
    count: number,
    key: (position: number) => string,
    include: (position: number) => boolean = () => true,
) => {
    const lists = new Map<number, AsyncIterator<CandidateView>>();
    for (let position = 0; position < count; position++)
        if (include(position))
            lists.set(
                position,
                readCandidates(relay, key(position))[Symbol.asyncIterator](),
            );
    return lists;
};

// Takes candidates from per-author discovery lists fairly: each round visits
// the next candidate of every list that still has one, in position order, so
// that no author's list, however long, delays or displaces another's. A
// visit returns whether it retires its position. The scan ends with the first
// value `result` gives after a visit or a round, or with none once every list
// is exhausted or retired; `afterRound`, when given, runs after each round
// that gives no value.
export const scanCandidatesFairly = async <Candidate, Result>(
    lists: Map<number, AsyncIterator<Candidate>>,
    visit: (position: number, candidate: Candidate) => Promise<boolean>,
    result: () => Result | undefined,
    afterRound?: () => Promise<void>,
): Promise<Result | undefined> => {
    let value = result();
    while (value === undefined && lists.size > 0) {
        for (const [position, candidates] of lists) {
            const next = await candidates.next();
            if (next.done) {
                lists.delete(position);
                continue;
            }
            if (await visit(position, next.value)) lists.delete(position);
            value = result();
            if (value !== undefined) return value;
        }
        await afterRound?.();
        value = result();
    }
    return value;
};

export const streamCandidateFile = async (
    relay: PublicRelay,
    candidate: CandidateView,
    name: string,
    maximum: number,
    accept: (bytes: Uint8Array) => void | Promise<void>,
) => {
    const file = (await candidate.manifest()).files.find(
        (entry) => entry.name === name,
    );
    if (
        !Number.isSafeInteger(maximum) ||
        maximum < 0 ||
        file === undefined ||
        file.length > maximum
    )
        throw new PublicInputFailure(
            'A candidate file is missing or exceeds its bound.',
        );
    let remaining = file.length;
    for (const id of file.chunks) {
        const length = Math.min(candidateChunkBytes, remaining);
        const bytes = await readBounded(relay.base + 'chunk/' + id, length);
        if (bytes.length !== length)
            throw new PublicInputFailure('A candidate chunk is incomplete.');
        await accept(bytes);
        remaining -= length;
    }
    return file.length;
};

export const readCandidateFile = async (
    relay: PublicRelay,
    candidate: CandidateView,
    name: string,
    maximum: number,
) => {
    if (!Number.isSafeInteger(maximum) || maximum < 0)
        throw new PublicInputFailure('A candidate file has an invalid bound.');
    let result: Uint8Array | undefined;
    let offset = 0;
    const file = (await candidate.manifest()).files.find(
        (entry) => entry.name === name,
    );
    if (file !== undefined && file.length <= maximum)
        result = new Uint8Array(file.length);
    await streamCandidateFile(relay, candidate, name, maximum, (bytes) => {
        result!.set(bytes, offset);
        offset += bytes.length;
    });
    return result!;
};
