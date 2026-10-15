import type { PublicProfileContext } from '../../module/context.js';
import {
    findCandidate,
    readCandidateFile,
    streamCandidateFile,
} from '../../relay/candidates.js';
import type { CandidateView } from '../../relay/candidates.js';
import type { PublicRelay } from '../../relay/relay.js';
import { hexadecimal } from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { polynomialFile } from '../contribution/contribution-offer.js';

import { aggregateCapacity, writeCache } from './setup-cache.js';
import { publicOperation, publicWork } from './setup-public-work.js';
import type { SetupSelection } from './setup-verification.js';

export const aggregateKey = (selection: Uint8Array) =>
    'aggregate/' + hexadecimal(selection);
export const evaluationKey = (aggregate: Uint8Array, ordinal: number) =>
    'aggregate-evaluation/' + hexadecimal(aggregate) + '/' + String(ordinal);

// Repackages bounded normalized output into the cache's coefficient-aligned
// chunks. No borrowed module view survives an awaited write.
const normalizedWriter = (
    context: PublicProfileContext,
    cache: IDBDatabase,
    polynomial: PublicProfileContext['profile']['contribution']['polynomials'][number],
) => {
    const buffer = new Uint8Array(aggregateCapacity(context, polynomial));
    let used = 0,
        offset = 0;
    const flush = async () => {
        const bytes = new Blob([buffer.subarray(0, used)]);
        await writeCache(cache, (store) =>
            store.put(bytes, [
                context.profile.setupContributorCount - 1,
                polynomial.expandedIndex,
                offset,
            ]),
        );
        offset += used;
        used = 0;
    };
    return {
        append: async (bytes: Uint8Array) => {
            if (bytes.length > polynomial.bytes - offset - used)
                throw new PublicInputFailure(
                    'A normalized aggregate exceeds its bound.',
                );
            for (let index = 0; index < bytes.length;) {
                const count = Math.min(
                    bytes.length - index,
                    buffer.length - used,
                );
                buffer.set(bytes.subarray(index, index + count), used);
                used += count;
                index += count;
                if (used === buffer.length) await flush();
            }
        },
        finish: async () => {
            if (offset + used !== polynomial.bytes)
                throw new PublicInputFailure(
                    'A normalized aggregate is incomplete.',
                );
            if (used > 0) await flush();
        },
    };
};

export const verifyEvaluationFile = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    candidate: CandidateView,
    ordinal: number,
) => {
    const bounds = context.profile.preparation.publishedAggregate;
    const header = new Uint8Array(bounds.proofHeaderBytes);
    let used = 0;
    await streamCandidateFile(
        relay,
        candidate,
        'proof.bin',
        bounds.maximumProofBytes,
        (bytes) => {
            let offset = 0;
            if (used < header.length) {
                const count = Math.min(header.length - used, bytes.length);
                header.set(bytes.subarray(0, count), used);
                offset += count;
                used += count;
                if (used === header.length)
                    publicWork(
                        context,
                        publicOperation.beginEvaluation,
                        header,
                        ordinal,
                    );
            }
            if (offset < bytes.length)
                publicWork(
                    context,
                    publicOperation.evaluationProof,
                    bytes.subarray(offset),
                );
        },
    );
    if (used !== header.length)
        throw new PublicInputFailure(
            'An aggregate evaluation proof is incomplete.',
        );
    publicWork(context, publicOperation.finishEvaluation);
};

export const readAggregateData = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    candidate: CandidateView,
    manifest: Uint8Array,
    cache: IDBDatabase,
) => {
    const bounds = context.profile.preparation.publishedAggregate;
    for (const polynomial of context.profile.contribution.polynomials.filter(
        (entry) =>
            context.profile.contribution.committedPolynomials.includes(
                entry.expandedIndex,
            ),
    )) {
        const bytes = polynomial.coefficients * bounds.limbs * manifest[0];
        const writer = normalizedWriter(context, cache, polynomial);
        let offset = 0;
        const length = await streamCandidateFile(
            relay,
            candidate,
            polynomialFile(polynomial.expandedIndex),
            bytes,
            async (incoming) => {
                for (
                    let start = 0;
                    start < incoming.length;
                    start += context.module.setup_chunk_capacity()
                ) {
                    const part = incoming.subarray(
                        start,
                        start + context.module.setup_chunk_capacity(),
                    );
                    const normalized = publicWork(
                        context,
                        publicOperation.aggregatePolynomial,
                        part,
                        polynomial.expandedIndex,
                        offset,
                    );
                    offset += part.length;
                    await writer.append(normalized);
                }
            },
        );
        if (length !== bytes)
            throw new PublicInputFailure(
                'A published aggregate polynomial is incomplete.',
            );
        await writer.finish();
    }
};

export const verifyPublishedAggregate = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    selection: SetupSelection,
    cache: IDBDatabase,
) => {
    const bounds = context.profile.preparation.publishedAggregate;
    await findCandidate(
        relay,
        aggregateKey(selection.identity),
        async (candidate) => {
            const manifest = await readCandidateFile(
                relay,
                candidate,
                'manifest.bin',
                bounds.manifestBytes,
            );
            const identity = publicWork(
                context,
                publicOperation.beginAggregate,
                manifest,
            );
            if (identity.length !== 64)
                throw new PublicInputFailure(
                    'The aggregate identity is incomplete.',
                );
            await readAggregateData(context, relay, candidate, manifest, cache);
            for (let ordinal = 0; ordinal < selection.offers.length; ordinal++)
                await findCandidate(
                    relay,
                    evaluationKey(identity, ordinal),
                    async (proof) => {
                        await verifyEvaluationFile(
                            context,
                            relay,
                            proof,
                            ordinal,
                        );
                    },
                );
            publicWork(context, publicOperation.finishAggregate);
        },
    );
};
