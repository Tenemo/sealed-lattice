import type { PublicProfileContext } from '../../module/context.js';
import {
    moduleCommand,
    tryModuleCommand,
    writeSetupInput,
} from '../../module/participant-module.js';
import {
    candidateChunkBytes,
    candidateManifestBytes,
} from '../../relay/candidate-codec.js';
import {
    findCandidate,
    readCandidateFile,
    streamCandidateFile,
} from '../../relay/candidates.js';
import { createCandidatePublication } from '../../relay/publication.js';
import { relayDownloadedBytes } from '../../relay/relay.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    equalBytes,
    readUnsigned16,
    readUnsigned32,
} from '../../shared/bytes.js';
import { PublicInputFailure, StorageFailure } from '../../shared/failures.js';
import { openDelivery } from '../../storage/delivery.js';
import {
    contributionCandidateKey,
    polynomialFile,
} from '../contribution/contribution-offer.js';
import type { ParticipantSession } from '../participant-session.js';

import {
    aggregateKey,
    evaluationKey,
    readAggregateData,
    verifyEvaluationFile,
} from './published-aggregate.js';
import { aggregateCapacity, readCachedAggregateChunk } from './setup-cache.js';
import {
    clearCollectionKind,
    collectionBlob,
    collectionBuffer,
    collectionBytes,
    collectionWriter,
    moveCollectedAggregate,
    writeCollection,
} from './setup-collection-cache.js';
import {
    publicOperation,
    publicStep,
    publicWork,
    selectionOperation,
} from './setup-public-work.js';
import { verifyOffer } from './setup-verification.js';
import type { SelectedOffer, SetupSelection } from './setup-verification.js';

// Leave one sixteenth of the download target for runtime delivery and bounded
// discovery metadata. Only complete public verification units cross a call.
const setupDownloadBudget = (2 ** 31 * 15) / 16;
export const setupDownloadFits = (bytes: number) =>
    relayDownloadedBytes() + bytes <= setupDownloadBudget;

type Polynomial =
    PublicProfileContext['profile']['contribution']['polynomials'][number];
const committed = (context: PublicProfileContext, index: number) =>
    context.profile.contribution.committedPolynomials.includes(index);
const outputWidth = (context: PublicProfileContext, polynomial: Polynomial) =>
    committed(context, polynomial.expandedIndex)
        ? context.profile.preparation.publishedAggregate.limbs *
          context.profile.preparation.publishedAggregate.generatedLimbBytes
        : polynomial.bytes / polynomial.coefficients;

export const fullOfferReadBytes = (context: PublicProfileContext) => {
    const bounds = context.profile.contribution;
    const sourceBytes = bounds.sourceCiphertextBytes;
    if (!Number.isSafeInteger(sourceBytes) || sourceBytes <= 0)
        throw new Error('The source family has no canonical length.');
    // Family ranges start at integer multiples of their fixed length. Their
    // largest offset inside a transport chunk is chunk minus gcd(chunk, length).
    let divisor = candidateChunkBytes;
    let remainder = sourceBytes;
    while (remainder !== 0) {
        const next = divisor % remainder;
        divisor = remainder;
        remainder = next;
    }
    const sourceReadBytes =
        candidateChunkBytes *
        Math.ceil(
            (sourceBytes + candidateChunkBytes - divisor) / candidateChunkBytes,
        );
    return (
        bounds.polynomials.reduce(
            (sum, polynomial) => sum + polynomial.bytes,
            0,
        ) +
        bounds.maximumProofBytes +
        candidateChunkBytes +
        bounds.bodyHeaderBytes +
        bounds.offerEnvelopeBytes +
        sourceReadBytes +
        context.profile.registration.signatureBytes +
        2 * candidateManifestBytes
    );
};

const resetCollection = async (
    context: PublicProfileContext,
    cache: IDBDatabase,
) => {
    await writeCollection(cache, (store) => store.clear());
    publicStep(context, publicOperation.beginCollection);
};

export const resumeCollection = async (
    session: ParticipantSession,
    cache: IDBDatabase,
    required?: readonly SelectedOffer[],
): Promise<SelectedOffer[]> => {
    const { context } = session;
    for (const kind of ['offer', 'job', 'proof'] as const)
        await clearCollectionKind(cache, kind);
    const record = await collectionBlob(cache, 'state');
    if (record === undefined) {
        publicStep(context, publicOperation.beginCollection);
        return [];
    }
    const maximum =
        context.profile.preparation.publishedAggregate
            .maximumCollectedReferenceBytes;
    const restored =
        record.size <= maximum
            ? tryModuleCommand(
                  context.module,
                  'selection',
                  selectionOperation.restoreCollection,
                  { input: await collectionBuffer(record) },
              )
            : undefined;
    if (restored === undefined) {
        await resetCollection(context, cache);
        return [];
    }
    if (restored.length % 66 !== 0)
        throw new Error('The collected offers have another shape.');
    const offers = Array.from({ length: restored.length / 66 }, (_, index) => ({
        position: readUnsigned16(restored, 66 * index),
        identity: restored.slice(66 * index + 2, 66 * (index + 1)),
    }));
    if (
        required !== undefined &&
        offers.some(
            (offer) =>
                !required.some(
                    (expected) =>
                        expected.position === offer.position &&
                        equalBytes(expected.identity, offer.identity),
                ),
        )
    ) {
        await resetCollection(context, cache);
        return [];
    }
    const complete = offers.length === context.profile.setupContributorCount;
    const data = await collectionBlob(cache, 'data');
    const retainedData =
        complete &&
        data?.size ===
            context.profile.preparation.publishedAggregate.retainedDataBytes;
    for (const polynomial of context.profile.contribution.polynomials) {
        if (retainedData && committed(context, polynomial.expandedIndex))
            continue;
        const capacity = aggregateCapacity(context, polynomial);
        const sourceWidth = polynomial.bytes / polynomial.coefficients;
        for (let offset = 0; offset < polynomial.bytes; offset += capacity) {
            const count = Math.min(capacity, polynomial.bytes - offset);
            const outputOffset =
                (offset / sourceWidth) * outputWidth(context, polynomial);
            const length =
                (count / sourceWidth) * outputWidth(context, polynomial);
            const blob = await collectionBlob(cache, [
                'sum',
                offers.length - 1,
                polynomial.expandedIndex,
                outputOffset,
            ]);
            if (blob?.size === length) continue;
            if (complete && !committed(context, polynomial.expandedIndex)) {
                try {
                    await readCachedAggregateChunk(
                        cache,
                        offers.length - 1,
                        polynomial.expandedIndex,
                        { offset, length: count },
                    );
                    continue;
                } catch (error) {
                    if (!(error instanceof StorageFailure)) throw error;
                }
            }
            await resetCollection(context, cache);
            return [];
        }
    }
    return offers;
};

export const collectOffer = async (
    session: ParticipantSession,
    relay: PublicRelay,
    cache: IDBDatabase,
    offers: SelectedOffer[],
    offer: SelectedOffer,
) => {
    const { context } = session;
    await clearCollectionKind(cache, 'offer');
    let writer: ReturnType<typeof collectionWriter> | undefined;
    await verifyOffer(context, relay, offer, async (index, offset, bytes) => {
        const polynomial = context.profile.contribution.polynomials.find(
            (candidate) => candidate.expandedIndex === index,
        );
        if (polynomial === undefined)
            throw new Error('The captured offer has an unknown polynomial.');
        if (offset === 0)
            writer = collectionWriter(
                cache,
                (recordOffset) => ['offer', index, recordOffset],
                aggregateCapacity(context, polynomial),
                polynomial.bytes,
            );
        if (writer === undefined)
            throw new Error('The offer capture has no writer.');
        await writer.append(bytes);
        if (
            offset + bytes.length === polynomial.bytes &&
            (await writer.finish()) !== polynomial.bytes
        )
            throw new PublicInputFailure(
                'A captured contribution is incomplete.',
            );
    });
    try {
        publicStep(
            context,
            publicOperation.beginCollectedOffer,
            offer.identity,
            offer.position,
        );
        for (const polynomial of context.profile.contribution.polynomials) {
            const capacity = aggregateCapacity(context, polynomial);
            const sourceWidth = polynomial.bytes / polynomial.coefficients;
            for (
                let offset = 0;
                offset < polynomial.bytes;
                offset += capacity
            ) {
                const length = Math.min(capacity, polynomial.bytes - offset);
                const incoming = await collectionBytes(
                    cache,
                    ['offer', polynomial.expandedIndex, offset],
                    length,
                );
                const outputOffset =
                    (offset / sourceWidth) * outputWidth(context, polynomial);
                const outputBytes =
                    (length / sourceWidth) * outputWidth(context, polynomial);
                const previous =
                    offers.length === 0
                        ? new Uint8Array(outputBytes)
                        : await collectionBytes(
                              cache,
                              [
                                  'sum',
                                  offers.length - 1,
                                  polynomial.expandedIndex,
                                  outputOffset,
                              ],
                              outputBytes,
                          );
                writeSetupInput(context.module, incoming);
                writeSetupInput(
                    context.module,
                    previous,
                    context.module.setup_chunk_capacity(),
                );
                if (
                    context.module.setup_public_work(
                        publicOperation.collectPolynomial,
                        polynomial.expandedIndex,
                        offset,
                        length,
                    ) !== 0 ||
                    context.module.setup_public_output_length() !== outputBytes
                )
                    throw new StorageFailure(
                        'The collected aggregate cache failed verification.',
                    );
                previous.set(
                    new Uint8Array(
                        context.module.memory.buffer,
                        context.module.setup_public_output_pointer(),
                        outputBytes,
                    ),
                );
                const value = new Blob([previous]);
                await writeCollection(cache, (store) => {
                    store.put(value, [
                        'sum',
                        offers.length,
                        polynomial.expandedIndex,
                        outputOffset,
                    ]);
                    store.delete(['offer', polynomial.expandedIndex, offset]);
                    if (offers.length > 0)
                        store.delete([
                            'sum',
                            offers.length - 1,
                            polynomial.expandedIndex,
                            outputOffset,
                        ]);
                });
            }
        }
        const count = publicWork(context, publicOperation.finishCollectedOffer);
        if (
            count.length !== 4 ||
            readUnsigned32(count, 0) !== offers.length + 1
        )
            throw new Error('The collected offer count changed.');
        const reference = moduleCommand(
            context.module,
            'selection',
            selectionOperation.retainCollection,
        );
        if (
            reference.length >
            context.profile.preparation.publishedAggregate
                .maximumCollectedReferenceBytes
        )
            throw new Error('The collected reference exceeds its bound.');
        await writeCollection(cache, (store) =>
            store.put(new Blob([reference.slice()]), 'state'),
        );
        offers.push(offer);
    } catch (error) {
        // A partial sum is disposable; its previous metadata must not restore it.
        try {
            await writeCollection(cache, (store) => store.clear());
        } catch (cause) {
            if (error instanceof Error) Object.assign(error, { cause });
        }
        throw error;
    }
};

const moveStreamedSums = async (
    context: PublicProfileContext,
    cache: IDBDatabase,
) => {
    const accepted = context.profile.setupContributorCount - 1;
    for (const polynomial of context.profile.contribution.polynomials.filter(
        (candidate) => !committed(context, candidate.expandedIndex),
    )) {
        const capacity = aggregateCapacity(context, polynomial);
        for (let offset = 0; offset < polynomial.bytes; offset += capacity) {
            const length = Math.min(capacity, polynomial.bytes - offset);
            const source = ['sum', accepted, polynomial.expandedIndex, offset];
            const value = await collectionBlob(cache, source);
            if (value === undefined) {
                await readCachedAggregateChunk(
                    cache,
                    accepted,
                    polynomial.expandedIndex,
                    { offset, length },
                );
                continue;
            }
            if (value.size !== length)
                throw new StorageFailure(
                    'A collected aggregate chunk is incomplete.',
                );
            await moveCollectedAggregate(
                cache,
                source,
                [accepted, polynomial.expandedIndex, offset],
                value,
            );
        }
    }
};

const generateEvaluation = async (
    session: ParticipantSession,
    relay: PublicRelay,
    cache: IDBDatabase,
    selection: SetupSelection,
    manifest: Uint8Array,
    identity: Uint8Array,
    ordinal: number,
) => {
    const { context } = session;
    const offer = selection.offers[ordinal];
    const polynomials = context.profile.contribution.polynomials.filter(
        (polynomial) => committed(context, polynomial.expandedIndex),
    );
    await findCandidate(
        relay,
        contributionCandidateKey(offer.position, offer.identity),
        async (candidate) => {
            await clearCollectionKind(cache, 'job');
            publicStep(
                context,
                publicOperation.beginEvaluationJob,
                manifest,
                ordinal,
            );
            for (const polynomial of polynomials) {
                publicStep(
                    context,
                    publicOperation.beginJobPolynomial,
                    undefined,
                    polynomial.expandedIndex,
                );
                const writer = collectionWriter(
                    cache,
                    (offset) => ['job', polynomial.expandedIndex, offset],
                    aggregateCapacity(context, polynomial),
                    polynomial.bytes,
                );
                await streamCandidateFile(
                    relay,
                    candidate,
                    polynomialFile(polynomial.expandedIndex),
                    polynomial.bytes,
                    async (bytes) => {
                        publicStep(
                            context,
                            publicOperation.jobPolynomial,
                            bytes,
                        );
                        await writer.append(bytes);
                    },
                );
                if ((await writer.finish()) !== polynomial.bytes)
                    throw new PublicInputFailure(
                        'An evaluation job input is incomplete.',
                    );
                publicStep(context, publicOperation.finishJobPolynomial);
            }
            for (const polynomial of polynomials) {
                publicStep(
                    context,
                    publicOperation.beginJobPolynomial,
                    undefined,
                    polynomial.expandedIndex,
                );
                const capacity = aggregateCapacity(context, polynomial);
                for (
                    let offset = 0;
                    offset < polynomial.bytes;
                    offset += capacity
                )
                    publicStep(
                        context,
                        publicOperation.jobPolynomial,
                        await collectionBytes(
                            cache,
                            ['job', polynomial.expandedIndex, offset],
                            Math.min(capacity, polynomial.bytes - offset),
                        ),
                    );
                publicStep(context, publicOperation.finishJobPolynomial);
            }
        },
    );
    await clearCollectionKind(cache, 'job');
    await clearCollectionKind(cache, 'proof');
    const bounds = context.profile.preparation.publishedAggregate;
    const writer = collectionWriter(
        cache,
        (offset) => ['proof', offset],
        candidateChunkBytes,
        bounds.maximumProofBytes,
    );
    for (;;) {
        const bytes = publicWork(context, publicOperation.nextJobOutput);
        if (bytes.length === 0) break;
        await writer.append(bytes);
    }
    const length = await writer.finish();
    const publication = createCandidatePublication(
        relay,
        evaluationKey(identity, ordinal),
        await openDelivery(context, session.root),
    );
    await publication.addStream('proof.bin', length, async (accept) => {
        for (let offset = 0; offset < length; offset += candidateChunkBytes)
            await accept(
                await collectionBytes(
                    cache,
                    ['proof', offset],
                    Math.min(candidateChunkBytes, length - offset),
                ),
            );
    });
    await publication.finish();
    await clearCollectionKind(cache, 'proof');
};

export const publishCollectedAggregate = async (
    session: ParticipantSession,
    relay: PublicRelay,
    cache: IDBDatabase,
    selection: SetupSelection,
): Promise<boolean> => {
    const { context } = session;
    const bounds = context.profile.preparation.publishedAggregate;
    const manifest = publicWork(context, publicOperation.sealCollection);
    const identity = publicWork(
        context,
        publicOperation.beginAggregate,
        manifest,
    );
    if (manifest.length !== bounds.manifestBytes || identity.length !== 64)
        throw new Error('The collected aggregate has another shape.');
    await moveStreamedSums(context, cache);
    const data = await collectionBlob(cache, 'data');
    const restored =
        data?.size === bounds.retainedDataBytes &&
        tryModuleCommand(
            context.module,
            'selection',
            selectionOperation.restoreAggregateData,
            {
                input: await collectionBuffer(data),
            },
        ) !== undefined;
    if (data !== undefined && !restored)
        await writeCollection(cache, (store) => store.delete('data'));
    const polynomials = context.profile.contribution.polynomials.filter(
        (polynomial) => committed(context, polynomial.expandedIndex),
    );
    const aggregateBytes = polynomials.reduce(
        (sum, polynomial) =>
            sum + polynomial.coefficients * bounds.limbs * manifest[0],
        0,
    );
    if (!restored) {
        if (!setupDownloadFits(aggregateBytes + 2 * candidateManifestBytes))
            return false;
        const publication = createCandidatePublication(
            relay,
            aggregateKey(selection.identity),
            await openDelivery(context, session.root),
        );
        await publication.addBytes('manifest.bin', manifest);
        for (const polynomial of polynomials) {
            const sourceWidth = polynomial.bytes / polynomial.coefficients;
            const capacity = aggregateCapacity(context, polynomial);
            await publication.addStream(
                polynomialFile(polynomial.expandedIndex),
                polynomial.coefficients * bounds.limbs * manifest[0],
                async (accept) => {
                    for (
                        let offset = 0;
                        offset < polynomial.bytes;
                        offset += capacity
                    ) {
                        const count = Math.min(
                            capacity,
                            polynomial.bytes - offset,
                        );
                        const outputOffset =
                            (offset / sourceWidth) *
                            outputWidth(context, polynomial);
                        const length =
                            (count / sourceWidth) *
                            outputWidth(context, polynomial);
                        const bytes = await collectionBytes(
                            cache,
                            [
                                'sum',
                                context.profile.setupContributorCount - 1,
                                polynomial.expandedIndex,
                                outputOffset,
                            ],
                            length,
                        );
                        for (
                            let start = 0;
                            start < bytes.length;
                            start += context.module.setup_chunk_capacity()
                        ) {
                            try {
                                publicStep(
                                    context,
                                    publicOperation.aggregatePolynomial,
                                    bytes.subarray(
                                        start,
                                        start +
                                            context.module.setup_chunk_capacity(),
                                    ),
                                    polynomial.expandedIndex,
                                    outputOffset + start,
                                );
                            } catch (error) {
                                if (error instanceof PublicInputFailure)
                                    throw Object.assign(
                                        new StorageFailure(
                                            'The collected aggregate cache failed verification.',
                                        ),
                                        { cause: error },
                                    );
                                throw error;
                            }
                        }
                        await accept(bytes);
                    }
                },
            );
        }
        await publication.finish();
        const reference = moduleCommand(
            context.module,
            'selection',
            selectionOperation.retainAggregateData,
        );
        if (reference.length !== bounds.retainedDataBytes)
            throw new Error('The aggregate data reference has another length.');
        await writeCollection(cache, (store) =>
            store.put(new Blob([reference.slice()]), 'data'),
        );
    }
    await clearCollectionKind(cache, 'sum');
    const jobBytes =
        polynomials.reduce((sum, polynomial) => sum + polynomial.bytes, 0) +
        2 * bounds.maximumProofBytes +
        4 * candidateManifestBytes;
    for (let ordinal = 0; ordinal < selection.offers.length; ordinal++) {
        if (
            !setupDownloadFits(
                bounds.maximumProofBytes + candidateManifestBytes,
            )
        )
            return false;
        try {
            await findCandidate(
                relay,
                evaluationKey(identity, ordinal),
                (candidate) =>
                    verifyEvaluationFile(context, relay, candidate, ordinal),
            );
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
            if (!setupDownloadFits(jobBytes)) return false;
            await generateEvaluation(
                session,
                relay,
                cache,
                selection,
                manifest,
                identity,
                ordinal,
            );
            await findCandidate(
                relay,
                evaluationKey(identity, ordinal),
                (candidate) =>
                    verifyEvaluationFile(context, relay, candidate, ordinal),
            );
        }
    }
    publicStep(context, publicOperation.finishAggregate);
    if (!setupDownloadFits(aggregateBytes + 2 * candidateManifestBytes))
        return false;
    await findCandidate(
        relay,
        aggregateKey(selection.identity),
        async (candidate) => {
            const published = await readCandidateFile(
                relay,
                candidate,
                'manifest.bin',
                bounds.manifestBytes,
            );
            if (!equalBytes(published, manifest))
                throw new PublicInputFailure(
                    'Another aggregate was published.',
                );
            publicStep(context, publicOperation.beginAggregate, manifest);
            await readAggregateData(context, relay, candidate, manifest, cache);
            publicStep(context, publicOperation.finishAggregateCache);
        },
    );
    return true;
};
