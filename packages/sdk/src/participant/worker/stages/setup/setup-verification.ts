import type {
    PublicContext,
    PublicProfileContext,
} from '../../module/context.js';
import {
    readModuleMemory,
    writeSetupInput,
} from '../../module/participant-module.js';
import { readParticipantProfile } from '../../module/runtime-bounds.js';
import type { CandidateView } from '../../relay/candidates.js';
import {
    candidateLists,
    findCandidate,
    readCandidateFile,
    readCandidates,
    scanCandidatesFairly,
    streamCandidateFile,
} from '../../relay/candidates.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    readUnsigned16,
    tupleFields,
    unsigned32,
} from '../../shared/bytes.js';
import {
    ModuleFailure,
    PublicInputFailure,
    ResourceFailure,
} from '../../shared/failures.js';
import { encodeSignedPacket } from '../../shared/signed-packet.js';
import type { SignedPacket } from '../../shared/signed-packet.js';
import {
    contributionCandidateKey,
    polynomialFile,
} from '../contribution/contribution.js';
import {
    proposalRegistrationBodyDigests,
    rosterBegin,
    streamRegistrations,
    validRegistrationBodyDigests,
} from '../roster/roster.js';

import {
    aggregateCapacity,
    openSetupCache,
    readCachedAggregateChunk,
    writeCache,
} from './setup-cache.js';

// The setup verification. The owning Rust verifiers authenticate the
// roster, the complete selected offers, the organizer's proposal and the
// endorsement certificate; a verifier without participant state verifies
// them from the poll's identity and the relay's public records alone.

export type SelectedOffer = Readonly<{
    position: number;
    identity: Uint8Array;
}>;

type SetupSelection = Readonly<{
    identity: Uint8Array;
    offers: readonly SelectedOffer[];
}>;

const offerKey = (offer: SelectedOffer) =>
    contributionCandidateKey(offer.position, offer.identity);

// These getters describe only a selection already authenticated by Rust.
const selectedSetup = (context: PublicProfileContext): SetupSelection => {
    const { module, profile } = context;
    const count = module.setup_selection_count();
    const pointer = module.setup_selection_identity_pointer();
    if (count !== profile.setupContributorCount || pointer === 0)
        throw new PublicInputFailure(
            'No authenticated setup selection is available.',
        );
    const identity = readModuleMemory(module, pointer, 64);
    const offers = Array.from({ length: count }, (_, ordinal) => {
        const position = module.setup_selection_position(ordinal) >>> 0;
        const bodyIdentityPointer =
            module.setup_selection_body_identity_pointer(ordinal);
        if (
            position >= profile.eligibleContributorCount ||
            bodyIdentityPointer === 0
        )
            throw new PublicInputFailure(
                'The setup selection has an invalid author.',
            );
        return {
            position,
            identity: readModuleMemory(module, bodyIdentityPointer, 64),
        };
    });
    return { identity, offers };
};

export const setupOutput = (context: PublicContext) =>
    readModuleMemory(
        context.module,
        context.module.setup_output_pointer(),
        context.module.setup_output_length(),
    );

export const authenticateSelection = (
    context: PublicProfileContext,
    packet: SignedPacket,
    retained = false,
) => {
    const bytes = encodeSignedPacket(packet);
    writeSetupInput(context.module, bytes);
    if (context.module.setup_selection_begin(bytes.length) !== 0)
        throw retained
            ? new Error('The retained setup selection was refused.')
            : new PublicInputFailure('The setup selection was refused.');
    return selectedSetup(context);
};

export const readSelection = async (
    context: PublicProfileContext,
    relay: PublicRelay,
): Promise<SignedPacket> =>
    findCandidate(relay, 'selection', async (candidate) => {
        const packet = {
            body: await readCandidateFile(
                relay,
                candidate,
                'selection.bin',
                context.profile.preparation.selectionBodyBytes,
            ),
            signature: await readCandidateFile(
                relay,
                candidate,
                'signature.bin',
                context.profile.registration.signatureBytes,
            ),
        };
        authenticateSelection(context, packet);
        return packet;
    });

// A bounded lookahead only. The later complete proof stream must reproduce
// these bytes inside Rust; an interrupted fetch supplies no verified record.
const readProofPrefix = async (
    relay: PublicRelay,
    candidate: CandidateView,
    maximum: number,
    length: number,
) => {
    const prefix = new Uint8Array(length);
    const complete = new Error('The bounded proof lookahead is complete.');
    let used = 0;
    try {
        await streamCandidateFile(
            relay,
            candidate,
            'proof.bin',
            maximum,
            (bytes) => {
                const count = Math.min(bytes.length, length - used);
                prefix.set(bytes.subarray(0, count), used);
                used += count;
                if (used === length) throw complete;
            },
        );
    } catch (error) {
        if (error !== complete) throw error;
    }
    if (used !== length)
        throw new PublicInputFailure('A contribution proof is incomplete.');
    return prefix;
};

const offerAvailable = (
    context: PublicProfileContext,
    offer: SelectedOffer,
) => {
    writeSetupInput(context.module, offer.identity);
    return (
        context.module.setup_offer_available(
            offer.position,
            offer.identity.length,
        ) === 1
    );
};

// Both discovery and selected aggregation authenticate the same complete
// envelope and lookahead before reading any polynomial under its named route.
const beginOffer = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    offer: SelectedOffer,
    candidate: CandidateView,
    begin: (length: number) => number,
) => {
    const { module, profile } = context;
    const bounds = profile.contribution;
    const envelope = await readCandidateFile(
        relay,
        candidate,
        'offer.bin',
        bounds.offerEnvelopeBytes,
    );
    const signature = await readCandidateFile(
        relay,
        candidate,
        'offer-signature.bin',
        profile.registration.signatureBytes,
    );
    const header = await readCandidateFile(
        relay,
        candidate,
        'body-header.bin',
        bounds.bodyHeaderBytes,
    );
    const proofPrefix = await readProofPrefix(
        relay,
        candidate,
        bounds.maximumProofBytes,
        bounds.proofHeaderBytes,
    );
    if (header.length !== bounds.bodyHeaderBytes)
        throw new PublicInputFailure('A contribution offer is incomplete.');
    const control = concatenate(
        unsigned32(envelope.length),
        envelope,
        signature,
        header,
        proofPrefix,
    );
    writeSetupInput(module, control);
    if (begin(control.length) !== 0)
        throw new PublicInputFailure('A contribution offer was refused.');
    // Check the authenticated envelope's transport destination before its
    // proof can replace any author in the module's verified-offer pool.
    const fields = tupleFields(envelope);
    if (
        readUnsigned16(fields[2], 0) !== offer.position ||
        !equalBytes(fields[4], offer.identity)
    )
        throw new PublicInputFailure(
            'The offer route names another body or author.',
        );
};

const streamOfferProof = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    candidate: CandidateView,
    absorb: (offset: number, length: number) => number,
) => {
    let offset = 0;
    await streamCandidateFile(
        relay,
        candidate,
        'proof.bin',
        context.profile.contribution.maximumProofBytes,
        (bytes) => {
            writeSetupInput(context.module, bytes);
            if (absorb(offset, bytes.length) !== 0)
                throw new PublicInputFailure(
                    'A contribution offer proof was refused.',
                );
            offset += bytes.length;
        },
    );
};

// Discovery never supplies verification authority. Complete named reads from
// the relay published store and the owning proof verifier establish the exact
// published dependency. Retention preserves those records; no receipt or
// arbitrary local buffer substitutes for that completed read and verification.
export const verifyOffer = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    offer: SelectedOffer,
) => {
    const { module, profile } = context;
    if (offerAvailable(context, offer)) return;
    await findCandidate(relay, offerKey(offer), async (candidate) => {
        await beginOffer(
            context,
            relay,
            offer,
            candidate,
            module.setup_offer_begin,
        );
        const bounds = profile.contribution;
        for (const polynomial of bounds.polynomials) {
            let offset = 0;
            const length = await streamCandidateFile(
                relay,
                candidate,
                polynomialFile(polynomial.expandedIndex),
                polynomial.bytes,
                (bytes) => {
                    writeSetupInput(module, bytes);
                    if (
                        module.setup_offer_polynomial(
                            polynomial.expandedIndex,
                            offset,
                            bytes.length,
                        ) !== 0
                    )
                        throw new PublicInputFailure(
                            'A contribution offer polynomial was refused.',
                        );
                    offset += bytes.length;
                },
            );
            if (length !== polynomial.bytes)
                throw new PublicInputFailure(
                    'A contribution offer polynomial is incomplete.',
                );
        }
        await streamOfferProof(
            context,
            relay,
            candidate,
            module.setup_offer_proof,
        );
        if (module.setup_offer_finish() !== 0)
            throw new PublicInputFailure('A contribution offer was refused.');
        if (!offerAvailable(context, offer))
            throw new PublicInputFailure(
                'The verified offer differs from its advertised identity.',
            );
    });
};

const aggregateOffer = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    cache: IDBDatabase,
    offer: SelectedOffer,
    candidate: CandidateView,
) => {
    const { module, profile } = context;
    const bounds = profile.contribution;
    const accepted = module.setup_accepted();
    const verified = offerAvailable(context, offer);
    if (verified) {
        if (module.setup_begin_selected_offer(offer.position) !== 0)
            throw new PublicInputFailure(
                'A selected verified offer was refused.',
            );
    } else
        await beginOffer(
            context,
            relay,
            offer,
            candidate,
            module.setup_begin_selected_offer_verification,
        );
    const chunk = module.setup_chunk_capacity();
    // One incoming chunk and one previous/output chunk suffice. Replacing
    // each ordinal in one transaction leaves only disposable mixed scratch
    // until the complete offer and every aggregate digest have verified.
    for (const polynomial of bounds.polynomials) {
        const capacity = aggregateCapacity(context, polynomial);
        const pending = new Uint8Array(capacity);
        let used = 0;
        let offset = 0;
        const absorb = async (incoming: Uint8Array) => {
            const prior =
                accepted === 0
                    ? new Uint8Array(incoming.length)
                    : await readCachedAggregateChunk(
                          cache,
                          accepted - 1,
                          polynomial.expandedIndex,
                          { offset, length: incoming.length },
                      );
            writeSetupInput(module, incoming);
            writeSetupInput(module, prior, chunk);
            if (
                module.setup_polynomial(
                    polynomial.expandedIndex,
                    offset,
                    incoming.length,
                ) !== 0
            )
                throw new PublicInputFailure(
                    'A contribution polynomial was refused.',
                );
            // Copy into the existing previous chunk before any awaited work;
            // no borrowed Wasm view escapes the synchronous module call.
            prior.set(
                new Uint8Array(
                    module.memory.buffer,
                    module.setup_input_pointer() + chunk,
                    incoming.length,
                ),
            );
            const output = new Blob([prior]);
            await writeCache(cache, (store) => {
                store.put(output, [accepted, polynomial.expandedIndex, offset]);
                if (accepted > 0)
                    store.delete([
                        accepted - 1,
                        polynomial.expandedIndex,
                        offset,
                    ]);
            });
            offset += incoming.length;
        };
        await streamCandidateFile(
            relay,
            candidate,
            polynomialFile(polynomial.expandedIndex),
            polynomial.bytes,
            async (bytes) => {
                for (let start = 0; start < bytes.length;) {
                    const count = Math.min(
                        bytes.length - start,
                        capacity - used,
                    );
                    pending.set(bytes.subarray(start, start + count), used);
                    start += count;
                    used += count;
                    if (used === capacity) {
                        await absorb(pending.subarray(0, used));
                        used = 0;
                    }
                }
            },
        );
        if (used > 0) await absorb(pending.subarray(0, used));
        if (offset !== polynomial.bytes)
            throw new PublicInputFailure(
                'A contribution polynomial is incomplete.',
            );
    }
    if (!verified)
        await streamOfferProof(
            context,
            relay,
            candidate,
            module.setup_selected_offer_proof,
        );
    if (
        module.setup_finish_selected_offer() !== 0 ||
        module.setup_accepted() !== accepted + 1
    )
        throw new PublicInputFailure(
            'A selected contribution aggregate was refused.',
        );
    if (!offerAvailable(context, offer))
        throw new PublicInputFailure(
            'The selected offer differs from its advertised identity.',
        );
};

export const aggregateSelection = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    selection: SetupSelection,
) => {
    const { module } = context;
    const candidates: (CandidateView | undefined)[] = selection.offers.map(
        () => undefined,
    );
    const streams = selection.offers.map((offer) =>
        readCandidates(relay, offerKey(offer))[Symbol.asyncIterator](),
    );
    let cache: IDBDatabase | undefined;
    try {
        cache = await openSetupCache(context.namespace);
        for (;;) {
            let retry = false;
            if (module.setup_selection_aggregate() !== 0)
                throw new PublicInputFailure(
                    'The selected aggregation was refused.',
                );
            try {
                await writeCache(cache, (store) => store.clear());
                for (const [index, offer] of selection.offers.entries()) {
                    if (candidates[index] === undefined) {
                        const next = await streams[index].next();
                        if (next.done)
                            throw new PublicInputFailure(
                                'A selected offer is unavailable.',
                            );
                        candidates[index] = next.value;
                    }
                    try {
                        await aggregateOffer(
                            context,
                            relay,
                            cache,
                            offer,
                            candidates[index],
                        );
                    } catch (error) {
                        if (error instanceof PublicInputFailure) {
                            candidates[index] = undefined;
                            retry = true;
                        }
                        throw error;
                    }
                }
                if (module.setup_selection_finish() !== 0)
                    throw new PublicInputFailure(
                        'The selected aggregate was refused.',
                    );
                return;
            } catch (error) {
                // The cache may now contain chunks from two different prefixes.
                // Only the scratch accumulator is discarded: verified offer holders,
                // retained input capabilities and private authority remain intact.
                let failure = error;
                try {
                    if (
                        !(error instanceof ResourceFailure) &&
                        !(error instanceof ModuleFailure) &&
                        module.setup_discard_aggregation() !== 0
                    )
                        throw Object.assign(
                            new Error(
                                'The aggregate scratch could not be discarded.',
                            ),
                            { cause: error },
                        );
                } catch (discardError) {
                    failure = discardError;
                }
                try {
                    if (cache !== undefined)
                        await writeCache(cache, (store) => store.clear());
                } catch (cleanupError) {
                    // Local/module failures take precedence over public cache
                    // availability. A later attempt must clear scratch again.
                    if (failure instanceof PublicInputFailure)
                        failure = cleanupError;
                }
                if (!retry || !(failure instanceof PublicInputFailure))
                    throw failure;
            }
        }
    } finally {
        cache?.close();
    }
};

// Each operation owns one Rust module; this records only whether that module
// has already restored the roster, never whether an offer or setup is valid.
export const preparedRosters = new WeakSet<object>();

export const authenticateCertificate = (
    context: PublicProfileContext,
    bytes: Uint8Array,
    retained = false,
) => {
    writeSetupInput(context.module, bytes);
    if (context.module.setup_certificate(bytes.length) !== 0)
        throw retained
            ? new Error('The retained setup certificate was refused.')
            : new PublicInputFailure('The setup certificate was refused.');
    return selectedSetup(context);
};

export const endorsementCandidateKey = (position: number) =>
    'selection-endorsement-' + String(position);

// A published complete certificate takes precedence over discovery or the
// participant's own endorsement. Otherwise collect independently authenticated
// endorsements of the organizer's proposal; invalid public entries are ignored.
export const readSetupCertificate = async (
    context: PublicProfileContext,
    relay: PublicRelay,
) => {
    for await (const candidate of readCandidates(relay, 'setup-certificate')) {
        try {
            const bytes = await readCandidateFile(
                relay,
                candidate,
                'certificate.bin',
                context.profile.preparation.certificateBytes,
            );
            authenticateCertificate(context, bytes);
            return { bytes, retrieved: candidate };
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    for await (const selection of readCandidates(relay, 'selection')) {
        try {
            authenticateSelection(context, {
                body: await readCandidateFile(
                    relay,
                    selection,
                    'selection.bin',
                    context.profile.preparation.selectionBodyBytes,
                ),
                signature: await readCandidateFile(
                    relay,
                    selection,
                    'signature.bin',
                    context.profile.registration.signatureBytes,
                ),
            });
            let endorsements = 0;
            await scanCandidatesFairly(
                candidateLists(
                    relay,
                    context.profile.participantCount,
                    endorsementCandidateKey,
                ),
                async (position, candidate) => {
                    try {
                        const bytes = await readCandidateFile(
                            relay,
                            candidate,
                            'endorsement.bin',
                            context.profile.preparation.endorsementPacketBytes,
                        );
                        if (
                            bytes.length !==
                                context.profile.preparation
                                    .endorsementPacketBytes ||
                            readUnsigned16(bytes, 0) !== position
                        )
                            return false;
                        writeSetupInput(context.module, bytes);
                        if (
                            context.module.setup_endorsement(bytes.length) !== 0
                        )
                            return false;
                        endorsements++;
                        return true;
                    } catch (error) {
                        if (!(error instanceof PublicInputFailure)) throw error;
                        return false;
                    }
                },
                () =>
                    endorsements >= context.profile.close.quorum
                        ? endorsements
                        : undefined,
            );
            if (context.module.setup_certificate_build() !== 0)
                throw new PublicInputFailure(
                    'A complete setup endorsement quorum is unavailable.',
                );
            const certificate = setupOutput(context);
            authenticateCertificate(context, certificate);
            return { bytes: certificate, retrieved: undefined };
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    throw new PublicInputFailure(
        'A complete setup endorsement quorum is unavailable.',
    );
};

export const verifyCertificateInputs = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    certificate: Uint8Array,
    retained = false,
) => {
    const selection = authenticateCertificate(context, certificate, retained);
    await aggregateSelection(context, relay, selection);
    if (context.module.setup_finish_certificate() !== 0)
        throw new PublicInputFailure(
            'The complete certified setup was refused.',
        );
    return selection;
};

const publishedRegistrationBodyDigests = (
    context: PublicContext,
    proposal: Uint8Array,
) => {
    let registrationBodyDigests: string[];
    try {
        registrationBodyDigests = proposalRegistrationBodyDigests(proposal);
    } catch {
        throw new PublicInputFailure('The roster proposal is malformed.');
    }
    if (!validRegistrationBodyDigests(registrationBodyDigests, context.limits))
        throw new PublicInputFailure('The roster proposal is malformed.');
    return registrationBodyDigests;
};

export const verifyPublicSetup = async (
    context: PublicContext,
    relay: PublicRelay,
    poll: Uint8Array,
): Promise<PublicProfileContext> => {
    const { module, limits } = context;
    const { registration } = limits;
    return findCandidate(relay, 'poll', async (pollCandidate) => {
        const definition = await readCandidateFile(
            relay,
            pollCandidate,
            'definition.bin',
            registration.maximumPollDefinitionBytes,
        );
        const pollSignature = await readCandidateFile(
            relay,
            pollCandidate,
            'signature.bin',
            registration.signatureBytes,
        );
        return findCandidate(relay, 'roster', async (rosterCandidate) => {
            const proposal = await readCandidateFile(
                relay,
                rosterCandidate,
                'proposal.bin',
                registration.maximumProposalBytes,
            );
            const proposalSignature = await readCandidateFile(
                relay,
                rosterCandidate,
                'signature.bin',
                registration.signatureBytes,
            );
            const registrationBodyDigests = publishedRegistrationBodyDigests(
                context,
                proposal,
            );
            const begin = rosterBegin(
                context,
                poll,
                definition,
                pollSignature,
                registrationBodyDigests.length,
            );
            writeSetupInput(module, begin);
            if (module.setup_roster_begin(begin.length) !== 0)
                throw new PublicInputFailure('The poll was refused.');
            await streamRegistrations(
                relay,
                registrationBodyDigests,
                registration,
                module.roster_open_records(),
                (operation, position, bytes) => {
                    writeSetupInput(module, bytes);
                    return (
                        module.setup_roster_record(
                            operation,
                            position,
                            bytes.length,
                        ) === 0
                    );
                },
            );
            const proposalPacket = concatenate(
                unsigned32(proposal.length),
                proposal,
                proposalSignature,
            );
            writeSetupInput(module, proposalPacket);
            if (module.setup_roster_finish(proposalPacket.length) !== 0)
                throw new PublicInputFailure(
                    'The roster proposal was refused.',
                );
            const profile = readParticipantProfile(
                module,
                limits,
                registrationBodyDigests.length,
                module.setup_option_count(),
            );
            if (
                profile === undefined ||
                proposal.length !== profile.proposalBytes
            )
                throw new PublicInputFailure(
                    'The poll names no supported profile.',
                );
            const profiled = { ...context, profile };
            preparedRosters.add(module);
            const certificate = await readSetupCertificate(profiled, relay);
            await verifyCertificateInputs(profiled, relay, certificate.bytes);
            return profiled;
        });
    });
};
