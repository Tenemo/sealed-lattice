import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import { ballotEnvelopeOffset } from '../../module/runtime-bounds.js';
import type { CandidateView } from '../../relay/candidates.js';
import {
    candidateLists,
    readCandidateFile,
    readCandidates,
    scanCandidatesFairly,
    streamCandidateFile,
} from '../../relay/candidates.js';
import { createCandidatePublication } from '../../relay/publication.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
} from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { openDelivery } from '../../storage/delivery.js';
import { closePhase } from '../../storage/root-generation.js';
import { ballotCandidateKey, readBallotBody } from '../ballot/ballot.js';

import {
    type CloseSession,
    tryCloseCommand,
    closeOperation,
    ownSubmission,
    closeCommand,
    nextSerial,
    appendEvent,
    learnSubmission,
    sealCloseRecord,
    responderFromListing,
    namesEnvelope,
    learnResponse,
    heldSubmissions,
    heldResponses,
    heldBallotBody,
    generationOf,
} from './close-custody.js';
import {
    closeIntentCandidateKey,
    closeProposalCandidateKey,
    closeResponseCandidateKey,
    closureBodyFile,
    closureResponseFile,
    closureSubmissionFile,
    isListedSubmission,
    isResponsePacket,
    listedEntryBytes,
    proposalResponses,
    responseIdentity,
    responseListing,
} from './close-records.js';
import { closeEventKind } from './close-state.js';

// The most entries a response lists, two envelopes for each slot, which also
// bounds the bodies the organizer can hold.
const maximumListedEntries = ({ close }: ParticipantProfile) =>
    (close.maximumResponseBodyBytes - close.minimumResponseBodyBytes) /
    listedEntryBytes;

// Delivers the own signed ballot once, from the ballot suffix.
export const deliverOwnBallot = async (session: CloseSession) => {
    const { ballot } = session;
    if (
        ballot === undefined ||
        session.state.events.some((event) => event.kind === closeEventKind.own)
    )
        return;
    const { context } = session.participant;
    // A late own ballot after the lock is refused and never listed.
    if (
        tryCloseCommand(
            context,
            closeOperation.beginHeldBody,
            0,
            ownSubmission(ballot),
        ) === undefined
    )
        return;
    await readBallotBody(ballot, (bytes) => {
        closeCommand(context, closeOperation.pushHeldBody, 0, bytes);
    });
    closeCommand(context, closeOperation.finishHeldBody);
    const serial = nextSerial(session.state);
    await appendEvent(session, {
        kind: closeEventKind.own,
        serial,
        length: 0,
        keys: [],
    });
    learnSubmission(session, serial, ballot.state.envelope);
};

// Read both parts from the same candidate; the owning close verifier decides
// authentication before it accepts any body or publishes a response.
const readSubmissionCandidate = async (
    profile: ParticipantProfile,
    relay: PublicRelay,
    candidate: CandidateView,
) => {
    try {
        const submission = concatenate(
            await readCandidateFile(
                relay,
                candidate,
                'envelope.bin',
                profile.ballot.envelopeBytes,
            ),
            await readCandidateFile(
                relay,
                candidate,
                'signature.bin',
                profile.registration.signatureBytes,
            ),
        );
        return submission.length === profile.close.submissionBytes
            ? submission
            : undefined;
    } catch (error) {
        if (error instanceof PublicInputFailure) return undefined;
        throw error;
    }
};

// Delivers a submission with its body from a route, sealing each body
// record as it passes the module. A refused, late or incomplete submission
// changes nothing. Returns whether the module accepted the body.
const deliverBody = async (
    session: CloseSession,
    relay: PublicRelay,
    submission: Uint8Array,
    candidate: CandidateView,
    name: string,
) => {
    const { context } = session.participant;
    const { profile } = context;
    if (
        tryCloseCommand(
            context,
            closeOperation.beginHeldBody,
            0,
            submission,
        ) === undefined
    )
        return false;
    const length = Number(
        readUnsigned64(submission, ballotEnvelopeOffset.bodyLength),
    );
    const { recordBytes, minimumBodyBytes, maximumBodyBytes } = profile.ballot;
    const event = {
        kind: closeEventKind.held,
        serial: nextSerial(session.state),
    };
    const added = [await sealCloseRecord(session, event, 0, submission)];
    let accepted = length >= minimumBodyBytes && length <= maximumBodyBytes;
    const pending = new Uint8Array(recordBytes);
    let used = 0;
    const flush = async () => {
        const bytes = pending.slice(0, used);
        used = 0;
        try {
            if (
                tryCloseCommand(
                    context,
                    closeOperation.pushHeldBody,
                    0,
                    bytes,
                ) === undefined
            )
                accepted = false;
            else
                added.push(
                    await sealCloseRecord(session, event, added.length, bytes),
                );
        } finally {
            bytes.fill(0);
        }
    };
    try {
        if (accepted)
            await streamCandidateFile(
                relay,
                candidate,
                name,
                length,
                async (bytes) => {
                    for (let start = 0; start < bytes.length && accepted;) {
                        const count = Math.min(
                            bytes.length - start,
                            recordBytes - used,
                        );
                        pending.set(bytes.subarray(start, start + count), used);
                        start += count;
                        used += count;
                        if (used === recordBytes) await flush();
                    }
                },
            );
        if (used > 0 && accepted) await flush();
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
        accepted = false;
    } finally {
        pending.fill(0);
    }
    // A stream may fail after its last payload byte. Cancel before finish so
    // that failed transport cannot install even a complete tentative body.
    if (!accepted) {
        closeCommand(context, closeOperation.discardHeldBody);
        return false;
    }
    if (tryCloseCommand(context, closeOperation.finishHeldBody) === undefined)
        return false;
    await appendEvent(
        session,
        { ...event, length, keys: added.map((record) => record.key) },
        added,
    );
    learnSubmission(session, event.serial, submission);
    return true;
};

// Tries every candidate in the author's finite published prefix. Exact
// duplicates and extra conflicting envelopes are refused by the close owner.
export const deliverBallot = async (
    session: CloseSession,
    relay: PublicRelay,
    author: number,
) => {
    const { context } = session.participant;
    for await (const candidate of readCandidates(
        relay,
        ballotCandidateKey(author),
    )) {
        const submission = await readSubmissionCandidate(
            context.profile,
            relay,
            candidate,
        );
        if (
            submission === undefined ||
            readUnsigned16(submission, ballotEnvelopeOffset.author) !== author
        )
            continue;
        await deliverBody(session, relay, submission, candidate, 'body.bin');
    }
};

// Takes each other published response not yet taken, with the listed
// envelopes from the same complete candidate. A failed candidate cannot
// consume its responder's chance to supply a later valid response.
export const takeResponses = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = session.participant;
    const { profile } = context;
    const { close, registration } = profile;
    const taken = new Set(session.responders.values());
    // Authentication does not establish body availability. Only the owning
    // close machine may prepare the organizer's response from a ready quorum.
    const restored = tryCloseCommand(context, closeOperation.prepareResponse);
    if (restored !== undefined) return restored;
    await deliverWantedBodies(session, relay);
    const recovered = tryCloseCommand(context, closeOperation.prepareResponse);
    if (recovered !== undefined) return recovered;
    let prepared: ReturnType<typeof tryCloseCommand>;
    return scanCandidatesFairly(
        candidateLists(
            relay,
            profile.participantCount,
            closeResponseCandidateKey,
            (position) =>
                position !== session.records.position && !taken.has(position),
        ),
        async (responder, candidate) => {
            let response: Uint8Array;
            let copies: Uint8Array;
            try {
                response = await readCandidateFile(
                    relay,
                    candidate,
                    'response.bin',
                    4 +
                        close.maximumResponseBodyBytes +
                        registration.signatureBytes,
                );
                copies = await readCandidateFile(
                    relay,
                    candidate,
                    'submissions.bin',
                    maximumListedEntries(profile) * close.submissionBytes,
                );
            } catch (error) {
                if (error instanceof PublicInputFailure) return false;
                throw error;
            }
            if (
                !isResponsePacket(profile, response) ||
                readUnsigned16(
                    response,
                    4 + close.minimumResponseBodyBytes - responderFromListing,
                ) !== responder
            )
                return false;
            const length = readUnsigned32(response, 0);
            const supplied: Uint8Array[] = [];
            for (
                let offset = 4 + close.minimumResponseBodyBytes, index = 0;
                offset + listedEntryBytes <= 4 + length;
                offset += listedEntryBytes, index++
            ) {
                const author = readUnsigned16(response, offset);
                const identity = response.subarray(
                    offset + 2,
                    offset + listedEntryBytes,
                );
                if (
                    session.known.has(hexadecimal(identity)) ||
                    supplied.some((value) =>
                        namesEnvelope(context, value, identity),
                    )
                )
                    continue;
                const submission = copies.subarray(
                    index * close.submissionBytes,
                    (index + 1) * close.submissionBytes,
                );
                if (isListedSubmission(context, submission, author, identity))
                    supplied.push(submission);
            }
            const record = concatenate(response, ...supplied);
            if (
                record.length > close.maximumResponseRecordBytes ||
                tryCloseCommand(
                    context,
                    closeOperation.admitResponse,
                    0,
                    record,
                ) === undefined
            )
                return false;
            const event = {
                kind: closeEventKind.response,
                serial: nextSerial(session.state),
            };
            const added = [await sealCloseRecord(session, event, 0, record)];
            await appendEvent(
                session,
                { ...event, length: record.length, keys: [added[0].key] },
                added,
            );
            learnResponse(session, event.serial, record);
            prepared = tryCloseCommand(context, closeOperation.prepareResponse);
            return true;
        },
        () => prepared,
        async () => {
            await deliverWantedBodies(session, relay);
            prepared = tryCloseCommand(context, closeOperation.prepareResponse);
        },
    );
};

// Delivers the bodies the taken responses need and the organizer lacks,
// each from its author's route or else from the copy a responder that lists
// it forwarded. The envelope comes from this root's custody, where a taken
// response delivered it, or from its author's route.
const deliverWantedBodies = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = session.participant;
    const { profile } = context;
    const wanted = closeCommand(context, closeOperation.wantedBodies);
    if (wanted.length === 0) return;
    const submissions = await heldSubmissions(session);
    const responses = await heldResponses(session);
    for (let offset = 0; offset < wanted.length; offset += listedEntryBytes) {
        const author = readUnsigned16(wanted, offset);
        const identity = wanted.slice(offset + 2, offset + listedEntryBytes);
        const submission = submissions.get(hexadecimal(identity));
        if (
            submission === undefined ||
            !isListedSubmission(context, submission, author, identity)
        )
            continue;
        const sources: [string, string][] = [
            [ballotCandidateKey(author), 'body.bin'],
        ];
        for (const [responder, response] of responses)
            if (
                responder !== session.records.position &&
                responseListing(profile, response).some((entry) =>
                    equalBytes(entry.identity, identity),
                )
            )
                sources.push([
                    closeResponseCandidateKey(responder),
                    closureBodyFile(identity),
                ]);
        let delivered = false;
        for (const [key, name] of sources) {
            for await (const candidate of readCandidates(relay, key)) {
                if (
                    await deliverBody(
                        session,
                        relay,
                        submission,
                        candidate,
                        name,
                    )
                ) {
                    delivered = true;
                    break;
                }
            }
            if (delivered) break;
        }
    }
};

// Delivers the organizer's copy of every close record its proposal depends
// on, each under its own identity: the named responses, every envelope they
// list and the body of each slot they list one envelope for. A participant whom the relay
// shows none of an author's or a responder's own records still finds them.
// Every copy comes from this root's custody, where the module accepted it
// before the proposal was prepared.
const publishClosure = async (
    session: CloseSession,
    publication: ReturnType<typeof createCandidatePublication>,
) => {
    const { context } = session.participant;
    const { profile } = context;
    const responses = await heldResponses(session);
    const submissions = await heldSubmissions(session);
    // The distinct envelopes the named responses list for each slot.
    const slots = Array.from(
        { length: profile.participantCount },
        () => new Map<string, Uint8Array>(),
    );
    for (const { responder, identity } of proposalResponses(
        profile,
        session.state.proposalPacket,
    )) {
        const response = responses.get(responder);
        if (
            response === undefined ||
            !equalBytes(responseIdentity(context, response), identity)
        )
            throw new Error('The proposal names a response not held.');
        await publication.addBytes(closureResponseFile(identity), response);
        for (const entry of responseListing(profile, response)) {
            const key = hexadecimal(entry.identity);
            if (slots[entry.author].has(key)) continue;
            const submission = submissions.get(key);
            if (submission === undefined)
                throw new Error('The proposal lists an envelope not held.');
            slots[entry.author].set(key, entry.identity);
            await publication.addBytes(
                closureSubmissionFile(entry.identity),
                submission,
            );
        }
    }
    for (const [author, listed] of slots.entries()) {
        if (listed.size !== 1) continue;
        const [identity] = listed.values();
        const held = await heldBallotBody(session, author, identity);
        if (held === undefined)
            throw new Error('The proposal needs a body not held.');
        const submission = submissions.get(hexadecimal(identity))!;
        await publication.addRetainedFile(
            closureBodyFile(identity),
            Number(readUnsigned64(submission, ballotEnvelopeOffset.bodyLength)),
            async (accept) => {
                await held(accept);
            },
            ballotCandidateKey(author),
            'body.bin',
        );
    }
};

// A copy of every envelope this participant's response lists, with its
// signature, in listing order, from this root's custody.
const listedCopies = async (session: CloseSession) => {
    const { profile } = session.participant.context;
    const held = await heldSubmissions(session);
    return concatenate(
        ...responseListing(profile, session.state.responsePacket).map(
            ({ identity }) => {
                const submission = held.get(hexadecimal(identity));
                if (submission === undefined)
                    throw new Error('The response lists an envelope not held.');
                return submission;
            },
        ),
    );
};

// Forwards the body of each slot this participant's response lists one
// envelope for, including its own if the original publication failed. An unsigned relay hint must not
// suppress required forwarding. Every copy comes from this root's custody.
const forwardListedBodies = async (
    session: CloseSession,
    publication: ReturnType<typeof createCandidatePublication>,
) => {
    const { profile } = session.participant.context;
    const submissions = await heldSubmissions(session);
    const listing = responseListing(profile, session.state.responsePacket);
    for (const { author, identity } of listing) {
        if (listing.filter((entry) => entry.author === author).length !== 1)
            continue;
        const held = await heldBallotBody(session, author, identity);
        if (held === undefined)
            throw new Error('The response lists a body not held.');
        const submission = submissions.get(hexadecimal(identity));
        if (submission === undefined)
            throw new Error('The response lists an envelope not held.');
        await publication.addRetainedFile(
            closureBodyFile(identity),
            Number(readUnsigned64(submission, ballotEnvelopeOffset.bodyLength)),
            async (accept) => {
                await held(accept);
            },
            ballotCandidateKey(author),
            'body.bin',
        );
    }
};

// Retransmits the retained signed close messages, inspecting the retained
// authority around every transfer. Each response and proposal is discovered
// only after its complete correlated dependency copies have been uploaded.
export const publishClose = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const generation = generationOf(session);
    const { state } = session;
    const { position } = session.records;
    const responder =
        !session.isOrganizer && generation >= closePhase.responded;
    if (generation < closePhase.locked) return;
    const { context, root } = session.participant;
    const delivery = await openDelivery(context, root);
    if (session.isOrganizer) {
        const publication = createCandidatePublication(
            relay,
            closeIntentCandidateKey,
            delivery,
        );
        await publication.addBytes('intent.bin', state.intentPacket);
        await publication.finish();
    }
    if (generation >= closePhase.responded) {
        const publication = createCandidatePublication(
            relay,
            closeResponseCandidateKey(position),
            delivery,
        );
        await publication.addBytes('response.bin', state.responsePacket);
        await publication.addBytes(
            'submissions.bin',
            await listedCopies(session),
        );
        if (responder) await forwardListedBodies(session, publication);
        await publication.finish();
    }
    if (generation === closePhase.proposed) {
        const publication = createCandidatePublication(
            relay,
            closeProposalCandidateKey,
            delivery,
        );
        await publication.addBytes('intent.bin', state.intentPacket);
        await publishClosure(session, publication);
        await publication.addBytes('proposal.bin', state.proposalPacket);
        await publication.finish();
    }
};
