import type { PublicProfileContext } from '../../module/context.js';
import {
    readModuleMemory,
    writeBufferInput,
} from '../../module/participant-module.js';
import type { CandidateView, PublicRelay } from '../../relay/relay.js';
import {
    findCandidate,
    readCandidateFile,
    readCandidates,
    streamCandidateFile,
} from '../../relay/relay.js';
import { concatenate, equalBytes, hexadecimal } from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { ballotCandidateKey } from '../ballot/ballot.js';
import {
    closeProposalCandidateKey,
    closureBodyFile,
    closureResponseFile,
    closureSubmissionFile,
    isListedSubmission,
    isResponsePacket,
    proposalResponses,
    responseIdentity,
    responseListing,
} from '../close/close-records.js';
import type { heldBallotBody } from '../close/close.js';
import { deliverFinalAggregate, readFinalAggregate } from '../setup/setup.js';

// The close barrier verifier. From the public close records, and the copies
// of them that a participant's close log holds, it authenticates the
// organizer's intent, the proposal, the responses the proposal names and each
// usable slot's body, and classifies each usable ballot as valid or invalid.

export const unusedWord = 0xff_ff_ff_ff;

// A usable slot's authenticated submission and its envelope identity, which
// addresses its body, and the route of the body copy the barrier accepted,
// or none for this root's custody.
export type UsableSlot = Readonly<{
    submission: Uint8Array;
    identity: Uint8Array;
    source?: Readonly<{ candidate: CandidateView; name: string }>;
}>;

// Reads a public record, or undefined when the relay lacks it.
const readCandidate = async (
    relay: PublicRelay,
    candidate: CandidateView,
    name: string,
    maximum: number,
) => {
    try {
        return await readCandidateFile(relay, candidate, name, maximum);
    } catch (error) {
        if (error instanceof PublicInputFailure) return undefined;
        throw error;
    }
};

// The close records a barrier verification reads, beside the copies of
// them that a participant's close log holds, which it takes before their
// public routes. A verifier without participant state holds none.
export type CloseRecordSource = Readonly<{
    context: PublicProfileContext;
    heldResponses: () => Promise<ReadonlyMap<number, Uint8Array>>;
    heldSubmissions: () => Promise<ReadonlyMap<string, Uint8Array>>;
    heldBody: (
        author: number,
        identity: Uint8Array,
    ) => ReturnType<typeof heldBallotBody>;
}>;

export const publicCloseRecords = (
    context: PublicProfileContext,
): CloseRecordSource => ({
    context,
    heldResponses: () => Promise.resolve(new Map()),
    heldSubmissions: () => Promise.resolve(new Map()),
    heldBody: () => Promise.resolve(undefined),
});

// Reads a usable body from its held copy, or from a route.
export const readBody = async (
    records: CloseRecordSource,
    relay: PublicRelay,
    author: number,
    identity: Uint8Array,
    source: UsableSlot['source'],
    consume: (bytes: Uint8Array) => void | Promise<void>,
) => {
    if (source !== undefined)
        return streamCandidateFile(
            relay,
            source.candidate,
            source.name,
            records.context.profile.ballot.maximumBodyBytes,
            consume,
        );
    const held = await records.heldBody(author, identity);
    if (held === undefined) throw new Error('The held ballot body is gone.');
    return held(consume);
};

// The close barrier verifier's operations, as its close command numbers
// them.
const barrierOperation = {
    begin: 1,
    intent: 2,
    envelope: 3,
    // A usable slot's body, named by its envelope identity and transferred
    // in chunks.
    beginBody: 4,
    pushBody: 5,
    finishBody: 6,
    response: 7,
    // The usable-slot bodies a proposal still needs, before its signature is
    // checked.
    requiredBodies: 8,
    proposal: 9,
    discardBody: 10,
} as const;

const barrierCommand = (
    context: PublicProfileContext,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeBufferInput(module, 'close', input);
    return module.close_command(operation, input.length) === 0;
};

const requireBarrier = (
    context: PublicProfileContext,
    operation: number,
    input: Uint8Array,
    reason: string,
) => {
    if (!barrierCommand(context, operation, input))
        throw new PublicInputFailure(reason);
};

// The response a proposal names: from its held copy, the organizer's
// closure or the responder's own route, the first copy whose body has the
// named identity.
const namedResponse = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    held: ReadonlyMap<number, Uint8Array>,
    responder: number,
    identity: Uint8Array,
    publication: CandidateView,
) => {
    const { profile } = context;
    const maximum =
        4 +
        profile.close.maximumResponseBodyBytes +
        profile.registration.signatureBytes;
    for (const candidate of [
        () => Promise.resolve(held.get(responder)),
        () =>
            readCandidate(
                relay,
                publication,
                closureResponseFile(identity),
                maximum,
            ),
    ]) {
        const response = await candidate();
        if (
            response !== undefined &&
            isResponsePacket(profile, response) &&
            equalBytes(responseIdentity(context, response), identity)
        )
            return response;
    }
    throw new PublicInputFailure('A named close response is unavailable.');
};

// An envelope a named response lists, with its signature: from its held
// copy, the organizer's closure or the author's own route, the first copy of
// that author's envelope with the listed identity.
const listedSubmission = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    held: ReadonlyMap<string, Uint8Array>,
    author: number,
    identity: Uint8Array,
    publication: CandidateView,
) => {
    const { profile } = context;
    for (const candidate of [
        () => Promise.resolve(held.get(hexadecimal(identity))),
        () =>
            readCandidate(
                relay,
                publication,
                closureSubmissionFile(identity),
                profile.close.submissionBytes,
            ),
    ]) {
        const submission = await candidate();
        if (
            submission !== undefined &&
            isListedSubmission(context, submission, author, identity)
        )
            return submission;
    }
    throw new PublicInputFailure('A listed envelope is unavailable.');
};

// Authenticates a usable slot's body from its held copy, the organizer's
// closure or the author's own route, restarting the body verifier after a
// refused or interrupted copy. Returns the accepted copy's route, or none
// for the held copy.
const verifyUsableBody = async (
    records: CloseRecordSource,
    relay: PublicRelay,
    author: number,
    identity: Uint8Array,
    publication: CandidateView,
) => {
    const { context } = records;
    const sources = async function* () {
        if ((await records.heldBody(author, identity)) !== undefined)
            yield undefined;
        yield { candidate: publication, name: closureBodyFile(identity) };
        for await (const candidate of readCandidates(
            relay,
            ballotCandidateKey(author),
        ))
            yield { candidate, name: 'body.bin' };
    };
    for await (const source of sources()) {
        requireBarrier(
            context,
            barrierOperation.beginBody,
            identity,
            'A usable body was refused.',
        );
        try {
            await readBody(
                records,
                relay,
                author,
                identity,
                source,
                (bytes) => {
                    requireBarrier(
                        context,
                        barrierOperation.pushBody,
                        bytes,
                        'A usable body was refused.',
                    );
                },
            );
            if (barrierCommand(context, barrierOperation.finishBody))
                return source;
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
        barrierCommand(context, barrierOperation.discardBody);
    }
    throw new PublicInputFailure('A usable body was refused.');
};

// Verifies the organizer's close barrier from the close records: the intent,
// the proposal's named responses with every envelope they list, and the body
// of each usable slot, each record from its held copy, the organizer's
// closure or its author's route. Returns each usable slot by its author.
export const verifyCloseBarrier = async (
    records: CloseRecordSource,
    relay: PublicRelay,
) => {
    const { context } = records;
    const { profile, module } = context;
    const { close, registration } = profile;
    const { signatureBytes } = registration;
    return findCandidate(
        relay,
        closeProposalCandidateKey,
        async (publication) => {
            if (!barrierCommand(context, barrierOperation.begin))
                throw new Error('The close verifier has no verified setup.');
            requireBarrier(
                context,
                barrierOperation.intent,
                await readCandidateFile(
                    relay,
                    publication,
                    'intent.bin',
                    4 + close.intentBodyBytes + signatureBytes,
                ),
                'The close intent was refused.',
            );
            const proposal = await readCandidateFile(
                relay,
                publication,
                'proposal.bin',
                4 + close.proposalBodyBytes + signatureBytes,
            );
            if (
                proposal.length !==
                4 + close.proposalBodyBytes + signatureBytes
            )
                throw new PublicInputFailure(
                    'The close proposal is incomplete.',
                );
            const responses = await records.heldResponses();
            const submissions = await records.heldSubmissions();
            const listed = new Map<
                string,
                { author: number; submission: Uint8Array }
            >();
            for (const { responder, identity } of proposalResponses(
                profile,
                proposal,
            )) {
                const response = await namedResponse(
                    context,
                    relay,
                    responses,
                    responder,
                    identity,
                    publication,
                );
                for (const entry of responseListing(profile, response)) {
                    const key = hexadecimal(entry.identity);
                    if (listed.has(key)) continue;
                    const submission = await listedSubmission(
                        context,
                        relay,
                        submissions,
                        entry.author,
                        entry.identity,
                        publication,
                    );
                    requireBarrier(
                        context,
                        barrierOperation.envelope,
                        submission,
                        'A listed envelope was refused.',
                    );
                    listed.set(key, { author: entry.author, submission });
                }
                requireBarrier(
                    context,
                    barrierOperation.response,
                    response,
                    'A close response was refused.',
                );
            }
            // Before any body is delivered, the usable-slot bodies the proposal still
            // needs are all of them.
            requireBarrier(
                context,
                barrierOperation.requiredBodies,
                proposal,
                'The close proposal was refused.',
            );
            const missing = readModuleMemory(
                module,
                module.close_missing_pointer(),
                module.close_missing_count() * 64,
            );
            const usable = new Map<number, UsableSlot>();
            for (let offset = 0; offset < missing.length; offset += 64) {
                const identity = missing.subarray(offset, offset + 64);
                const slot = listed.get(hexadecimal(identity));
                if (slot === undefined)
                    throw new Error(
                        'The close verifier needs an unlisted body.',
                    );
                usable.set(slot.author, {
                    submission: slot.submission,
                    identity: identity.slice(),
                    source: await verifyUsableBody(
                        records,
                        relay,
                        slot.author,
                        identity,
                        publication,
                    ),
                });
            }
            requireBarrier(
                context,
                barrierOperation.proposal,
                proposal,
                'The close barrier was refused.',
            );
            return usable;
        },
    );
};

const classifierInput = (context: PublicProfileContext, bytes: Uint8Array) => {
    const { module } = context;
    writeBufferInput(module, 'ballotBody', bytes);
    return bytes.length;
};

// Starts the owning signed-ballot classifier on a usable submission and its
// body header, and delivers its FHE key from the verified aggregate when
// the body relation needs it. The module derives the fixed auxiliary pair.
const beginClassification = async (
    context: PublicProfileContext,
    submission: Uint8Array,
    header: Uint8Array,
) => {
    const { module } = context;
    if (
        module.ballot_classification_begin(
            classifierInput(context, concatenate(submission, header)),
        ) !== 0
    )
        throw new PublicInputFailure('A usable ballot was refused.');
    if (module.ballot_classification_requires_key() === 1) {
        const index = module.ballot_classification_key_index() >>> 0;
        if (
            index === unusedWord ||
            module.ballot_classification_key_begin(index) !== 0
        )
            throw new Error('The ballot classifier refused its key.');
        await deliverFinalAggregate(context, async () => {
            await readFinalAggregate(context, index, (_offset, bytes) => {
                if (
                    module.ballot_classification_key_chunk(
                        classifierInput(context, bytes),
                    ) !== 0
                )
                    throw new PublicInputFailure('A ballot key was refused.');
            });
            if (module.ballot_classification_key_finish() !== 0)
                throw new PublicInputFailure('A ballot key was refused.');
        });
    }
};

// Classifies one usable ballot as valid or invalid. The body must be the one
// the barrier authenticated, or the classifier refuses it.
export const classifyBallot = async (
    records: CloseRecordSource,
    relay: PublicRelay,
    author: number,
    slot: UsableSlot,
) => {
    const { context } = records;
    const { module, profile } = context;
    const { headerBytes } = profile.ballot;
    let header: Uint8Array = new Uint8Array();
    await readBody(
        records,
        relay,
        author,
        slot.identity,
        slot.source,
        async (bytes) => {
            let rest = bytes;
            if (header.length < headerBytes) {
                const taken = rest.subarray(0, headerBytes - header.length);
                header = concatenate(header, taken);
                rest = rest.subarray(taken.length);
                if (header.length < headerBytes) return;
                await beginClassification(context, slot.submission, header);
            }
            if (
                rest.length > 0 &&
                module.ballot_classification_chunk(
                    classifierInput(context, rest),
                ) !== 0
            )
                throw new PublicInputFailure('A usable ballot was refused.');
        },
    );
    const classification =
        header.length === headerBytes
            ? module.ballot_classification_finish()
            : 0;
    if (classification === 0)
        throw new PublicInputFailure('A usable ballot changed.');
    return classification === 1;
};
