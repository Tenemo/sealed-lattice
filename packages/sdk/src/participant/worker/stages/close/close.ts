import { readCandidateFile, readCandidates } from '../../relay/candidates.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    equalBytes,
    hexadecimal,
    readUnsigned64,
    unsigned64,
} from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { encodeSignedPacket } from '../../shared/signed-packet.js';
import {
    ballotPhase,
    closePhase,
    rootGeneration,
} from '../../storage/root-generation.js';

import {
    type CloseSession,
    generationOf,
    closeCommand,
    closeOperation,
    commitClose,
    tryCloseCommand,
    nextSerial,
    startCloseWork,
} from './close-custody.js';
import {
    deliverOwnBallot,
    deliverBallot,
    takeResponses,
} from './close-delivery.js';
import { closeIntentCandidateKey } from './close-records.js';
import type { CloseEvent, CloseState } from './close-state.js';
import { closeEventKind, collectingCloseState } from './close-state.js';

type CloseParameters = Readonly<{
    // The organizer's close time in Unix milliseconds, only before an intent.
    closeTime?: bigint;
}>;

// The close time a request supplies, or undefined when it is malformed.
export const parseCloseParameters = (
    parameters: Readonly<Record<string, unknown>>,
): CloseParameters | undefined => {
    const { closeTime } = parameters;
    if (closeTime === undefined) return {};
    return typeof closeTime === 'number' &&
        Number.isSafeInteger(closeTime) &&
        closeTime >= 0
        ? { closeTime: BigInt(closeTime) }
        : undefined;
};

// The organizer's intent. Its exact body enters the root before the
// signature exists; an interrupted signing recomputes the same body from the
// retained close time, which ends the body.
const signIntent = async (session: CloseSession, closeTime?: bigint) => {
    const { context } = session.participant;
    let body: Uint8Array;
    if (generationOf(session) === closePhase.intent) {
        const retained = session.state.intentBody;
        body = closeCommand(
            context,
            closeOperation.prepareIntent,
            0,
            retained.subarray(-8),
        );
        if (!equalBytes(body, retained))
            throw new Error('The retained intent body changed.');
    } else {
        if (closeTime === undefined)
            throw new Error('No close time was requested.');
        body = closeCommand(
            context,
            closeOperation.prepareIntent,
            0,
            unsigned64(closeTime),
        );
        await commitClose(session, {
            generation: closePhase.intent,
            state: {
                ...session.state,
                intentBody: body,
            },
        });
    }
    const signature = closeCommand(context, closeOperation.sign, 0, body);
    return encodeSignedPacket({ body, signature });
};

// Locks the first authenticated intent. The lock's transaction retires the
// events of submissions timed after the close time, which no response can
// list, and appends the lock event, so replay applies it where it arrived.
const lockIntent = async (session: CloseSession, intentPacket: Uint8Array) => {
    const { context } = session.participant;
    if (
        tryCloseCommand(context, closeOperation.lockIntent, 0, intentPacket) ===
        undefined
    )
        throw new PublicInputFailure('The close intent was refused.');
    const { close } = session.participant.context.profile;
    const closeTime = readUnsigned64(
        intentPacket,
        4 + close.intentBodyBytes - 8,
    );
    const serial = nextSerial(session.state);
    const late = (event: CloseEvent) => {
        const submission = session.submissions.get(event.serial);
        return submission !== undefined && submission.ballotTime > closeTime;
    };
    const retired = session.state.events.filter(late);
    await commitClose(session, {
        generation: closePhase.locked,
        state: {
            ...collectingCloseState(),
            events: [
                ...session.state.events.filter((event) => !late(event)),
                { kind: closeEventKind.lock, serial, length: 0, keys: [] },
            ],
            intentPacket,
        },
        retired: retired.map((event) => event.serial),
    });
    for (const event of retired) {
        const submission = session.submissions.get(event.serial);
        if (submission !== undefined)
            session.known.delete(hexadecimal(submission.identity));
        session.submissions.delete(event.serial);
    }
};

// This participant's one response. Its exact body enters the root
// before the signature exists; an interrupted signing must recompute the
// same body from the replayed log. The organizer then takes its own response
// and retains its proposal exact body with it. Returns whether the
// organizer's proposal is prepared in this instance.
const respond = async (session: CloseSession, preparedBody?: Uint8Array) => {
    const { context } = session.participant;
    const resumed = generationOf(session) === closePhase.responding;
    const body =
        preparedBody ??
        tryCloseCommand(context, closeOperation.prepareResponse);
    if (body === undefined) {
        if (resumed)
            throw new Error('The retained response can no longer be prepared.');
        return false;
    }
    if (resumed) {
        if (!equalBytes(body, session.state.responseBody))
            throw new Error(
                'The replayed response differs from the retained one.',
            );
    } else
        await commitClose(session, {
            generation: closePhase.responding,
            state: {
                ...session.state,
                responseBody: body,
            },
        });
    const signature = closeCommand(context, closeOperation.sign, 0, body);
    const responsePacket = encodeSignedPacket({ body, signature });
    let state: CloseState = {
        ...session.state,
        responseBody: new Uint8Array(),
        responsePacket,
    };
    if (session.isOrganizer) {
        closeCommand(context, closeOperation.admitResponse, 0, responsePacket);
        state = {
            ...state,
            proposalBody: closeCommand(context, closeOperation.prepareProposal),
        };
    }
    await commitClose(session, { generation: closePhase.responded, state });
    return session.isOrganizer;
};

// Signs the organizer's retained proposal. A restored organizer takes its
// own response again and must prepare the same proposal first.
const propose = async (session: CloseSession, prepared: boolean) => {
    const { context } = session.participant;
    if (!prepared) {
        closeCommand(
            context,
            closeOperation.admitResponse,
            0,
            session.state.responsePacket,
        );
        if (
            !equalBytes(
                closeCommand(context, closeOperation.prepareProposal),
                session.state.proposalBody,
            )
        )
            throw new Error(
                'The replayed proposal differs from the retained one.',
            );
    }
    const signature = closeCommand(
        context,
        closeOperation.sign,
        0,
        session.state.proposalBody,
    );
    await commitClose(session, {
        generation: closePhase.proposed,
        state: {
            ...session.state,
            proposalBody: new Uint8Array(),
            proposalPacket: encodeSignedPacket({
                body: session.state.proposalBody,
                signature,
            }),
        },
    });
};

// Only the owning lock may select an organizer's intent from discovery.
const lockAvailableIntent = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const { close, registration } = session.participant.context.profile;
    for await (const candidate of readCandidates(
        relay,
        closeIntentCandidateKey,
    )) {
        try {
            const intent = await readCandidateFile(
                relay,
                candidate,
                'intent.bin',
                4 + close.intentBodyBytes + registration.signatureBytes,
            );
            await lockIntent(session, intent);
            return true;
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    return false;
};

// A participant other than the organizer whose setup was just verified in
// this instance, before any ballot attempt, locks the organizer's published
// intent: it learned that ballot submission closed before it could vote, so
// it never starts a ballot. Returns whether it locked; without an authentic
// published intent it can still vote.
export const lockPublishedIntent = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    if (
        session.isOrganizer ||
        generationOf(session) !== rootGeneration.setupRetained
    )
        return false;
    await startCloseWork(session);
    return lockAvailableIntent(session, relay);
};

// One operation's close work after the complete setup verified in this instance.
export const advanceClose = async (
    session: CloseSession,
    relay: PublicRelay,
    request: CloseParameters,
) => {
    const generation = () => generationOf(session);
    const collecting = () =>
        generation() !== closePhase.intent &&
        generation() < closePhase.responding;
    await startCloseWork(session);
    if (collecting()) {
        // Every other roster position's published ballot, so that an honest
        // participant holds every ballot it can read before it responds.
        await deliverOwnBallot(session);
        for (
            let author = 0;
            author < session.participant.context.profile.participantCount;
            author++
        )
            if (author !== session.records.position)
                await deliverBallot(session, relay, author);
    }
    // A locked ballot attempt completes before any intent is locked.
    const unlocked =
        generation() === rootGeneration.setupRetained ||
        generation() === ballotPhase.signed;
    if (session.isOrganizer) {
        if (
            generation() === closePhase.intent ||
            (unlocked && request.closeTime !== undefined)
        )
            await lockIntent(
                session,
                await signIntent(session, request.closeTime),
            );
    } else if (unlocked) {
        await lockAvailableIntent(session, relay);
    }
    let responseBody: Uint8Array | undefined;
    if (session.isOrganizer && generation() === closePhase.locked)
        responseBody = await takeResponses(session, relay);
    let prepared = false;
    if (
        generation() === closePhase.locked ||
        generation() === closePhase.responding
    )
        prepared = await respond(session, responseBody);
    if (session.isOrganizer && generation() === closePhase.responded)
        await propose(session, prepared);
};
