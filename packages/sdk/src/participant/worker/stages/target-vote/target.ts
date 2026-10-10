import { writeModuleInput } from '../../module/context.js';
import type { ParticipantProfileContext } from '../../module/context.js';
import {
    readModuleMemory,
    readParticipantOutput,
} from '../../module/participant-module.js';
import { createCandidatePublication } from '../../relay/publication.js';
import type { PublicRelay } from '../../relay/relay.js';
import { equalBytes } from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { openDelivery } from '../../storage/delivery.js';
import { targetPhase } from '../../storage/root-generation.js';
import { commitRoot, dataRecordInventory } from '../../storage/root.js';
import { retainedBallotRecords } from '../ballot/ballot.js';
import { completedClosePhase } from '../close/close-state.js';
import type { CloseSession } from '../close/close.js';
import {
    completedCloseRecords,
    heldBallotBody,
    heldResponses,
    heldSubmissions,
    restoreCompletedClose,
} from '../close/close.js';

import { CloseRecordSource } from './close-barrier.js';
import {
    evaluateClosedTarget,
    restoreEvaluation,
    retainEvaluation,
} from './evaluation.js';
import {
    ballotInclusions,
    decodeTargetState,
    encodeTargetState,
} from './target-state.js';
import type { TargetState } from './target-state.js';

// A participant's target signing. It verifies the organizer's close barrier
// from the public close records, classifies each usable ballot, evaluates
// the public ranking target and retains the exact target body and the own
// ballot's status in it before its target vote exists. An interrupted signing
// evaluates again and must reproduce the retained body. A verifier without
// participant state verifies the barrier, classifies and evaluates from the
// public records alone, in its own working storage, and retains nothing.

export const targetVoteCandidateKey = (position: number) =>
    'target-vote-' + String(position);

const participantCloseRecords = (session: CloseSession): CloseRecordSource => ({
    context: session.participant.context,
    heldResponses: () => heldResponses(session),
    heldSubmissions: () => heldSubmissions(session),
    heldBody: (author, identity) => heldBallotBody(session, author, identity),
});

// The finality work's operations, as the module's finality command numbers
// them.
export const finalityOperation = {
    // The own ballot's status and the target body to retain before signing.
    begin: 0,
    signVote: 1,
    restoreSignedTarget: 2,
    certifiedBallotInclusion: 3,
} as const;

const finalityCommand = (
    context: ParticipantProfileContext,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeModuleInput(context, input);
    if (module.participant_finality_command(operation, input.length) !== 0)
        throw new Error(
            'The finality work refused operation ' + String(operation) + '.',
        );
    return readParticipantOutput(module);
};

// The own ballot's status in the target this instance certified, which the
// finality work reads for a participant that signed no target of its own.
export const certifiedBallotInclusion = (
    context: ParticipantProfileContext,
) => {
    const output = finalityCommand(
        context,
        finalityOperation.certifiedBallotInclusion,
    );
    if (output.length !== 1 || output[0] >= ballotInclusions.length)
        throw new Error('The finality work reported no ballot status.');
    return ballotInclusions[output[0]];
};

// The retained target signing state, or undefined before it begins.
export const resumeTarget = (close: CloseSession): TargetState | undefined => {
    const { root, context } = close.participant;
    if (root.head.generation < targetPhase.intent) return undefined;
    const bytes = root.manifest.suffixes.target;
    if (bytes === undefined) throw new Error('No target state is retained.');
    return decodeTargetState(
        context.profile,
        root.head.generation,
        close.isOrganizer,
        bytes,
    );
};

const commitTarget = async (
    close: CloseSession,
    generation: number,
    state: TargetState,
) => {
    const { participant } = close;
    const { context, root } = participant;
    const encoded = encodeTargetState(generation, state);
    if (encoded.length > context.profile.target.maximumStateBytes)
        throw new Error('The target state exceeds its bound.');
    participant.root = await commitRoot(context, root, {
        generation,
        manifest: {
            ...root.manifest,
            suffixes: { ...root.manifest.suffixes, target: encoded },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...retainedBallotRecords(participant, close.records),
            ...completedCloseRecords(close),
        ],
    });
};

// Ends a worker whose operation retained the target it evaluated before its
// other work, so that a fresh worker restores it for the rest of the
// operation.
export class EvaluationRetained extends Error {}

// The target this participant evaluated earlier, restored from its retained
// copy, or else the target evaluated now from the public close records and
// retained, which ends a separately evaluating worker. The completed close
// and the verified setup must be restored in this instance first. Returns
// the target body and whether it was restored.
export const restoreOrEvaluateTarget = async (
    close: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = close.participant;
    if (await restoreEvaluation(context)) {
        const { module } = context;
        return {
            body: readModuleMemory(
                module,
                module.evaluation_target_body_pointer(),
                module.evaluation_target_body_length(),
            ),
            restored: true,
        };
    }
    const { body } = await evaluateClosedTarget(
        participantCloseRecords(close),
        relay,
    );
    await retainEvaluation(context);
    if (context.separateEvaluation)
        throw new EvaluationRetained('The evaluated target is retained.');
    return { body, restored: false };
};

// Evaluates the target from the public close records and signs this
// participant's target vote. The owning setup verifier must have verified
// the complete setup in this instance first. The signing state retains the
// own ballot's status in the target. Returns how many slots were usable and
// how many usable ballots were valid.
export const signTarget = async (close: CloseSession, relay: PublicRelay) => {
    const { participant } = close;
    const { context } = participant;
    await restoreCompletedClose(close);
    const { body, usableSubmissions, acceptedBallots } =
        await evaluateClosedTarget(participantCloseRecords(close), relay);
    await retainEvaluation(context);
    const finality = finalityCommand(context, finalityOperation.begin);
    if (!equalBytes(finality.subarray(1), body))
        throw new Error('The finality work names another target.');
    const code = finality[0];
    if (code >= ballotInclusions.length)
        throw new Error('The finality work reported no ballot status.');
    const ballotInclusion = ballotInclusions[code];
    let state = resumeTarget(close);
    if (state === undefined) {
        state = {
            predecessor: completedClosePhase(close.isOrganizer),
            ballotInclusion,
            body,
            vote: new Uint8Array(),
        };
        await commitTarget(close, targetPhase.intent, state);
    } else if (!equalBytes(state.body, body))
        throw new PublicInputFailure(
            'The public close records name another target.',
        );
    else if (state.ballotInclusion !== ballotInclusion)
        throw new Error('The finality work reported another ballot status.');
    const vote = finalityCommand(
        context,
        finalityOperation.signVote,
        state.body,
    );
    await commitTarget(close, targetPhase.signed, {
        ...state,
        vote,
    });
    return { usableSubmissions, acceptedBallots };
};

// Delivers the signed target vote, and the organizer the target body,
// inspecting the retained authority around every transfer.
export const publishTarget = async (
    close: CloseSession,
    relay: PublicRelay,
) => {
    const state = resumeTarget(close);
    const { context, root } = close.participant;
    if (state === undefined || root.head.generation < targetPhase.signed)
        return;
    const delivery = await openDelivery(context, root);
    const publication = createCandidatePublication(
        relay,
        targetVoteCandidateKey(close.records.position),
        delivery,
    );
    await publication.addBytes('vote.bin', state.vote);
    if (close.isOrganizer) await publication.addBytes('target.bin', state.body);
    await publication.finish();
};
