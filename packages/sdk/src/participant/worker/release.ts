import { retainedBallotRecords } from './ballot.js';
import {
    concatenate,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
    unsigned32,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import { completedCloseRecords, restoreCompletedClose } from './close.js';
import type { CloseSession } from './close.js';
import { writeModuleInput } from './context.js';
import type {
    ParticipantProfileContext,
    PublicProfileContext,
} from './context.js';
import { contributionRecords } from './contribution.js';
import { openDelivery } from './delivery.js';
import { PublicInputFailure } from './failures.js';
import { custodyIdentity, custodyPurpose } from './identity.js';
import {
    operationSeedBytes,
    readModuleMemory,
    seededRandomness,
    writeBufferInput,
} from './participant-module.js';
import { openRecord, sealRecord } from './private-records.js';
import {
    createCandidatePublication,
    readCandidateFile,
    readCandidates,
    streamCandidateFile,
} from './relay.js';
import type { PublicRelay } from './relay.js';
import {
    decodeReleaseState,
    encodeReleaseState,
    releaseRecordAssociatedData,
    releaseRecordInventory,
    releaseRecordLengths,
} from './release-state.js';
import type { ReleaseState } from './release-state.js';
import { releasePhase, targetPhase } from './root-generation.js';
import { commitRoot, dataRecordInventory } from './root.js';
import { deliverFinalAggregate, readFinalAggregate } from './setup.js';
import { snapshotParticipant } from './storage.js';
import type { BallotInclusion, TargetState } from './target-state.js';
import {
    certifiedBallotInclusion,
    discardEvaluation,
    finalityOperation,
    restoreOrEvaluateTarget,
    resumeTarget,
    targetVoteCandidateKey,
} from './target.js';

// A participant's release of its share of the certified target. The release
// follows the participant's own signed target, or its completed close when it
// signed no target and a certificate already exists; a pending target
// signature cannot be bypassed. Each operation restores the completed close and
// any signed target, restores the target this participant evaluated or else
// evaluates it from the public close records, and certifies it from the
// published votes; only the certificate verifier creates the release
// context. The
// seed of all release randomness enters the root before any private
// generation, and the module proves the release from that seed alone, so an
// interrupted generation draws the same bytes again. The body and envelope
// are retained before the signing intent, and the intent before the signature.

export type ReleaseSession = {
    readonly close: CloseSession;
    // The participant's own signed target, when the release follows it.
    readonly signed: TargetState | undefined;
    // The certified target body and its digest, once known: from the signed
    // target or the retained release state, or from the first certified
    // evaluation of a release that follows the completed close.
    target: Readonly<{ body: Uint8Array; digest: Uint8Array }> | undefined;
    state: ReleaseState | undefined;
    // The proof-stream bytes the module drew, when this operation generated the
    // release.
    proofRandomBytes?: number;
};

const releaseTarget = (session: ReleaseSession) => {
    if (session.target === undefined)
        throw new Error('No certified target is retained.');
    return session.target;
};

const generationOf = (session: ReleaseSession) =>
    session.close.participant.root.head.generation;

const words = (bytes: Uint8Array) =>
    Array.from({ length: Math.floor(bytes.length / 4) }, (_unused, index) =>
        readUnsigned32(bytes, 4 * index),
    );

// Decodes the retained release state beneath its predecessor. A release that
// follows the completed close keeps an empty target field. Every listed
// release record must be stored and nothing else.
export const resumeRelease = async (
    close: CloseSession,
): Promise<ReleaseSession> => {
    const { root, context } = close.participant;
    const { generation } = root.head;
    const closed = completedClosePhase(close.isOrganizer);
    if (generation !== closed && generation < targetPhase.signed)
        throw new Error('No completed close or signed target is retained.');
    const bytes = root.manifest.suffixes.release;
    const state =
        generation < releasePhase.locked
            ? undefined
            : bytes === undefined
              ? undefined
              : decodeReleaseState(
                    context.profile,
                    generation,
                    close.isOrganizer,
                    bytes,
                );
    if (generation >= releasePhase.locked && state === undefined)
        throw new Error('No release state is retained.');
    const followsClose = generation === closed || state?.predecessor === closed;
    if (
        followsClose &&
        generation !== closed &&
        root.manifest.suffixes.target?.length !== 0
    )
        throw new Error('The release names another predecessor.');
    const signed = followsClose ? undefined : resumeTarget(close);
    if (!followsClose && signed === undefined)
        throw new Error('No signed target is retained.');
    if (
        state !== undefined &&
        signed !== undefined &&
        !equalBytes(state.target, signed.body)
    )
        throw new Error('The release names another target.');
    const snapshot = await snapshotParticipant(context.database);
    if (snapshot.counts.release !== (state?.bodyKeys.length ?? 0))
        throw new Error('The release records changed.');
    const body = signed?.body ?? state?.target;
    return {
        close,
        signed,
        target:
            body === undefined
                ? undefined
                : {
                      body,
                      digest: custodyIdentity(
                          context.module,
                          custodyPurpose.target,
                          body,
                      ),
                  },
        state,
    };
};

// The release work's operations, as the module's release command numbers
// them.
const releaseOperation = {
    // Proves the release from the randomness of its seed.
    create: 0,
    bodySlice: 1,
    // Imports a retained body, which the module verifies again.
    beginImport: 2,
    pushImport: 3,
    finishImport: 4,
    sign: 5,
} as const;

const releaseCommand = (
    context: ParticipantProfileContext,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeModuleInput(context, input);
    if (module.participant_release_command(operation, input.length) !== 0)
        throw new Error(
            'The release work refused operation ' + String(operation) + '.',
        );
    return readModuleMemory(
        module,
        module.contribution_output_pointer(),
        module.contribution_output_length(),
    );
};

// The completion verifier's operations, as its command numbers them.
const completionOperation = {
    beginVotes: 0,
    insertVote: 1,
    certify: 2,
    // A release share's two public operands, the constant then the linear
    // polynomial, each delivered in chunks.
    beginShareConstant: 3,
    pushOperand: 4,
    finishOperand: 5,
    authenticateRelease: 6,
    beginReleaseBody: 7,
    pushReleaseBody: 8,
    finishRelease: 9,
    result: 10,
} as const;

const tryCompletionCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeBufferInput(module, 'completion', input);
    if (module.completion_command(operation, argument, input.length) !== 0)
        return undefined;
    return readModuleMemory(
        module,
        module.completion_output_pointer(),
        module.completion_output_length(),
    );
};

const completionCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const output = tryCompletionCommand(context, operation, argument, input);
    if (output === undefined)
        throw new Error(
            'The completion refused operation ' + String(operation) + '.',
        );
    return output;
};

// Certifies the target from the published target votes, stopping at the
// certificate threshold. A missing or refused vote is skipped; too few leave
// the participant pending. A restored target that the votes leave
// uncertified while one of them was refused, as every vote for another target
// is, is discarded, so that the next operation evaluates the target the public
// close records name; missing votes alone keep it. Returns whether the target
// is encrypted.
export const certifyTarget = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    restored: boolean,
) => {
    const [count, threshold] = words(
        completionCommand(context, completionOperation.beginVotes),
    );
    let accepted = 0;
    let refused = false;
    const pending = new Map(
        Array.from(
            { length: count },
            (_, position) =>
                [
                    position,
                    readCandidates(relay, targetVoteCandidateKey(position))[
                        Symbol.asyncIterator
                    ](),
                ] as const,
        ),
    );
    while (pending.size > 0 && accepted < threshold) {
        for (const [position, candidates] of pending) {
            const next = await candidates.next();
            if (next.done) {
                pending.delete(position);
                continue;
            }
            let vote: Uint8Array;
            try {
                vote = await readCandidateFile(
                    relay,
                    next.value,
                    'vote.bin',
                    context.profile.target.votePacketBytes,
                );
            } catch (error) {
                if (error instanceof PublicInputFailure) continue;
                throw error;
            }
            // A copied valid vote in another author's discovery list must
            // not consume that list's opportunity to supply its own vote.
            if (
                vote.length !== context.profile.target.votePacketBytes ||
                readUnsigned16(vote, 0) !== position
            )
                continue;
            const inserted = tryCompletionCommand(
                context,
                completionOperation.insertVote,
                0,
                vote,
            );
            if (inserted === undefined) refused = true;
            else {
                accepted = words(inserted)[1];
                pending.delete(position);
                if (accepted >= threshold) break;
            }
        }
    }
    const certified = tryCompletionCommand(
        context,
        completionOperation.certify,
    );
    if (certified === undefined) {
        if (restored && refused) await discardEvaluation(context);
        throw new PublicInputFailure('The target votes are incomplete.');
    }
    return words(certified)[0] === 1;
};

// Creates the certified release context of one position from its two share
// polynomials of the verified aggregate.
const establishReleaseContext = async (
    context: PublicProfileContext,
    position: number,
) => {
    const stream = (index: number) =>
        readFinalAggregate(context, index, (offset, bytes) => {
            if (
                tryCompletionCommand(
                    context,
                    completionOperation.pushOperand,
                    offset,
                    bytes,
                ) === undefined
            )
                throw new PublicInputFailure('A release key was refused.');
        });
    // Finishing a polynomial checks its bytes against the retained setup
    // reference.
    const finish = () => {
        const output = tryCompletionCommand(
            context,
            completionOperation.finishOperand,
        );
        if (output === undefined)
            throw new PublicInputFailure('A release key was refused.');
        return output;
    };
    const constant = words(
        completionCommand(
            context,
            completionOperation.beginShareConstant,
            position,
        ),
    )[0];
    await deliverFinalAggregate(context, async () => {
        await stream(constant);
        await stream(words(finish())[0]);
        finish();
    });
};

const openReleaseRecord = (session: ReleaseSession, index: number) => {
    const { context } = session.close.participant;
    const { state } = session;
    if (state === undefined) throw new Error('No release state is retained.');
    const length = releaseRecordLengths(context.profile, state.bodyLength)[
        index
    ];
    return openRecord(
        context.database,
        'release',
        index,
        {
            key: state.bodyKeys[index],
            additionalData: releaseRecordAssociatedData(
                session.close.records,
                releaseTarget(session).digest,
                index,
                length,
            ),
        },
        length,
    );
};

type AddedRecord = Readonly<{
    index: number;
    key: Uint8Array;
    ciphertext: Uint8Array;
}>;

const sealReleaseRecord = async (
    session: ReleaseSession,
    index: number,
    bytes: Uint8Array,
): Promise<AddedRecord> => ({
    index,
    ...(await sealRecord(
        releaseRecordAssociatedData(
            session.close.records,
            releaseTarget(session).digest,
            index,
            bytes.length,
        ),
        bytes,
    )),
});

type ReleaseTransition = Readonly<{
    generation: number;
    state: ReleaseState;
    added?: readonly AddedRecord[];
}>;

const commitRelease = async (
    session: ReleaseSession,
    transition: ReleaseTransition,
) => {
    const { close } = session;
    const { participant } = close;
    const { context, root } = participant;
    const { profile } = context;
    const encoded = encodeReleaseState(transition.generation, transition.state);
    if (encoded.length > profile.release.maximumStateBytes)
        throw new Error('The release state exceeds its bound.');
    participant.root = await commitRoot(context, root, {
        generation: transition.generation,
        manifest: {
            ...root.manifest,
            suffixes: {
                ...root.manifest.suffixes,
                target: root.manifest.suffixes.target ?? new Uint8Array(),
                release: encoded,
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(participant),
            ...retainedBallotRecords(participant, close.records),
            ...completedCloseRecords(close),
            ...(session.state === undefined
                ? []
                : releaseRecordInventory(
                      profile,
                      close.records,
                      releaseTarget(session).digest,
                      session.state,
                  )),
        ],
        write: (transaction) => {
            const store = transaction.objectStore('release');
            for (const record of transition.added ?? [])
                store.add(
                    new Blob([new Uint8Array(record.ciphertext)]),
                    record.index,
                );
        },
    });
    session.state = transition.state;
    for (const record of transition.added ?? [])
        (await openReleaseRecord(session, record.index)).fill(0);
};

// Locks the certified target the release follows and the own ballot's
// status in it, then the seed of all its randomness.
const lockRelease = async (
    session: ReleaseSession,
    ballotInclusion: BallotInclusion,
) => {
    if (generationOf(session) < releasePhase.locked)
        await commitRelease(session, {
            generation: releasePhase.locked,
            state: {
                predecessor:
                    session.signed === undefined
                        ? completedClosePhase(session.close.isOrganizer)
                        : targetPhase.signed,
                ballotInclusion,
                target: releaseTarget(session).body,
                seed: new Uint8Array(),
                bodyLength: 0,
                bodyKeys: [],
                envelope: new Uint8Array(),
                signature: new Uint8Array(),
            },
        });
    if (generationOf(session) === releasePhase.locked) {
        const { state } = session;
        if (state === undefined)
            throw new Error('No locked release is retained.');
        await commitRelease(session, {
            generation: releasePhase.ready,
            state: {
                ...state,
                seed: crypto.getRandomValues(
                    new Uint8Array(operationSeedBytes),
                ),
            },
        });
    }
};

// Generates the release body from the seed alone and retains its records and
// envelope before any signature, retiring the seed.
const proveRelease = async (session: ReleaseSession) => {
    const { context } = session.close.participant;
    const { profile, module } = context;
    const bounds = profile.release;
    const { state } = session;
    if (state === undefined) throw new Error('No release seed is retained.');
    const randomness = seededRandomness(module, 'release', state.seed);
    let envelope: Uint8Array;
    try {
        envelope = releaseCommand(
            context,
            releaseOperation.create,
            releaseTarget(session).body,
        );
        session.proofRandomBytes = randomness.proofDrawn();
    } finally {
        randomness.discard();
    }
    // The envelope ends with the body length and the body identity.
    const bodyLength = Number(
        readUnsigned64(envelope, bounds.envelopeBytes - 64 - 8),
    );
    if (
        envelope.length !== bounds.envelopeBytes ||
        bodyLength < bounds.minimumBodyBytes ||
        bodyLength > bounds.maximumBodyBytes
    )
        throw new Error('The release envelope is malformed.');
    const added: AddedRecord[] = [];
    for (const [index, length] of releaseRecordLengths(
        profile,
        bodyLength,
    ).entries())
        added.push(
            await sealReleaseRecord(
                session,
                index,
                releaseCommand(
                    context,
                    releaseOperation.bodySlice,
                    concatenate(
                        unsigned32(index * bounds.recordBytes),
                        unsigned32(length),
                    ),
                ),
            ),
        );
    await commitRelease(session, {
        generation: releasePhase.body,
        state: {
            ...state,
            seed: new Uint8Array(),
            bodyLength,
            bodyKeys: added.map((record) => record.key),
            envelope,
        },
        added,
    });
};

// Imports the retained unsigned body, which the owning proof verifier checks
// again under the actual certificate before a signature.
const restoreReleaseBody = async (session: ReleaseSession) => {
    const { context } = session.close.participant;
    const { state } = session;
    if (state === undefined) throw new Error('No release body is retained.');
    releaseCommand(context, releaseOperation.beginImport, state.envelope);
    for (let index = 0; index < state.bodyKeys.length; index++) {
        const bytes = await openReleaseRecord(session, index);
        releaseCommand(context, releaseOperation.pushImport, bytes);
    }
    releaseCommand(context, releaseOperation.finishImport);
};

// The verified body transaction already locks the exact signing envelope.
const signRelease = async (session: ReleaseSession) => {
    const { context } = session.close.participant;
    if (session.state === undefined)
        throw new Error('No release body is retained.');
    const state = session.state;
    const packet = releaseCommand(
        context,
        releaseOperation.sign,
        state.envelope,
    );
    await commitRelease(session, {
        generation: releasePhase.signed,
        state: {
            ...state,

            signature: packet.slice(state.envelope.length),
        },
    });
};

// Restores the signed target the credential retains, so a release can only
// follow that target.
const restoreSignedTarget = (
    context: ParticipantProfileContext,
    signed: TargetState,
) => {
    const { module } = context;
    const { body, vote } = signed;
    writeModuleInput(context, concatenate(unsigned32(body.length), body, vote));
    if (
        module.participant_finality_command(
            finalityOperation.restoreSignedTarget,
            4 + body.length + vote.length,
        ) !== 0
    )
        throw new Error('The signed target can no longer be restored.');
};

// Advances this participant's release to its signature. The owning setup
// verifier must have verified the complete setup in this instance first.
// Returns whether the certified target carries a result to release, and the
// own ballot's status in it: the signed target's, or else the one the
// finality work reads from the certified target, which a locked release
// retains.
export const advanceRelease = async (
    session: ReleaseSession,
    relay: PublicRelay,
) => {
    const { close } = session;
    const { context } = close.participant;
    await restoreCompletedClose(close);
    if (session.signed !== undefined)
        restoreSignedTarget(context, session.signed);
    const evaluated = await restoreOrEvaluateTarget(close, relay);
    if (
        session.target !== undefined &&
        !equalBytes(evaluated.body, session.target.body)
    ) {
        if (evaluated.restored) await discardEvaluation(context);
        throw new PublicInputFailure(
            'The public close records name another target.',
        );
    }
    const encrypted = await certifyTarget(context, relay, evaluated.restored);
    const ballotInclusion =
        session.signed?.ballotInclusion ?? certifiedBallotInclusion(context);
    if (
        session.state !== undefined &&
        session.state.ballotInclusion !== ballotInclusion
    )
        throw new Error('The release names another ballot status.');
    if (!encrypted) return { encrypted, ballotInclusion };
    // A release that follows the completed close takes the certified target.
    session.target ??= {
        body: evaluated.body,
        digest: custodyIdentity(
            context.module,
            custodyPurpose.target,
            evaluated.body,
        ),
    };
    await establishReleaseContext(context, close.records.position);
    await lockRelease(session, ballotInclusion);
    if (generationOf(session) === releasePhase.ready)
        await proveRelease(session);
    else await restoreReleaseBody(session);
    await signRelease(session);
    return { encrypted, ballotInclusion };
};

// Delivers the signed release body and then its envelope packet, inspecting
// the retained authority around every transfer.
export const publishRelease = async (
    session: ReleaseSession,
    relay: PublicRelay,
) => {
    const { state } = session;
    if (state === undefined || generationOf(session) < releasePhase.signed)
        return;
    const { context, root } = session.close.participant;
    const delivery = await openDelivery(context, root, {
        release: state.bodyKeys.length,
    });
    const publication = createCandidatePublication(
        relay,
        releaseCandidateKey(session.close.records.position),
        delivery,
    );
    await publication.addStream(
        'body.bin',
        state.bodyLength,
        async (accept) => {
            for (let index = 0; index < state.bodyKeys.length; index++) {
                const bytes = await openReleaseRecord(session, index);
                try {
                    await accept(bytes);
                } finally {
                    bytes.fill(0);
                }
            }
        },
    );
    await publication.addBytes(
        'envelope.bin',
        concatenate(state.envelope, state.signature),
    );
    await publication.finish();
};

const releaseCandidateKey = (position: number) => 'release-' + String(position);

// Combines the published release shares of the target this instance
// certified into the result: the ordered option identifiers, or none for a
// certified no-result target. Each share passes the owning envelope and body
// verifiers under its position's release context; too few verified shares
// leave the work pending.
export const combineReleaseShares = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    encrypted: boolean,
) => {
    const { profile } = context;
    const bounds = profile.release;
    let result = encrypted
        ? undefined
        : tryCompletionCommand(context, completionOperation.result);
    const pending = new Map(
        Array.from(
            { length: profile.participantCount },
            (_, position) =>
                [
                    position,
                    readCandidates(relay, releaseCandidateKey(position))[
                        Symbol.asyncIterator
                    ](),
                ] as const,
        ),
    );
    while (result === undefined && pending.size > 0) {
        for (const [position, candidates] of pending) {
            const next = await candidates.next();
            if (next.done) {
                pending.delete(position);
                continue;
            }
            let packet: Uint8Array;
            try {
                packet = await readCandidateFile(
                    relay,
                    next.value,
                    'envelope.bin',
                    bounds.envelopeBytes + profile.registration.signatureBytes,
                );
            } catch (error) {
                if (error instanceof PublicInputFailure) continue;
                throw error;
            }
            await establishReleaseContext(context, position);
            const authenticated = tryCompletionCommand(
                context,
                completionOperation.authenticateRelease,
                0,
                packet,
            );
            if (authenticated === undefined) continue;
            let header: Uint8Array = new Uint8Array();
            let accepted = true;
            try {
                await streamCandidateFile(
                    relay,
                    next.value,
                    'body.bin',
                    bounds.maximumBodyBytes,
                    (bytes) => {
                        let rest = bytes;
                        if (header.length < bounds.bodyHeaderBytes) {
                            const taken = rest.subarray(
                                0,
                                bounds.bodyHeaderBytes - header.length,
                            );
                            header = concatenate(header, taken);
                            rest = rest.subarray(taken.length);
                            if (header.length < bounds.bodyHeaderBytes) return;
                            accepted &&=
                                tryCompletionCommand(
                                    context,
                                    completionOperation.beginReleaseBody,
                                    0,
                                    header,
                                ) !== undefined;
                        }
                        if (rest.length > 0 && accepted)
                            accepted =
                                tryCompletionCommand(
                                    context,
                                    completionOperation.pushReleaseBody,
                                    0,
                                    rest,
                                ) !== undefined;
                    },
                );
            } catch (error) {
                if (!(error instanceof PublicInputFailure)) throw error;
                accepted = false;
            }
            if (
                !accepted ||
                tryCompletionCommand(
                    context,
                    completionOperation.finishRelease,
                ) === undefined
            )
                continue;
            pending.delete(position);
            result = tryCompletionCommand(context, completionOperation.result);
            if (result !== undefined) break;
        }
    }
    if (result === undefined)
        throw new PublicInputFailure('The release shares are incomplete.');
    const identifiers: string[] = [];
    const decoder = new TextDecoder('utf-8', { fatal: true });
    for (
        let offset = 4, index = 0;
        index < readUnsigned32(result, 0);
        index++
    ) {
        const length = readUnsigned32(result, offset);
        identifiers.push(
            decoder.decode(result.subarray(offset + 4, offset + 4 + length)),
        );
        offset += 4 + length;
    }
    return { encrypted, identifiers };
};

// Combines published release shares of the certified target into the result
// in this participant's own module, once its completed close and the target
// it evaluated are restored and the target is certified.
export const computeResult = async (
    close: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = close.participant;
    await restoreCompletedClose(close);
    const { restored } = await restoreOrEvaluateTarget(close, relay);
    return combineReleaseShares(
        context,
        relay,
        await certifyTarget(context, relay, restored),
    );
};
