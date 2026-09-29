import { retainedBallotRecords } from './ballot.js';
import {
    concatenate,
    equalBytes,
    readUnsigned32,
    readUnsigned64,
    unsigned32,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import { completedCloseRecords, restoreCompletedClose } from './close.js';
import type { CloseSession } from './close.js';
import { PublicInputFailure, sessionInput } from './context.js';
import type { ProfileContext } from './context.js';
import { contributionRecords } from './contribution.js';
import { openDelivery } from './delivery.js';
import { custodyIdentity, custodyPurpose } from './identity.js';
import {
    operationSeedBytes,
    readKernel,
    seededRandomness,
    writeChunkInput,
} from './kernel.js';
import {
    publishChunk,
    publishRecord,
    readPublic,
    recordPublic,
    streamPublic,
} from './public.js';
import type { PublicRelay } from './public.js';
import { openRecord, sealRecord } from './records.js';
import {
    decodeReleaseState,
    encodeReleaseState,
    releasePhase,
    releaseRecordAssociatedData,
    releaseRecordInventory,
    releaseRecordLengths,
} from './release-state.js';
import type { ReleaseState } from './release-state.js';
import { commitRoot, dataRecordInventory } from './root.js';
import { deliverFinalAggregate, readFinalAggregate } from './setup.js';
import { snapshotParticipant } from './storage.js';
import { targetPhase } from './target-state.js';
import type { TargetState } from './target-state.js';
import {
    completionDirectory,
    discardEvaluation,
    restoreOrEvaluateTarget,
    resumeTarget,
} from './target.js';

// A participant's release of its share of the certified target. The release
// follows the participant's own signed target, or its completed close when it
// signed no target and a certificate already exists; a pending target
// signature cannot be bypassed. Each visit restores the completed close and
// any signed target, restores the target this participant evaluated or else
// evaluates it from the public close records, and certifies it from the
// published votes; only the certificate verifier creates the release
// context. The
// seed of all release randomness enters the root before any private
// generation, and the module proves the release from that seed alone, so an
// interrupted generation draws the same bytes again. The body and envelope
// are retained before the signing coins, and the coins before the signature.

const coinBytes = 32;

export type ReleaseSession = {
    readonly close: CloseSession;
    // The participant's own signed target, when the release follows it.
    readonly signed: TargetState | undefined;
    // The certified target body and its digest, once known: from the signed
    // target or the retained release state, or from the first certified
    // evaluation of a release that follows the completed close.
    target: Readonly<{ body: Uint8Array; digest: Uint8Array }> | undefined;
    state: ReleaseState | undefined;
    // The proof-stream bytes the module drew, when this visit generated the
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
    const closed = completedClosePhase(close.organizer);
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
                    close.organizer,
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
                          context.kernel,
                          custodyPurpose.target,
                          body,
                      ),
                  },
        state,
    };
};

const releaseCommand = (
    context: ProfileContext,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    sessionInput(context, input);
    if (kernel.participant_release_command(operation, input.length) !== 0)
        throw new Error(
            'The release work refused operation ' + String(operation) + '.',
        );
    return readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
};

const tryCompletionCommand = (
    context: ProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    writeChunkInput(kernel, kernel.completion_input_pointer(), input);
    if (kernel.completion_command(operation, argument, input.length) !== 0)
        return undefined;
    return readKernel(
        kernel,
        kernel.completion_output_pointer(),
        kernel.completion_output_length(),
    );
};

const completionCommand = (
    context: ProfileContext,
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
// is, is discarded, so that the next visit evaluates the target the public
// close records name; missing votes alone keep it. Returns whether the target
// is encrypted.
const certifyTarget = async (
    context: ProfileContext,
    relay: PublicRelay,
    restored: boolean,
) => {
    const [count, threshold] = words(completionCommand(context, 0));
    let accepted = 0;
    let refused = false;
    for (
        let position = 0;
        position < count && accepted < threshold;
        position++
    ) {
        let vote: Uint8Array;
        try {
            vote = await readPublic(
                relay,
                completionDirectory +
                    'target-vote-' +
                    String(position) +
                    '.bin',
                context.profile.target.votePacketBytes,
            );
        } catch (error) {
            if (error instanceof PublicInputFailure) continue;
            throw error;
        }
        const inserted = tryCompletionCommand(context, 1, 0, vote);
        if (inserted === undefined) refused = true;
        else accepted = words(inserted)[1];
    }
    const certified = tryCompletionCommand(context, 2);
    if (certified === undefined) {
        if (restored && refused) await discardEvaluation(context);
        throw new PublicInputFailure('The target votes are incomplete.');
    }
    // The evaluator supplies these exact certified bytes even when this
    // visit restored its local target and never fetched the relay's copy.
    // A fresh public reader checks them against its own recomputation.
    if (relay.recorder !== undefined) {
        const { kernel } = context;
        await recordPublic(
            relay,
            completionDirectory + 'target.bin',
            readKernel(
                kernel,
                kernel.evaluation_target_body_pointer(),
                kernel.evaluation_target_body_length(),
            ),
        );
    }
    return words(certified)[0] === 1;
};

// Creates the certified release context of one position from its two share
// polynomials of the verified aggregate.
const establishReleaseContext = async (
    context: ProfileContext,
    position: number,
) => {
    const stream = (index: number) =>
        readFinalAggregate(context, index, (offset, bytes) => {
            if (tryCompletionCommand(context, 4, offset, bytes) === undefined)
                throw new PublicInputFailure('A release key was refused.');
        });
    // Finishing a polynomial checks its bytes against the retained setup
    // reference.
    const finish = () => {
        const output = tryCompletionCommand(context, 5);
        if (output === undefined)
            throw new PublicInputFailure('A release key was refused.');
        return output;
    };
    const constant = words(completionCommand(context, 3, position))[0];
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

// Locks the certified target the release follows, then the seed of all its
// randomness.
const lockRelease = async (session: ReleaseSession) => {
    if (generationOf(session) < releasePhase.locked)
        await commitRelease(session, {
            generation: releasePhase.locked,
            state: {
                predecessor:
                    session.signed === undefined
                        ? completedClosePhase(session.close.organizer)
                        : targetPhase.signed,
                target: releaseTarget(session).body,
                seed: new Uint8Array(),
                bodyLength: 0,
                bodyKeys: [],
                envelope: new Uint8Array(),
                coins: new Uint8Array(),
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
    const { profile, kernel, handlers } = context;
    const bounds = profile.release;
    const { state } = session;
    if (state === undefined) throw new Error('No release seed is retained.');
    const randomness = seededRandomness(kernel, 'release', state.seed);
    let envelope: Uint8Array;
    try {
        handlers.random = randomness.random;
        envelope = releaseCommand(context, 0, releaseTarget(session).body);
        session.proofRandomBytes = randomness.proofDrawn();
    } finally {
        handlers.random = undefined;
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
                    1,
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
    releaseCommand(context, 2, state.envelope);
    for (let index = 0; index < state.bodyKeys.length; index++) {
        const bytes = await openReleaseRecord(session, index);
        releaseCommand(context, 3, bytes);
    }
    releaseCommand(context, 4);
};

// Retains the signing coins and signs the exact envelope.
const signRelease = async (session: ReleaseSession) => {
    const { context } = session.close.participant;
    if (session.state === undefined)
        throw new Error('No release body is retained.');
    if (generationOf(session) === releasePhase.body)
        await commitRelease(session, {
            generation: releasePhase.intent,
            state: {
                ...session.state,
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
        });
    const state = session.state;
    const packet = releaseCommand(
        context,
        5,
        concatenate(state.envelope, state.coins),
    );
    await commitRelease(session, {
        generation: releasePhase.signed,
        state: {
            ...state,
            coins: new Uint8Array(),
            signature: packet.slice(state.envelope.length),
        },
    });
};

// Restores the signed target the credential retains, so a release can only
// follow that target.
const restoreSignedTarget = (context: ProfileContext, signed: TargetState) => {
    const { kernel } = context;
    const { body, vote } = signed;
    sessionInput(context, concatenate(unsigned32(body.length), body, vote));
    if (
        kernel.participant_finality_command(
            2,
            4 + body.length + vote.length,
        ) !== 0
    )
        throw new Error('The signed target can no longer be restored.');
};

// Advances this participant's release to its signature. The owning setup
// verifier must have verified the complete setup in this instance first.
// Once the target is certified, and before any release randomness, the
// visit may archive the certified target closure it read. Returns whether
// the certified target carries a result to release.
export const advanceRelease = async (
    session: ReleaseSession,
    relay: PublicRelay,
    archiveClosure?: () => Promise<void>,
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
    await archiveClosure?.();
    if (!encrypted) return false;
    // A release that follows the completed close takes the certified target.
    session.target ??= {
        body: evaluated.body,
        digest: custodyIdentity(
            context.kernel,
            custodyPurpose.target,
            evaluated.body,
        ),
    };
    await establishReleaseContext(context, close.records.position);
    await lockRelease(session);
    if (generationOf(session) === releasePhase.ready)
        await proveRelease(session);
    else await restoreReleaseBody(session);
    await signRelease(session);
    return true;
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
    const position = String(session.close.records.position);
    const delivery = await openDelivery(context, root, {
        release: state.bodyKeys.length,
    });
    for (let index = 0; index < state.bodyKeys.length; index++) {
        const bytes = await openReleaseRecord(session, index);
        await delivery.transfer(
            () =>
                publishChunk(
                    relay,
                    completionDirectory + 'release-' + position + '.bin',
                    index * context.profile.release.recordBytes,
                    bytes,
                ),
            bytes,
        );
    }
    await delivery.transfer(() =>
        publishRecord(
            relay,
            completionDirectory + 'release-envelope-' + position + '.bin',
            concatenate(state.envelope, state.signature),
        ),
    );
};

// Combines published release shares of the certified target into the result
// in this participant's own module: the ordered option identifiers, or none
// for a certified no-result target. Each share passes the owning envelope
// and body verifiers under its position's release context; too few verified
// shares leave the participant pending.
export const computeResult = async (
    close: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = close.participant;
    const { profile } = context;
    const bounds = profile.release;
    await restoreCompletedClose(close);
    const { restored } = await restoreOrEvaluateTarget(close, relay);
    const encrypted = await certifyTarget(context, relay, restored);
    let result = encrypted ? undefined : tryCompletionCommand(context, 10);
    for (
        let position = 0;
        result === undefined && position < profile.participantCount;
        position++
    ) {
        let packet: Uint8Array;
        try {
            packet = await readPublic(
                relay,
                completionDirectory +
                    'release-envelope-' +
                    String(position) +
                    '.bin',
                bounds.envelopeBytes + profile.registration.signatureBytes,
            );
        } catch (error) {
            if (error instanceof PublicInputFailure) continue;
            throw error;
        }
        await establishReleaseContext(context, position);
        const authenticated = tryCompletionCommand(context, 6, 0, packet);
        if (authenticated === undefined) continue;
        let header: Uint8Array = new Uint8Array();
        let accepted = true;
        try {
            await streamPublic(
                relay,
                completionDirectory + 'release-' + String(position) + '.bin',
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
                            tryCompletionCommand(context, 7, 0, header) !==
                            undefined;
                    }
                    if (rest.length > 0 && accepted)
                        accepted =
                            tryCompletionCommand(context, 8, 0, rest) !==
                            undefined;
                },
            );
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
            accepted = false;
        }
        if (!accepted || tryCompletionCommand(context, 9) === undefined)
            continue;
        result = tryCompletionCommand(context, 10);
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
