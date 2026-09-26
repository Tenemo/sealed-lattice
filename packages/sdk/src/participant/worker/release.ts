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
import { custodyIdentity, custodyPurpose } from './identity.js';
import { readKernel, writeChunkInput } from './kernel.js';
import type { KernelHandlers, ParticipantKernel } from './kernel.js';
import {
    publishChunk,
    publishRecord,
    readPublic,
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
    releaseRecordKind,
    releaseRecordLengths,
} from './release-state.js';
import type { ReleaseState } from './release-state.js';
import { commitRoot, dataRecordInventory } from './root.js';
import { readFinalAggregate } from './setup.js';
import { snapshotParticipant } from './storage.js';
import { targetPhase } from './target-state.js';
import type { TargetState } from './target-state.js';
import {
    completionDirectory,
    evaluateClosedTarget,
    resumeTarget,
} from './target.js';

// A participant's release of its share of the certified target. The release
// follows the participant's own signed target, or its completed close when it
// signed no target and a certificate already exists; a pending target
// signature cannot be bypassed. Each visit restores the completed close and
// any signed target, evaluates the target again from the public close records
// and certifies it from the published votes; only the certificate verifier
// creates the release context. The
// journal of original random bytes enters the root before any private
// generation, and the module proves the release from that journal alone, so
// an interrupted generation replays the same bytes. The body and envelope
// are retained before the signing coins, and the coins before the signature.

const coinBytes = 32;
const randomRequestBytes = 65_536;

export type ReleaseSession = {
    readonly close: CloseSession;
    // The participant's own signed target, when the release follows it.
    readonly signed: TargetState | undefined;
    // The certified target body and its digest, once known: from the signed
    // target or the retained release state, or from the first certified
    // evaluation of a release that follows the completed close.
    target: Readonly<{ body: Uint8Array; digest: Uint8Array }> | undefined;
    state: ReleaseState | undefined;
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

const recordCount = (state: ReleaseState | undefined) =>
    state === undefined ? 0 : state.journalKeys.length + state.bodyKeys.length;

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
        generation < releasePhase.journal
            ? undefined
            : bytes === undefined
              ? undefined
              : decodeReleaseState(
                    context.profile,
                    generation,
                    close.organizer,
                    bytes,
                );
    if (generation >= releasePhase.journal && state === undefined)
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
    if (snapshot.counts.release !== recordCount(state))
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

// Certifies the evaluated target from the published target votes, stopping
// at the certificate threshold. A missing or refused vote is skipped; too few
// leave the participant pending. Returns whether the target is encrypted.
const certifyTarget = async (context: ProfileContext, relay: PublicRelay) => {
    const [count, threshold] = words(completionCommand(context, 0));
    let accepted = 0;
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
        if (inserted !== undefined) accepted = words(inserted)[1];
    }
    const certified = tryCompletionCommand(context, 2);
    if (certified === undefined)
        throw new PublicInputFailure('The target votes are incomplete.');
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
    await stream(words(completionCommand(context, 3, position))[0]);
    await stream(words(completionCommand(context, 5))[0]);
    completionCommand(context, 5);
};

const openReleaseRecord = (
    session: ReleaseSession,
    kind: number,
    index: number,
) => {
    const { context } = session.close.participant;
    const { state } = session;
    if (state === undefined) throw new Error('No release state is retained.');
    const journal = kind === releaseRecordKind.journal;
    const length = releaseRecordLengths(
        context.profile,
        journal ? context.profile.release.journalBytes : state.bodyLength,
    )[index];
    return openRecord(
        context.database,
        'release',
        [kind, index],
        {
            key: (journal ? state.journalKeys : state.bodyKeys)[index],
            additionalData: releaseRecordAssociatedData(
                session.close.records,
                releaseTarget(session).digest,
                kind,
                index,
                length,
            ),
        },
        length,
    );
};

type AddedRecord = Readonly<{
    kind: number;
    index: number;
    key: Uint8Array;
    ciphertext: Uint8Array;
}>;

const sealReleaseRecord = async (
    session: ReleaseSession,
    kind: number,
    index: number,
    bytes: Uint8Array,
): Promise<AddedRecord> => ({
    kind,
    index,
    ...(await sealRecord(
        releaseRecordAssociatedData(
            session.close.records,
            releaseTarget(session).digest,
            kind,
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
    retireJournal?: boolean;
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
            if (transition.retireJournal === true)
                store.delete(
                    IDBKeyRange.bound(
                        [releaseRecordKind.journal],
                        [releaseRecordKind.body],
                        false,
                        true,
                    ),
                );
            for (const record of transition.added ?? [])
                store.add(new Blob([new Uint8Array(record.ciphertext)]), [
                    record.kind,
                    record.index,
                ]);
        },
    });
    session.state = transition.state;
    for (const record of transition.added ?? [])
        (await openReleaseRecord(session, record.kind, record.index)).fill(0);
};

// Appends the journal's original random bytes one record at a time; the
// append of the final record enters the ready phase.
const appendJournal = async (session: ReleaseSession) => {
    const { profile } = session.close.participant.context;
    const lengths = releaseRecordLengths(profile, profile.release.journalBytes);
    while (generationOf(session) < releasePhase.ready) {
        const state: ReleaseState = session.state ?? {
            predecessor:
                session.signed === undefined
                    ? completedClosePhase(session.close.organizer)
                    : targetPhase.signed,
            target: releaseTarget(session).body,
            journalKeys: [],
            bodyLength: 0,
            bodyKeys: [],
            envelope: new Uint8Array(),
            coins: new Uint8Array(),
            signature: new Uint8Array(),
        };
        const index = state.journalKeys.length;
        const bytes = new Uint8Array(lengths[index]);
        let added: AddedRecord;
        try {
            for (let offset = 0; offset < bytes.length;)
                offset += crypto.getRandomValues(
                    bytes.subarray(offset, offset + randomRequestBytes),
                ).length;
            added = await sealReleaseRecord(
                session,
                releaseRecordKind.journal,
                index,
                bytes,
            );
        } finally {
            bytes.fill(0);
        }
        const journalKeys = [...state.journalKeys, added.key];
        await commitRelease(session, {
            generation:
                journalKeys.length === lengths.length
                    ? releasePhase.ready
                    : releasePhase.journal,
            state: { ...state, journalKeys },
            added: [added],
        });
    }
};

// Loads the complete journal into the module's entropy queue one record at
// a time, clearing each plaintext.
const loadJournal = async (session: ReleaseSession) => {
    const { context } = session.close.participant;
    const { kernel, profile } = context;
    if (kernel.release_entropy_command(0, profile.release.journalBytes) !== 0)
        throw new Error('The release entropy refused its journal.');
    const lengths = releaseRecordLengths(profile, profile.release.journalBytes);
    for (let index = 0; index < lengths.length; index++) {
        const bytes = await openReleaseRecord(
            session,
            releaseRecordKind.journal,
            index,
        );
        try {
            writeChunkInput(
                kernel,
                kernel.release_entropy_input_pointer(),
                bytes,
            );
            if (kernel.release_entropy_command(1, bytes.length) !== 0)
                throw new Error('The release entropy refused a record.');
        } finally {
            bytes.fill(0);
        }
    }
};

// Answers the release prover's proof randomness from the loaded journal in
// its original order. The queue refuses an over-budget read or exhaustion,
// and no other randomness is drawn; each copied output is cleared.
export const journalRandomness =
    (kernel: ParticipantKernel): NonNullable<KernelHandlers['random']> =>
    (source, target) => {
        if (source !== 'proof')
            throw new Error('Unexpected participant randomness request.');
        if (kernel.release_entropy_command(2, target.length) !== 0)
            throw new Error(
                'The release journal refused a randomness request.',
            );
        const output = new Uint8Array(
            kernel.memory.buffer,
            kernel.release_entropy_output_pointer() >>> 0,
            target.length,
        );
        target.set(output);
        output.fill(0);
    };

// Generates the release body from the journal and retains its records and
// envelope before any signature.
const proveRelease = async (session: ReleaseSession) => {
    const { context } = session.close.participant;
    const { profile, kernel, handlers } = context;
    const bounds = profile.release;
    let envelope: Uint8Array;
    try {
        await loadJournal(session);
        handlers.random = journalRandomness(kernel);
        envelope = releaseCommand(context, 0, releaseTarget(session).body);
    } finally {
        handlers.random = undefined;
        // Clears any journal bytes the prover left unread.
        kernel.release_entropy_command(3, 0);
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
                releaseRecordKind.body,
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
    const state = session.state;
    if (state === undefined) throw new Error('No release journal is retained.');
    await commitRelease(session, {
        generation: releasePhase.body,
        state: {
            ...state,
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
        const bytes = await openReleaseRecord(
            session,
            releaseRecordKind.body,
            index,
        );
        releaseCommand(context, 3, bytes);
    }
    releaseCommand(context, 4);
};

// Retains the signing coins, signs the exact envelope and retires the
// journal with the signature.
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
            journalKeys: [],
            coins: new Uint8Array(),
            signature: packet.slice(state.envelope.length),
        },
        retireJournal: true,
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
// Returns whether the certified target carries a result to release.
export const advanceRelease = async (
    session: ReleaseSession,
    relay: PublicRelay,
) => {
    const { close } = session;
    const { context } = close.participant;
    await restoreCompletedClose(close);
    if (session.signed !== undefined)
        restoreSignedTarget(context, session.signed);
    const evaluated = await evaluateClosedTarget(context, relay);
    if (
        session.target !== undefined &&
        !equalBytes(evaluated.body, session.target.body)
    )
        throw new PublicInputFailure(
            'The public close records name another target.',
        );
    if (!(await certifyTarget(context, relay))) return false;
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
    await appendJournal(session);
    if (generationOf(session) === releasePhase.ready)
        await proveRelease(session);
    else await restoreReleaseBody(session);
    await signRelease(session);
    return true;
};

// Delivers the signed release body and its envelope packet.
export const publishRelease = async (
    session: ReleaseSession,
    relay: PublicRelay,
) => {
    const { state } = session;
    if (state === undefined || generationOf(session) < releasePhase.signed)
        return;
    const { profile } = session.close.participant.context;
    const position = String(session.close.records.position);
    for (let index = 0; index < state.bodyKeys.length; index++)
        await publishChunk(
            relay,
            completionDirectory + 'release-' + position + '.bin',
            index * profile.release.recordBytes,
            await openReleaseRecord(session, releaseRecordKind.body, index),
        );
    await publishRecord(
        relay,
        completionDirectory + 'release-envelope-' + position + '.bin',
        concatenate(state.envelope, state.signature),
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
    await evaluateClosedTarget(context, relay);
    const encrypted = await certifyTarget(context, relay);
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
