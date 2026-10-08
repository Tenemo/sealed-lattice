import { writeModuleInput } from '../../module/context.js';
import type { ParticipantProfileContext } from '../../module/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '../../module/custody-identity.js';
import {
    operationSeedBytes,
    readParticipantOutput,
    seededRandomness,
} from '../../module/participant-module.js';
import { createCandidatePublication } from '../../relay/relay.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    readUnsigned64,
    unsigned32,
} from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { snapshotParticipant } from '../../storage/database.js';
import { openDelivery } from '../../storage/delivery.js';
import type { SealedRecord } from '../../storage/private-records.js';
import { openRecord, sealRecord } from '../../storage/private-records.js';
import { releasePhase, targetPhase } from '../../storage/root-generation.js';
import { commitRoot, dataRecordInventory } from '../../storage/root.js';
import { retainedBallotRecords } from '../ballot/ballot.js';
import { completedClosePhase } from '../close/close-state.js';
import type { CloseSession } from '../close/close.js';
import {
    completedCloseRecords,
    restoreCompletedClose,
} from '../close/close.js';
import { discardEvaluation } from '../target-vote/evaluation.js';
import type {
    BallotInclusion,
    TargetState,
} from '../target-vote/target-state.js';
import {
    certifiedBallotInclusion,
    finalityOperation,
    restoreOrEvaluateTarget,
    resumeTarget,
} from '../target-vote/target.js';

import {
    decodeReleaseState,
    encodeReleaseState,
    releaseRecordAssociatedData,
    releaseRecordInventory,
    releaseRecordLengths,
} from './release-state.js';
import type { ReleaseState } from './release-state.js';
import {
    certifyTarget,
    combineReleaseShares,
    establishReleaseContext,
    releaseCandidateKey,
} from './release-verification.js';

// A participant's release of its share of the certified target. The release
// follows the participant's own signed target, or its completed close when it
// signed no target and a certificate already exists; a pending target
// signature cannot be bypassed. Each operation restores the completed close
// and any signed target, restores the target this participant evaluated or
// else evaluates it from the public close records, and certifies it from the
// published votes; only the certificate verifier creates the release context.
// The seed of all release randomness enters the root before any private
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
    return readParticipantOutput(module);
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

const sealReleaseRecord = async (
    session: ReleaseSession,
    index: number,
    bytes: Uint8Array,
): Promise<SealedRecord> => ({
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
    added?: readonly SealedRecord[];
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
    const added: SealedRecord[] = [];
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
