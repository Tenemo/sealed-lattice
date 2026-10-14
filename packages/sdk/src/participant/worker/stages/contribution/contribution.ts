import type { ParticipantProfileContext } from '../../module/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '../../module/custody-identity.js';
import {
    moduleCommand,
    operationSeedBytes,
    readModuleMemory,
    seededRandomness,
    tryModuleCommand,
    writeProofInput,
} from '../../module/participant-module.js';
import { chunkBytes, recordKeyBytes } from '../../module/runtime-bounds.js';
import { findCandidate, readCandidateFile } from '../../relay/candidates.js';
import type { PublicRelay } from '../../relay/relay.js';
import { isContributionSession } from '../../runtime/participant-session.js';
import type {
    ParticipantSession,
    ContributionSession,
} from '../../runtime/participant-session.js';
import {
    concatenate,
    equalBytes,
    unsigned16,
    unsigned64,
} from '../../shared/bytes.js';
import { PublicInputFailure, StorageFailure } from '../../shared/failures.js';
import {
    addParticipantRecords,
    awaitLater,
    hasStorageRoom,
    readParticipantValue,
    recordBytes,
} from '../../storage/database.js';
import { rootGeneration } from '../../storage/root-generation.js';
import { dataKind, readDataKind } from '../../storage/root.js';
import {
    proposalRegistrationBodyDigests,
    registrationFile,
    registrationCandidateKey,
} from '../roster/roster.js';

import {
    type SealedOutput,
    sealContributionRecord,
    commitContribution,
    openContributionRecord,
    signing,
    offerSigningOperation,
} from './contribution-custody.js';
import { createProofWriter, proofLength } from './contribution-proof.js';
import { contributionPhase, proofObject } from './contribution-state.js';
import type {
    ContributionRecord,
    ContributionState,
    CheckpointRecord,
} from './contribution-state.js';

// The sealed checkpoint bytes one write stores while the next are sealed.
const checkpointWriteBytes = 4 << 20;

// Prover phases: generation below one hundred, then one hundred plus the
// proof phase.
const proverPhase = {
    firstInitialize: 103,
    firstColumn: 104,
    polynomials: 107,
    output: 110,
    done: 111,
} as const;

const proverOperation = {
    generate: 2,
    step: 7,
    beginPolynomial: 8,
    pushPolynomial: 9,
    finishPolynomial: 10,
    nextOutput: 11,
    consumePredecessor: 14,
} as const;

const checkpointOperation = {
    exportHeader: 1,
    seal: 2,
    complete: 3,
    import: 4,
    open: 5,
    finish: 6,
} as const;

const proverOutput = (context: ParticipantProfileContext) =>
    readModuleMemory(
        context.module,
        context.module.contribution_proof_output_pointer(),
        context.module.contribution_proof_output_length(),
    );

// Whether the checkpoint accepted the operation.
const checkpoint = (
    context: ParticipantProfileContext,
    operation: number,
    position = 0,
    bytes: Uint8Array = new Uint8Array(),
) =>
    tryModuleCommand(context.module, 'contributionCheckpoint', operation, {
        argument: position,
        input: bytes,
    }) !== undefined;

// Runs prover commands with the randomness of one generation or
// continuation, which the module expands from its retained seed. Only
// generation emits statement output; its retained body output is sealed and
// stored as it arrives.
const proverRun = (session: ContributionSession, statement: boolean) => {
    const { context } = session;
    const { module, handlers, profile } = context;
    const bounds = profile.contribution;
    const bodyObjects = new Set(
        bounds.publicRecords.map((record) => record.object),
    );
    const lengths = new Map<number, number>();
    const pending: { object: number; offset: number; bytes: Uint8Array }[] = [];
    const stored: ContributionRecord[] = [];
    let current = 0;
    let emitted = 0;
    const randomness = seededRandomness(
        module,
        'contribution',
        session.state.seed,
    );
    handlers.contribution = (object, offset, bytes) => {
        if (
            !statement ||
            (object !== current && object !== current + 1) ||
            object > bounds.expandedPolynomials ||
            bytes.length < 1 ||
            bytes.length > chunkBytes ||
            offset !== (lengths.get(object) ?? 0) ||
            bytes.length > bounds.statementBytes - emitted
        )
            throw new Error('Invalid generated contribution output.');
        current = object;
        if (bodyObjects.has(object)) pending.push({ object, offset, bytes });
        lengths.set(object, offset + bytes.length);
        emitted += bytes.length;
    };
    // Seals body output in the profile's record order and stores it.
    const storeRecords = async (records: typeof pending) => {
        const outputs: SealedOutput[] = [];
        try {
            for (const [index, record] of records.entries()) {
                const expected = bounds.publicRecords[stored.length + index];
                if (
                    stored.length + index >= bounds.publicRecords.length ||
                    record.object !== expected.object ||
                    record.offset !== expected.offset ||
                    record.bytes.length !== expected.length
                )
                    throw new Error('Generated body output is noncanonical.');
            }
            const sealed = await Promise.allSettled(
                records.map((record) =>
                    sealContributionRecord(
                        session,
                        record.object,
                        record.offset,
                        record.bytes,
                    ),
                ),
            );
            for (const result of sealed) {
                if (result.status === 'rejected') throw result.reason;
                outputs.push(result.value);
            }
        } finally {
            for (const record of records) record.bytes.fill(0);
        }
        if (outputs.length === 0) return;
        await addParticipantRecords(
            context.database,
            'contribution',
            outputs.map((output) => ({
                key: [output.record.object, output.record.offset],
                bytes: output.ciphertext,
            })),
        );
        stored.push(...outputs.map((output) => output.record));
    };
    // Stores the pending body output once every earlier store ends, while
    // the prover continues. A prover command waits only for the stores
    // before the latest, so at most one runs beside the prover.
    let storing: Promise<void> = Promise.resolve();
    const store = () => {
        const records = pending.splice(0);
        storing = awaitLater(storing.then(() => storeRecords(records)));
        return storing;
    };
    const advance = async (
        operation: number,
        argument = 0,
        bytes: Uint8Array = new Uint8Array(),
    ) => {
        moduleCommand(module, 'contributionProof', operation, {
            argument,
            input: bytes,
        });
        const earlier = storing;
        void store();
        await earlier;
    };
    return {
        advance,
        store,
        // Waits until every body output emitted so far is stored.
        flush: () => storing,
        stored,
        phase: () => module.contribution_proof_phase(),
        objects: () => lengths.size,
        emitted: () => emitted,
        close: () => {
            handlers.contribution = undefined;
            for (const record of pending) record.bytes.fill(0);
            pending.length = 0;
            randomness.discard();
        },
    };
};

export const beginContribution = async (
    session: ParticipantSession,
): Promise<ContributionSession> => {
    const { context, root } = session;
    if (
        root.head.generation !== rootGeneration.preparation ||
        session.state !== undefined ||
        context.position >= context.profile.eligibleContributorCount
    )
        throw new Error('No confirmed roster awaits an eligible offer.');
    if (
        !(await hasStorageRoom(
            context.profile.contribution.requiredStorageBytes,
        ))
    )
        throw new StorageFailure('The origin lacks room for a contribution.');
    const state: ContributionState = {
        phase: contributionPhase.generationIntent,
        position: context.position,
        header: new Uint8Array(),
        publicRecords: [],
        privateRecords: [],
        signingRecords: [],
        seed: crypto.getRandomValues(new Uint8Array(operationSeedBytes)),
    };
    await commitContribution(session, { state });
    if (!isContributionSession(session))
        throw new Error('No contribution intent was retained.');
    return session;
};

// Generates the contribution from the intent's seed, advances the proof to
// the last first-oracle column, and retains the sealed checkpoint with the
// body polynomials. The checkpoint retires the seed. An interrupted
// generation runs again from the same seed once its stored records are
// discarded.
export const generateContribution = async (session: ContributionSession) => {
    const { context } = session;
    const { module, profile } = context;
    const bounds = profile.contribution;
    if (session.state.phase !== contributionPhase.generationIntent)
        throw new Error('No contribution intent is locked.');
    const run = proverRun(session, true);
    const privateRecords: CheckpointRecord[] = [];
    let header: Uint8Array;
    try {
        if (module.begin_contribution(session.state.position) !== 0)
            throw new Error('The credential refused contribution generation.');
        await run.store();
        while (run.phase() < 100) await run.advance(proverOperation.generate);
        await run.flush();
        if (
            run.phase() !== proverPhase.firstInitialize ||
            run.objects() !== bounds.expandedPolynomials + 1 ||
            run.emitted() !== bounds.statementBytes ||
            run.stored.length !== bounds.publicRecords.length
        )
            throw new Error('The generated contribution is incomplete.');
        // The checkpoint follows every first-oracle column but the last.
        for (let step = 0; step < bounds.firstOracleColumns + 2; step++)
            await run.advance(proverOperation.step);
        if (
            run.phase() !== proverPhase.firstColumn ||
            module.contribution_checkpoint_records() !==
                bounds.checkpointLengths.length ||
            !checkpoint(context, checkpointOperation.exportHeader)
        )
            throw new Error('The first-oracle checkpoint is unavailable.');
        header = proverOutput(context);
        if (
            header.length < 1 ||
            header.length > bounds.maximumCheckpointHeaderBytes
        )
            throw new Error('The checkpoint header has an invalid length.');
        // Each batch is written while the next one is sealed. The module
        // draws each record's fresh key and returns it ahead of the record.
        const batch: { key: number; bytes: Uint8Array }[] = [];
        let batchBytes = 0;
        let writing: Promise<void> = Promise.resolve();
        context.handlers.random = (target) => {
            crypto.getRandomValues(target);
        };
        for (const [index, length] of bounds.checkpointLengths.entries()) {
            if (!checkpoint(context, checkpointOperation.seal))
                throw new Error('A checkpoint record was refused.');
            const output = proverOutput(context);
            const key = output.slice(0, recordKeyBytes);
            output.fill(0, 0, recordKeyBytes);
            const sealed = output.subarray(recordKeyBytes);
            if (sealed.length !== length)
                throw new Error('A checkpoint record has another length.');
            privateRecords.push({
                key,
                hash: custodyIdentity(module, custodyPurpose.record, sealed),
            });
            batch.push({ key: index, bytes: sealed });
            batchBytes += sealed.length;
            if (
                batchBytes >= checkpointWriteBytes ||
                index === bounds.checkpointLengths.length - 1
            ) {
                await writing;
                writing = awaitLater(
                    addParticipantRecords(
                        context.database,
                        'checkpoint',
                        batch.splice(0),
                    ),
                );
                batchBytes = 0;
            }
        }
        await writing;
        await run.flush();
        if (!checkpoint(context, checkpointOperation.complete))
            throw new Error('The checkpoint is incomplete.');
    } finally {
        context.handlers.random = undefined;
        run.close();
    }
    await commitContribution(session, {
        state: {
            ...session.state,
            phase: contributionPhase.checkpoint,
            header,
            publicRecords: run.stored,
            privateRecords,
            seed: new Uint8Array(),
        },
        staged: true,
    });
};

// Resumes the checkpointed prover in a new instance. Each recipient key comes
// from its public registration and must match the checkpoint's key hash.
export const restoreCheckpoint = async (
    session: ContributionSession,
    relay: PublicRelay,
) => {
    const { context, state } = session;
    const { module, profile } = context;
    const phase = session.state.phase;
    if (
        phase !== contributionPhase.checkpoint &&
        phase !== contributionPhase.continuationIntent
    )
        throw new Error('No contribution checkpoint is retained.');
    if (
        !checkpoint(
            context,
            checkpointOperation.import,
            state.position,
            concatenate(
                session.records.poll,
                session.records.proposal,
                state.header,
            ),
        )
    )
        throw new Error('The retained proof context was refused.');
    for (const [index, record] of state.privateRecords.entries()) {
        const blob = await readParticipantValue(
            context.database,
            'checkpoint',
            index,
        );
        const length = profile.contribution.checkpointLengths[index];
        if (!(blob instanceof Blob) || blob.size !== length)
            throw new Error('A checkpoint record is missing.');
        const sealed = await recordBytes(blob);
        if (
            !equalBytes(
                custodyIdentity(context.module, custodyPurpose.record, sealed),
                record.hash,
            )
        )
            throw new Error('A checkpoint record changed.');
        const input = concatenate(record.key, sealed);
        try {
            if (!checkpoint(context, checkpointOperation.open, 0, input))
                throw new Error('A checkpoint record was refused.');
        } finally {
            input.fill(0);
        }
    }
    const registrationBodyDigests = proposalRegistrationBodyDigests(
        await readDataKind(context, session.root.manifest, dataKind.proposal),
    );
    for (const [
        position,
        registrationBodyDigest,
    ] of registrationBodyDigests.entries()) {
        await findCandidate(
            relay,
            registrationCandidateKey(registrationBodyDigest),
            async (candidate) => {
                const key = await readCandidateFile(
                    relay,
                    candidate,
                    registrationFile.publicKey,
                    profile.registration.publicKeyBytes,
                );
                writeProofInput(module, key);
                if (
                    module.contribution_checkpoint_key(position, key.length) !==
                    0
                )
                    throw new PublicInputFailure(
                        'A recipient key does not match the checkpoint.',
                    );
            },
        );
    }
    if (
        !checkpoint(context, checkpointOperation.finish) ||
        module.contribution_proof_phase() !== proverPhase.firstColumn
    )
        throw new Error('The contribution did not resume exactly.');
};

// Locks the continuation with a fresh randomness seed, completes the proof
// over the retained body, and retains the complete body, which retires the
// seed. An interrupted continuation runs again from the same seed once its
// stored proof records are discarded.
export const continueContribution = async (session: ContributionSession) => {
    const { context } = session;
    const { profile } = context;
    const bounds = profile.contribution;
    const phase = session.state.phase;
    if (
        phase !== contributionPhase.checkpoint &&
        phase !== contributionPhase.continuationIntent
    )
        throw new Error('No contribution checkpoint is retained.');
    if (phase === contributionPhase.checkpoint)
        await commitContribution(session, {
            state: {
                ...session.state,
                phase: contributionPhase.continuationIntent,
                seed: crypto.getRandomValues(
                    new Uint8Array(operationSeedBytes),
                ),
            },
        });
    const { state } = session;
    const run = proverRun(session, false);
    const proof: ContributionRecord[] = [];
    const writer = createProofWriter(bounds, async (slot, bytes) => {
        const output = await sealContributionRecord(
            session,
            proofObject(profile),
            slot.offset,
            bytes,
        );
        await addParticipantRecords(context.database, 'contribution', [
            {
                key: [output.record.object, output.record.offset],
                bytes: output.ciphertext,
            },
        ]);
        proof.push(output.record);
    });
    let header: Uint8Array;
    // The retained body records in the order the prover takes them; the
    // next one is opened while the prover takes the current one.
    const retained = Array.from(
        { length: bounds.expandedPolynomials },
        (_, index) =>
            state.publicRecords.filter((record) => record.object === index + 1),
    );
    const order = retained.flat();
    let taken = 0;
    let opening =
        order.length > 0
            ? awaitLater(openContributionRecord(session, order[0]))
            : undefined;
    const openNext = async () => {
        if (opening === undefined)
            throw new Error('A contribution record is missing.');
        const bytes = await opening;
        taken++;
        opening =
            taken < order.length
                ? awaitLater(openContributionRecord(session, order[taken]))
                : undefined;
        return bytes;
    };
    try {
        while (run.phase() !== proverPhase.polynomials)
            await run.advance(proverOperation.step);
        for (const [index, records] of retained.entries()) {
            if (records.length === 0) {
                await run.advance(proverOperation.consumePredecessor, index);
                continue;
            }
            await run.advance(proverOperation.beginPolynomial, index);
            for (let count = records.length; count > 0; count--) {
                const bytes = await openNext();
                try {
                    await run.advance(proverOperation.pushPolynomial, 0, bytes);
                } finally {
                    bytes.fill(0);
                }
            }
            await run.advance(proverOperation.finishPolynomial);
        }
        // The linear oracle, then the folded combination.
        await run.advance(proverOperation.step);
        await run.advance(proverOperation.step);
        while (run.phase() === proverPhase.output) {
            await run.advance(proverOperation.nextOutput);
            const bytes = proverOutput(context);
            try {
                await writer.append(bytes);
            } finally {
                bytes.fill(0);
            }
        }
        if (run.phase() !== proverPhase.done)
            throw new Error('The continued proof is incomplete.');
        // The own intent remains at phase six while the same record writer
        // fills every remaining profile slot, including padding-only slots.
        const length = await writer.finish();
        header = signing(
            context,
            offerSigningOperation.bodyHeader,
            concatenate(unsigned16(state.position), unsigned64(BigInt(length))),
        );
        if (proofLength(bounds, header) !== length)
            throw new Error(
                'The original contribution header has another proof length.',
            );
    } finally {
        writer.close();
        // A record opened ahead that the prover never took is cleared too.
        if (opening !== undefined)
            (await opening.catch(() => undefined))?.fill(0);
        run.close();
    }
    await commitContribution(session, {
        state: {
            ...state,
            phase: contributionPhase.body,
            header,
            publicRecords: [...state.publicRecords, ...proof],
            privateRecords: [],
            seed: new Uint8Array(),
        },
        staged: true,
        clearCheckpoint: true,
    });
};
