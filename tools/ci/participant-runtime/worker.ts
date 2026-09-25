import { stopParticipant } from '../protocol-participant-stop.js';

import {
    beginBallot,
    completeBallot,
    parseBallotScores,
    publishBallot,
    resumeBallot,
} from './ballot.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    fromHexadecimal,
    hexadecimal,
    sha512,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import {
    advanceClose,
    closeEvents,
    isCloseComplete,
    parseCloseRequest,
    publishClose,
    resumeClose,
} from './close.js';
import { PublicInputFailure } from './context.js';
import type { ParticipantContext } from './context.js';
import {
    beginContribution,
    confirmContribution,
    continueContribution,
    generateContribution,
    openContribution,
    publishConfirmation,
    publishOpening,
    restoreCheckpoint,
    resumeContribution,
    storedConfirmation,
} from './contribution.js';
import { parseParticipantDescriptor } from './descriptor.js';
import type { ParticipantDescriptor } from './descriptor.js';
import { createEnrollment, restoreEnrollment } from './enrollment.js';
import type { EnrollmentRequest, RestoredEnrollment } from './enrollment.js';
import { instantiateParticipantKernel } from './kernel.js';
import { publishRecord, readBounded } from './public.js';
import type { PublicRelay } from './public.js';
import {
    authenticateRoot,
    dataKind,
    readDataKind,
    StoragePending,
} from './root.js';
import type { AuthenticatedRoot } from './root.js';
import {
    acceptRoster,
    parseRecordIds,
    proposeRoster,
    registrationFile,
    registrationPath,
    reverifyRoster,
    signRoster,
} from './roster.js';
import { retainSetup, reverifySetup, verifySetup } from './setup.js';
import { openParticipantDatabase } from './storage.js';
import { targetPhase } from './target-state.js';
import { publishTarget, signTarget } from './target.js';

// The application page supplies the descriptor and the exact identities of
// the code it verified; the worker fetches the module itself and recomputes
// the runtime identity that every retained root binds.
type WorkerCommand = Readonly<{
    operation: string;
    origin: string;
    descriptor: unknown;
    identity: Readonly<{
        runtime: string;
        source: string;
        module: string;
        worker: string;
    }>;
    parameters: Readonly<Record<string, unknown>>;
}>;

export type WorkerResult = Readonly<
    | { status: 'completed'; details: Readonly<Record<string, unknown>> }
    | { status: 'refused' }
    | { status: 'pending'; reason: string }
    | {
          status: 'stopped';
          reason: string;
          stopPersistence: 'confirmed' | 'unconfirmed';
      }
>;

const runtimeLabel = 'participant-runtime/7';
const maximumModuleBytes = 8_388_608;

const fetchModule = async (origin: string, expected: string) => {
    const module = await readBounded(
        origin + '/participant.wasm',
        maximumModuleBytes,
    );
    if (hexadecimal(await sha512(module)) !== expected)
        throw new PublicInputFailure('The participant module changed.');
    return module;
};

const runtimeIdentity = async (
    command: WorkerCommand,
    descriptor: ParticipantDescriptor,
    module: Uint8Array,
) =>
    sha512(
        concatenate(
            encodeText(runtimeLabel),
            fromHexadecimal(command.identity.source),
            await sha512(module),
            fromHexadecimal(command.identity.worker),
            await sha512(encodeText(JSON.stringify(descriptor))),
        ),
    );

const text = (value: unknown) => {
    if (typeof value !== 'string')
        throw new PublicInputFailure('Malformed text parameter.');
    return value;
};

// Byte parameters cross the page boundary as lower-case hexadecimal.
const bytes = (value: unknown) => fromHexadecimal(text(value));

// Publishes every public record the current root holds: the registration
// record, and the organizer's poll, proposal and proposal signature.
const publishRecords = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
) => {
    const read = (kind: number) =>
        readDataKind(context.database, root.manifest, kind);
    const id = hexadecimal(enrollment.bodyDigest);
    for (const [kind, file] of [
        [dataKind.publicKey, registrationFile.publicKey],
        [dataKind.proof, registrationFile.proof],
        [dataKind.header, registrationFile.header],
        [dataKind.signature, registrationFile.signature],
    ] as const)
        await publishRecord(
            relay,
            registrationPath(id, file),
            await read(kind),
        );
    if (!enrollment.isOrganizer) return;
    await publishRecord(
        relay,
        'poll-definition.bin',
        await read(dataKind.pollDefinition),
    );
    await publishRecord(
        relay,
        'poll-signature.bin',
        await read(dataKind.pollSignature),
    );
    if (root.head.generation >= 3) {
        await publishRecord(
            relay,
            'proposal.bin',
            await read(dataKind.proposal),
        );
        await publishRecord(
            relay,
            'proposal-signature.bin',
            await read(dataKind.proposalSignature),
        );
    }
};

const summary = (root: AuthenticatedRoot, enrollment: RestoredEnrollment) => ({
    generation: root.head.generation,
    rootHash: root.head.hash,
    poll: hexadecimal(root.manifest.poll),
    bodyDigest: hexadecimal(enrollment.bodyDigest),
    username: enrollment.username,
    isOrganizer: enrollment.isOrganizer,
});

const execute = async (
    context: ParticipantContext,
    relay: PublicRelay,
    command: WorkerCommand,
    started: () => void,
): Promise<WorkerResult> => {
    const parameters = command.parameters;
    if (command.operation === 'create') {
        const role = text(parameters.role);
        let request: EnrollmentRequest;
        if (role === 'creator')
            request = {
                role,
                manifest: bytes(parameters.manifest),
                topCount: Number(parameters.topCount),
                username: text(parameters.username),
            };
        else if (role === 'join')
            request = {
                role,
                poll: bytes(parameters.poll),
                definition: bytes(parameters.definition),
                definitionSignature: bytes(parameters.definitionSignature),
                username: text(parameters.username),
            };
        else return { status: 'refused' };
        const root = await createEnrollment(context, request, started);
        if (root === undefined) return { status: 'refused' };
        const enrollment = await restoreEnrollment(context, root, true);
        return { status: 'completed', details: summary(root, enrollment) };
    }
    started();
    let root = await authenticateRoot(
        context.database,
        context.runtime,
        context.descriptor,
    );
    const enrollment = await restoreEnrollment(context, root, false);
    if (
        parameters.poll !== undefined &&
        parameters.poll !== hexadecimal(root.manifest.poll)
    )
        return { status: 'refused' };
    switch (command.operation) {
        case 'status':
            break;
        case 'publish':
            await publishRecords(context, relay, root, enrollment);
            break;
        case 'propose-roster': {
            const recordIds = parseRecordIds(parameters.recordIds);
            if (root.head.generation === 2) {
                const proposal = await reverifyRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                );
                if (proposal.recordIds.join(',') !== recordIds.join(','))
                    return { status: 'refused' };
                root = await signRoster(context, root, proposal);
            } else {
                const proposed = await proposeRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                    recordIds,
                );
                if (proposed === undefined) return { status: 'refused' };
                root = proposed;
            }
            break;
        }
        case 'accept-roster': {
            const accepted = await acceptRoster(
                context,
                relay,
                root,
                enrollment,
                parseRecordIds(parameters.recordIds),
            );
            if (accepted === undefined) return { status: 'refused' };
            root = accepted;
            break;
        }
        case 'contribute': {
            // Generation and continuation each draw their randomness once;
            // an interrupted intent cannot resume.
            if (root.head.generation < 3 || root.head.generation >= 7)
                return { status: 'refused' };
            if (root.head.generation === 4 || root.head.generation === 6)
                throw new Error('Interrupted contribution work cannot resume.');
            let session;
            if (root.head.generation === 3) {
                session = await beginContribution(
                    context,
                    root,
                    await reverifyRoster(context, relay, root, enrollment),
                );
                await generateContribution(session);
            } else {
                session = await resumeContribution(context, root);
                await restoreCheckpoint(session, relay);
            }
            await continueContribution(session);
            root = session.root;
            break;
        }
        case 'confirm': {
            if (root.head.generation < 7) return { status: 'refused' };
            const session = await resumeContribution(context, root);
            const confirmation =
                root.head.generation >= 9
                    ? await storedConfirmation(session)
                    : await confirmContribution(session);
            root = session.root;
            await publishConfirmation(session, relay, confirmation);
            break;
        }
        case 'open': {
            if (root.head.generation < 9) return { status: 'refused' };
            const session = await resumeContribution(
                context,
                root,
                await reverifyRoster(context, relay, root, enrollment),
            );
            await confirmContribution(session);
            const opening = await openContribution(session, relay);
            root = session.root;
            await publishOpening(session, relay, opening);
            break;
        }
        case 'verify-setup': {
            if (root.head.generation !== 11) return { status: 'refused' };
            const session = await resumeContribution(context, root);
            root = await retainSetup(
                session,
                await verifySetup(session, relay),
            );
            break;
        }
        case 'ballot': {
            // Generation twelve starts an attempt with the requested scores.
            // A retained attempt continues only with its locked scores, and a
            // signed ballot is only delivered again, also after an intent.
            const generation = root.head.generation;
            const scores =
                parameters.scores === undefined
                    ? undefined
                    : parseBallotScores(context.descriptor, parameters.scores);
            if (
                generation < 12 ||
                (parameters.scores !== undefined && scores === undefined) ||
                (generation === 12 && scores === undefined) ||
                (generation >= 17 && scores !== undefined)
            )
                return { status: 'refused' };
            const contribution = await resumeContribution(context, root);
            let session;
            if (scores !== undefined && generation === 12)
                session = await beginBallot(contribution, scores);
            else {
                session = await resumeBallot(contribution);
                if (
                    session === undefined ||
                    (scores !== undefined &&
                        !equalBytes(scores, session.state.scores))
                )
                    return { status: 'refused' };
            }
            await completeBallot(session);
            root = contribution.root;
            await publishBallot(session, relay);
            break;
        }
        case 'close': {
            // Only the organizer opens the close, and only before an intent
            // and with no ballot attempt pending.
            const request = parseCloseRequest(context.descriptor, parameters);
            const generation = root.head.generation;
            if (
                request === undefined ||
                generation < 12 ||
                (request.closeTime !== undefined &&
                    (!enrollment.isOrganizer ||
                        (generation !== 12 && generation !== 17)))
            )
                return { status: 'refused' };
            const contribution = await resumeContribution(context, root);
            const session = await resumeClose(
                contribution,
                enrollment.isOrganizer,
            );
            if (!isCloseComplete(session)) {
                await reverifySetup(contribution, relay);
                await advanceClose(session, relay, request);
            }
            root = contribution.root;
            await publishClose(session, relay);
            return {
                status: 'completed',
                details: {
                    ...summary(root, enrollment),
                    closeEvents: closeEvents(session),
                },
            };
        }
        case 'target': {
            // Target signing follows the completed close; a signed vote is
            // only delivered again.
            const generation = root.head.generation;
            if (generation < completedClosePhase(enrollment.isOrganizer))
                return { status: 'refused' };
            const contribution = await resumeContribution(context, root);
            const session = await resumeClose(
                contribution,
                enrollment.isOrganizer,
            );
            let signed = {};
            if (generation < targetPhase.signed) {
                await reverifySetup(contribution, relay);
                signed = await signTarget(session, relay);
            }
            root = contribution.root;
            await publishTarget(session, relay);
            return {
                status: 'completed',
                details: { ...summary(root, enrollment), ...signed },
            };
        }
        default:
            return { status: 'refused' };
    }
    return { status: 'completed', details: summary(root, enrollment) };
};

const run = async (command: WorkerCommand): Promise<WorkerResult> => {
    if (
        !isSecureContext ||
        typeof navigator.locks !== 'object' ||
        typeof crypto.subtle !== 'object' ||
        typeof indexedDB !== 'object'
    )
        return { status: 'refused' };
    const descriptor = parseParticipantDescriptor(command.descriptor);
    const relay: PublicRelay = { origin: command.origin };
    let database: IDBDatabase | undefined;
    let authorityStarted = false;
    try {
        const moduleBytes = await fetchModule(
            command.origin,
            command.identity.module,
        );
        const runtime = await runtimeIdentity(command, descriptor, moduleBytes);
        if (hexadecimal(runtime) !== command.identity.runtime)
            return { status: 'refused' };
        const module = await WebAssembly.compile(new Uint8Array(moduleBytes));
        database = await openParticipantDatabase();
        const opened = database;
        return await navigator.locks.request(
            'sealed-lattice-participant',
            async () => {
                const { kernel, handlers } =
                    await instantiateParticipantKernel(module);
                return execute(
                    { database: opened, kernel, handlers, descriptor, runtime },
                    relay,
                    command,
                    () => {
                        authorityStarted = true;
                    },
                );
            },
        );
    } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        if (error instanceof PublicInputFailure)
            return { status: 'pending', reason };
        if (error instanceof StoragePending)
            return { status: 'pending', reason };
        if (database === undefined || !authorityStarted)
            return { status: 'pending', reason };
        const stop = await stopParticipant(database);
        return {
            status: 'stopped',
            reason,
            stopPersistence: stop.stopPersistence,
        };
    } finally {
        database?.close();
    }
};

self.onmessage = (event: MessageEvent<WorkerCommand>) => {
    void run(event.data).then(
        (result) => self.postMessage(result),
        (error: unknown) =>
            self.postMessage({
                status: 'pending',
                reason: error instanceof Error ? error.message : String(error),
            }),
    );
};
