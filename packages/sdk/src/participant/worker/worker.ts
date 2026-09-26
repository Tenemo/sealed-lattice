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
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import {
    advanceClose,
    closeEvents,
    isCloseComplete,
    lockPublishedIntent,
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
    discardInterruptedRecords,
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
import { releasePhase } from './release-state.js';
import {
    advanceRelease,
    computeResult,
    publishRelease,
    resumeRelease,
} from './release.js';
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
import { stopParticipant } from './stop.js';
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

// The pinned delivery digest that gates executing the module, and the runtime
// identity derived from the delivered files' digests. Neither is an identity
// the participant binds into protocol or retained state.
const deliveryDigest = async (bytes: Uint8Array) =>
    new Uint8Array(
        await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
    );

const fetchModule = async (origin: string, expected: string) => {
    const module = await readBounded(
        origin + '/participant.wasm',
        maximumModuleBytes,
    );
    if (hexadecimal(await deliveryDigest(module)) !== expected)
        throw new PublicInputFailure('The participant module changed.');
    return module;
};

const runtimeIdentity = async (
    command: WorkerCommand,
    descriptor: ParticipantDescriptor,
    module: Uint8Array,
) =>
    deliveryDigest(
        concatenate(
            encodeText(runtimeLabel),
            fromHexadecimal(command.identity.source),
            await deliveryDigest(module),
            fromHexadecimal(command.identity.worker),
            await deliveryDigest(encodeText(JSON.stringify(descriptor))),
        ),
    );

const text = (value: unknown) => {
    if (typeof value !== 'string')
        throw new PublicInputFailure('Malformed text parameter.');
    return value;
};

// Byte parameters cross the page boundary as lower-case hexadecimal; any
// other text is a malformed request, not a local fault.
const bytes = (value: unknown) => {
    const encoded = text(value);
    if (!/^(?:[0-9a-f]{2})*$/u.test(encoded))
        throw new PublicInputFailure('Malformed byte parameter.');
    return fromHexadecimal(encoded);
};

// Publishes every public record the current root holds: the registration
// record, and the organizer's poll, proposal and proposal signature.
const publishRecords = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
) => {
    const read = (kind: number) => readDataKind(context, root.manifest, kind);
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

// What this participant's ballot is: open once the verified setup is
// retained, in progress from the attempt lock, signed, or impossible once the
// participant learned that ballot submission closed without a ballot of its
// own.
const ballotState = (root: AuthenticatedRoot) => {
    const { generation } = root.head;
    if (generation < 12) return undefined;
    if (generation === 12) return 'open';
    if (generation < 17) return 'in progress';
    return (root.manifest.suffixes.ballot?.length ?? 0) > 0
        ? 'signed'
        : 'could not vote';
};

const summary = (root: AuthenticatedRoot, enrollment: RestoredEnrollment) => ({
    generation: root.head.generation,
    rootHash: root.head.hash,
    poll: hexadecimal(root.manifest.poll),
    bodyDigest: hexadecimal(enrollment.bodyDigest),
    username: enrollment.username,
    isOrganizer: enrollment.isOrganizer,
    ballot: ballotState(root),
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
    let root = await authenticateRoot(context);
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
            // Generation and continuation each draw their randomness from a
            // seed retained before they start, so an interrupted one runs
            // again from its seed once what it stored is discarded.
            const { generation } = root.head;
            if (generation < 3 || generation >= 7) return { status: 'refused' };
            if (generation === 4 || generation === 6)
                await discardInterruptedRecords(context, root);
            let session;
            if (generation === 3 || generation === 4) {
                const proposal = await reverifyRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                );
                session =
                    generation === 3
                        ? await beginContribution(context, root, proposal)
                        : await resumeContribution(context, root, proposal);
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
            // A participant that finds the organizer's close intent once its
            // setup is retained learned that ballot submission closed before
            // it could vote: it locks the intent and starts no ballot.
            session.root = root;
            await lockPublishedIntent(
                await resumeClose(session, enrollment.isOrganizer),
                relay,
            );
            root = session.root;
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
            // only delivered again. A release that followed the completed
            // close spent the target purpose without a vote.
            const generation = root.head.generation;
            if (
                generation < completedClosePhase(enrollment.isOrganizer) ||
                (generation >= releasePhase.journal &&
                    root.manifest.suffixes.target?.length === 0)
            )
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
        case 'release': {
            // Release follows this participant's signed target, or its
            // completed close when it signed no target and a certificate
            // already exists; a pending target signature cannot be
            // bypassed. A signed release is only delivered again.
            const generation = root.head.generation;
            if (
                generation !== completedClosePhase(enrollment.isOrganizer) &&
                generation < targetPhase.signed
            )
                return { status: 'refused' };
            const contribution = await resumeContribution(context, root);
            const session = await resumeRelease(
                await resumeClose(contribution, enrollment.isOrganizer),
            );
            let released = {};
            if (generation < releasePhase.signed) {
                // A release continued from an earlier visit reports the
                // generation and journal records it resumed from.
                const resumed =
                    session.state === undefined
                        ? {}
                        : {
                              resumedFrom: {
                                  generation,
                                  journalRecords:
                                      session.state.journalKeys.length,
                              },
                          };
                await reverifySetup(contribution, relay);
                const encrypted = await advanceRelease(session, relay);
                released = {
                    ...resumed,
                    predecessor: session.state?.predecessor,
                    encrypted,
                };
            }
            root = contribution.root;
            await publishRelease(session, relay);
            return {
                status: 'completed',
                details: { ...summary(root, enrollment), ...released },
            };
        }
        case 'result': {
            // Any participant past its close combines the published release
            // shares in its own module; the result is not published.
            if (
                root.head.generation <
                completedClosePhase(enrollment.isOrganizer)
            )
                return { status: 'refused' };
            const contribution = await resumeContribution(context, root);
            const session = await resumeClose(
                contribution,
                enrollment.isOrganizer,
            );
            await reverifySetup(contribution, relay);
            return {
                status: 'completed',
                details: {
                    ...summary(root, enrollment),
                    ...(await computeResult(session, relay)),
                },
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
            async (): Promise<WorkerResult> => {
                try {
                    const { kernel, handlers } =
                        await instantiateParticipantKernel(module);
                    return await execute(
                        {
                            database: opened,
                            kernel,
                            handlers,
                            descriptor,
                            runtime,
                        },
                        relay,
                        command,
                        () => {
                            authorityStarted = true;
                        },
                    );
                } catch (error) {
                    // A local failure after authority started stops the
                    // participant before any other operation takes the lock.
                    if (
                        !authorityStarted ||
                        error instanceof PublicInputFailure ||
                        error instanceof StoragePending
                    )
                        throw error;
                    const stop = await stopParticipant(opened);
                    return {
                        status: 'stopped',
                        reason:
                            error instanceof Error
                                ? error.message
                                : String(error),
                        stopPersistence: stop.stopPersistence,
                    };
                }
            },
        );
    } catch (error) {
        // Public input, pending storage and failures before authority
        // started leave the participant pending.
        return {
            status: 'pending',
            reason: error instanceof Error ? error.message : String(error),
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
