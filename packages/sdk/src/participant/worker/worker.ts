import {
    beginBallot,
    completeBallot,
    parseBallotScores,
    publishBallot,
    resumeBallot,
} from './ballot.js';
import { readParticipantLimits } from './bounds.js';
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
import {
    InvalidRequest,
    isSetupContributor,
    PublicInputFailure,
} from './context.js';
import type { ParticipantContext, ProfileContext } from './context.js';
import {
    beginContribution,
    confirmContribution,
    confirmRoster,
    continueContribution,
    discardInterruptedRecords,
    generateContribution,
    openContribution,
    publishConfirmation,
    publishOpening,
    restoreCheckpoint,
    resumeContribution,
    resumeParticipant,
    storedConfirmation,
} from './contribution.js';
import { openDelivery } from './delivery.js';
import { createEnrollment, restoreEnrollment } from './enrollment.js';
import type { EnrollmentRequest, RestoredEnrollment } from './enrollment.js';
import { participantRuntimeLabel } from './identity.js';
import {
    instantiateParticipantKernel,
    ModuleFailure,
    ResourceFailure,
} from './kernel.js';
import type { ParticipantKernel } from './kernel.js';
import { pendingCause } from './outcome.js';
import type {
    ParticipantPendingCause,
    ParticipantRefusalReason,
} from './outcome.js';
import {
    helperRole,
    listenAsHelper,
    startParallelHelpers,
} from './parallel.js';
import type { ParallelHelpers } from './parallel.js';
import { publishRecord, readBounded } from './public.js';
import type { PublicRelay } from './public.js';
import { decodeReleaseState, releasePhase } from './release-state.js';
import {
    advanceRelease,
    computeResult,
    publishRelease,
    resumeRelease,
} from './release.js';
import { authenticateRoot, dataKind, readDataKind } from './root.js';
import type { AuthenticatedRoot } from './root.js';
import {
    acceptRoster,
    parseRecordIds,
    proposeRoster,
    registrationFile,
    registrationPath,
    retainedProfile,
    reverifyRoster,
    signRoster,
} from './roster.js';
import { restoreSetup, retainSetup, verifySetup } from './setup.js';
import { stopParticipant } from './stop.js';
import {
    deleteWorkingStorage,
    namespacedName,
    openParticipantDatabase,
    participantNamespacePattern,
    StoragePending,
    storedRuntime,
} from './storage.js';
import { decodeTargetState, targetPhase } from './target-state.js';
import {
    certifiedBallotStatus,
    EvaluationRetained,
    publishTarget,
    signTarget,
} from './target.js';
import { verifyPublishedOutcome } from './verifier.js';

// The application's SDK supplies the namespace of the participant's local
// state, the relay's base URL, the module's URL and the identities its build
// recorded; the worker fetches the module itself and recomputes the runtime
// identity that every retained root binds. Every bound comes from the module and the retained
// state, never from the page. When the page separates evaluation, a worker
// that retains the target it evaluated before the operation's other work
// ends there, and the page runs the operation again in a fresh worker.
type WorkerCommand = Readonly<{
    operation: string;
    namespace: string;
    relay: string;
    module: string;
    identity: Readonly<{
        runtime: string;
        source: string;
        module: string;
        worker: string;
    }>;
    parameters: Readonly<Record<string, unknown>>;
    separateEvaluation?: boolean;
}>;

// An evaluated result reports the memory of a worker that retained the
// target it evaluated, and is never an operation's result. A refused result
// says why, and a participant that another runtime created is refused with
// that runtime's identity when its head names one. A pending result names
// what the participant waits for.
export type WorkerResult = Readonly<
    | { status: 'completed'; details: Readonly<Record<string, unknown>> }
    | {
          status: 'refused';
          reason: Exclude<ParticipantRefusalReason, 'another runtime'>;
      }
    | { status: 'refused'; reason: 'another runtime'; runtime?: string }
    | { status: 'pending'; cause: ParticipantPendingCause; reason: string }
    | {
          status: 'stopped';
          reason: string;
          stopPersistence: 'confirmed' | 'unconfirmed';
      }
    | { status: 'evaluated'; memory: OperationMemory }
>;

const maximumModuleBytes = 8_388_608;

// A refused request changed nothing.
const refused = (
    reason: Exclude<ParticipantRefusalReason, 'another runtime'>,
) => ({ status: 'refused', reason }) as const;

// The pinned delivery digest that gates executing the module, and the runtime
// identity derived from the delivered files' digests. Neither is an identity
// the participant binds into protocol or retained state.
const deliveryDigest = async (bytes: Uint8Array) =>
    new Uint8Array(
        await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
    );

const fetchModule = async (url: string, expected: string) => {
    const module = await readBounded(url, maximumModuleBytes);
    if (hexadecimal(await deliveryDigest(module)) !== expected)
        throw new PublicInputFailure('The participant module changed.');
    return module;
};

// An absolute HTTP or HTTPS URL in its canonical form.
const httpUrl = (value: unknown) => {
    if (typeof value !== 'string' || !URL.canParse(value)) return undefined;
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') &&
        url.href === value
        ? url
        : undefined;
};

// A base URL ends with a slash and has no query or fragment, so every
// record name extends its path.
const isBaseUrl = (value: unknown) => {
    const url = httpUrl(value);
    return (
        url !== undefined &&
        url.pathname.endsWith('/') &&
        url.search === '' &&
        url.hash === ''
    );
};

const isWellFormed = (command: WorkerCommand) =>
    typeof command.namespace === 'string' &&
    participantNamespacePattern.test(command.namespace) &&
    isBaseUrl(command.relay) &&
    httpUrl(command.module) !== undefined &&
    (command.separateEvaluation === undefined ||
        typeof command.separateEvaluation === 'boolean');

const runtimeIdentity = async (
    identity: WorkerCommand['identity'],
    module: Uint8Array,
) =>
    deliveryDigest(
        concatenate(
            encodeText(participantRuntimeLabel),
            fromHexadecimal(identity.source),
            await deliveryDigest(module),
            fromHexadecimal(identity.worker),
        ),
    );

const text = (value: unknown) => {
    if (typeof value !== 'string')
        throw new InvalidRequest('Malformed text parameter.');
    return value;
};

// Byte parameters cross the page boundary as lower-case hexadecimal; any
// other text is a malformed request, not a local fault.
const bytes = (value: unknown) => {
    const encoded = text(value);
    if (!/^(?:[0-9a-f]{2})*$/u.test(encoded))
        throw new InvalidRequest('Malformed byte parameter.');
    return fromHexadecimal(encoded);
};

// Publishes every public record the current root holds: the registration
// record, and the organizer's poll, proposal and proposal signature. The
// retained authority is inspected around every transfer.
const publishRecords = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
) => {
    const id = hexadecimal(enrollment.bodyDigest);
    const files: [number, string][] = [
        [dataKind.publicKey, registrationPath(id, registrationFile.publicKey)],
        [dataKind.proof, registrationPath(id, registrationFile.proof)],
        [dataKind.header, registrationPath(id, registrationFile.header)],
        [dataKind.signature, registrationPath(id, registrationFile.signature)],
    ];
    if (enrollment.isOrganizer) {
        files.push(
            [dataKind.pollDefinition, 'poll-definition.bin'],
            [dataKind.pollSignature, 'poll-signature.bin'],
        );
        if (root.head.generation >= 3)
            files.push(
                [dataKind.proposal, 'proposal.bin'],
                [dataKind.proposalSignature, 'proposal-signature.bin'],
            );
    }
    const delivery = await openDelivery(context, root);
    for (const [kind, name] of files) {
        const record = await readDataKind(context, root.manifest, kind);
        await delivery.transfer(() => publishRecord(relay, name, record));
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

// The own ballot's status in the certified target, which the target
// signing state retains from the evaluation on, and the release state of a
// participant that signed no target from its lock on. A participant that
// signed no target and locked no release retains none.
const ballotStatus = (
    root: AuthenticatedRoot,
    organizer: boolean,
    profiled: ProfileContext | undefined,
) => {
    const { generation } = root.head;
    const { target, release } = root.manifest.suffixes;
    if (profiled === undefined) return undefined;
    if (
        generation >= targetPhase.intent &&
        target !== undefined &&
        target.length !== 0
    )
        return decodeTargetState(
            profiled.profile,
            generation,
            organizer,
            target,
        ).ballotStatus;
    return generation < releasePhase.locked || release === undefined
        ? undefined
        : decodeReleaseState(profiled.profile, generation, organizer, release)
              .ballotStatus;
};

// Whether the participant contributes setup key material is known once its
// roster is retained.
const summary = (
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    profiled: ProfileContext | undefined,
) => ({
    generation: root.head.generation,
    rootHash: root.head.hash,
    poll: hexadecimal(root.manifest.poll),
    bodyDigest: hexadecimal(enrollment.bodyDigest),
    username: enrollment.username,
    isOrganizer: enrollment.isOrganizer,
    isSetupContributor:
        profiled === undefined ? undefined : isSetupContributor(profiled),
    ballot: ballotState(root),
    ballotStatus: ballotStatus(root, enrollment.isOrganizer, profiled),
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
                maximumParticipants: Number(parameters.maximumParticipants),
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
        else return refused('invalid request');
        const root = await createEnrollment(context, request, started);
        if (typeof root === 'string') return refused(root);
        const enrollment = await restoreEnrollment(context, root, true);
        return {
            status: 'completed',
            details: summary(root, enrollment, undefined),
        };
    }
    // An empty namespace holds no participant, and a participant that another
    // runtime created is that runtime's to continue: this worker cannot open
    // its root, so no authority starts, nothing is written and nothing can
    // stop.
    const stored = await storedRuntime(context.database);
    if (stored.status === 'empty') return refused('no participant');
    if (
        stored.status === 'named' &&
        stored.runtime !== hexadecimal(context.runtime)
    )
        return {
            status: 'refused',
            reason: 'another runtime',
            ...(stored.runtime === undefined
                ? {}
                : { runtime: stored.runtime }),
        };
    started();
    let root = await authenticateRoot(context);
    const enrollment = await restoreEnrollment(context, root, false);
    if (
        parameters.poll !== undefined &&
        parameters.poll !== hexadecimal(root.manifest.poll)
    )
        return refused('another poll');
    // The retained roster names the profile from generation two on; every
    // operation past the roster runs only at such a generation.
    const profiled =
        root.head.generation >= 2
            ? await retainedProfile(context, root, enrollment)
            : undefined;
    // What an operation reports beside the participant's summary.
    let reported: Readonly<Record<string, unknown>> = {};
    const profileContext = (): ProfileContext => {
        if (profiled === undefined)
            throw new Error('The participant profile is not known.');
        return profiled;
    };
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
                    return refused('invalid request');
                root = await signRoster(context, root, proposal);
                reported = { rosterUsernames: proposal.usernames };
            } else {
                const proposed = await proposeRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                    recordIds,
                );
                if (proposed === undefined) return refused('unavailable');
                root = proposed.root;
                reported = { rosterUsernames: proposed.usernames };
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
            if (accepted === undefined) return refused('unavailable');
            root = accepted.root;
            reported = { rosterUsernames: accepted.usernames };
            break;
        }
        case 'contribute': {
            // Only a setup contributor contributes. Generation and
            // continuation each draw their randomness from a seed retained
            // before they start, so an interrupted one runs again from its
            // seed once what it stored is discarded.
            const { generation } = root.head;
            if (
                generation < 3 ||
                generation >= 7 ||
                !isSetupContributor(profileContext())
            )
                return refused('unavailable');
            if (generation === 4 || generation === 6)
                await discardInterruptedRecords(profileContext(), root);
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
                        ? await beginContribution(
                              profileContext(),
                              root,
                              proposal,
                          )
                        : await resumeContribution(
                              profileContext(),
                              root,
                              proposal,
                          );
                await generateContribution(session);
            } else {
                session = await resumeContribution(profileContext(), root);
                await restoreCheckpoint(session, relay);
            }
            await continueContribution(session);
            root = session.root;
            break;
        }
        case 'confirm': {
            // Every participant confirms the roster once: a setup
            // contributor with its contribution, any other participant
            // with its own registration body.
            if (!isSetupContributor(profileContext())) {
                if (root.head.generation < 3) return refused('unavailable');
                const session = await resumeParticipant(profileContext(), root);
                const confirmation = await confirmRoster(session);
                root = session.root;
                await publishConfirmation(session, relay, confirmation);
                break;
            }
            if (root.head.generation < 7) return refused('unavailable');
            const session = await resumeContribution(profileContext(), root);
            const confirmation =
                root.head.generation >= 9
                    ? await storedConfirmation(session)
                    : await confirmContribution(session);
            root = session.root;
            await publishConfirmation(session, relay, confirmation);
            break;
        }
        case 'open': {
            if (
                root.head.generation < 9 ||
                !isSetupContributor(profileContext())
            )
                return refused('unavailable');
            const session = await resumeContribution(
                profileContext(),
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
            // A setup contributor verifies the setup behind its opening, and
            // any other participant behind its signed roster confirmation.
            if (
                profiled === undefined ||
                root.head.generation !== (isSetupContributor(profiled) ? 11 : 9)
            )
                return refused('unavailable');
            const session = await resumeParticipant(profiled, root);
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
            if (profiled === undefined || generation < 12)
                return refused('unavailable');
            const scores =
                parameters.scores === undefined
                    ? undefined
                    : parseBallotScores(profiled.profile, parameters.scores);
            if (
                (parameters.scores !== undefined && scores === undefined) ||
                (generation === 12 && scores === undefined)
            )
                return refused('invalid request');
            if (generation >= 17 && scores !== undefined)
                return refused('unavailable');
            const participant = await resumeParticipant(profileContext(), root);
            let session;
            if (scores !== undefined && generation === 12)
                session = await beginBallot(participant, scores);
            else {
                session = await resumeBallot(participant);
                if (session === undefined) return refused('unavailable');
                if (
                    scores !== undefined &&
                    !equalBytes(scores, session.state.scores)
                )
                    return refused('invalid request');
            }
            await completeBallot(session, relay);
            root = participant.root;
            await publishBallot(session, relay);
            // A ballot created in this visit reports the proof randomness
            // the module drew.
            if (session.proofRandomBytes !== undefined)
                reported = { proofRandomBytes: session.proofRandomBytes };
            break;
        }
        case 'close': {
            // Only the organizer opens the close, and only before an intent
            // and with no ballot attempt pending.
            const generation = root.head.generation;
            if (profiled === undefined || generation < 12)
                return refused('unavailable');
            const request = parseCloseRequest(
                profiled.profile,
                profiled.position,
                parameters,
            );
            if (
                request === undefined ||
                (request.closeTime !== undefined && !enrollment.isOrganizer)
            )
                return refused('invalid request');
            if (
                request.closeTime !== undefined &&
                generation !== 12 &&
                generation !== 17
            )
                return refused('unavailable');
            const participant = await resumeParticipant(profileContext(), root);
            const session = await resumeClose(
                participant,
                enrollment.isOrganizer,
            );
            if (!isCloseComplete(session)) {
                await restoreSetup(participant, relay);
                await advanceClose(session, relay, request);
            }
            root = participant.root;
            await publishClose(session, relay);
            return {
                status: 'completed',
                details: {
                    ...summary(root, enrollment, profiled),
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
                (generation >= releasePhase.locked &&
                    root.manifest.suffixes.target?.length === 0)
            )
                return refused('unavailable');
            const participant = await resumeParticipant(profileContext(), root);
            const session = await resumeClose(
                participant,
                enrollment.isOrganizer,
            );
            let signed = {};
            if (generation < targetPhase.signed) {
                await restoreSetup(participant, relay);
                signed = await signTarget(session, relay);
            }
            root = participant.root;
            await publishTarget(session, relay);
            return {
                status: 'completed',
                details: { ...summary(root, enrollment, profiled), ...signed },
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
                return refused('unavailable');
            const participant = await resumeParticipant(profileContext(), root);
            const session = await resumeRelease(
                await resumeClose(participant, enrollment.isOrganizer),
            );
            let released = {};
            if (generation < releasePhase.signed) {
                // A release continued from an earlier visit reports the
                // generation it resumed from.
                const resumed =
                    session.state === undefined
                        ? {}
                        : { resumedFrom: { generation } };
                await restoreSetup(participant, relay);
                const advanced = await advanceRelease(session, relay);
                // A release generated in this visit reports the proof
                // randomness the module drew.
                const { proofRandomBytes } = session;
                released = {
                    ...resumed,
                    predecessor: session.state?.predecessor,
                    ...advanced,
                    ...(proofRandomBytes === undefined
                        ? {}
                        : { proofRandomBytes }),
                };
            }
            root = participant.root;
            await publishRelease(session, relay);
            return {
                status: 'completed',
                details: {
                    ...summary(root, enrollment, profiled),
                    ...released,
                },
            };
        }
        case 'result': {
            // Any participant past its close combines the published release
            // shares in its own module; the result is not published.
            if (
                root.head.generation <
                completedClosePhase(enrollment.isOrganizer)
            )
                return refused('unavailable');
            const participant = await resumeParticipant(profileContext(), root);
            const session = await resumeClose(
                participant,
                enrollment.isOrganizer,
            );
            await restoreSetup(participant, relay);
            const result = await computeResult(session, relay);
            const summarized = summary(root, enrollment, profiled);
            return {
                status: 'completed',
                details: {
                    ...summarized,
                    // A participant that retains no status reads it from
                    // the target this visit certified.
                    ...(summarized.ballotStatus === undefined
                        ? {
                              ballotStatus: certifiedBallotStatus(
                                  participant.context,
                              ),
                          }
                        : {}),
                    ...result,
                },
            };
        }
        default:
            return refused('invalid request');
    }
    // A roster retained by this operation names the profile only now.
    return {
        status: 'completed',
        details: {
            ...summary(
                root,
                enrollment,
                profiled ??
                    (root.head.generation >= 2
                        ? await retainedProfile(context, root, enrollment)
                        : undefined),
            ),
            ...reported,
        },
    };
};

// The WebAssembly memory a completed operation held: the worker instance's
// linear memory and how far its allocations reached, and its helpers' and
// the shared arena's, beside the bounds of the operation's memory plan.
const operationMemory = (
    kernel: ParticipantKernel,
    helpers: ParallelHelpers,
    evaluation: boolean,
) => ({
    workerBytes: kernel.memory.buffer.byteLength,
    workerUsedBytes: kernel.linear_memory_high_water() >>> 0,
    workerBoundBytes:
        kernel.worker_memory_bound(helpers.count, evaluation ? 1 : 0) >>> 0,
    helpers: helpers.count,
    helperBoundBytes:
        kernel.helper_memory_bound(helpers.count, evaluation ? 1 : 0) >>> 0,
    ...helpers.memory(),
});
type OperationMemory = ReturnType<typeof operationMemory>;

// The operations that evaluate the ranking program, whose helpers keep the
// evaluation's tables and the polynomials its multiplications keep.
const evaluatingOperations: ReadonlySet<string> = new Set([
    'target',
    'release',
    'result',
]);

const run = async (
    command: WorkerCommand,
    helperPorts: readonly MessagePort[],
): Promise<WorkerResult> => {
    if (
        !isSecureContext ||
        typeof navigator.locks !== 'object' ||
        typeof crypto.subtle !== 'object' ||
        typeof indexedDB !== 'object'
    )
        return refused('unsupported browser');
    if (!isWellFormed(command)) return refused('invalid request');
    const relay: PublicRelay = { base: command.relay };
    let database: IDBDatabase | undefined;
    let helpers: ParallelHelpers | undefined;
    let authorityStarted = false;
    try {
        const moduleBytes = await fetchModule(
            command.module,
            command.identity.module,
        );
        const runtime = await runtimeIdentity(command.identity, moduleBytes);
        if (hexadecimal(runtime) !== command.identity.runtime)
            return refused('runtime mismatch');
        const module = await WebAssembly.compile(new Uint8Array(moduleBytes));
        const evaluation = evaluatingOperations.has(command.operation);
        const started = startParallelHelpers(module, helperPorts, evaluation);
        database = await openParticipantDatabase(command.namespace);
        helpers = await started;
        const opened = database;
        const parallel = helpers;
        return await navigator.locks.request(
            namespacedName('sealed-lattice-participant', command.namespace),
            async (): Promise<WorkerResult> => {
                let kernel: ParticipantKernel | undefined;
                try {
                    const instance = await instantiateParticipantKernel(
                        module,
                        parallel,
                    );
                    kernel = instance.kernel;
                    // The worker's share of the operation's memory plan,
                    // whose other shares the started helpers hold, bounds
                    // its instance before the first allocation.
                    if (
                        kernel.worker_reserve(
                            parallel.count,
                            evaluation ? 1 : 0,
                        ) !== 0
                    )
                        throw new Error(
                            'The participant module refused its memory plan.',
                        );
                    const result = await execute(
                        {
                            namespace: command.namespace,
                            database: opened,
                            kernel,
                            handlers: instance.handlers,
                            parallel,
                            runtime,
                            limits: readParticipantLimits(kernel),
                            separateEvaluation:
                                command.separateEvaluation === true,
                        },
                        relay,
                        command,
                        () => {
                            authorityStarted = true;
                        },
                    );
                    return result.status === 'completed'
                        ? {
                              status: 'completed',
                              details: {
                                  ...result.details,
                                  memory: operationMemory(
                                      kernel,
                                      parallel,
                                      evaluation,
                                  ),
                              },
                          }
                        : result;
                } catch (error) {
                    // The worker's memory, and its helpers', ends with them,
                    // so the page runs the rest of an operation that
                    // retained the target it evaluated in fresh ones.
                    if (
                        error instanceof EvaluationRetained &&
                        kernel !== undefined
                    )
                        return {
                            status: 'evaluated',
                            memory: operationMemory(
                                kernel,
                                parallel,
                                evaluation,
                            ),
                        };
                    // A malformed request is refused before the operation
                    // changes anything.
                    if (error instanceof InvalidRequest)
                        return refused('invalid request');
                    // A local failure after authority started stops the
                    // participant before any other operation takes the lock.
                    // A failed helper, an exhausted memory bound and a module
                    // call that ended without returning touch no retained
                    // state and leave the participant pending.
                    if (
                        !authorityStarted ||
                        error instanceof PublicInputFailure ||
                        error instanceof StoragePending ||
                        error instanceof ResourceFailure ||
                        error instanceof ModuleFailure
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
        // Public input, pending storage, resource and module failures and
        // failures before authority started leave the participant pending.
        return {
            status: 'pending',
            cause: pendingCause(error),
            reason: error instanceof Error ? error.message : String(error),
        };
    } finally {
        helpers?.stop();
        database?.close();
    }
};

// A verification of a poll's outcome from the relay's public records alone,
// in a fresh worker that holds no participant state. The page names the
// poll's identity, and the module refuses a poll of another runtime.
type VerificationCommand = Readonly<{
    operation: 'verify-outcome';
    poll: string;
    relay: string;
    module: string;
    identity: WorkerCommand['identity'];
}>;

const isVerification = (
    command: WorkerCommand | VerificationCommand,
): command is VerificationCommand => command.operation === 'verify-outcome';

const isWellFormedVerification = (command: VerificationCommand) =>
    typeof command.poll === 'string' &&
    /^[0-9a-f]{128}$/u.test(command.poll) &&
    isBaseUrl(command.relay) &&
    httpUrl(command.module) !== undefined;

// A verification's public working storage, named apart from every
// participant's, since no participant namespace has a full stop.
const verificationNamespace = (poll: string) => 'verification.' + poll;

const runVerification = async (
    command: VerificationCommand,
    helperPorts: readonly MessagePort[],
): Promise<WorkerResult> => {
    if (
        !isSecureContext ||
        typeof navigator.locks !== 'object' ||
        typeof crypto.subtle !== 'object' ||
        typeof indexedDB !== 'object'
    )
        return refused('unsupported browser');
    if (!isWellFormedVerification(command)) return refused('invalid request');
    let helpers: ParallelHelpers | undefined;
    try {
        const moduleBytes = await fetchModule(
            command.module,
            command.identity.module,
        );
        const runtime = await runtimeIdentity(command.identity, moduleBytes);
        if (hexadecimal(runtime) !== command.identity.runtime)
            return refused('runtime mismatch');
        const module = await WebAssembly.compile(new Uint8Array(moduleBytes));
        helpers = await startParallelHelpers(module, helperPorts, true);
        const parallel = helpers;
        const namespace = verificationNamespace(command.poll);
        return await navigator.locks.request(
            namespacedName('sealed-lattice-verification', namespace),
            async (): Promise<WorkerResult> => {
                const { kernel, handlers } = await instantiateParticipantKernel(
                    module,
                    parallel,
                );
                if (kernel.worker_reserve(parallel.count, 1) !== 0)
                    throw new Error(
                        'The participant module refused its memory plan.',
                    );
                try {
                    const outcome = await verifyPublishedOutcome(
                        {
                            namespace,
                            kernel,
                            handlers,
                            parallel,
                            runtime,
                            limits: readParticipantLimits(kernel),
                        },
                        { base: command.relay },
                        fromHexadecimal(command.poll),
                    );
                    return {
                        status: 'completed',
                        details: {
                            poll: command.poll,
                            ...outcome,
                            memory: operationMemory(kernel, parallel, true),
                        },
                    };
                } finally {
                    await deleteWorkingStorage(namespace);
                }
            },
        );
    } catch (error) {
        return {
            status: 'pending',
            cause: pendingCause(error),
            reason: error instanceof Error ? error.message : String(error),
        };
    } finally {
        helpers?.stop();
    }
};

self.onmessage = (
    event: MessageEvent<
        WorkerCommand | VerificationCommand | typeof helperRole
    >,
) => {
    if (event.data === helperRole) {
        self.onmessage = null;
        listenAsHelper(event.ports[0]);
        self.postMessage(true);
        return;
    }
    const command = event.data;
    void (
        isVerification(command)
            ? runVerification(command, event.ports)
            : run(command, event.ports)
    ).then(
        (result) => self.postMessage(result),
        (error: unknown) =>
            self.postMessage({
                status: 'pending',
                cause: pendingCause(error),
                reason: error instanceof Error ? error.message : String(error),
            }),
    );
};
