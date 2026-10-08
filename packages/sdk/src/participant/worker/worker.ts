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
    parseCloseParameters,
    publishClose,
    resumeClose,
} from './close.js';
import { isEligibleContributor } from './context.js';
import type { ParticipantContext, ProfileContext } from './context.js';
import {
    beginContribution,
    confirmRoster,
    continueContribution,
    generateContribution,
    isContributionSession,
    publishOffer,
    restoreCheckpoint,
    resumeParticipant,
    signContribution,
} from './contribution.js';
import { createEnrollment, restoreEnrollment } from './enrollment.js';
import type { EnrollmentRequest, RestoredEnrollment } from './enrollment.js';
import {
    classifyFailure,
    InvalidRequest,
    pendingCause,
    PublicInputFailure,
} from './failures.js';
import { participantRuntimeLabel } from './identity.js';
import {
    instantiateParticipantKernel,
    requireInputCapacities,
} from './kernel.js';
import type { ParticipantKernel } from './kernel.js';
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
import { endorseSetup, selectSetup } from './preparation-selection.js';
import { readBounded } from './public.js';
import type { PublicRelay } from './public.js';
import { publishRegistrationRecords } from './registration-publication.js';
import { decodeReleaseState } from './release-state.js';
import {
    advanceRelease,
    computeResult,
    publishRelease,
    resumeRelease,
} from './release.js';
import {
    ballotPhase,
    releasePhase,
    rootGeneration,
    targetPhase,
} from './root-generation.js';
import { authenticateRoot } from './root.js';
import type { AuthenticatedRoot } from './root.js';
import {
    acceptRoster,
    parseRegistrationBodyDigests,
    proposeRoster,
    retainedProfile,
    reverifyRoster,
    signRoster,
} from './roster.js';
import { restoreSetup, retainSetup, verifySetup } from './setup.js';
import { stopParticipant } from './stop.js';
import type { StopPersistence } from './stop.js';
import {
    deleteWorkingStorage,
    namespacedName,
    openParticipantDatabase,
    participantNamespacePattern,
    storedRuntime,
} from './storage.js';
import { decodeTargetState } from './target-state.js';
import {
    certifiedBallotInclusion,
    EvaluationRetained,
    largestBufferInputBytes,
    publishTarget,
    signTarget,
} from './target.js';
import { verifyPublishedOutcome } from './verifier.js';

// The application's SDK supplies the namespace of the participant's local
// state, the relay's base URL, the module's URL and the identities its build
// recorded; the worker fetches the module itself and recomputes the runtime
// identity that every retained root binds. Protocol bounds come from the
// verified module and retained state, never from the page. When the page separates evaluation, a worker
// that retains the target it evaluated before the operation's other work
// ends there, and the page runs the operation again in a fresh worker.
type WorkerCommand = Readonly<{
    operation: string;
    namespace: string;
    relay: string;
    module: string;
    identity: Readonly<{
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
// that runtime's identity, which its head names. A pending result names what
// the participant waits for.
export type WorkerResult = Readonly<
    | { status: 'completed'; details: Readonly<Record<string, unknown>> }
    | {
          status: 'refused';
          reason: Exclude<ParticipantRefusalReason, 'another runtime'>;
      }
    | { status: 'refused'; reason: 'another runtime'; runtime: string }
    | { status: 'pending'; cause: ParticipantPendingCause; detail: string }
    | {
          status: 'stopped';
          detail: string;
          stopPersistence: StopPersistence;
      }
    | { status: 'evaluated'; memory: OperationMemory }
>;

const maximumModuleBytes = 8_388_608;

// A refused request changed nothing.
const refused = (
    reason: Exclude<ParticipantRefusalReason, 'another runtime'>,
) => ({ status: 'refused', reason }) as const;

// The pinned module digest gates execution. The runtime identity combines it
// with the pinned source and worker digests and binds protocol contexts and
// retained state; it is distinct from module-owned protocol object identities.
const deliveryDigest = async (bytes: Uint8Array<ArrayBuffer>) =>
    new Uint8Array(await crypto.subtle.digest('SHA-512', bytes));

const fetchModule = async (url: string, expected: string) => {
    const bytes = await readBounded(url, maximumModuleBytes);
    const digest = await deliveryDigest(bytes);
    if (hexadecimal(digest) !== expected)
        throw new PublicInputFailure('The participant module changed.');
    return { bytes, digest };
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
    moduleDigest: Uint8Array<ArrayBuffer>,
) =>
    deliveryDigest(
        concatenate(
            encodeText(participantRuntimeLabel),
            fromHexadecimal(identity.source),
            moduleDigest,
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

// What this participant's ballot is: open once the verified setup is
// retained, in progress from the attempt lock, signed, or impossible once the
// participant learned that ballot submission closed without a ballot of its
// own.
const ballotState = (root: AuthenticatedRoot) => {
    const { generation } = root.head;
    if (generation < rootGeneration.setupRetained) return undefined;
    if (generation === rootGeneration.setupRetained) return 'open';
    if (generation < ballotPhase.signed) return 'in progress';
    return (root.manifest.suffixes.ballot?.length ?? 0) > 0
        ? 'signed'
        : 'could not vote';
};

// The own ballot's status in the certified target, which the target
// signing state retains from the evaluation on, and the release state of a
// participant that signed no target from its lock on. A participant that
// signed no target and locked no release retains none.
const ballotInclusion = (
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
        ).ballotInclusion;
    return generation < releasePhase.locked || release === undefined
        ? undefined
        : decodeReleaseState(profiled.profile, generation, organizer, release)
              .ballotInclusion;
};

// Whether the participant contributes setup key material is known once its
// roster is retained.
const summary = (
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    profiled: ProfileContext | undefined,
) => ({
    generation: root.head.generation,
    poll: hexadecimal(root.manifest.poll),
    registrationBodyDigest: hexadecimal(enrollment.registrationBodyDigest),
    username: enrollment.username,
    isOrganizer: enrollment.isOrganizer,
    question: enrollment.poll.question,
    options: enrollment.poll.options,
    topCount: enrollment.poll.topCount,
    isEligibleContributor:
        profiled === undefined ? undefined : isEligibleContributor(profiled),
    ballotState: ballotState(root),
    ballotInclusion: ballotInclusion(root, enrollment.isOrganizer, profiled),
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
        if (role === 'organizer') {
            const { options } = parameters;
            if (!Array.isArray(options))
                throw new InvalidRequest('Malformed option labels.');
            request = {
                role,
                question: text(parameters.question),
                options: (options as unknown[]).map((label) => text(label)),
                topCount: Number(parameters.topCount),
                maximumParticipants: Number(parameters.maximumParticipants),
                username: text(parameters.username),
            };
        } else if (role === 'joiner')
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
            runtime: stored.runtime,
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
        root.head.generation >= rootGeneration.rosterLocked
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
            if (root.head.generation === rootGeneration.preparation)
                await resumeParticipant(profileContext(), root);
            await publishRegistrationRecords(context, relay, root, enrollment);
            break;
        case 'propose-roster': {
            const registrationBodyDigests = parseRegistrationBodyDigests(
                parameters.registrationBodyDigests,
            );
            if (root.head.generation === rootGeneration.rosterLocked) {
                const proposal = await reverifyRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                );
                if (
                    proposal.registrationBodyDigests.join(',') !==
                    registrationBodyDigests.join(',')
                )
                    return refused('invalid request');
                root = await signRoster(context, root, proposal);
                reported = { rosterUsernames: proposal.usernames };
            } else {
                const proposed = await proposeRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                    registrationBodyDigests,
                );
                if (proposed === undefined)
                    return refused('unavailable operation');
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
                parseRegistrationBodyDigests(
                    parameters.registrationBodyDigests,
                ),
            );
            if (accepted === undefined) return refused('unavailable operation');
            root = accepted.root;
            reported = { rosterUsernames: accepted.usernames };
            break;
        }
        case 'confirm': {
            if (
                root.head.generation !== rootGeneration.rosterSigned &&
                root.head.generation !== rootGeneration.preparation
            )
                return refused('unavailable operation');
            const session = await resumeParticipant(profileContext(), root);
            await confirmRoster(session);
            root = session.root;
            break;
        }
        case 'contribute': {
            if (
                root.head.generation !== rootGeneration.preparation ||
                !isEligibleContributor(profileContext())
            )
                return refused('unavailable operation');
            let session = await resumeParticipant(profileContext(), root);
            if (session.state === undefined || session.state.phase === 4) {
                const proposal = await reverifyRoster(
                    context,
                    relay,
                    root,
                    enrollment,
                );
                if (
                    !equalBytes(proposal.identity, session.records.proposal) ||
                    proposal.position !== session.records.position ||
                    context.kernel.confirm_roster() !== 0
                )
                    throw new Error('The verified original roster changed.');
                if (!isContributionSession(session))
                    session = await beginContribution(session);
                if (!isContributionSession(session))
                    throw new Error('No offer intent is retained.');
                await generateContribution(session);
            } else if (session.state.phase === 5 || session.state.phase === 6) {
                if (!isContributionSession(session))
                    throw new Error('No own proof checkpoint is retained.');
                await restoreCheckpoint(session, relay);
            }
            if (!isContributionSession(session))
                throw new Error('No own offer is retained.');
            if (session.state.phase === 5 || session.state.phase === 6)
                await continueContribution(session);
            const offer = await signContribution(session);
            root = session.root;
            await publishOffer(session, relay, offer);
            break;
        }
        case 'select-setup': {
            if (
                root.head.generation !== rootGeneration.preparation ||
                !enrollment.isOrganizer
            )
                return refused('unavailable operation');
            const session = await resumeParticipant(profileContext(), root);
            await selectSetup(session, relay);
            root = session.root;
            break;
        }
        case 'endorse-setup': {
            if (root.head.generation !== rootGeneration.preparation)
                return refused('unavailable operation');
            const session = await resumeParticipant(profileContext(), root);
            await endorseSetup(session, relay);
            root = session.root;
            break;
        }
        case 'verify-setup': {
            // Any original member may activate the uniquely certified setup.
            if (
                profiled === undefined ||
                root.head.generation !== rootGeneration.preparation
            )
                return refused('unavailable operation');
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
        case 'cast-ballot': {
            // Generation twelve starts an attempt with the requested scores.
            // A retained attempt continues only with its locked scores, and a
            // signed ballot is only delivered again, also after an intent.
            const generation = root.head.generation;
            if (
                profiled === undefined ||
                generation < rootGeneration.setupRetained
            )
                return refused('unavailable operation');
            const scores =
                parameters.scores === undefined
                    ? undefined
                    : parseBallotScores(profiled.profile, parameters.scores);
            if (
                (parameters.scores !== undefined && scores === undefined) ||
                (generation === rootGeneration.setupRetained &&
                    scores === undefined)
            )
                return refused('invalid request');
            if (generation >= ballotPhase.signed && scores !== undefined)
                return refused('unavailable operation');
            const participant = await resumeParticipant(profileContext(), root);
            let session;
            if (
                scores !== undefined &&
                generation === rootGeneration.setupRetained
            )
                session = await beginBallot(participant, scores);
            else {
                session = await resumeBallot(participant);
                if (session === undefined)
                    return refused('unavailable operation');
                if (
                    scores !== undefined &&
                    !equalBytes(scores, session.state.scores)
                )
                    return refused('invalid request');
            }
            await completeBallot(session, relay);
            root = participant.root;
            await publishBallot(session, relay);
            // A ballot created in this operation reports the proof randomness
            // the module drew.
            if (session.proofRandomBytes !== undefined)
                reported = { proofRandomBytes: session.proofRandomBytes };
            break;
        }
        case 'close': {
            // Only the organizer opens the close, and only before an intent
            // and with no ballot attempt pending.
            const generation = root.head.generation;
            if (
                profiled === undefined ||
                generation < rootGeneration.setupRetained
            )
                return refused('unavailable operation');
            const request = parseCloseParameters(parameters);
            if (
                request === undefined ||
                (request.closeTime !== undefined && !enrollment.isOrganizer)
            )
                return refused('invalid request');
            if (
                request.closeTime !== undefined &&
                generation !== rootGeneration.setupRetained &&
                generation !== ballotPhase.signed
            )
                return refused('unavailable operation');
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
        case 'sign-target': {
            // Target signing follows the completed close; a signed vote is
            // only delivered again. A release that followed the completed
            // close spent the target purpose without a vote.
            const generation = root.head.generation;
            if (
                generation < completedClosePhase(enrollment.isOrganizer) ||
                (generation >= releasePhase.locked &&
                    root.manifest.suffixes.target?.length === 0)
            )
                return refused('unavailable operation');
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
            // already exists; a pending target vote cannot be
            // bypassed. A signed release is only delivered again.
            const generation = root.head.generation;
            if (
                generation !== completedClosePhase(enrollment.isOrganizer) &&
                generation < targetPhase.signed
            )
                return refused('unavailable operation');
            const participant = await resumeParticipant(profileContext(), root);
            const session = await resumeRelease(
                await resumeClose(participant, enrollment.isOrganizer),
            );
            let released = {};
            if (generation < releasePhase.signed) {
                // A release continued from an earlier operation reports the
                // generation it resumed from.
                const resumed =
                    session.state === undefined
                        ? {}
                        : { resumedFrom: { generation } };
                await restoreSetup(participant, relay);
                const advanced = await advanceRelease(session, relay);
                // A release generated in this operation reports the proof
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
        case 'compute-result': {
            // Any participant past its close combines the published release
            // shares in its own module; the result is not published.
            if (
                root.head.generation <
                completedClosePhase(enrollment.isOrganizer)
            )
                return refused('unavailable operation');
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
                    // the target this operation certified.
                    ...(summarized.ballotInclusion === undefined
                        ? {
                              ballotInclusion: certifiedBallotInclusion(
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
                    (root.head.generation >= rootGeneration.rosterLocked
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
    'sign-target',
    'release',
    'compute-result',
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
        const delivered = await fetchModule(
            command.module,
            command.identity.module,
        );
        const runtime = await runtimeIdentity(
            command.identity,
            delivered.digest,
        );
        const module = await WebAssembly.compile(delivered.bytes);
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
                    requireInputCapacities(
                        kernel,
                        largestBufferInputBytes(kernel),
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
                    // changes anything. A local failure after authority
                    // started stops the participant before any other
                    // operation takes the lock. A failed helper, an exhausted
                    // memory bound and a module call that ended without
                    // returning touch no retained state and leave the
                    // participant pending. Enrollment converts failures after
                    // its intent but before retaining its secrets into local
                    // state loss instead.
                    const outcome = classifyFailure(error, authorityStarted);
                    if (outcome.status === 'refused')
                        return refused(outcome.reason);
                    if (outcome.status === 'pending') throw error;
                    const stopPersistence = await stopParticipant(opened);
                    return {
                        status: 'stopped',
                        detail:
                            error instanceof Error
                                ? error.message
                                : String(error),
                        stopPersistence,
                    };
                }
            },
        );
    } catch (error) {
        // An unrecognized participant database is refused before anything is
        // written to it. Public input, pending storage, resource and module
        // failures and failures before authority started leave the
        // participant pending.
        const outcome = classifyFailure(error, false);
        if (outcome.status === 'refused') return refused(outcome.reason);
        return {
            status: 'pending',
            cause: pendingCause(error),
            detail: error instanceof Error ? error.message : String(error),
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
        const delivered = await fetchModule(
            command.module,
            command.identity.module,
        );
        const runtime = await runtimeIdentity(
            command.identity,
            delivered.digest,
        );
        const module = await WebAssembly.compile(delivered.bytes);
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
                requireInputCapacities(kernel, largestBufferInputBytes(kernel));
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
            detail: error instanceof Error ? error.message : String(error),
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
                detail: error instanceof Error ? error.message : String(error),
            }),
    );
};
