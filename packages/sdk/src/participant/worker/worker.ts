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
import { isSetupContributor, PublicInputFailure } from './context.js';
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
import { instantiateParticipantKernel, ResourceFailure } from './kernel.js';
import type { ParticipantKernel } from './kernel.js';
import {
    helperRole,
    listenAsHelper,
    startParallelHelpers,
} from './parallel.js';
import type { ParallelHelpers } from './parallel.js';
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
    retainedProfile,
    reverifyRoster,
    signRoster,
} from './roster.js';
import { restoreSetup, retainSetup, verifySetup } from './setup.js';
import { stopParticipant } from './stop.js';
import {
    isEmptyParticipant,
    namespacedName,
    openParticipantDatabase,
    participantNamespacePattern,
} from './storage.js';
import { targetPhase } from './target-state.js';
import { EvaluationRetained, publishTarget, signTarget } from './target.js';
import {
    createTranscriptRecorder,
    discoverTranscripts,
    openArchive,
    openTranscriptSource,
} from './transcript.js';
import type { ArchivedTranscript, WorkerArchive } from './transcript.js';

// The application's SDK supplies the namespace of the participant's local
// state, the relay's base URL, the module's URL, the identities its build
// recorded and, when the application configures one, the archive; the worker
// fetches the module itself and recomputes the runtime identity that every
// retained root binds. Every bound comes from the module and the retained
// state, never from the page. When the page separates evaluation, a worker
// that retains the target it evaluated before the operation's other work
// ends there, and the page runs the operation again in a fresh worker.
type WorkerCommand = Readonly<{
    operation: string;
    namespace: string;
    relay: string;
    module: string;
    archive?: WorkerArchive;
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
// target it evaluated, and is never an operation's result.
export type WorkerResult = Readonly<
    | { status: 'completed'; details: Readonly<Record<string, unknown>> }
    | { status: 'refused' }
    | { status: 'pending'; reason: string }
    | {
          status: 'stopped';
          reason: string;
          stopPersistence: 'confirmed' | 'unconfirmed';
      }
    | { status: 'evaluated'; memory: OperationMemory }
>;

const maximumModuleBytes = 8_388_608;

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

// An archive names its fault bound, 1 to 32 replicas with their ML-DSA-65
// verification keys, and the foundation kernel with its SHA-256 digest.
const isArchive = (archive: unknown) => {
    if (archive === undefined) return true;
    if (typeof archive !== 'object' || archive === null) return false;
    const { faultBound, replicas, kernel, kernelSha256 } = archive as Record<
        string,
        unknown
    >;
    return (
        Number.isSafeInteger(faultBound) &&
        (faultBound as number) >= 0 &&
        Array.isArray(replicas) &&
        replicas.length >= 1 &&
        replicas.length <= 32 &&
        replicas.every((replica: unknown) => {
            if (typeof replica !== 'object' || replica === null) return false;
            const { baseUrl, verificationKey } = replica as Record<
                string,
                unknown
            >;
            return (
                isBaseUrl(baseUrl) &&
                typeof verificationKey === 'string' &&
                /^[0-9a-f]{3904}$/u.test(verificationKey)
            );
        }) &&
        httpUrl(kernel) !== undefined &&
        typeof kernelSha256 === 'string' &&
        /^[0-9a-f]{64}$/u.test(kernelSha256)
    );
};

const isWellFormed = (command: WorkerCommand) =>
    typeof command.namespace === 'string' &&
    participantNamespacePattern.test(command.namespace) &&
    isBaseUrl(command.relay) &&
    httpUrl(command.module) !== undefined &&
    isArchive(command.archive) &&
    (command.separateEvaluation === undefined ||
        typeof command.separateEvaluation === 'boolean');

const runtimeIdentity = async (command: WorkerCommand, module: Uint8Array) =>
    deliveryDigest(
        concatenate(
            encodeText(participantRuntimeLabel),
            fromHexadecimal(command.identity.source),
            await deliveryDigest(module),
            fromHexadecimal(command.identity.worker),
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

// An archived transcript's index: its identity and its record's length.
const transcriptReference = (value: unknown) => {
    if (typeof value !== 'object' || value === null)
        throw new PublicInputFailure('Malformed transcript parameter.');
    const { identity, byteLength } = value as Record<string, unknown>;
    if (
        typeof identity !== 'string' ||
        !/^[0-9a-f]{128}$/u.test(identity) ||
        !Number.isSafeInteger(byteLength) ||
        (byteLength as number) < 1 ||
        (byteLength as number) > 1_572_864
    )
        throw new PublicInputFailure('Malformed transcript parameter.');
    return { identity, byteLength: byteLength as number };
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
        return {
            status: 'completed',
            details: summary(root, enrollment, undefined),
        };
    }
    // An empty namespace holds no participant, so no authority starts and
    // nothing can stop.
    if (await isEmptyParticipant(context.database))
        return { status: 'refused' };
    started();
    let root = await authenticateRoot(context);
    const enrollment = await restoreEnrollment(context, root, false);
    if (
        parameters.poll !== undefined &&
        parameters.poll !== hexadecimal(root.manifest.poll)
    )
        return { status: 'refused' };
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
                return { status: 'refused' };
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
                if (root.head.generation < 3) return { status: 'refused' };
                const session = await resumeParticipant(profileContext(), root);
                const confirmation = await confirmRoster(session);
                root = session.root;
                await publishConfirmation(session, relay, confirmation);
                break;
            }
            if (root.head.generation < 7) return { status: 'refused' };
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
                return { status: 'refused' };
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
                return { status: 'refused' };
            const session = await resumeParticipant(profiled, root);
            const recorder =
                command.archive === undefined
                    ? undefined
                    : createTranscriptRecorder(
                          await openArchive(
                              command.archive,
                              hexadecimal(root.manifest.poll),
                          ),
                      );
            const verified = await verifySetup(
                session,
                recorder === undefined ? relay : { ...relay, recorder },
            );
            // The index is retained only after the owning verifier accepted
            // every recorded input and the replicas retained the closure.
            const setupArchive = await recorder?.archive();
            root = await retainSetup(
                session,
                verified,
                setupArchive?.transcript,
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
                parameters.scores === undefined || profiled === undefined
                    ? undefined
                    : parseBallotScores(profiled.profile, parameters.scores);
            if (
                generation < 12 ||
                (parameters.scores !== undefined && scores === undefined) ||
                (generation === 12 && scores === undefined) ||
                (generation >= 17 && scores !== undefined)
            )
                return { status: 'refused' };
            const participant = await resumeParticipant(profileContext(), root);
            let session;
            if (scores !== undefined && generation === 12)
                session = await beginBallot(participant, scores);
            else {
                session = await resumeBallot(participant);
                if (
                    session === undefined ||
                    (scores !== undefined &&
                        !equalBytes(scores, session.state.scores))
                )
                    return { status: 'refused' };
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
            const request =
                profiled === undefined
                    ? undefined
                    : parseCloseRequest(profiled.profile, parameters);
            const generation = root.head.generation;
            if (
                request === undefined ||
                generation < 12 ||
                (request.closeTime !== undefined &&
                    (!enrollment.isOrganizer ||
                        (generation !== 12 && generation !== 17)))
            )
                return { status: 'refused' };
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
                return { status: 'refused' };
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
            // bypassed. With an archive, the visit that certifies the target
            // before any release randomness first archives the certified
            // target closure it read, as one transcript that more replicas
            // than the fault bound acknowledge; a visit may instead read an
            // archived closure the request names. A signed release is only
            // delivered again.
            const generation = root.head.generation;
            if (
                (generation !== completedClosePhase(enrollment.isOrganizer) &&
                    generation < targetPhase.signed) ||
                (parameters.transcript !== undefined &&
                    (command.archive === undefined ||
                        generation >= releasePhase.signed))
            )
                return { status: 'refused' };
            const archiving =
                parameters.transcript === undefined &&
                generation < releasePhase.locked;
            const archive =
                command.archive === undefined ||
                (!archiving && parameters.transcript === undefined)
                    ? undefined
                    : await openArchive(
                          command.archive,
                          hexadecimal(root.manifest.poll),
                      );
            const recorder =
                archive === undefined || !archiving
                    ? undefined
                    : createTranscriptRecorder(archive);
            const source: PublicRelay =
                archive !== undefined && parameters.transcript !== undefined
                    ? {
                          ...relay,
                          transcript: await openTranscriptSource(
                              archive,
                              transcriptReference(parameters.transcript),
                          ),
                      }
                    : recorder === undefined
                      ? relay
                      : { ...relay, recorder };
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
                await restoreSetup(participant, source);
                let closure: ArchivedTranscript | undefined;
                const encrypted = await advanceRelease(
                    session,
                    source,
                    recorder === undefined
                        ? undefined
                        : async () => {
                              closure = await recorder.archive();
                          },
                );
                // A release generated in this visit reports the proof
                // randomness the module drew.
                const { proofRandomBytes } = session;
                released = {
                    ...resumed,
                    predecessor: session.state?.predecessor,
                    encrypted,
                    ...(closure === undefined ? {} : { closure }),
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
        case 'result':
        case 'archive': {
            // Any participant past its close combines the published release
            // shares in its own module; the result is not published. The
            // visit reads the relay or the archived transcript the request
            // names, and archiving sends every record it reads to the
            // replicas as one transcript, acknowledged once verified.
            if (
                root.head.generation <
                    completedClosePhase(enrollment.isOrganizer) ||
                (parameters.transcript !== undefined &&
                    command.operation === 'archive')
            )
                return { status: 'refused' };
            const archived =
                command.operation === 'archive' ||
                parameters.transcript !== undefined;
            if (archived && command.archive === undefined)
                return { status: 'refused' };
            const archive =
                command.archive === undefined || !archived
                    ? undefined
                    : await openArchive(
                          command.archive,
                          hexadecimal(root.manifest.poll),
                      );
            const recorder =
                archive === undefined || command.operation !== 'archive'
                    ? undefined
                    : createTranscriptRecorder(archive);
            const source: PublicRelay =
                archive !== undefined && parameters.transcript !== undefined
                    ? {
                          ...relay,
                          transcript: await openTranscriptSource(
                              archive,
                              transcriptReference(parameters.transcript),
                          ),
                      }
                    : recorder === undefined
                      ? relay
                      : { ...relay, recorder };
            const participant = await resumeParticipant(profileContext(), root);
            const session = await resumeClose(
                participant,
                enrollment.isOrganizer,
            );
            await restoreSetup(participant, source);
            const result = await computeResult(session, source);
            const transcript =
                recorder === undefined ? undefined : await recorder.archive();
            return {
                status: 'completed',
                details: {
                    ...summary(root, enrollment, profiled),
                    ...result,
                    ...transcript,
                },
            };
        }
        case 'transcripts': {
            // The transcripts the archive holds for the poll are hints for a
            // later result visit, which verifies whichever it reads.
            if (command.archive === undefined) return { status: 'refused' };
            return {
                status: 'completed',
                details: {
                    ...summary(root, enrollment, profiled),
                    transcripts: await discoverTranscripts(
                        await openArchive(
                            command.archive,
                            hexadecimal(root.manifest.poll),
                        ),
                    ),
                },
            };
        }
        default:
            return { status: 'refused' };
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
    'archive',
]);

const run = async (
    command: WorkerCommand,
    helperPorts: readonly MessagePort[],
): Promise<WorkerResult> => {
    if (
        !isSecureContext ||
        typeof navigator.locks !== 'object' ||
        typeof crypto.subtle !== 'object' ||
        typeof indexedDB !== 'object' ||
        !isWellFormed(command)
    )
        return { status: 'refused' };
    const relay: PublicRelay = { base: command.relay };
    let database: IDBDatabase | undefined;
    let helpers: ParallelHelpers | undefined;
    let authorityStarted = false;
    try {
        const moduleBytes = await fetchModule(
            command.module,
            command.identity.module,
        );
        const runtime = await runtimeIdentity(command, moduleBytes);
        if (hexadecimal(runtime) !== command.identity.runtime)
            return { status: 'refused' };
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
                    // A local failure after authority started stops the
                    // participant before any other operation takes the lock.
                    // A failed helper or an exhausted memory bound touches no
                    // retained state and leaves the participant pending.
                    if (
                        !authorityStarted ||
                        error instanceof PublicInputFailure ||
                        error instanceof StoragePending ||
                        error instanceof ResourceFailure
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
        // Public input, pending storage, resource failures and failures
        // before authority started leave the participant pending.
        return {
            status: 'pending',
            reason: error instanceof Error ? error.message : String(error),
        };
    } finally {
        helpers?.stop();
        database?.close();
    }
};

self.onmessage = (event: MessageEvent<WorkerCommand | typeof helperRole>) => {
    if (event.data === helperRole) {
        self.onmessage = null;
        listenAsHelper(event.ports[0]);
        self.postMessage(true);
        return;
    }
    void run(event.data, event.ports).then(
        (result) => self.postMessage(result),
        (error: unknown) =>
            self.postMessage({
                status: 'pending',
                reason: error instanceof Error ? error.message : String(error),
            }),
    );
};
