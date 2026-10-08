import { isEligibleContributor } from '../module/context.js';
import type {
    ParticipantContext,
    ParticipantProfileContext,
} from '../module/context.js';
import type { PublicRelay } from '../relay/relay.js';
import { equalBytes, fromHexadecimal, hexadecimal } from '../shared/bytes.js';
import { InvalidRequest } from '../shared/failures.js';
import {
    beginBallot,
    completeBallot,
    parseBallotScores,
    publishBallot,
    resumeBallot,
} from '../stages/ballot/ballot.js';
import {
    advanceClose,
    closeEvents,
    isCloseComplete,
    lockPublishedIntent,
    parseCloseParameters,
    publishClose,
    resumeClose,
} from '../stages/close/close.js';
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
} from '../stages/contribution/contribution.js';
import type { EnrollmentRequest } from '../stages/enrollment/enrollment.js';
import {
    createEnrollment,
    restoreEnrollment,
} from '../stages/enrollment/enrollment.js';
import {
    advanceRelease,
    computeResult,
    publishRelease,
    resumeRelease,
} from '../stages/release/release.js';
import { publishRegistrationRecords } from '../stages/roster/registration-publication.js';
import {
    acceptRoster,
    parseRegistrationBodyDigests,
    proposeRoster,
    retainedProfile,
    reverifyRoster,
    signRoster,
} from '../stages/roster/roster.js';
import { endorseSetup, selectSetup } from '../stages/setup/setup-selection.js';
import {
    restoreSetup,
    retainSetup,
    verifySetup,
} from '../stages/setup/setup.js';
import {
    certifiedBallotInclusion,
    publishTarget,
    signTarget,
} from '../stages/target-vote/target.js';
import { storedRuntime } from '../storage/database.js';
import {
    ballotPhase,
    releasePhase,
    rootGeneration,
    targetPhase,
} from '../storage/root-generation.js';
import { authenticateRoot } from '../storage/root.js';

import { isOperationAvailable } from './operation-availability.js';
import { summary } from './participant-summary.js';
import { refused } from './worker-messages.js';
import type { WorkerCommand, WorkerResult } from './worker-messages.js';

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

// Runs one participant operation once its module, storage and helpers are
// ready, under the participant's lock. The callback marks where authority
// starts.
export const executeOperation = async (
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
    const profileContext = (): ParticipantProfileContext => {
        if (profiled === undefined)
            throw new Error('The participant profile is not known.');
        return profiled;
    };
    const available = isOperationAvailable(command.operation, {
        generation: root.head.generation,
        isOrganizer: enrollment.isOrganizer,
        hasProfile: profiled !== undefined,
        isEligibleContributor:
            profiled !== undefined && isEligibleContributor(profiled),
        spentTargetVote:
            root.head.generation >= releasePhase.locked &&
            root.manifest.suffixes.target?.length === 0,
    });
    if (available === undefined) return refused('invalid request');
    if (!available) return refused('unavailable operation');
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
            const session = await resumeParticipant(profileContext(), root);
            await confirmRoster(session);
            root = session.root;
            break;
        }
        case 'contribute': {
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
                    context.module.confirm_roster() !== 0
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
            const session = await resumeParticipant(profileContext(), root);
            await selectSetup(session, relay);
            root = session.root;
            break;
        }
        case 'endorse-setup': {
            const session = await resumeParticipant(profileContext(), root);
            await endorseSetup(session, relay);
            root = session.root;
            break;
        }
        case 'verify-setup': {
            const session = await resumeParticipant(profileContext(), root);
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
            const scores =
                parameters.scores === undefined
                    ? undefined
                    : parseBallotScores(
                          profileContext().profile,
                          parameters.scores,
                      );
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
            // A signed vote is only delivered again.
            const generation = root.head.generation;
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
            // A release without a target of its own needs an existing
            // certificate. A signed release is only delivered again.
            const generation = root.head.generation;
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
