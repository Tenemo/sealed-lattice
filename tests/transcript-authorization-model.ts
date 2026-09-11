// Authorization-policy model only. The ECHO/READY close extension has a
// delayed-delivery stall captured by publication-close-race-model.ts; these
// global transitions do not establish a live distributed close protocol.
export const completionParticipantCount = 10;
export const completionCertificateThreshold = 7;
const completionReleaseThreshold = 4;

type IgnoredReason =
    | 'ballot-period-closed'
    | 'conflicting-ballot-certificate'
    | 'conflicting-ballot-echo'
    | 'conflicting-ballot-ready'
    | 'duplicate-message'
    | 'invalid-context'
    | 'invalid-echo-certificate'
    | 'invalid-finality-signature'
    | 'invalid-release-share'
    | 'invalid-signature'
    | 'invalid-setup-contribution'
    | 'invalid-setup-receipt'
    | 'participant-state-unavailable'
    | 'release-before-finality'
    | 'terminal-state'
    | 'wrong-finality-target'
    | 'wrong-release-target';

type BallotCandidate = Readonly<{
    author: number;
    echoSigners: ReadonlySet<number>;
    readySigners: ReadonlySet<number>;
    verified: boolean;
}>;

type TranscriptTerminal =
    | Readonly<{ kind: 'no-result'; targetIdentity: string }>
    | Readonly<{
          kind: 'result';
          orderedOptionPositions: readonly number[];
          targetIdentity: string;
      }>;

export type TranscriptState = Readonly<{
    phase:
        | 'ballots-closing'
        | 'ballots-open'
        | 'certified'
        | 'preparation'
        | 'terminal';
    setupContributions: ReadonlyMap<number, string>;
    setupReceipts: ReadonlyMap<number, string>;
    ballotEchoLocks: ReadonlyMap<string, string>;
    ballotReadyLocks: ReadonlyMap<string, string>;
    ballotCandidates: ReadonlyMap<string, BallotCandidate>;
    publishedSubmissions: ReadonlyMap<number, string>;
    acceptedBallots: ReadonlyMap<number, string>;
    closeLocks: ReadonlySet<number>;
    closeLogs: ReadonlyMap<number, readonly string[]>;
    finalityLocks: ReadonlyMap<number, string>;
    finalitySignatures: ReadonlyMap<string, ReadonlySet<number>>;
    releaseShares: ReadonlyMap<number, string>;
    stoppedParticipants: ReadonlySet<number>;
    corruptParticipants: ReadonlySet<number>;
    certifiedTarget: string | null;
    expectedOrderedOptionPositions: readonly number[];
    terminal: TranscriptTerminal | null;
}>;

export type TranscriptEvent =
    | Readonly<{
          author: number;
          contextValid: boolean;
          envelopeIdentity: string;
          envelopeSignatureValid: boolean;
          echoSignatureValid: boolean;
          kind: 'ballot-echo';
          proofValid: boolean;
          signer: number;
      }>
    | Readonly<{
          author: number;
          contextValid: boolean;
          echoCertificateValid: boolean;
          envelopeIdentity: string;
          kind: 'ballot-ready';
          readySignatureValid: boolean;
          signer: number;
      }>
    | Readonly<{
          contextValid: boolean;
          kind: 'close-lock';
          readyEnvelopeIdentities: readonly string[];
          signatureValid: boolean;
          signer: number;
      }>
    | Readonly<{
          kind: 'finality-signature';
          signatureValid: boolean;
          signer: number;
          targetIdentity: string;
      }>
    | Readonly<{ kind: 'relay-omission' }>
    | Readonly<{
          kind: 'release-share';
          participant: number;
          proofValid: boolean;
          shareIdentity: string;
          targetIdentity: string;
      }>
    | Readonly<{
          contextValid: boolean;
          identity: string;
          kind: 'setup-contribution';
          participant: number;
          proofValid: boolean;
          signatureValid: boolean;
      }>
    | Readonly<{
          contextValid: boolean;
          contributionInventoryIdentity: string;
          kind: 'setup-receipt';
          participant: number;
          shareOpeningsValid: boolean;
          signatureValid: boolean;
      }>
    | Readonly<{ kind: 'state-loss'; participant: number }>;

type TranscriptOutcome =
    | Readonly<{
          accepted?: boolean;
          certificateComplete?: boolean;
          closeComplete?: boolean;
          echoCertificateComplete?: boolean;
          kind: 'processed';
          published?: boolean;
          publicationCertificateComplete?: boolean;
          releaseComplete?: boolean;
          verified?: boolean;
      }>
    | TranscriptTerminal
    | Readonly<{ kind: 'ignored'; reason: IgnoredReason }>
    | Readonly<{ kind: 'pending'; reason: 'missing-dependency' }>
    | Readonly<{
          completionBoundaryCrossed: boolean;
          kind: 'stopped';
      }>;

export type TranscriptTransition = Readonly<{
    outcome: TranscriptOutcome;
    state: TranscriptState;
}>;

export const createTranscriptState = (
    expectedOrderedOptionPositions: readonly number[] = [0],
    corruptParticipants: ReadonlySet<number> = new Set([0, 1, 2]),
): TranscriptState => {
    if (corruptParticipants.size > 3) {
        throw new RangeError('The corrupt set exceeds the completion bound.');
    }
    for (const participant of corruptParticipants) {
        if (
            !Number.isSafeInteger(participant) ||
            participant < 0 ||
            participant >= completionParticipantCount
        ) {
            throw new RangeError(
                'A corrupt participant is outside the completion roster.',
            );
        }
    }
    return {
        phase: 'preparation',
        setupContributions: new Map(),
        setupReceipts: new Map(),
        ballotEchoLocks: new Map(),
        ballotReadyLocks: new Map(),
        ballotCandidates: new Map(),
        publishedSubmissions: new Map(),
        acceptedBallots: new Map(),
        closeLocks: new Set(),
        closeLogs: new Map(),
        finalityLocks: new Map(),
        finalitySignatures: new Map(),
        releaseShares: new Map(),
        stoppedParticipants: new Set(),
        corruptParticipants: new Set(corruptParticipants),
        certifiedTarget: null,
        expectedOrderedOptionPositions: [...expectedOrderedOptionPositions],
        terminal: null,
    };
};

const cloneState = (state: TranscriptState): TranscriptState => ({
    ...state,
    setupContributions: new Map(state.setupContributions),
    setupReceipts: new Map(state.setupReceipts),
    ballotEchoLocks: new Map(state.ballotEchoLocks),
    ballotReadyLocks: new Map(state.ballotReadyLocks),
    ballotCandidates: new Map(
        [...state.ballotCandidates].map(([identity, candidate]) => [
            identity,
            {
                ...candidate,
                echoSigners: new Set(candidate.echoSigners),
                readySigners: new Set(candidate.readySigners),
            },
        ]),
    ),
    publishedSubmissions: new Map(state.publishedSubmissions),
    acceptedBallots: new Map(state.acceptedBallots),
    closeLocks: new Set(state.closeLocks),
    closeLogs: new Map(
        [...state.closeLogs].map(([signer, identities]) => [
            signer,
            [...identities],
        ]),
    ),
    finalityLocks: new Map(state.finalityLocks),
    finalitySignatures: new Map(
        [...state.finalitySignatures].map(([target, signers]) => [
            target,
            new Set(signers),
        ]),
    ),
    releaseShares: new Map(state.releaseShares),
    stoppedParticipants: new Set(state.stoppedParticipants),
    corruptParticipants: new Set(state.corruptParticipants),
    expectedOrderedOptionPositions: [...state.expectedOrderedOptionPositions],
});

const requireParticipant = (participant: number): void => {
    if (
        !Number.isSafeInteger(participant) ||
        participant < 0 ||
        participant >= completionParticipantCount
    ) {
        throw new RangeError('participant is outside the completion roster.');
    }
};

const ignored = (
    state: TranscriptState,
    reason: IgnoredReason,
): TranscriptTransition => ({ state, outcome: { kind: 'ignored', reason } });

const ballotLockKey = (signer: number, author: number): string =>
    `${String(signer)}:${String(author)}`;

const readyLogForSigner = (
    state: TranscriptState,
    signer: number,
): readonly string[] =>
    [...state.ballotCandidates]
        .filter(([_identity, candidate]) => candidate.readySigners.has(signer))
        .map(([identity]) => identity)
        .sort();

const arraysEqual = (
    left: readonly string[],
    right: readonly string[],
): boolean =>
    left.length === right.length &&
    left.every((value, index) => value === right[index]);

export const deriveSetupContributionInventoryIdentity = (
    state: TranscriptState,
): string => {
    if (state.setupContributions.size !== completionParticipantCount) {
        throw new Error('The setup contribution inventory is incomplete.');
    }
    const inventory = [...state.setupContributions]
        .sort(([left], [right]) => left - right)
        .map(
            ([participant, identity]) =>
                `${String(participant)}=${identity.length}:${identity}`,
        )
        .join(',');
    return `setup:${inventory.length}:${inventory}`;
};

export const deriveFinalityTargetIdentity = (
    state: TranscriptState,
): string => {
    if (state.phase !== 'ballots-closing' && state.phase !== 'certified') {
        throw new Error('The ballot inventory is not closed.');
    }
    const inventory = [...state.publishedSubmissions]
        .sort(([left], [right]) => left - right)
        .map(([author, identity]) => {
            const candidate = state.ballotCandidates.get(identity);
            if (candidate === undefined) {
                throw new Error('A published submission is absent.');
            }
            return `${String(author)}=${identity.length}:${identity}:${candidate.verified ? 'verified' : 'invalid'}`;
        })
        .join(',');
    return `target:${inventory.length}:${inventory}`;
};

export const isBallotCounted = (
    state: TranscriptState,
    author: number,
): boolean =>
    state.acceptedBallots.has(author) &&
    (state.certifiedTarget !== null || state.terminal !== null);

export const applyTranscriptEvent = (
    current: TranscriptState,
    event: TranscriptEvent,
): TranscriptTransition => {
    const state = cloneState(current);
    if (state.terminal !== null) return ignored(state, 'terminal-state');

    if (event.kind === 'relay-omission') {
        return {
            state,
            outcome: { kind: 'pending', reason: 'missing-dependency' },
        };
    }
    if (event.kind === 'state-loss') {
        requireParticipant(event.participant);
        const stoppedParticipants = new Set(state.stoppedParticipants).add(
            event.participant,
        );
        return {
            state: { ...state, stoppedParticipants },
            outcome: {
                kind: 'stopped',
                completionBoundaryCrossed: state.certifiedTarget !== null,
            },
        };
    }

    if (event.kind === 'setup-contribution') {
        requireParticipant(event.participant);
        if (state.phase !== 'preparation') {
            return ignored(state, 'duplicate-message');
        }
        if (state.stoppedParticipants.has(event.participant)) {
            return ignored(state, 'participant-state-unavailable');
        }
        if (!event.signatureValid) return ignored(state, 'invalid-signature');
        if (!event.contextValid) return ignored(state, 'invalid-context');
        if (!event.proofValid) {
            return ignored(state, 'invalid-setup-contribution');
        }
        const prior = state.setupContributions.get(event.participant);
        if (prior !== undefined) {
            return ignored(
                state,
                prior === event.identity
                    ? 'duplicate-message'
                    : 'invalid-setup-contribution',
            );
        }
        const setupContributions = new Map(state.setupContributions).set(
            event.participant,
            event.identity,
        );
        return {
            state: {
                ...state,
                setupContributions,
            },
            outcome: { kind: 'processed', accepted: true, verified: true },
        };
    }

    if (event.kind === 'setup-receipt') {
        requireParticipant(event.participant);
        if (state.phase !== 'preparation') {
            return ignored(state, 'duplicate-message');
        }
        if (state.stoppedParticipants.has(event.participant)) {
            return ignored(state, 'participant-state-unavailable');
        }
        if (state.setupContributions.size !== completionParticipantCount) {
            return {
                state,
                outcome: { kind: 'pending', reason: 'missing-dependency' },
            };
        }
        if (!event.signatureValid) return ignored(state, 'invalid-signature');
        if (!event.contextValid) return ignored(state, 'invalid-context');
        if (
            !event.shareOpeningsValid ||
            event.contributionInventoryIdentity !==
                deriveSetupContributionInventoryIdentity(state)
        ) {
            return ignored(state, 'invalid-setup-receipt');
        }
        if (state.setupReceipts.has(event.participant)) {
            return ignored(state, 'duplicate-message');
        }
        const setupReceipts = new Map(state.setupReceipts).set(
            event.participant,
            event.contributionInventoryIdentity,
        );
        return {
            state: {
                ...state,
                setupReceipts,
                phase:
                    setupReceipts.size === completionParticipantCount
                        ? 'ballots-open'
                        : 'preparation',
            },
            outcome: { kind: 'processed', accepted: true, verified: true },
        };
    }

    if (event.kind === 'ballot-echo') {
        requireParticipant(event.author);
        requireParticipant(event.signer);
        if (state.phase === 'preparation') {
            return {
                state,
                outcome: { kind: 'pending', reason: 'missing-dependency' },
            };
        }
        if (
            state.phase !== 'ballots-open' ||
            (state.closeLocks.has(event.signer) &&
                !state.corruptParticipants.has(event.signer))
        ) {
            return ignored(state, 'ballot-period-closed');
        }
        if (state.stoppedParticipants.has(event.signer)) {
            return ignored(state, 'participant-state-unavailable');
        }
        if (!event.envelopeSignatureValid || !event.echoSignatureValid) {
            return ignored(state, 'invalid-signature');
        }
        if (!event.contextValid) return ignored(state, 'invalid-context');

        const lockKey = ballotLockKey(event.signer, event.author);
        const priorLock = state.ballotEchoLocks.get(lockKey);
        const existingCandidate = state.ballotCandidates.get(
            event.envelopeIdentity,
        );
        if (existingCandidate?.echoSigners.has(event.signer) === true) {
            return ignored(state, 'duplicate-message');
        }
        if (
            priorLock !== undefined &&
            !state.corruptParticipants.has(event.signer)
        ) {
            return ignored(
                state,
                priorLock === event.envelopeIdentity
                    ? 'duplicate-message'
                    : 'conflicting-ballot-echo',
            );
        }
        if (
            existingCandidate !== undefined &&
            (existingCandidate.author !== event.author ||
                existingCandidate.verified !== event.proofValid)
        ) {
            return ignored(state, 'invalid-context');
        }

        const ballotEchoLocks = new Map(state.ballotEchoLocks);
        if (!state.corruptParticipants.has(event.signer)) {
            ballotEchoLocks.set(lockKey, event.envelopeIdentity);
        }
        const echoSigners = new Set(existingCandidate?.echoSigners).add(
            event.signer,
        );
        const ballotCandidates = new Map(state.ballotCandidates).set(
            event.envelopeIdentity,
            {
                author: event.author,
                echoSigners,
                readySigners: new Set(existingCandidate?.readySigners),
                verified: event.proofValid,
            },
        );
        return {
            state: {
                ...state,
                ballotCandidates,
                ballotEchoLocks,
            },
            outcome: {
                kind: 'processed',
                accepted: false,
                echoCertificateComplete:
                    echoSigners.size >= completionCertificateThreshold,
                published: false,
                verified: event.proofValid,
            },
        };
    }

    if (event.kind === 'ballot-ready') {
        requireParticipant(event.author);
        requireParticipant(event.signer);
        if (state.phase === 'preparation') {
            return {
                state,
                outcome: { kind: 'pending', reason: 'missing-dependency' },
            };
        }
        if (
            state.phase !== 'ballots-open' ||
            (state.closeLocks.has(event.signer) &&
                !state.corruptParticipants.has(event.signer))
        ) {
            return ignored(state, 'ballot-period-closed');
        }
        if (state.stoppedParticipants.has(event.signer)) {
            return ignored(state, 'participant-state-unavailable');
        }
        if (!event.readySignatureValid) {
            return ignored(state, 'invalid-signature');
        }
        if (!event.contextValid) return ignored(state, 'invalid-context');

        const candidate = state.ballotCandidates.get(event.envelopeIdentity);
        if (
            !event.echoCertificateValid ||
            candidate === undefined ||
            candidate.author !== event.author ||
            candidate.echoSigners.size < completionCertificateThreshold
        ) {
            return ignored(state, 'invalid-echo-certificate');
        }

        const lockKey = ballotLockKey(event.signer, event.author);
        const priorLock = state.ballotReadyLocks.get(lockKey);
        if (candidate.readySigners.has(event.signer)) {
            return ignored(state, 'duplicate-message');
        }
        if (
            priorLock !== undefined &&
            !state.corruptParticipants.has(event.signer)
        ) {
            return ignored(
                state,
                priorLock === event.envelopeIdentity
                    ? 'duplicate-message'
                    : 'conflicting-ballot-ready',
            );
        }

        const ballotReadyLocks = new Map(state.ballotReadyLocks);
        if (!state.corruptParticipants.has(event.signer)) {
            ballotReadyLocks.set(lockKey, event.envelopeIdentity);
        }
        const readySigners = new Set(candidate.readySigners).add(event.signer);
        const ballotCandidates = new Map(state.ballotCandidates).set(
            event.envelopeIdentity,
            { ...candidate, readySigners },
        );
        const publishedSubmissions = new Map(state.publishedSubmissions);
        const publicationCertificateComplete =
            readySigners.size >= completionCertificateThreshold;
        if (publicationCertificateComplete) {
            const priorPublished = publishedSubmissions.get(event.author);
            if (
                priorPublished !== undefined &&
                priorPublished !== event.envelopeIdentity
            ) {
                return ignored(state, 'conflicting-ballot-certificate');
            }
            publishedSubmissions.set(event.author, event.envelopeIdentity);
        }
        return {
            state: {
                ...state,
                ballotCandidates,
                ballotReadyLocks,
                publishedSubmissions,
            },
            outcome: {
                kind: 'processed',
                accepted: false,
                publicationCertificateComplete,
                published: publicationCertificateComplete,
                verified: candidate.verified,
            },
        };
    }

    if (event.kind === 'close-lock') {
        requireParticipant(event.signer);
        if (state.phase === 'preparation') {
            return {
                state,
                outcome: { kind: 'pending', reason: 'missing-dependency' },
            };
        }
        if (
            state.phase !== 'ballots-open' &&
            state.phase !== 'ballots-closing'
        ) {
            return ignored(state, 'duplicate-message');
        }
        if (state.stoppedParticipants.has(event.signer)) {
            return ignored(state, 'participant-state-unavailable');
        }
        if (!event.signatureValid) return ignored(state, 'invalid-signature');
        if (!event.contextValid) return ignored(state, 'invalid-context');
        if (state.closeLocks.has(event.signer)) {
            return ignored(state, 'duplicate-message');
        }
        const expectedReadyLog = readyLogForSigner(state, event.signer);
        if (!arraysEqual(event.readyEnvelopeIdentities, expectedReadyLog)) {
            return ignored(state, 'invalid-context');
        }
        if (
            expectedReadyLog.some((identity) => {
                const candidate = state.ballotCandidates.get(identity);
                return (
                    candidate === undefined ||
                    state.publishedSubmissions.get(candidate.author) !==
                        identity
                );
            })
        ) {
            return {
                state,
                outcome: { kind: 'pending', reason: 'missing-dependency' },
            };
        }
        const closeLocks = new Set(state.closeLocks).add(event.signer);
        const closeLogs = new Map(state.closeLogs).set(event.signer, [
            ...event.readyEnvelopeIdentities,
        ]);
        const closeComplete = closeLocks.size >= completionCertificateThreshold;
        const acceptedBallots =
            closeComplete && state.phase === 'ballots-open'
                ? new Map(
                      [...state.publishedSubmissions].filter(
                          ([_author, identity]) =>
                              state.ballotCandidates.get(identity)?.verified ===
                              true,
                      ),
                  )
                : state.acceptedBallots;
        return {
            state: {
                ...state,
                acceptedBallots,
                closeLocks,
                closeLogs,
                phase: closeComplete ? 'ballots-closing' : 'ballots-open',
            },
            outcome: { kind: 'processed', closeComplete },
        };
    }

    if (event.kind === 'finality-signature') {
        requireParticipant(event.signer);
        if (state.phase !== 'ballots-closing' && state.phase !== 'certified') {
            return {
                state,
                outcome: { kind: 'pending', reason: 'missing-dependency' },
            };
        }
        if (state.stoppedParticipants.has(event.signer)) {
            return ignored(state, 'participant-state-unavailable');
        }
        if (!event.signatureValid) {
            return ignored(state, 'invalid-finality-signature');
        }
        if (
            !state.closeLocks.has(event.signer) ||
            event.targetIdentity !== deriveFinalityTargetIdentity(state)
        ) {
            return ignored(state, 'wrong-finality-target');
        }
        const priorTarget = state.finalityLocks.get(event.signer);
        if (
            priorTarget !== undefined &&
            !state.corruptParticipants.has(event.signer)
        ) {
            return ignored(
                state,
                priorTarget === event.targetIdentity
                    ? 'duplicate-message'
                    : 'wrong-finality-target',
            );
        }
        const finalityLocks = new Map(state.finalityLocks);
        if (!state.corruptParticipants.has(event.signer)) {
            finalityLocks.set(event.signer, event.targetIdentity);
        }
        const signers = new Set(
            state.finalitySignatures.get(event.targetIdentity),
        ).add(event.signer);
        const finalitySignatures = new Map(state.finalitySignatures).set(
            event.targetIdentity,
            signers,
        );
        const certificateComplete =
            signers.size >= completionCertificateThreshold;
        if (certificateComplete && state.acceptedBallots.size === 0) {
            const terminal = {
                kind: 'no-result',
                targetIdentity: event.targetIdentity,
            } as const;
            return {
                state: {
                    ...state,
                    certifiedTarget: event.targetIdentity,
                    finalityLocks,
                    finalitySignatures,
                    phase: 'terminal',
                    terminal,
                },
                outcome: terminal,
            };
        }
        return {
            state: {
                ...state,
                certifiedTarget: certificateComplete
                    ? event.targetIdentity
                    : state.certifiedTarget,
                finalityLocks,
                finalitySignatures,
                phase: certificateComplete ? 'certified' : state.phase,
            },
            outcome: { kind: 'processed', certificateComplete },
        };
    }

    requireParticipant(event.participant);
    if (state.stoppedParticipants.has(event.participant)) {
        return ignored(state, 'participant-state-unavailable');
    }
    if (state.certifiedTarget === null) {
        return ignored(state, 'release-before-finality');
    }
    if (event.targetIdentity !== state.certifiedTarget) {
        return ignored(state, 'wrong-release-target');
    }
    if (!event.proofValid || state.releaseShares.has(event.participant)) {
        return ignored(state, 'invalid-release-share');
    }
    const releaseShares = new Map(state.releaseShares).set(
        event.participant,
        event.shareIdentity,
    );
    const releaseComplete = releaseShares.size >= completionReleaseThreshold;
    if (releaseComplete) {
        const terminal = {
            kind: 'result',
            orderedOptionPositions: [...state.expectedOrderedOptionPositions],
            targetIdentity: event.targetIdentity,
        } as const;
        return {
            state: { ...state, releaseShares, phase: 'terminal', terminal },
            outcome: terminal,
        };
    }
    return {
        state: { ...state, releaseShares },
        outcome: { kind: 'processed', releaseComplete },
    };
};
