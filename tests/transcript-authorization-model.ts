export const completionParticipantCount = 10;
export const completionCertificateThreshold = 7;
const completionReleaseThreshold = 4;

type IgnoredReason =
    | 'ballot-period-closed'
    | 'conflicting-ballot-certificate'
    | 'conflicting-ballot-receipt'
    | 'duplicate-message'
    | 'invalid-context'
    | 'invalid-finality-signature'
    | 'invalid-release-share'
    | 'invalid-signature'
    | 'invalid-setup-contribution'
    | 'participant-state-unavailable'
    | 'release-before-finality'
    | 'terminal-state'
    | 'wrong-finality-target'
    | 'wrong-release-target';

type BallotCandidate = Readonly<{
    author: number;
    receiptSigners: ReadonlySet<number>;
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
    ballotReceiptLocks: ReadonlyMap<string, string>;
    ballotCandidates: ReadonlyMap<string, BallotCandidate>;
    publishedSubmissions: ReadonlyMap<number, string>;
    acceptedBallots: ReadonlyMap<number, string>;
    closeLocks: ReadonlySet<number>;
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
          kind: 'ballot-receipt';
          proofValid: boolean;
          receiptSignatureValid: boolean;
          signer: number;
      }>
    | Readonly<{
          contextValid: boolean;
          kind: 'close-lock';
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
    | Readonly<{ kind: 'state-loss'; participant: number }>;

type TranscriptOutcome =
    | Readonly<{
          accepted?: boolean;
          certificateComplete?: boolean;
          closeComplete?: boolean;
          kind: 'processed';
          published?: boolean;
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
        ballotReceiptLocks: new Map(),
        ballotCandidates: new Map(),
        publishedSubmissions: new Map(),
        acceptedBallots: new Map(),
        closeLocks: new Set(),
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
    ballotReceiptLocks: new Map(state.ballotReceiptLocks),
    ballotCandidates: new Map(
        [...state.ballotCandidates].map(([identity, candidate]) => [
            identity,
            {
                ...candidate,
                receiptSigners: new Set(candidate.receiptSigners),
            },
        ]),
    ),
    publishedSubmissions: new Map(state.publishedSubmissions),
    acceptedBallots: new Map(state.acceptedBallots),
    closeLocks: new Set(state.closeLocks),
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

const receiptLockKey = (signer: number, author: number): string =>
    `${String(signer)}:${String(author)}`;

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
                phase:
                    setupContributions.size === completionParticipantCount
                        ? 'ballots-open'
                        : 'preparation',
            },
            outcome: { kind: 'processed', accepted: true, verified: true },
        };
    }

    if (event.kind === 'ballot-receipt') {
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
        if (!event.envelopeSignatureValid || !event.receiptSignatureValid) {
            return ignored(state, 'invalid-signature');
        }
        if (!event.contextValid) return ignored(state, 'invalid-context');

        const lockKey = receiptLockKey(event.signer, event.author);
        const priorLock = state.ballotReceiptLocks.get(lockKey);
        const existingCandidate = state.ballotCandidates.get(
            event.envelopeIdentity,
        );
        if (existingCandidate?.receiptSigners.has(event.signer) === true) {
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
                    : 'conflicting-ballot-receipt',
            );
        }
        if (
            existingCandidate !== undefined &&
            (existingCandidate.author !== event.author ||
                existingCandidate.verified !== event.proofValid)
        ) {
            return ignored(state, 'invalid-context');
        }

        const ballotReceiptLocks = new Map(state.ballotReceiptLocks);
        if (!state.corruptParticipants.has(event.signer)) {
            ballotReceiptLocks.set(lockKey, event.envelopeIdentity);
        }
        const receiptSigners = new Set(existingCandidate?.receiptSigners).add(
            event.signer,
        );
        const ballotCandidates = new Map(state.ballotCandidates).set(
            event.envelopeIdentity,
            {
                author: event.author,
                receiptSigners,
                verified: event.proofValid,
            },
        );
        const publishedSubmissions = new Map(state.publishedSubmissions);
        const certificateComplete =
            receiptSigners.size >= completionCertificateThreshold;
        if (certificateComplete) {
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
                ballotReceiptLocks,
                publishedSubmissions,
            },
            outcome: {
                kind: 'processed',
                accepted: false,
                certificateComplete,
                published: certificateComplete,
                verified: event.proofValid,
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
        const closeLocks = new Set(state.closeLocks).add(event.signer);
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
