import { describe, expect, it } from 'vitest';

import {
    applyTranscriptEvent,
    completionCertificateThreshold,
    completionParticipantCount,
    createTranscriptState,
    deriveFinalityTargetIdentity,
    deriveSetupContributionInventoryIdentity,
    isBallotCounted,
    type TranscriptState,
} from '#tests/transcript-authorization-model.js';

const advance = (
    state: TranscriptState,
    event: Parameters<typeof applyTranscriptEvent>[1],
): TranscriptState => applyTranscriptEvent(state, event).state;

const readyForBallots = (): TranscriptState => {
    let state = createTranscriptState([2, 0]);
    for (
        let participant = 0;
        participant < completionParticipantCount;
        participant += 1
    ) {
        state = advance(state, {
            kind: 'setup-contribution',
            participant,
            identity: `setup-${String(participant)}`,
            contextValid: true,
            proofValid: true,
            signatureValid: true,
        });
    }
    const contributionInventoryIdentity =
        deriveSetupContributionInventoryIdentity(state);
    for (
        let participant = 0;
        participant < completionParticipantCount;
        participant += 1
    ) {
        state = advance(state, {
            kind: 'setup-receipt',
            participant,
            contributionInventoryIdentity,
            contextValid: true,
            shareOpeningsValid: true,
            signatureValid: true,
        });
    }
    return state;
};

const echoBallot = (
    initial: TranscriptState,
    author: number,
    envelopeIdentity: string,
    proofValid = true,
): TranscriptState => {
    let state = initial;
    for (let signer = 0; signer < completionCertificateThreshold; signer += 1) {
        state = advance(state, {
            kind: 'ballot-echo',
            author,
            signer,
            envelopeIdentity,
            contextValid: true,
            echoSignatureValid: true,
            envelopeSignatureValid: true,
            proofValid,
        });
    }
    return state;
};

const publishBallot = (
    initial: TranscriptState,
    author: number,
    envelopeIdentity: string,
    proofValid = true,
): TranscriptState => {
    let state = echoBallot(initial, author, envelopeIdentity, proofValid);
    for (let signer = 0; signer < completionCertificateThreshold; signer += 1) {
        state = advance(state, {
            kind: 'ballot-ready',
            author,
            signer,
            envelopeIdentity,
            contextValid: true,
            echoCertificateValid: true,
            readySignatureValid: true,
        });
    }
    return state;
};

const closeBallots = (initial: TranscriptState): TranscriptState => {
    let state = initial;
    for (let signer = 0; signer < completionCertificateThreshold; signer += 1) {
        const readyEnvelopeIdentities = [...state.ballotCandidates]
            .filter(([_identity, candidate]) =>
                candidate.readySigners.has(signer),
            )
            .map(([identity]) => identity)
            .sort();
        state = advance(state, {
            kind: 'close-lock',
            signer,
            contextValid: true,
            readyEnvelopeIdentities,
            signatureValid: true,
        });
    }
    return state;
};

const certify = (initial: TranscriptState): TranscriptState => {
    let state = initial;
    const targetIdentity = deriveFinalityTargetIdentity(state);
    for (let signer = 0; signer < completionCertificateThreshold; signer += 1) {
        state = advance(state, {
            kind: 'finality-signature',
            signer,
            signatureValid: true,
            targetIdentity,
        });
    }
    return state;
};

describe('transcript authorization model', () => {
    it('separates verified publication from acceptance at close', () => {
        let state = readyForBallots();
        state = publishBallot(state, 0, 'signed-invalid-ballot', false);
        expect(state.publishedSubmissions.get(0)).toBe('signed-invalid-ballot');
        expect(state.acceptedBallots.size).toBe(0);

        state = publishBallot(state, 1, 'valid-ballot');
        expect(state.publishedSubmissions.get(1)).toBe('valid-ballot');
        expect(state.acceptedBallots.size).toBe(0);

        state = closeBallots(state);
        expect(state.acceptedBallots.get(1)).toBe('valid-ballot');
        expect(state.acceptedBallots.has(0)).toBe(false);
    });

    it('ignores invalid preparation and remains unresolved', () => {
        let state = createTranscriptState();
        const invalid = applyTranscriptEvent(state, {
            kind: 'setup-contribution',
            participant: 0,
            identity: 'invalid-setup',
            contextValid: true,
            proofValid: false,
            signatureValid: true,
        });
        expect(invalid.outcome).toEqual({
            kind: 'ignored',
            reason: 'invalid-setup-contribution',
        });
        expect(invalid.state.phase).toBe('preparation');
        expect(invalid.state.terminal).toBeNull();

        state = advance(state, { kind: 'state-loss', participant: 0 });
        expect(
            applyTranscriptEvent(state, {
                kind: 'setup-contribution',
                participant: 0,
                identity: 'late-valid-setup',
                contextValid: true,
                proofValid: true,
                signatureValid: true,
            }).outcome,
        ).toEqual({
            kind: 'ignored',
            reason: 'participant-state-unavailable',
        });
        expect(state.phase).toBe('preparation');
    });

    it('requires every participant to verify its private setup openings', () => {
        let state = createTranscriptState();
        for (
            let participant = 0;
            participant < completionParticipantCount;
            participant += 1
        ) {
            state = advance(state, {
                kind: 'setup-contribution',
                participant,
                identity: `setup-${String(participant)}`,
                contextValid: true,
                proofValid: true,
                signatureValid: true,
            });
        }
        expect(state.phase).toBe('preparation');
        const contributionInventoryIdentity =
            deriveSetupContributionInventoryIdentity(state);
        expect(
            applyTranscriptEvent(state, {
                kind: 'setup-receipt',
                participant: 0,
                contributionInventoryIdentity,
                contextValid: true,
                shareOpeningsValid: false,
                signatureValid: true,
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'invalid-setup-receipt' });
        for (
            let participant = 0;
            participant < completionParticipantCount - 1;
            participant += 1
        ) {
            state = advance(state, {
                kind: 'setup-receipt',
                participant,
                contributionInventoryIdentity,
                contextValid: true,
                shareOpeningsValid: true,
                signatureValid: true,
            });
        }
        expect(state.phase).toBe('preparation');
        state = advance(state, {
            kind: 'setup-receipt',
            participant: completionParticipantCount - 1,
            contributionInventoryIdentity,
            contextValid: true,
            shareOpeningsValid: true,
            signatureValid: true,
        });
        expect(state.phase).toBe('ballots-open');
    });

    it('gives each hostile pre-close transition one stable classification', () => {
        let state = readyForBallots();
        expect(
            applyTranscriptEvent(state, {
                kind: 'ballot-echo',
                author: 0,
                signer: 0,
                envelopeIdentity: 'forged',
                contextValid: true,
                echoSignatureValid: true,
                envelopeSignatureValid: false,
                proofValid: true,
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'invalid-signature' });
        expect(
            applyTranscriptEvent(state, {
                kind: 'ballot-echo',
                author: 0,
                signer: 0,
                envelopeIdentity: 'wrong-context',
                contextValid: false,
                echoSignatureValid: true,
                envelopeSignatureValid: true,
                proofValid: true,
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'invalid-context' });

        const receipt = {
            kind: 'ballot-echo',
            author: 0,
            signer: 0,
            envelopeIdentity: 'candidate',
            contextValid: true,
            echoSignatureValid: true,
            envelopeSignatureValid: true,
            proofValid: true,
        } as const;
        state = advance(state, receipt);
        expect(applyTranscriptEvent(state, receipt).outcome).toEqual({
            kind: 'ignored',
            reason: 'duplicate-message',
        });
        expect(
            applyTranscriptEvent(state, { kind: 'relay-omission' }).outcome,
        ).toEqual({ kind: 'pending', reason: 'missing-dependency' });
        expect(
            applyTranscriptEvent(state, {
                kind: 'release-share',
                participant: 0,
                targetIdentity: 'uncertified',
                proofValid: true,
                shareIdentity: 'early-share',
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'release-before-finality' });
    });

    it('requires echo evidence and makes a ready signer wait for publication', () => {
        let state = readyForBallots();
        expect(
            applyTranscriptEvent(state, {
                kind: 'ballot-ready',
                author: 0,
                signer: 3,
                envelopeIdentity: 'candidate',
                contextValid: true,
                echoCertificateValid: true,
                readySignatureValid: true,
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'invalid-echo-certificate' });

        state = echoBallot(state, 0, 'candidate');
        state = advance(state, {
            kind: 'ballot-ready',
            author: 0,
            signer: 3,
            envelopeIdentity: 'candidate',
            contextValid: true,
            echoCertificateValid: true,
            readySignatureValid: true,
        });
        expect(
            applyTranscriptEvent(state, {
                kind: 'close-lock',
                signer: 3,
                contextValid: true,
                readyEnvelopeIdentities: ['candidate'],
                signatureValid: true,
            }).outcome,
        ).toEqual({ kind: 'pending', reason: 'missing-dependency' });

        for (const signer of [0, 1, 2, 4, 5, 6]) {
            state = advance(state, {
                kind: 'ballot-ready',
                author: 0,
                signer,
                envelopeIdentity: 'candidate',
                contextValid: true,
                echoCertificateValid: true,
                readySignatureValid: true,
            });
        }
        expect(state.publishedSubmissions.get(0)).toBe('candidate');
        expect(
            applyTranscriptEvent(state, {
                kind: 'close-lock',
                signer: 3,
                contextValid: true,
                readyEnvelopeIdentities: ['candidate'],
                signatureValid: true,
            }).outcome,
        ).toMatchObject({ kind: 'processed' });
    });

    it('preserves an accepted ballot when later conflicting work appears', () => {
        let state = publishBallot(readyForBallots(), 0, 'accepted-ballot');
        expect(state.publishedSubmissions.get(0)).toBe('accepted-ballot');
        let honestConflictOutcome:
            ReturnType<typeof applyTranscriptEvent>['outcome'] | undefined;
        for (const signer of [0, 1, 2, 3, 7, 8, 9]) {
            const conflict = applyTranscriptEvent(state, {
                kind: 'ballot-echo',
                author: 0,
                signer,
                envelopeIdentity: 'conflicting-ballot',
                contextValid: true,
                echoSignatureValid: true,
                envelopeSignatureValid: true,
                proofValid: true,
            });
            if (signer === 3) {
                honestConflictOutcome = conflict.outcome;
            } else {
                state = conflict.state;
            }
        }
        expect(honestConflictOutcome).toEqual({
            kind: 'ignored',
            reason: 'conflicting-ballot-echo',
        });
        expect(state.publishedSubmissions.get(0)).toBe('accepted-ballot');
        expect(state.publishedSubmissions.size).toBe(1);
        state = closeBallots(state);
        expect(state.acceptedBallots.get(0)).toBe('accepted-ballot');
    });

    it('closes without ballots and certifies no result', () => {
        const closing = closeBallots(readyForBallots());
        expect(closing.phase).toBe('ballots-closing');
        const terminal = certify(closing);
        expect(terminal.terminal).toEqual({
            kind: 'no-result',
            targetIdentity: deriveFinalityTargetIdentity(closing),
        });
    });

    it('ignores late ballots and signatures for a different inventory', () => {
        const closing = closeBallots(
            publishBallot(readyForBallots(), 0, 'accepted-ballot'),
        );
        expect(
            applyTranscriptEvent(closing, {
                kind: 'ballot-echo',
                author: 1,
                signer: 7,
                envelopeIdentity: 'late-ballot',
                contextValid: true,
                echoSignatureValid: true,
                envelopeSignatureValid: true,
                proofValid: true,
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'ballot-period-closed' });
        expect(
            applyTranscriptEvent(closing, {
                kind: 'finality-signature',
                signer: 0,
                signatureValid: true,
                targetIdentity: 'different-inventory',
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'wrong-finality-target' });
    });

    it('completes after three losses despite invalid corrupt shares', () => {
        let state = certify(
            closeBallots(
                publishBallot(readyForBallots(), 0, 'accepted-ballot'),
            ),
        );
        const targetIdentity = state.certifiedTarget;
        expect(targetIdentity).not.toBeNull();
        expect(isBallotCounted(state, 0)).toBe(true);
        for (const participant of [0, 1, 2]) {
            state = advance(state, { kind: 'state-loss', participant });
        }
        expect(
            applyTranscriptEvent(state, {
                kind: 'release-share',
                participant: 3,
                targetIdentity: targetIdentity ?? '',
                proofValid: false,
                shareIdentity: 'invalid',
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'invalid-release-share' });
        expect(
            applyTranscriptEvent(state, {
                kind: 'release-share',
                participant: 3,
                targetIdentity: 'wrong-target',
                proofValid: true,
                shareIdentity: 'wrong-target-share',
            }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'wrong-release-target' });
        for (const participant of [4, 5, 6, 7]) {
            state = advance(state, {
                kind: 'release-share',
                participant,
                targetIdentity: targetIdentity ?? '',
                proofValid: true,
                shareIdentity: `share-${String(participant)}`,
            });
        }
        expect(state.terminal).toEqual({
            kind: 'result',
            orderedOptionPositions: [2, 0],
            targetIdentity,
        });
    });

    it('allows every honest close signer to join before finality', () => {
        let state = closeBallots(
            publishBallot(readyForBallots(), 0, 'accepted-ballot'),
        );
        for (const signer of [7, 8, 9]) {
            state = advance(state, {
                kind: 'close-lock',
                signer,
                contextValid: true,
                readyEnvelopeIdentities: [],
                signatureValid: true,
            });
        }
        const targetIdentity = deriveFinalityTargetIdentity(state);
        for (const signer of [3, 4, 5, 6, 7, 8, 9]) {
            state = advance(state, {
                kind: 'finality-signature',
                signer,
                signatureValid: true,
                targetIdentity,
            });
        }
        expect(state.phase).toBe('certified');
        expect(state.certifiedTarget).toBe(targetIdentity);
    });

    it('makes a verified terminal absorbing', () => {
        const terminal = certify(closeBallots(readyForBallots()));
        expect(
            applyTranscriptEvent(terminal, { kind: 'relay-omission' }).outcome,
        ).toEqual({ kind: 'ignored', reason: 'terminal-state' });
    });
});
