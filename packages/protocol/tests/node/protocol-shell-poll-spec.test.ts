import { describe, expect, it } from 'vitest';

import { validatePollSpec } from '../../src/protocol-shell/index';
import type { PollSpecInput } from '../../src/protocol-shell/index';

const createValidPollSpecInput = (
    overrides: Partial<PollSpecInput> = {},
): PollSpecInput => ({
    ceremonyId: 'ceremony-2026-board',
    question: 'Select the top priorities',
    options: Array.from({ length: 20 }, (_value, index) => `Option ${index}`),
    kTop: 20,
    ...overrides,
});

const expectErrorCodes = (
    input: unknown,
    expectedCodes: readonly string[],
): void => {
    const validation = validatePollSpec(input);

    expect(validation.ok).toBe(false);
    if (!validation.ok) {
        expect(validation.errors.map((error) => error.code)).toEqual(
            expectedCodes,
        );
    }
};

describe('protocol-shell poll-spec validation', () => {
    it('normalizes the supported score domain and policies', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                scoreDomain: {
                    min: 1,
                    max: 10,
                    skippedOptionScore: 1,
                },
                duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
                tiePolicy: 'HigherScoreThenLowerOptionIndex',
            }),
        );

        expect(validation).toEqual({
            ok: true,
            normalized: createValidPollSpecInput({
                scoreDomain: {
                    min: 1,
                    max: 10,
                    skippedOptionScore: 1,
                },
                duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
                tiePolicy: 'HigherScoreThenLowerOptionIndex',
            }),
        });
    });

    it('applies default score and policy choices', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                options: ['A', 'B', 'C'],
                kTop: 2,
            }),
        );

        expect(validation).toMatchObject({
            ok: true,
            normalized: {
                scoreDomain: {
                    min: 1,
                    max: 10,
                    skippedOptionScore: 1,
                },
                duplicateBallotPolicy: 'LastValidBeforeVotingClosedCounts',
                tiePolicy: 'HigherScoreThenLowerOptionIndex',
            },
        });
    });

    it('rejects option count, question, kTop, score, and policy errors', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                ceremonyId: '',
                question: '',
                options: [],
                kTop: 0,
                scoreDomain: {
                    min: 1,
                    max: 9,
                    skippedOptionScore: 1,
                } as unknown as PollSpecInput['scoreDomain'],
                duplicateBallotPolicy:
                    'FirstBallotCounts' as PollSpecInput['duplicateBallotPolicy'],
                tiePolicy: 'RandomTieBreak' as PollSpecInput['tiePolicy'],
            }),
            [
                'EmptyCeremonyId',
                'EmptyQuestion',
                'InvalidOptionCount',
                'InvalidKTop',
                'UnsupportedScoreDomain',
                'UnsupportedDuplicateBallotPolicy',
                'UnsupportedTiePolicy',
            ],
        );
    });

    it('returns structured errors for malformed JavaScript input', () => {
        const decodedPollSpec: unknown = {
            ceremonyId: 'ceremony',
            question: 'Question',
            options: ['A', 42, 'B'],
            kTop: 2,
        };

        expectErrorCodes({}, [
            'EmptyCeremonyId',
            'EmptyQuestion',
            'InvalidOptionCount',
            'InvalidKTop',
        ]);

        expectErrorCodes(decodedPollSpec, ['EmptyOptionLabel']);
    });

    it('rejects too many options and kTop larger than the option count', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                options: Array.from(
                    { length: 21 },
                    (_value, index) => `Option ${index}`,
                ),
                kTop: 22,
            }),
            ['InvalidOptionCount', 'InvalidKTop'],
        );
    });

    it('rejects empty and duplicate option labels by exact comparison', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                options: ['Alpha', '', 'Alpha', 'Ａlpha'],
                kTop: 1,
            }),
            ['EmptyOptionLabel', 'DuplicateOptionLabel'],
        );
    });

    it('accepts visually similar but byte-distinct option labels', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                options: ['Alpha', 'Ａlpha'],
                kTop: 1,
            }),
        );

        expect(validation.ok).toBe(true);
    });
});
