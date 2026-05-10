import { describe, expect, it } from 'vitest';

import {
    validatePollSpec,
    validatePollSpecFromUnknown,
} from '../../src/protocol-shell/index';
import type { PollSpecInput } from '../../src/protocol-shell/index';

const createValidPollSpecInput = (
    overrides: Partial<PollSpecInput> = {},
): PollSpecInput => ({
    pollId: 'poll-2026-board',
    question: 'Select the top priorities',
    options: Array.from({ length: 20 }, (_value, index) => `Option ${index}`),
    topOptionCount: 20,
    ...overrides,
});

const expectErrorCodes = (
    input: unknown,
    expectedCodes: readonly string[],
): void => {
    const validation = validatePollSpecFromUnknown(input);

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
                topOptionCount: 2,
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

    it('rejects option count, question, topOptionCount, score, and policy errors', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                pollId: '',
                question: '',
                options: [],
                topOptionCount: 0,
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
                'EmptyPollId',
                'EmptyQuestion',
                'InvalidOptionCount',
                'InvalidTopOptionCount',
                'UnsupportedScoreDomain',
                'UnsupportedDuplicateBallotPolicy',
                'UnsupportedTiePolicy',
            ],
        );
    });

    it('returns structured errors for malformed JavaScript input', () => {
        const decodedPollSpec: unknown = {
            pollId: 'poll',
            question: 'Question',
            options: ['A', 42, 'B'],
            topOptionCount: 2,
        };

        expectErrorCodes({}, [
            'EmptyPollId',
            'EmptyQuestion',
            'InvalidOptionCount',
            'InvalidTopOptionCount',
        ]);

        expectErrorCodes(decodedPollSpec, ['EmptyOptionLabel']);
    });

    it('rejects too many options and topOptionCount larger than the option count', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                options: Array.from(
                    { length: 21 },
                    (_value, index) => `Option ${index}`,
                ),
                topOptionCount: 22,
            }),
            ['InvalidOptionCount', 'InvalidTopOptionCount'],
        );
    });

    it('rejects empty and duplicate option labels by exact comparison', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                options: ['Alpha', '', 'Alpha', 'Alpha '],
                topOptionCount: 1,
            }),
            ['EmptyOptionLabel', 'DuplicateOptionLabel'],
        );
    });

    it('accepts labels that differ only by trailing whitespace under exact comparison', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                options: ['Alpha', 'Alpha '],
                topOptionCount: 1,
            }),
        );

        expect(validation.ok).toBe(true);
    });
});
