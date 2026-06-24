import type { PollSpecInput } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { validatePollSpec } from '#packages/protocol/src/lifecycle/poll-spec';

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
    const validation = validatePollSpec(input);

    expect(validation.ok).toBe(false);
    if (!validation.ok) {
        expect(validation.errors.map((error) => error.code)).toEqual(
            expectedCodes,
        );
    }
};

describe('election foundation poll-spec validation', () => {
    it('normalizes the supported score domain and policies', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                scoreDomain: {
                    min: 1,
                    max: 10,
                    skippedOptionScore: 1,
                },
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
                maxRosterSize: 20,
                minRosterSize: 10,
                smallRosterPolicy: 'ForbidMicroRoster',
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
                maxRosterSize: 20,
                minRosterSize: 10,
                smallRosterPolicy: 'ForbidMicroRoster',
            },
        });
    });

    it('accepts explicit roster bounds and parameter family policy', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                maxRosterSize: 20,
                minRosterSize: 11,
                smallRosterPolicy: 'WarnMicroRoster',
            }),
        );

        expect(validation).toMatchObject({
            ok: true,
            normalized: {
                maxRosterSize: 20,
                minRosterSize: 11,
                smallRosterPolicy: 'WarnMicroRoster',
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
            }),
            [
                'EmptyPollId',
                'EmptyQuestion',
                'InvalidOptionCount',
                'InvalidTopOptionCount',
                'UnsupportedScoreDomain',
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

    it('returns structured errors for non-number top option counts', () => {
        expectErrorCodes(
            {
                pollId: 'poll',
                question: 'Question',
                options: ['A', 'B'],
                topOptionCount: 1n,
            },
            ['InvalidTopOptionCount'],
        );
    });

    it('rejects unsupported roster policy and invalid roster bounds', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                maxRosterSize: 2,
                minRosterSize: 51,
                smallRosterPolicy:
                    'SilentMicroRoster' as PollSpecInput['smallRosterPolicy'],
            }),
            ['UnsupportedSmallRosterPolicy', 'InvalidRosterBounds'],
        );
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

    it('rejects empty and duplicate option labels after Unicode normalization', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                options: [
                    'Alpha',
                    '',
                    'Alpha',
                    'Alpha ',
                    'Cafe\u0301',
                    'Caf\u00e9',
                ],
                topOptionCount: 1,
            }),
            [
                'EmptyOptionLabel',
                'DuplicateOptionLabel',
                'DuplicateOptionLabel',
            ],
        );
    });

    it('accepts labels that differ only by trailing whitespace after normalization', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                options: ['Alpha', 'Alpha '],
                topOptionCount: 1,
            }),
        );

        expect(validation.ok).toBe(true);
    });
});
