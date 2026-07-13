import { foundationProfile, type PollSpecInput } from '@sealed-lattice/types';
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

    expect(validation.isValid).toBe(false);
    if (!validation.isValid) {
        expect(validation.errors.map((error) => error.code)).toEqual(
            expectedCodes,
        );
    }
};

describe('election foundation poll-spec validation', () => {
    it('normalizes roster bounds and policy', () => {
        const validation = validatePollSpec(createValidPollSpecInput());

        expect(validation).toEqual({
            isValid: true,
            normalized: createValidPollSpecInput({
                maxRosterSize: 20,
                minRosterSize: 10,
                smallRosterPolicy: 'ForbidMicroRoster',
            }),
        });
    });

    it('applies default roster choices', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                options: ['A', 'B', 'C'],
                topOptionCount: 2,
            }),
        );

        expect(validation).toMatchObject({
            isValid: true,
            normalized: {
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
                smallRosterPolicy: 'AllowMicroRoster',
            }),
        );

        expect(validation).toMatchObject({
            isValid: true,
            normalized: {
                maxRosterSize: 20,
                minRosterSize: 11,
                smallRosterPolicy: 'AllowMicroRoster',
            },
        });
    });

    it('rejects option count, question, and topOptionCount errors', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                pollId: '',
                question: '',
                options: [],
                topOptionCount: 0,
            }),
            [
                'EmptyPollId',
                'EmptyQuestion',
                'InvalidOptionCount',
                'InvalidTopOptionCount',
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

    it('rejects empty, duplicate, and non-ASCII hash-critical text', () => {
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
                'UnsupportedHashCriticalText',
                'UnsupportedHashCriticalText',
            ],
        );

        expectErrorCodes(
            createValidPollSpecInput({
                pollId: 'g\u0142osowanie',
                question: 'Wyb\u00f3r',
            }),
            ['UnsupportedHashCriticalText', 'UnsupportedHashCriticalText'],
        );
    });

    it('enforces the identifier and aggregate display-text budgets', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                pollId: 'p'.repeat(
                    foundationProfile.maximumIdentifierByteLength + 1,
                ),
            }),
            ['UnsupportedHashCriticalText'],
        );

        const exactBudgetValidation = validatePollSpec(
            createValidPollSpecInput({
                options: ['A'],
                question: 'Q'.repeat(
                    foundationProfile.maximumCopiedBufferByteLength - 1,
                ),
                topOptionCount: 1,
            }),
        );
        expect(exactBudgetValidation.isValid).toBe(true);

        expectErrorCodes(
            createValidPollSpecInput({
                options: ['A'],
                question: 'Q'.repeat(
                    foundationProfile.maximumCopiedBufferByteLength,
                ),
                topOptionCount: 1,
            }),
            ['UnsupportedHashCriticalText'],
        );
    });
});
