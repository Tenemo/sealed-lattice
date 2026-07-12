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
            isValid: true,
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
            isValid: true,
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
            isValid: true,
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

    it('does not execute poll, option, or score-domain accessors', () => {
        let accessorReadCount = 0;
        const pollWithAccessor = createValidPollSpecInput();
        Object.defineProperty(pollWithAccessor, 'pollId', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'executed';
            },
        });
        const optionAccessor = ['Alpha', 'Beta'];
        Object.defineProperty(optionAccessor, '1', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'executed';
            },
        });
        const scoreDomainWithAccessor: Record<string, unknown> = {
            max: 10,
            skippedOptionScore: 1,
        };
        Object.defineProperty(scoreDomainWithAccessor, 'min', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 1;
            },
        });

        expectErrorCodes(pollWithAccessor, ['EmptyPollId']);
        expectErrorCodes(
            createValidPollSpecInput({
                options: optionAccessor,
                topOptionCount: 1,
            }),
            ['EmptyOptionLabel'],
        );
        expectErrorCodes(
            createValidPollSpecInput({
                scoreDomain:
                    scoreDomainWithAccessor as PollSpecInput['scoreDomain'],
            }),
            ['UnsupportedScoreDomain'],
        );
        expect(accessorReadCount).toBe(0);
    });

    it('rejects sparse options and custom score-domain prototypes', () => {
        const sparseOptions = new Array<string>(2);
        sparseOptions[0] = 'Alpha';
        const customScoreDomain = Object.create({ min: 1 }) as Record<
            string,
            number
        >;
        customScoreDomain.max = 10;
        customScoreDomain.skippedOptionScore = 1;

        expectErrorCodes(
            createValidPollSpecInput({
                options: sparseOptions,
                topOptionCount: 1,
            }),
            ['EmptyOptionLabel'],
        );
        expectErrorCodes(
            createValidPollSpecInput({
                scoreDomain: customScoreDomain as PollSpecInput['scoreDomain'],
            }),
            ['UnsupportedScoreDomain'],
        );
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

    it('accepts ASCII labels that differ only by trailing whitespace', () => {
        const validation = validatePollSpec(
            createValidPollSpecInput({
                options: ['Alpha', 'Alpha '],
                topOptionCount: 1,
            }),
        );

        expect(validation.isValid).toBe(true);
    });
});
