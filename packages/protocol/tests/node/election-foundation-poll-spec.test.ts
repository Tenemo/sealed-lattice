import {
    configurableOptionCountRange,
    foundationProfile,
    type PollSpecInput,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    prepareFoundationManifestIngress,
    validatePollSpec,
} from '#packages/protocol/src/lifecycle/poll-spec';

const createValidPollSpecInput = (
    overrides: Partial<PollSpecInput> = {},
): PollSpecInput => {
    const optionCount =
        overrides.options?.length ?? foundationProfile.optionCount;
    return {
        pollId: 'poll-2026-board',
        question: 'Select the top priorities',
        options: Array.from(
            { length: optionCount },
            (_value, index) => `Option ${index}`,
        ),
        topOptionCount: optionCount,
        ...overrides,
    };
};

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

describe('pre-protocol poll input validation', () => {
    it('accepts every bounded option count and refuses counts outside the family', () => {
        for (
            let optionCount = configurableOptionCountRange.minimum;
            optionCount <= configurableOptionCountRange.maximum;
            optionCount += 1
        ) {
            const input = createValidPollSpecInput({
                options: Array.from(
                    { length: optionCount },
                    (_value, optionIndex) => `Option ${optionIndex}`,
                ),
                topOptionCount: optionCount,
            });
            expect(validatePollSpec(input)).toEqual({
                isValid: true,
                normalized: input,
            });
        }

        expectErrorCodes(
            createValidPollSpecInput({
                options: ['Only option'],
                topOptionCount: 1,
            }),
            ['InvalidOptionCount'],
        );
        expectErrorCodes(
            createValidPollSpecInput({
                options: Array.from(
                    { length: configurableOptionCountRange.maximum + 1 },
                    (_value, optionIndex) => `Option ${optionIndex}`,
                ),
            }),
            ['InvalidOptionCount'],
        );
    });

    it('deterministically assigns canonical option indexes and identifiers', () => {
        const validation = validatePollSpec(createValidPollSpecInput());
        expect(validation.isValid).toBe(true);
        if (!validation.isValid) {
            return;
        }

        const ingress = prepareFoundationManifestIngress(validation.normalized);
        expect(ingress.displayTitle).toBe(validation.normalized.question);
        expect(ingress.optionDefinitions).toHaveLength(
            foundationProfile.optionCount,
        );
        expect(ingress.optionDefinitions[0]).toEqual({
            displayLabel: 'Option 0',
            optionIdentifier: 'option-0',
            optionIndex: 0,
        });
        expect(ingress.optionDefinitions[9]).toEqual({
            displayLabel: 'Option 9',
            optionIdentifier: 'option-9',
            optionIndex: 9,
        });
    });

    it('confines pre-protocol identifiers and top counts outside canonical manifest ingress', () => {
        const firstValidation = validatePollSpec(
            createValidPollSpecInput({
                pollId: 'display-flow-a',
                topOptionCount: 3,
            }),
        );
        const secondValidation = validatePollSpec(
            createValidPollSpecInput({
                pollId: 'display-flow-b',
                topOptionCount: 7,
            }),
        );
        expect(firstValidation.isValid).toBe(true);
        expect(secondValidation.isValid).toBe(true);
        if (!firstValidation.isValid || !secondValidation.isValid) {
            return;
        }

        const firstIngress = prepareFoundationManifestIngress(
            firstValidation.normalized,
        );
        const secondIngress = prepareFoundationManifestIngress(
            secondValidation.normalized,
        );
        expect(firstIngress).toEqual(secondIngress);
        expect(Object.keys(firstIngress)).toEqual([
            'displayTitle',
            'optionDefinitions',
        ]);
    });

    it('ignores untrusted protocol identity fields without invoking their accessors', () => {
        let accessorInvocations = 0;
        const untrustedInput = createValidPollSpecInput() as Record<
            string,
            unknown
        >;
        Object.defineProperties(untrustedInput, {
            actionIdentifier: {
                enumerable: true,
                get: () => {
                    accessorInvocations += 1;
                    return 'untrusted-action';
                },
            },
            ceremonyIdentifier: {
                enumerable: true,
                get: () => {
                    accessorInvocations += 1;
                    return 'untrusted-ceremony';
                },
            },
            suiteIdentifier: {
                enumerable: true,
                get: () => {
                    accessorInvocations += 1;
                    return 'untrusted-suite';
                },
            },
        });

        const directIngress = prepareFoundationManifestIngress(
            untrustedInput as unknown as PollSpecInput,
        );
        const validation = validatePollSpec(untrustedInput);
        expect(validation.isValid).toBe(true);
        expect(accessorInvocations).toBe(0);
        if (!validation.isValid) {
            return;
        }

        expect(Object.keys(validation.normalized)).toEqual([
            'pollId',
            'question',
            'options',
            'topOptionCount',
        ]);
        const expectedIngress = prepareFoundationManifestIngress(
            createValidPollSpecInput(),
        );
        expect(directIngress).toEqual(expectedIngress);
        expect(prepareFoundationManifestIngress(validation.normalized)).toEqual(
            expectedIngress,
        );
        expect(accessorInvocations).toBe(0);
    });

    it('rejects missing identifiers, labels, options, and top counts', () => {
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

    it('returns structured errors for hostile JavaScript input without invoking accessors', () => {
        let accessorInvocations = 0;
        const input = createValidPollSpecInput() as Record<string, unknown>;
        Object.defineProperty(input, 'question', {
            get: () => {
                accessorInvocations += 1;
                return 'Question';
            },
        });

        expectErrorCodes(input, ['EmptyQuestion']);
        expect(accessorInvocations).toBe(0);
        expectErrorCodes({}, [
            'EmptyPollId',
            'EmptyQuestion',
            'InvalidOptionCount',
            'InvalidTopOptionCount',
        ]);
    });

    it('rejects empty and duplicate labels but accepts assigned Unicode display text', () => {
        const options = createValidPollSpecInput().options.slice();
        options[1] = '';
        options[2] = 'Option 0';
        expectErrorCodes(createValidPollSpecInput({ options }), [
            'EmptyOptionLabel',
            'DuplicateOptionLabel',
        ]);

        const validation = validatePollSpec(
            createValidPollSpecInput({
                question: 'Wybór priorytetów',
                options: Array.from(
                    { length: foundationProfile.optionCount },
                    (_value, index) => `Opcja ${String(index)} ł`,
                ),
            }),
        );
        expect(validation.isValid).toBe(true);
    });

    it('rejects non-printable identifiers and malformed Unicode display text', () => {
        expectErrorCodes(
            createValidPollSpecInput({ pollId: 'poll\nsecond-line' }),
            ['UnsupportedHashCriticalText'],
        );
        expectErrorCodes(createValidPollSpecInput({ question: '\ud800' }), [
            'UnsupportedHashCriticalText',
        ]);
    });

    it('enforces the identifier and aggregate display-text byte budgets', () => {
        expectErrorCodes(
            createValidPollSpecInput({
                pollId: 'p'.repeat(
                    foundationProfile.maximumIdentifierByteLength + 1,
                ),
            }),
            ['UnsupportedHashCriticalText'],
        );

        const optionLabels = Array.from(
            { length: foundationProfile.optionCount },
            (_value, index) => `O${String(index)}`,
        );
        const optionByteLength = optionLabels.reduce(
            (total, label) => total + new TextEncoder().encode(label).length,
            0,
        );
        const canonicalManifestNonDisplayByteLength =
            30 +
            36 * foundationProfile.optionCount +
            Array.from(
                { length: foundationProfile.optionCount },
                (_value, optionIndex) => `option-${String(optionIndex)}`,
            ).reduce(
                (byteLength, identifier) =>
                    byteLength + new TextEncoder().encode(identifier).length,
                0,
            );
        const exactBudgetValidation = validatePollSpec(
            createValidPollSpecInput({
                options: optionLabels,
                question: 'Q'.repeat(
                    foundationProfile.maximumCopiedBufferByteLength -
                        canonicalManifestNonDisplayByteLength -
                        optionByteLength,
                ),
            }),
        );
        expect(exactBudgetValidation.isValid).toBe(true);

        expectErrorCodes(
            createValidPollSpecInput({
                options: optionLabels,
                question: 'Q'.repeat(
                    foundationProfile.maximumCopiedBufferByteLength -
                        canonicalManifestNonDisplayByteLength -
                        optionByteLength +
                        1,
                ),
            }),
            ['UnsupportedHashCriticalText'],
        );
    });
});
