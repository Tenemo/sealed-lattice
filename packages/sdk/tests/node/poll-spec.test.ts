import { configurableOptionCountRange } from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

import { createMaximumAcceptedPollSpec } from '../maximum-manifest-fixture.js';

import {
    foundationManifestInputFromPollSpec,
    validatePollSpec,
    type PollSpec,
} from '#packages/sdk/src/poll-spec';

const prototypeOptionCount = 10;
// A poll has 2 to 20 options.
const goalOptionCountRange = { minimum: 2, maximum: 20 } as const;

const validPollSpec = (
    optionCount: number = prototypeOptionCount,
): PollSpec => ({
    question: 'Select priorities',
    options: Array.from(
        { length: optionCount },
        (_value, optionIndex) => `Option ${String(optionIndex)}`,
    ),
});

const errorCodes = (input: unknown): readonly string[] => {
    const validation = validatePollSpec(input);
    expect(validation.isValid).toBe(false);
    return validation.isValid
        ? []
        : validation.errors.map((error) => error.code);
};

describe('poll input validation', () => {
    it('accepts every supported option count and derives deterministic manifest input', () => {
        expect(configurableOptionCountRange).toEqual(goalOptionCountRange);
        for (
            let optionCount = goalOptionCountRange.minimum;
            optionCount <= goalOptionCountRange.maximum;
            optionCount += 1
        ) {
            const input = validPollSpec(optionCount);
            expect(validatePollSpec(input)).toEqual({
                isValid: true,
                normalized: input,
            });
        }

        const manifestInput =
            foundationManifestInputFromPollSpec(validPollSpec());
        expect(manifestInput.optionDefinitions[0]).toEqual({
            displayLabel: 'Option 0',
            optionIdentifier: 'option-0',
            optionIndex: 0,
        });
        expect(
            manifestInput.optionDefinitions[
                manifestInput.optionDefinitions.length - 1
            ],
        ).toEqual({
            displayLabel: 'Option 9',
            optionIdentifier: 'option-9',
            optionIndex: 9,
        });
    });

    it('rejects unsupported counts, empty or duplicate labels, and malformed Unicode', () => {
        expect(errorCodes({ question: '', options: [] })).toEqual([
            'EmptyQuestion',
            'InvalidOptionCount',
        ]);
        for (const optionCount of [
            goalOptionCountRange.minimum - 1,
            goalOptionCountRange.maximum + 1,
        ]) {
            expect(errorCodes(validPollSpec(optionCount))).toEqual([
                'InvalidOptionCount',
            ]);
        }
        expect(
            errorCodes({
                question: '\ud800',
                options: ['same', 'same'],
            }),
        ).toEqual(['UnsupportedHashCriticalText', 'DuplicateOptionLabel']);
        expect(
            errorCodes({ question: 'Question', options: ['valid', ''] }),
        ).toEqual(['EmptyOptionLabel']);
    });

    it('compares labels in the normalized form the kernel stores', () => {
        expect(
            errorCodes({
                question: 'Question',
                options: ['caf\u00e9', 'cafe\u0301', 'other'],
            }),
        ).toEqual(['DuplicateOptionLabel']);
        expect(
            validatePollSpec({
                question: 'Question',
                options: ['caf\u00e9', 'cafe', 'Caf\u00e9'],
            }).isValid,
        ).toBe(true);
    });

    it('reserves the command response framing at the exact display-text ceiling', () => {
        const exactPollSpec = createMaximumAcceptedPollSpec();

        expect(validatePollSpec(exactPollSpec).isValid).toBe(true);
        expect(
            errorCodes({
                ...exactPollSpec,
                question: `${exactPollSpec.question}Q`,
            }),
        ).toEqual(['UnsupportedHashCriticalText']);
        // U+0958 has three UTF-8 bytes but six under NFC, so the question
        // leaves too little of the budget for the final two labels.
        const expanded = validatePollSpec({
            ...exactPollSpec,
            question: `${exactPollSpec.question.slice(3)}\u0958`,
        });
        expect(
            expanded.isValid
                ? []
                : expanded.errors.map(({ code, field }) => [code, field]),
        ).toEqual([
            ['UnsupportedHashCriticalText', 'options[8]'],
            ['UnsupportedHashCriticalText', 'options[9]'],
        ]);
    });
});
