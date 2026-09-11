import { configurableOptionCountRange } from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

import { createMaximumAcceptedPollSpec } from '../maximum-manifest-fixture.js';

import {
    foundationManifestInputFromPollSpec,
    validatePollSpec,
    type PollSpec,
} from '#packages/sdk/src/poll-spec';

const prototypeOptionCount = 10;

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
        for (
            let optionCount = configurableOptionCountRange.minimum;
            optionCount <= configurableOptionCountRange.maximum;
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

    it('reserves the command response framing at the exact display-text ceiling', () => {
        const exactPollSpec = createMaximumAcceptedPollSpec();

        expect(validatePollSpec(exactPollSpec).isValid).toBe(true);
        expect(
            errorCodes({
                ...exactPollSpec,
                question: `${exactPollSpec.question}Q`,
            }),
        ).toEqual(['UnsupportedHashCriticalText']);
    });
});
