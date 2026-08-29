import {
    configurableOptionCountRange,
    maximumFoundationCopiedBufferByteLength,
} from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

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

    it('enforces the exact aggregate display-text byte ceiling', () => {
        const options = Array.from(
            { length: prototypeOptionCount },
            (_value, optionIndex) => `O${String(optionIndex)}`,
        );
        const encoder = new TextEncoder();
        const optionBytes = options.reduce(
            (total, label) => total + encoder.encode(label).byteLength,
            0,
        );
        const framingBytes =
            30 +
            36 * prototypeOptionCount +
            Array.from(
                { length: prototypeOptionCount },
                (_value, optionIndex) => `option-${String(optionIndex)}`,
            ).reduce(
                (total, identifier) =>
                    total + encoder.encode(identifier).byteLength,
                0,
            );
        const exactQuestion = 'Q'.repeat(
            maximumFoundationCopiedBufferByteLength -
                framingBytes -
                optionBytes,
        );

        expect(
            validatePollSpec({ question: exactQuestion, options }).isValid,
        ).toBe(true);
        expect(errorCodes({ question: `${exactQuestion}Q`, options })).toEqual([
            'UnsupportedHashCriticalText',
        ]);
    });
});
