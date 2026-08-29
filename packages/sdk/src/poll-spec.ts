import {
    configurableOptionCountRange,
    maximumFoundationCopiedBufferByteLength,
    type FoundationManifestInput,
} from '@sealed-lattice/wasm';

export type PollSpec = Readonly<{
    readonly question: string;
    readonly options: readonly string[];
}>;

export type PollSpecValidationErrorCode =
    | 'EmptyQuestion'
    | 'UnsupportedHashCriticalText'
    | 'InvalidOptionCount'
    | 'EmptyOptionLabel'
    | 'DuplicateOptionLabel';

export type PollSpecValidationError = Readonly<{
    readonly code: PollSpecValidationErrorCode;
    readonly field: string;
    readonly message: string;
}>;

export type PollSpecValidation =
    | Readonly<{
          readonly isValid: true;
          readonly normalized: PollSpec;
      }>
    | Readonly<{
          readonly isValid: false;
          readonly errors: readonly PollSpecValidationError[];
      }>;

const textEncoder = new TextEncoder();

const canonicalManifestNonDisplayByteLength = (optionCount: number): number =>
    30 +
    36 * optionCount +
    Array.from({ length: optionCount }, (_, optionIndex) =>
        textEncoder.encode(`option-${String(optionIndex)}`),
    ).reduce((byteLength, identifier) => byteLength + identifier.byteLength, 0);

export const validatePollSpec = (input: unknown): PollSpecValidation => {
    const errors: PollSpecValidationError[] = [];
    const optionLabels = new Set<string>();
    const inputRecord =
        input !== null && typeof input === 'object'
            ? (input as Readonly<Record<string, unknown>>)
            : {};
    const question = inputRecord.question;
    const rawOptions = inputRecord.options;
    const validatedOptions: string[] = [];

    const options = Array.isArray(rawOptions)
        ? (rawOptions as readonly unknown[])
        : undefined;
    const optionCount = options?.length ?? 0;

    const optionCountIsSupported =
        options !== undefined &&
        optionCount >= configurableOptionCountRange.minimum &&
        optionCount <= configurableOptionCountRange.maximum;
    const framedOptionCount = optionCountIsSupported
        ? optionCount
        : configurableOptionCountRange.maximum;
    let remainingDisplayTextByteLength =
        maximumFoundationCopiedBufferByteLength -
        canonicalManifestNonDisplayByteLength(framedOptionCount);
    const consumeDisplayTextBytes = (value: string): boolean => {
        const byteLength = textEncoder.encode(value).byteLength;
        if (byteLength > remainingDisplayTextByteLength) {
            return false;
        }
        remainingDisplayTextByteLength -= byteLength;
        return true;
    };

    if (typeof question !== 'string' || question.length === 0) {
        errors.push({
            code: 'EmptyQuestion',
            field: 'question',
            message: 'question must be a nonempty string.',
        });
    } else if (!question.isWellFormed() || !consumeDisplayTextBytes(question)) {
        errors.push({
            code: 'UnsupportedHashCriticalText',
            field: 'question',
            message:
                'question must be well-formed Unicode and fit the display-text budget.',
        });
    }

    if (!optionCountIsSupported) {
        errors.push({
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must contain between 2 and 20 labels.',
        });
    }

    for (
        let optionIndex = 0;
        options !== undefined &&
        optionCountIsSupported &&
        optionIndex < optionCount;
        optionIndex += 1
    ) {
        const optionLabel = options[optionIndex];
        if (typeof optionLabel !== 'string' || optionLabel.length === 0) {
            errors.push({
                code: 'EmptyOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be nonempty strings.',
            });
            continue;
        }
        if (
            !optionLabel.isWellFormed() ||
            !consumeDisplayTextBytes(optionLabel)
        ) {
            errors.push({
                code: 'UnsupportedHashCriticalText',
                field: `options[${optionIndex}]`,
                message:
                    'option labels must be well-formed Unicode and fit the display-text budget.',
            });
            continue;
        }
        if (optionLabels.has(optionLabel)) {
            errors.push({
                code: 'DuplicateOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be unique.',
            });
        }

        optionLabels.add(optionLabel);
        validatedOptions.push(optionLabel);
    }

    if (errors.length > 0) {
        return { isValid: false, errors };
    }

    return {
        isValid: true,
        normalized: {
            question: typeof question === 'string' ? question : '',
            options: validatedOptions,
        },
    };
};

export const foundationManifestInputFromPollSpec = (
    pollSpec: PollSpec,
): FoundationManifestInput => ({
    displayTitle: pollSpec.question,
    optionDefinitions: pollSpec.options.map((displayLabel, optionIndex) => ({
        displayLabel,
        optionIdentifier: `option-${String(optionIndex)}`,
        optionIndex,
    })),
});
