import {
    configurableOptionCountRange,
    foundationProfile,
    type FoundationManifestInput,
} from '@sealed-lattice/wasm/published-sdk';

const invalidDataProperty = Symbol('invalid-data-property');

type OwnPropertyDescriptors = Readonly<Record<PropertyKey, PropertyDescriptor>>;

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

const ownPropertyDescriptors = (
    value: object,
): OwnPropertyDescriptors | undefined => {
    try {
        return Object.getOwnPropertyDescriptors(value);
    } catch {
        return undefined;
    }
};

const ordinaryRecordDescriptors = (
    value: unknown,
): OwnPropertyDescriptors | undefined => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return undefined;
    }
    try {
        const prototype = Reflect.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            return undefined;
        }
    } catch {
        return undefined;
    }

    return ownPropertyDescriptors(value);
};

const dataPropertyValue = (
    descriptors: OwnPropertyDescriptors | undefined,
    propertyName: string,
): unknown => {
    const descriptor = descriptors?.[propertyName];
    if (descriptor === undefined) {
        return undefined;
    }

    return 'value' in descriptor ? descriptor.value : invalidDataProperty;
};

const isWellFormedString = (value: string): boolean => {
    for (
        let codeUnitIndex = 0;
        codeUnitIndex < value.length;
        codeUnitIndex += 1
    ) {
        const codeUnit = value.charCodeAt(codeUnitIndex);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const followingCodeUnit = value.charCodeAt(codeUnitIndex + 1);
            if (
                codeUnitIndex + 1 >= value.length ||
                followingCodeUnit < 0xdc00 ||
                followingCodeUnit > 0xdfff
            ) {
                return false;
            }
            codeUnitIndex += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return false;
        }
    }
    return true;
};

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
    const inputDescriptors = ordinaryRecordDescriptors(input);
    const question = dataPropertyValue(inputDescriptors, 'question');
    const rawOptions = dataPropertyValue(inputDescriptors, 'options');
    const validatedOptions: string[] = [];

    let optionCount = 0;
    let optionDescriptors: OwnPropertyDescriptors | undefined;
    if (Array.isArray(rawOptions)) {
        try {
            const prototype = Reflect.getPrototypeOf(rawOptions);
            if (prototype === Array.prototype || prototype === null) {
                optionDescriptors = ownPropertyDescriptors(rawOptions);
            }
        } catch {
            optionDescriptors = undefined;
        }
        const lengthDescriptor = optionDescriptors?.length;
        if (
            lengthDescriptor !== undefined &&
            'value' in lengthDescriptor &&
            Number.isSafeInteger(lengthDescriptor.value) &&
            lengthDescriptor.value >= 0
        ) {
            optionCount = lengthDescriptor.value as number;
        } else {
            optionDescriptors = undefined;
        }
    }

    const optionCountIsSupported =
        optionCount >= configurableOptionCountRange.minimum &&
        optionCount <= configurableOptionCountRange.maximum;
    const framedOptionCount = optionCountIsSupported
        ? optionCount
        : configurableOptionCountRange.maximum;
    let remainingDisplayTextByteLength =
        foundationProfile.maximumCopiedBufferByteLength -
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
    } else if (
        !isWellFormedString(question) ||
        !consumeDisplayTextBytes(question)
    ) {
        errors.push({
            code: 'UnsupportedHashCriticalText',
            field: 'question',
            message:
                'question must be well-formed Unicode and fit the display-text budget.',
        });
    }

    if (optionDescriptors === undefined || !optionCountIsSupported) {
        errors.push({
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must contain between 2 and 20 labels.',
        });
    }

    for (
        let optionIndex = 0;
        optionDescriptors !== undefined &&
        optionCountIsSupported &&
        optionIndex < optionCount;
        optionIndex += 1
    ) {
        const optionLabel = dataPropertyValue(
            optionDescriptors,
            String(optionIndex),
        );
        if (typeof optionLabel !== 'string' || optionLabel.length === 0) {
            errors.push({
                code: 'EmptyOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be nonempty strings.',
            });
            continue;
        }
        if (
            !isWellFormedString(optionLabel) ||
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
): FoundationManifestInput =>
    Object.freeze({
        displayTitle: pollSpec.question,
        optionDefinitions: Object.freeze(
            pollSpec.options.map((displayLabel, optionIndex) =>
                Object.freeze({
                    displayLabel,
                    optionIdentifier: `option-${String(optionIndex)}`,
                    optionIndex,
                }),
            ),
        ),
    });
