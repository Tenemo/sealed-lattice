import {
    configurableOptionCountRange,
    foundationProfile,
    type PollSpec,
    type PollSpecValidation,
    type PollSpecValidationError,
} from '@sealed-lattice/types';
import type { FoundationManifestInput } from '@sealed-lattice/wasm';

const invalidDataProperty = Symbol('invalid-data-property');

type OwnPropertyDescriptors = Readonly<Record<PropertyKey, PropertyDescriptor>>;

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

const containsOnlyPrintableAsciiCharacters = (value: string): boolean => {
    for (
        let characterIndex = 0;
        characterIndex < value.length;
        characterIndex += 1
    ) {
        const characterCode = value.charCodeAt(characterIndex);
        if (characterCode < 0x20 || characterCode > 0x7e) {
            return false;
        }
    }
    return true;
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

// The Rust tuple codec remains authoritative. This mirrors only its fixed
// framing and the deterministic option identifiers so ingress can enforce the
// same copied-buffer budget before crossing the WASM boundary.
const canonicalManifestNonDisplayByteLength = (optionCount: number): number =>
    30 +
    36 * optionCount +
    Array.from({ length: optionCount }, (_, optionIndex) =>
        textEncoder.encode(`option-${String(optionIndex)}`),
    ).reduce((byteLength, identifier) => byteLength + identifier.byteLength, 0);

export const validatePollSpec = (input: unknown): PollSpecValidation => {
    const errors: PollSpecValidationError[] = [];
    const optionLabels = new Set<string>();
    const inputRecordDescriptors = ordinaryRecordDescriptors(input);
    const pollId = dataPropertyValue(inputRecordDescriptors, 'pollId');
    const question = dataPropertyValue(inputRecordDescriptors, 'question');
    const rawOptions = dataPropertyValue(inputRecordDescriptors, 'options');
    const topOptionCount = dataPropertyValue(
        inputRecordDescriptors,
        'topOptionCount',
    );
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

    const structurallyBoundedOptionCount =
        optionCount >= configurableOptionCountRange.minimum &&
        optionCount <= configurableOptionCountRange.maximum;
    const framingOptionCount = structurallyBoundedOptionCount
        ? optionCount
        : configurableOptionCountRange.maximum;
    let remainingDisplayTextByteLength =
        foundationProfile.maximumCopiedBufferByteLength -
        canonicalManifestNonDisplayByteLength(framingOptionCount);
    const consumeDisplayTextByteLength = (value: string): boolean => {
        const byteLength = textEncoder.encode(value).byteLength;
        if (byteLength > remainingDisplayTextByteLength) {
            return false;
        }
        remainingDisplayTextByteLength -= byteLength;

        return true;
    };

    if (typeof pollId !== 'string' || pollId.length === 0) {
        errors.push({
            code: 'EmptyPollId',
            field: 'pollId',
            message: 'pollId must be a nonempty string.',
        });
    } else if (
        pollId.length > foundationProfile.maximumIdentifierByteLength ||
        !containsOnlyPrintableAsciiCharacters(pollId)
    ) {
        errors.push({
            code: 'UnsupportedHashCriticalText',
            field: 'pollId',
            message:
                'pollId must contain only printable ASCII characters and fit the foundation identifier limit.',
        });
    }
    if (typeof question !== 'string' || question.length === 0) {
        errors.push({
            code: 'EmptyQuestion',
            field: 'question',
            message: 'question must be a nonempty string.',
        });
    } else if (
        !isWellFormedString(question) ||
        !consumeDisplayTextByteLength(question)
    ) {
        errors.push({
            code: 'UnsupportedHashCriticalText',
            field: 'question',
            message:
                'question must be well-formed Unicode and fit the bounded poll display-text budget.',
        });
    }
    if (optionDescriptors === undefined || !structurallyBoundedOptionCount) {
        errors.push({
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must contain between 2 and 20 labels.',
        });
    }

    for (
        let optionIndex = 0;
        optionDescriptors !== undefined &&
        structurallyBoundedOptionCount &&
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
            !consumeDisplayTextByteLength(optionLabel)
        ) {
            errors.push({
                code: 'UnsupportedHashCriticalText',
                field: `options[${optionIndex}]`,
                message:
                    'option labels must be well-formed Unicode and fit the bounded poll display-text budget.',
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

    if (
        typeof topOptionCount !== 'number' ||
        !Number.isInteger(topOptionCount) ||
        topOptionCount < 1 ||
        topOptionCount > optionCount
    ) {
        errors.push({
            code: 'InvalidTopOptionCount',
            field: 'topOptionCount',
            message: 'topOptionCount must be between 1 and options.length.',
        });
    }
    if (errors.length > 0) {
        return {
            isValid: false,
            errors,
        };
    }

    return {
        isValid: true,
        normalized: {
            pollId: typeof pollId === 'string' ? pollId : '',
            question: typeof question === 'string' ? question : '',
            options: validatedOptions,
            topOptionCount:
                typeof topOptionCount === 'number' ? topOptionCount : 0,
        } satisfies PollSpec,
    };
};

export type FoundationManifestIngress = FoundationManifestInput;

/** Converts validated pre-protocol input into the one canonical manifest shape. */
export const prepareFoundationManifestIngress = (
    pollSpec: PollSpec,
): FoundationManifestIngress => {
    const validation = validatePollSpec(pollSpec);
    if (!validation.isValid) {
        throw new TypeError(
            'The poll input cannot produce a bounded canonical manifest.',
        );
    }

    return Object.freeze({
        displayTitle: validation.normalized.question,
        optionDefinitions: Object.freeze(
            validation.normalized.options.map((displayLabel, optionIndex) =>
                Object.freeze({
                    displayLabel,
                    optionIdentifier: `option-${String(optionIndex)}`,
                    optionIndex,
                }),
            ),
        ),
    });
};
