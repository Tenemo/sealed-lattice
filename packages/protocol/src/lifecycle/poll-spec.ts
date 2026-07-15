import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import {
    foundationProfile,
    type PollSpec,
    type PollSpecValidation,
    type PollSpecValidationError,
    type ProtocolHash,
    type SmallRosterPolicy,
} from '@sealed-lattice/types';

import {
    defaultSmallRosterPolicy,
    maximumSupportedRosterSize,
    minimumSupportedRosterSize,
} from './roster-policy.js';

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

const supportedSmallRosterPolicies = new Set<SmallRosterPolicy>([
    'ForbidMicroRoster',
    'AllowMicroRoster',
]);

const isSupportedSmallRosterPolicy = (
    smallRosterPolicy: unknown,
): smallRosterPolicy is SmallRosterPolicy =>
    smallRosterPolicy === undefined ||
    (typeof smallRosterPolicy === 'string' &&
        supportedSmallRosterPolicies.has(
            smallRosterPolicy as SmallRosterPolicy,
        ));

const normalizeRosterBound = (value: unknown, defaultValue: number): number =>
    value === undefined
        ? defaultValue
        : typeof value === 'number'
          ? value
          : Number.NaN;

const containsOnlyAsciiCharacters = (value: string): boolean => {
    for (
        let characterIndex = 0;
        characterIndex < value.length;
        characterIndex += 1
    ) {
        if (value.charCodeAt(characterIndex) > 0x7f) {
            return false;
        }
    }
    return true;
};

export const derivePollSpecHash = (pollSpec: PollSpec): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'PollSpec',
        maxRosterSize: pollSpec.maxRosterSize,
        minRosterSize: pollSpec.minRosterSize,
        options: pollSpec.options,
        pollId: pollSpec.pollId,
        question: pollSpec.question,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        topOptionCount: pollSpec.topOptionCount,
    });

export const validatePollSpec = (input: unknown): PollSpecValidation => {
    const errors: PollSpecValidationError[] = [];
    const optionLabels = new Set<string>();
    const inputRecordDescriptors = ordinaryRecordDescriptors(input);
    let remainingDisplayTextByteLength =
        foundationProfile.maximumCopiedBufferByteLength;
    const consumeDisplayTextByteLength = (value: string): boolean => {
        if (value.length > remainingDisplayTextByteLength) {
            return false;
        }
        remainingDisplayTextByteLength -= value.length;

        return true;
    };
    const pollId = dataPropertyValue(inputRecordDescriptors, 'pollId');
    const question = dataPropertyValue(inputRecordDescriptors, 'question');
    const rawOptions = dataPropertyValue(inputRecordDescriptors, 'options');
    const topOptionCount = dataPropertyValue(
        inputRecordDescriptors,
        'topOptionCount',
    );
    const smallRosterPolicy = dataPropertyValue(
        inputRecordDescriptors,
        'smallRosterPolicy',
    );
    const minRosterSize = dataPropertyValue(
        inputRecordDescriptors,
        'minRosterSize',
    );
    const maxRosterSize = dataPropertyValue(
        inputRecordDescriptors,
        'maxRosterSize',
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

    if (typeof pollId !== 'string' || pollId.length === 0) {
        errors.push({
            code: 'EmptyPollId',
            field: 'pollId',
            message: 'pollId must be a nonempty string.',
        });
    } else if (
        pollId.length > foundationProfile.maximumIdentifierByteLength ||
        !containsOnlyAsciiCharacters(pollId)
    ) {
        errors.push({
            code: 'UnsupportedHashCriticalText',
            field: 'pollId',
            message:
                'pollId must contain only ASCII characters and fit the foundation identifier limit.',
        });
    }
    if (typeof question !== 'string' || question.length === 0) {
        errors.push({
            code: 'EmptyQuestion',
            field: 'question',
            message: 'question must be a nonempty string.',
        });
    } else if (
        question.length > foundationProfile.maximumCopiedBufferByteLength ||
        !containsOnlyAsciiCharacters(question) ||
        !consumeDisplayTextByteLength(question)
    ) {
        errors.push({
            code: 'UnsupportedHashCriticalText',
            field: 'question',
            message:
                'question must contain only ASCII characters and fit the bounded poll display-text budget.',
        });
    }
    if (
        optionDescriptors === undefined ||
        optionCount < 1 ||
        optionCount > 20
    ) {
        errors.push({
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must be an array with 1 to 20 labels.',
        });
    }

    for (
        let optionIndex = 0;
        optionDescriptors !== undefined &&
        optionCount <= 20 &&
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
            optionLabel.length >
                foundationProfile.maximumCopiedBufferByteLength ||
            !containsOnlyAsciiCharacters(optionLabel) ||
            !consumeDisplayTextByteLength(optionLabel)
        ) {
            errors.push({
                code: 'UnsupportedHashCriticalText',
                field: `options[${optionIndex}]`,
                message:
                    'option labels must contain only ASCII characters and fit the bounded poll display-text budget.',
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
    if (!isSupportedSmallRosterPolicy(smallRosterPolicy)) {
        errors.push({
            code: 'UnsupportedSmallRosterPolicy',
            field: 'smallRosterPolicy',
            message:
                'smallRosterPolicy must be ForbidMicroRoster or AllowMicroRoster.',
        });
    }

    const normalizedMinRosterSize = normalizeRosterBound(minRosterSize, 10);
    const normalizedMaxRosterSize = normalizeRosterBound(
        maxRosterSize,
        maximumSupportedRosterSize,
    );
    if (
        !Number.isInteger(normalizedMinRosterSize) ||
        !Number.isInteger(normalizedMaxRosterSize) ||
        normalizedMinRosterSize < minimumSupportedRosterSize ||
        normalizedMaxRosterSize > maximumSupportedRosterSize ||
        normalizedMinRosterSize > normalizedMaxRosterSize
    ) {
        errors.push({
            code: 'InvalidRosterBounds',
            field: 'minRosterSize',
            message:
                'Roster bounds must be integer bounds in 3..20 with minRosterSize not greater than maxRosterSize.',
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
            minRosterSize: normalizedMinRosterSize,
            maxRosterSize: normalizedMaxRosterSize,
            smallRosterPolicy:
                smallRosterPolicy === undefined
                    ? defaultSmallRosterPolicy
                    : (smallRosterPolicy as SmallRosterPolicy),
        } satisfies PollSpec,
    };
};
