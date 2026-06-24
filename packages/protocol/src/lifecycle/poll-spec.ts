import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    PollSpec,
    PollSpecValidation,
    PollSpecValidationError,
    ProtocolHash,
    ScoreDomain,
    SmallRosterPolicy,
} from '@sealed-lattice/types';

import { isRecord } from '../common/verification-helpers.js';

import {
    defaultScoreDomain,
    defaultSmallRosterPolicy,
    maximumSupportedRosterSize,
    minimumSupportedRosterSize,
} from './roster-policy.js';

const isSupportedScoreDomain = (scoreDomain: unknown): boolean =>
    scoreDomain === undefined ||
    (isRecord(scoreDomain) &&
        scoreDomain.min === 1 &&
        scoreDomain.max === 10 &&
        scoreDomain.skippedOptionScore === 1);

const normalizeScoreDomain = (
    scoreDomain: ScoreDomain | undefined,
): ScoreDomain => scoreDomain ?? defaultScoreDomain;

const supportedSmallRosterPolicies = new Set<SmallRosterPolicy>([
    'ForbidMicroRoster',
    'WarnMicroRoster',
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
    typeof value === 'number' ? value : defaultValue;

export const derivePollSpecHash = (pollSpec: PollSpec): ProtocolHash =>
    deriveProtocolHash('PollSpecHash', {
        maxRosterSize: pollSpec.maxRosterSize,
        minRosterSize: pollSpec.minRosterSize,
        options: pollSpec.options,
        pollId: pollSpec.pollId,
        question: pollSpec.question,
        scoreDomain: pollSpec.scoreDomain,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        topOptionCount: pollSpec.topOptionCount,
    });

export const validatePollSpec = (input: unknown): PollSpecValidation => {
    const errors: PollSpecValidationError[] = [];
    const optionLabels = new Set<string>();
    const inputRecord: Readonly<Record<string, unknown>> = isRecord(input)
        ? input
        : {};
    const pollId =
        typeof inputRecord.pollId === 'string' ? inputRecord.pollId : undefined;
    const question =
        typeof inputRecord.question === 'string'
            ? inputRecord.question
            : undefined;
    const rawOptions = inputRecord.options;
    const options: readonly unknown[] = Array.isArray(rawOptions)
        ? rawOptions
        : [];
    const topOptionCount = inputRecord.topOptionCount;
    const scoreDomain = inputRecord.scoreDomain;
    const smallRosterPolicy = inputRecord.smallRosterPolicy;
    const minRosterSize = inputRecord.minRosterSize;
    const maxRosterSize = inputRecord.maxRosterSize;
    const normalizedOptions: string[] = [];

    if (pollId === undefined || pollId.length === 0) {
        errors.push({
            code: 'EmptyPollId',
            field: 'pollId',
            message: 'pollId must be a nonempty string.',
        });
    }
    if (question === undefined || question.length === 0) {
        errors.push({
            code: 'EmptyQuestion',
            field: 'question',
            message: 'question must be a nonempty string.',
        });
    }
    if (
        !Array.isArray(rawOptions) ||
        options.length < 1 ||
        options.length > 20
    ) {
        errors.push({
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must be an array with 1 to 20 labels.',
        });
    }

    options.forEach((optionLabel, optionIndex) => {
        if (typeof optionLabel !== 'string' || optionLabel.length === 0) {
            errors.push({
                code: 'EmptyOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be nonempty strings.',
            });
            return;
        }
        const normalizedOptionLabel = optionLabel.normalize('NFC');
        if (optionLabels.has(normalizedOptionLabel)) {
            errors.push({
                code: 'DuplicateOptionLabel',
                field: `options[${optionIndex}]`,
                message:
                    'option labels must be unique after Unicode NFC normalization.',
            });
        }

        optionLabels.add(normalizedOptionLabel);
        normalizedOptions.push(normalizedOptionLabel);
    });

    if (
        typeof topOptionCount !== 'number' ||
        !Number.isInteger(topOptionCount) ||
        topOptionCount < 1 ||
        topOptionCount > options.length
    ) {
        errors.push({
            code: 'InvalidTopOptionCount',
            field: 'topOptionCount',
            message: 'topOptionCount must be between 1 and options.length.',
        });
    }
    if (!isSupportedScoreDomain(scoreDomain)) {
        errors.push({
            code: 'UnsupportedScoreDomain',
            field: 'scoreDomain',
            message: 'scoreDomain must be exactly 1..10 with skipped score 1.',
        });
    }
    if (!isSupportedSmallRosterPolicy(smallRosterPolicy)) {
        errors.push({
            code: 'UnsupportedSmallRosterPolicy',
            field: 'smallRosterPolicy',
            message:
                'smallRosterPolicy must be ForbidMicroRoster, WarnMicroRoster, or AllowMicroRoster.',
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
            ok: false,
            errors,
        };
    }

    return {
        ok: true,
        normalized: {
            pollId: pollId ?? '',
            question: question ?? '',
            options: normalizedOptions,
            topOptionCount:
                typeof topOptionCount === 'number' ? topOptionCount : 0,
            scoreDomain: normalizeScoreDomain(
                scoreDomain as ScoreDomain | undefined,
            ),
            minRosterSize: normalizedMinRosterSize,
            maxRosterSize: normalizedMaxRosterSize,
            smallRosterPolicy:
                smallRosterPolicy === undefined
                    ? defaultSmallRosterPolicy
                    : (smallRosterPolicy as SmallRosterPolicy),
        } satisfies PollSpec,
    };
};
