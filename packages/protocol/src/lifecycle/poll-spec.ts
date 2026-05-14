import type {
    DuplicateBallotPolicy,
    PollSpec,
    PollSpecValidation,
    PollSpecValidationError,
    ScoreDomain,
    TiePolicy,
} from '@sealed-lattice/types';

import {
    defaultDuplicateBallotPolicy,
    defaultScoreDomain,
    defaultTiePolicy,
} from './profiles.js';

const addError = (
    errors: PollSpecValidationError[],
    error: PollSpecValidationError,
): void => {
    errors.push(error);
};

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null;

const isSupportedScoreDomain = (scoreDomain: unknown): boolean =>
    scoreDomain === undefined ||
    (isRecord(scoreDomain) &&
        scoreDomain.min === 1 &&
        scoreDomain.max === 10 &&
        scoreDomain.skippedOptionScore === 1);

const normalizeScoreDomain = (
    scoreDomain: ScoreDomain | undefined,
): ScoreDomain => scoreDomain ?? defaultScoreDomain;

const normalizeDuplicateBallotPolicy = (
    duplicateBallotPolicy: DuplicateBallotPolicy | undefined,
): DuplicateBallotPolicy =>
    duplicateBallotPolicy ?? defaultDuplicateBallotPolicy;

const normalizeTiePolicy = (tiePolicy: TiePolicy | undefined): TiePolicy =>
    tiePolicy ?? defaultTiePolicy;

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
    const duplicateBallotPolicy = inputRecord.duplicateBallotPolicy;
    const tiePolicy = inputRecord.tiePolicy;
    const normalizedOptions: string[] = [];

    if (pollId === undefined || pollId.length === 0) {
        addError(errors, {
            code: 'EmptyPollId',
            field: 'pollId',
            message: 'pollId must be a nonempty string.',
        });
    }
    if (question === undefined || question.length === 0) {
        addError(errors, {
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
        addError(errors, {
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must be an array with 1 to 20 labels.',
        });
    }

    options.forEach((optionLabel, optionIndex) => {
        if (typeof optionLabel !== 'string' || optionLabel.length === 0) {
            addError(errors, {
                code: 'EmptyOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be nonempty strings.',
            });
            return;
        }
        if (optionLabels.has(optionLabel)) {
            addError(errors, {
                code: 'DuplicateOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be unique by exact comparison.',
            });
        }

        optionLabels.add(optionLabel);
        normalizedOptions.push(optionLabel);
    });

    if (
        typeof topOptionCount !== 'number' ||
        !Number.isInteger(topOptionCount) ||
        topOptionCount < 1 ||
        topOptionCount > options.length
    ) {
        addError(errors, {
            code: 'InvalidTopOptionCount',
            field: 'topOptionCount',
            message: 'topOptionCount must be between 1 and options.length.',
        });
    }
    if (!isSupportedScoreDomain(scoreDomain)) {
        addError(errors, {
            code: 'UnsupportedScoreDomain',
            field: 'scoreDomain',
            message: 'scoreDomain must be exactly 1..10 with skipped score 1.',
        });
    }
    if (
        duplicateBallotPolicy !== undefined &&
        duplicateBallotPolicy !== defaultDuplicateBallotPolicy
    ) {
        addError(errors, {
            code: 'UnsupportedDuplicateBallotPolicy',
            field: 'duplicateBallotPolicy',
            message:
                'duplicateBallotPolicy must be LastValidBeforeVotingClosedCounts.',
        });
    }
    if (tiePolicy !== undefined && tiePolicy !== defaultTiePolicy) {
        addError(errors, {
            code: 'UnsupportedTiePolicy',
            field: 'tiePolicy',
            message: 'tiePolicy must be HigherScoreThenLowerOptionIndex.',
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
            duplicateBallotPolicy: normalizeDuplicateBallotPolicy(
                duplicateBallotPolicy as DuplicateBallotPolicy | undefined,
            ),
            tiePolicy: normalizeTiePolicy(tiePolicy as TiePolicy | undefined),
        } satisfies PollSpec,
    };
};
