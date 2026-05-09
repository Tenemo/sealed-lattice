import {
    defaultDuplicateBallotPolicy,
    defaultScoreDomain,
    defaultTiePolicy,
} from './profiles.js';
import type {
    DuplicateBallotPolicy,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    ScoreDomain,
    TiePolicy,
} from './types.js';

const addError = (
    errors: PollSpecValidationError[],
    error: PollSpecValidationError,
): void => {
    errors.push(error);
};

const isSupportedScoreDomain = (
    scoreDomain: ScoreDomain | undefined,
): boolean =>
    scoreDomain === undefined ||
    (scoreDomain.min === 1 &&
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

export const validatePollSpec = (input: PollSpecInput): PollSpecValidation => {
    const errors: PollSpecValidationError[] = [];
    const optionLabels = new Set<string>();

    if (input.ceremonyId.length === 0) {
        addError(errors, {
            code: 'EmptyCeremonyId',
            field: 'ceremonyId',
            message: 'ceremonyId must be nonempty.',
        });
    }
    if (input.question.length === 0) {
        addError(errors, {
            code: 'EmptyQuestion',
            field: 'question',
            message: 'question must be nonempty.',
        });
    }
    if (input.options.length < 1 || input.options.length > 20) {
        addError(errors, {
            code: 'InvalidOptionCount',
            field: 'options',
            message: 'options must contain between 1 and 20 labels.',
        });
    }

    input.options.forEach((optionLabel, optionIndex) => {
        if (optionLabel.length === 0) {
            addError(errors, {
                code: 'EmptyOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be nonempty.',
            });
        }
        if (optionLabels.has(optionLabel)) {
            addError(errors, {
                code: 'DuplicateOptionLabel',
                field: `options[${optionIndex}]`,
                message: 'option labels must be unique by exact comparison.',
            });
        }

        optionLabels.add(optionLabel);
    });

    if (
        !Number.isInteger(input.kTop) ||
        input.kTop < 1 ||
        input.kTop > input.options.length
    ) {
        addError(errors, {
            code: 'InvalidKTop',
            field: 'kTop',
            message: 'kTop must be between 1 and options.length.',
        });
    }
    if (!isSupportedScoreDomain(input.scoreDomain)) {
        addError(errors, {
            code: 'UnsupportedScoreDomain',
            field: 'scoreDomain',
            message: 'scoreDomain must be exactly 1..10 with skipped score 1.',
        });
    }
    if (
        input.duplicateBallotPolicy !== undefined &&
        input.duplicateBallotPolicy !== defaultDuplicateBallotPolicy
    ) {
        addError(errors, {
            code: 'UnsupportedDuplicateBallotPolicy',
            field: 'duplicateBallotPolicy',
            message:
                'duplicateBallotPolicy must be LastValidBeforeVotingClosedCounts.',
        });
    }
    if (input.tiePolicy !== undefined && input.tiePolicy !== defaultTiePolicy) {
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
            ceremonyId: input.ceremonyId,
            question: input.question,
            options: [...input.options],
            kTop: input.kTop,
            scoreDomain: normalizeScoreDomain(input.scoreDomain),
            duplicateBallotPolicy: normalizeDuplicateBallotPolicy(
                input.duplicateBallotPolicy,
            ),
            tiePolicy: normalizeTiePolicy(input.tiePolicy),
        } satisfies PollSpec,
    };
};
