import type { BallotPrivacyBackendProofComponentId } from '../relation-backend-lowering.js';

import { thirtyTwoByteLowercaseHexPattern } from './statement-contracts.js';

const requireObjectContract = (
    value: unknown,
    label: string,
): Readonly<Record<string, unknown>> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${label} must be an object.`);
    }

    return value as Readonly<Record<string, unknown>>;
};

const requireContractStringField = (input: {
    readonly contract: unknown;
    readonly fieldName: string;
    readonly label: string;
}): string => {
    const value = requireObjectContract(input.contract, input.label)[
        input.fieldName
    ];
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${input.label}.${input.fieldName} must be a string.`);
    }

    return value;
};

const requireContractIntegerField = (input: {
    readonly contract: unknown;
    readonly fieldName: string;
    readonly label: string;
}): number => {
    const value = requireObjectContract(input.contract, input.label)[
        input.fieldName
    ];
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        Object.is(value, -0)
    ) {
        throw new Error(
            `${input.label}.${input.fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const requireContractDecimalStringField = (input: {
    readonly contract: unknown;
    readonly fieldName: string;
    readonly label: string;
}): string => {
    const value = requireObjectContract(input.contract, input.label)[
        input.fieldName
    ];
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
            throw new Error(
                `${input.label}.${input.fieldName} must be a canonical unsigned decimal integer.`,
            );
        }

        return value.toString();
    }
    if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/u.test(value)) {
        return value;
    }

    throw new Error(
        `${input.label}.${input.fieldName} must be a canonical unsigned decimal integer.`,
    );
};

const requireContractProfileId = (input: {
    readonly contract: unknown;
    readonly expectedProfileId: string;
    readonly label: string;
}): void => {
    const profileId = requireContractStringField({
        contract: input.contract,
        fieldName: 'profileId',
        label: input.label,
    });
    if (profileId !== input.expectedProfileId) {
        throw new Error(
            `${input.label} must use profile ${input.expectedProfileId}.`,
        );
    }
};

const requireRandomnessHex = (value: string, label: string): void => {
    if (!thirtyTwoByteLowercaseHexPattern.test(value)) {
        throw new Error(`${label} must be 32 lowercase hexadecimal bytes.`);
    }
};

const requireComponentContract = <Value>(
    values: Readonly<Record<BallotPrivacyBackendProofComponentId, Value>>,
    componentId: BallotPrivacyBackendProofComponentId,
    label: string,
): Value => {
    const value = values[componentId];
    if (value === undefined) {
        throw new Error(`${label}.${componentId} is required.`);
    }

    return value;
};

const requirePartialComponentContract = <Value>(
    values: Readonly<
        Partial<Record<BallotPrivacyBackendProofComponentId, Value>>
    >,
    componentId: BallotPrivacyBackendProofComponentId,
    label: string,
): Value => {
    const value = values[componentId];
    if (value === undefined) {
        throw new Error(`${label}.${componentId} is required.`);
    }

    return value;
};

const assertProofParameterSetMatchesStatement = (input: {
    readonly coefficientModulus: string;
    readonly expectedProfileId: string;
    readonly label: string;
    readonly parameterSet: unknown;
    readonly sourceRingDegree: number;
    readonly statementColumns: number;
    readonly statementRows: number;
}): void => {
    requireContractProfileId({
        contract: input.parameterSet,
        expectedProfileId: input.expectedProfileId,
        label: input.label,
    });
    const ringDegree = requireContractIntegerField({
        contract: input.parameterSet,
        fieldName: 'ringDegree',
        label: input.label,
    });
    if (ringDegree !== input.sourceRingDegree) {
        throw new Error(
            `${input.label}.ringDegree must match the proof statement source ring degree.`,
        );
    }
    const statementRows = requireContractIntegerField({
        contract: input.parameterSet,
        fieldName: 'statementRows',
        label: input.label,
    });
    if (statementRows !== input.statementRows) {
        throw new Error(
            `${input.label}.statementRows must match the proof statement row count.`,
        );
    }
    const statementColumns = requireContractIntegerField({
        contract: input.parameterSet,
        fieldName: 'statementColumns',
        label: input.label,
    });
    if (statementColumns !== input.statementColumns) {
        throw new Error(
            `${input.label}.statementColumns must match the proof statement column count.`,
        );
    }
    const coefficientModulus = requireContractDecimalStringField({
        contract: input.parameterSet,
        fieldName: 'coefficientModulus',
        label: input.label,
    });
    if (coefficientModulus !== input.coefficientModulus) {
        throw new Error(
            `${input.label}.coefficientModulus must match the proof statement modulus.`,
        );
    }
};

const assertProofEncodingMatchesStatement = (input: {
    readonly encoding: unknown;
    readonly expectedProfileId: string;
    readonly label: string;
    readonly sourceRingDegree: number;
    readonly statementColumns: number;
}): void => {
    requireContractProfileId({
        contract: input.encoding,
        expectedProfileId: input.expectedProfileId,
        label: input.label,
    });
    const shortResponseVectorLength = requireContractIntegerField({
        contract: input.encoding,
        fieldName: 'shortResponseVectorLength',
        label: input.label,
    });
    const proofRingDegree = requireContractIntegerField({
        contract: input.encoding,
        fieldName: 'ringDegree',
        label: input.label,
    });
    if (input.sourceRingDegree % proofRingDegree !== 0) {
        throw new Error(
            `${input.label}.ringDegree must divide the proof statement source ring degree.`,
        );
    }
    const sourcePolynomialSplitFactor =
        input.sourceRingDegree / proofRingDegree;
    const expectedShortResponseVectorLength =
        input.statementColumns * sourcePolynomialSplitFactor + 1;
    if (shortResponseVectorLength !== expectedShortResponseVectorLength) {
        throw new Error(
            `${input.label}.shortResponseVectorLength must match the split proof statement column count plus one.`,
        );
    }
};

export {
    requireObjectContract,
    requireContractIntegerField,
    requireContractDecimalStringField,
    requireContractProfileId,
    requireRandomnessHex,
    requireComponentContract,
    requirePartialComponentContract,
    assertProofParameterSetMatchesStatement,
    assertProofEncodingMatchesStatement,
};
