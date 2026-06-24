// BDLOP setup commitment value shaping: the full public commitment value, the
// hash-bound commitment root payload, the kernel commitment computation bridge,
// and the canonical parser that re-validates a transported commitment value.
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupCommitmentProfileId,
    type JsonRecord,
    type SetupCommitmentOpeningComputation,
    type SetupCommitmentOpeningComputer,
    type SetupCommitmentValue,
} from './constants-and-types.js';
import {
    assertJsonRecord,
    assertJsonRecordArray,
    assertResidueVector,
    coefficientVectorHash512,
    nonNegativeSafeIntegerField,
    positiveSafeIntegerField,
} from './encoding.js';

export const setupCommitmentFullValue = (
    commitment: SetupCommitmentValue,
): JsonRecord => ({
    objectType: 'SetupCommitment',
    objectVersion: 1,
    profileId: setupCommitmentProfileId,
    sourceRnsLimbIndex: commitment.sourceRnsLimbIndex,
    sourceMessageModulus: commitment.sourceMessageModulus,
    shamirCoefficientIndex: commitment.shamirCoefficientIndex,
    ringDegree: commitment.ringDegree,
    commitmentLimbs: commitment.commitmentLimbs.map((limb) => ({
        commitmentModulusIndex: limb.commitmentModulusIndex,
        modulus: limb.modulus,
        rows: limb.rows,
    })),
});

export const setupCommitmentRootPayload = (
    commitment: SetupCommitmentValue,
): JsonRecord => ({
    objectType: 'SetupCommitment',
    objectVersion: 1,
    profileId: setupCommitmentProfileId,
    sourceRnsLimbIndex: commitment.sourceRnsLimbIndex,
    sourceMessageModulus: commitment.sourceMessageModulus,
    shamirCoefficientIndex: commitment.shamirCoefficientIndex,
    ringDegree: commitment.ringDegree,
    commitmentLimbs: commitment.commitmentLimbs.map((limb) => ({
        commitmentModulusIndex: limb.commitmentModulusIndex,
        modulus: limb.modulus,
        rowCoefficientHash512: limb.rows.map((row) =>
            coefficientVectorHash512(
                row,
                'sealed-lattice-bdlop-commitment/row-coefficients-v1',
            ),
        ),
    })),
});

export const computeSetupCommitmentWithKernel = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly shamirCoefficientIndex: number;
    readonly messageCoefficients: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
    readonly ringDegree: number;
    readonly setupCommitmentComputer: SetupCommitmentOpeningComputer;
}): SetupCommitmentOpeningComputation =>
    input.setupCommitmentComputer({
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceRnsLimbIndex: input.sourceRnsLimbIndex,
        sourceMessageModulus: input.sourceMessageModulus,
        shamirCoefficientIndex: input.shamirCoefficientIndex,
        messageCoefficients: input.messageCoefficients,
        randomnessByColumn: input.randomnessByColumn,
        ringDegree: input.ringDegree,
    });

export const parseSetupCommitmentValue = (
    value: unknown,
    objectPath: string,
): SetupCommitmentValue => {
    const commitment = assertJsonRecord(value, objectPath);
    if (commitment.objectType !== 'SetupCommitment') {
        throw new Error(`${objectPath}.objectType must be SetupCommitment.`);
    }
    if (commitment.objectVersion !== 1) {
        throw new Error(`${objectPath}.objectVersion must be 1.`);
    }
    if (commitment.profileId !== setupCommitmentProfileId) {
        throw new Error(
            `${objectPath}.profileId must be ${setupCommitmentProfileId}.`,
        );
    }
    const sourceRnsLimbIndex = nonNegativeSafeIntegerField(
        commitment.sourceRnsLimbIndex,
        `${objectPath}.sourceRnsLimbIndex`,
    );
    const sourceMessageModulus = positiveSafeIntegerField(
        commitment.sourceMessageModulus,
        `${objectPath}.sourceMessageModulus`,
    );
    const shamirCoefficientIndex = nonNegativeSafeIntegerField(
        commitment.shamirCoefficientIndex,
        `${objectPath}.shamirCoefficientIndex`,
    );
    const ringDegree = positiveSafeIntegerField(
        commitment.ringDegree,
        `${objectPath}.ringDegree`,
    );
    const commitmentLimbs = assertJsonRecordArray(
        commitment.commitmentLimbs,
        `${objectPath}.commitmentLimbs`,
    ).map((commitmentLimb, commitmentLimbIndex) => {
        const limbPath = `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}`;
        const commitmentModulusIndex = nonNegativeSafeIntegerField(
            commitmentLimb.commitmentModulusIndex,
            `${limbPath}.commitmentModulusIndex`,
        );
        const modulus = positiveSafeIntegerField(
            commitmentLimb.modulus,
            `${limbPath}.modulus`,
        );
        if (!Array.isArray(commitmentLimb.rows)) {
            throw new TypeError(`${limbPath}.rows must be an array.`);
        }
        const rows = commitmentLimb.rows.map((rowValue, rowIndex) => {
            if (!Array.isArray(rowValue)) {
                throw new TypeError(
                    `${limbPath}.rows.${String(rowIndex)} must be an array.`,
                );
            }
            const row = rowValue.map((coefficient, coefficientIndex) => {
                if (typeof coefficient !== 'number') {
                    throw new TypeError(
                        `${limbPath}.rows.${String(rowIndex)}.${String(coefficientIndex)} must be a number.`,
                    );
                }

                return coefficient;
            });
            assertResidueVector(
                row,
                modulus,
                ringDegree,
                `${limbPath}.rows.${String(rowIndex)}`,
            );

            return row;
        });

        return {
            commitmentModulusIndex,
            modulus,
            rows,
        };
    });

    return {
        sourceRnsLimbIndex,
        sourceMessageModulus,
        shamirCoefficientIndex,
        ringDegree,
        commitmentLimbs,
    };
};
