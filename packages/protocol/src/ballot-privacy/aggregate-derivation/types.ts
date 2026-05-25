import {
    aggregateDerivationProofEncodingProfileId,
    aggregateDerivationProofParameterProfileId,
    type AggregateDerivationProofVerificationInput,
    type AggregateDerivationStatement,
    type AggregateShareCommitment,
    type ProtocolDigest,
} from '@sealed-lattice/types';

import type {
    DensePolynomial,
    SparseMatrixEntry,
    SparseTargetVectorEntry,
} from '../ballot-proof-linear-statement/statement-contracts.js';

import { aggregateDerivationComponentId } from './constants.js';

export type AggregateDerivationProofParameterSet = {
    readonly coefficientModulus: string;
    readonly expectedProofSizeBytes?: number;
    readonly profileId: typeof aggregateDerivationProofParameterProfileId;
    readonly proofSystemRingDegree: 64;
    readonly relation: 'A*w + t = 0';
    readonly ringDegree: 256;
    readonly source: string;
    readonly statementColumns: number;
    readonly statementRows: number;
    readonly witnessL2BoundSquared: number;
};

export type AggregateDerivationProofEncoding = {
    readonly challengeCoefficientBitLength: 5;
    readonly challengeCoefficientModulus: 17;
    readonly coefficientModulus: string;
    readonly compressedCoefficientBitLength: 35;
    readonly compressedCommitmentVectorLength: 18;
    readonly euclideanResponseLog2StandardDeviation: 14;
    readonly euclideanResponseVectorLength: 4;
    readonly expectedProofSizeBytes?: number;
    readonly fullSizeCoefficientBitLength: 47;
    readonly hashMaskVectorLength: 2;
    readonly hintVectorLength: 18;
    readonly infinityResponseLog2StandardDeviation: 22;
    readonly infinityResponseVectorLength: 4;
    readonly profileId: typeof aggregateDerivationProofEncodingProfileId;
    readonly randomnessResponseLog2StandardDeviation: 12;
    readonly randomnessResponseVectorLength: 41;
    readonly ringDegree: 64;
    readonly shortResponseLog2StandardDeviation: 18;
    readonly shortResponseVectorLength: number;
    readonly source: string;
    readonly targetCommitmentVectorLength: 12;
};

export type AggregateDerivationProofStatement = {
    readonly aggregateDerivationStatementDigest: ProtocolDigest;
    readonly aggregateShareCommitmentDigest: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly componentId: typeof aggregateDerivationComponentId;
    readonly matrixCoefficientRepresentation: 'centeredSignedSourceModulus';
    readonly objectType: 'AggregateDerivationSparseLinearProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: typeof aggregateDerivationProofParameterProfileId;
    readonly proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1';
    readonly projectionCoverage: 'aggregate-derivation-full-encoded-layout';
    readonly relation: 'A*w + t = 0';
    readonly sourceRingDegree: 256;
    readonly sparseStatementMatrixDigest: ProtocolDigest;
    readonly sparseStatementMatrixEntries: readonly SparseMatrixEntry[];
    readonly sparseStatementTermCount: string;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly targetCoefficientRepresentation: 'centeredSignedSourceModulus';
    readonly targetVectorDigest: ProtocolDigest;
    readonly targetVectorEntries: readonly SparseTargetVectorEntry[];
    readonly targetVectorEntryCount: string;
    readonly witnessL2BoundSquared: string;
};

export type AggregateDerivationWitnessInput = {
    readonly aggregateIntegerShareVector: readonly number[];
    readonly aggregateOpeningRandomness: readonly number[];
};

export type AggregateDerivationProofBuildInput = {
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly statement: AggregateDerivationStatement;
    readonly witness: AggregateDerivationWitnessInput;
};

export type AggregateDerivationProofBuildOutput = {
    readonly proofEncoding: AggregateDerivationProofEncoding;
    readonly proofInput: Omit<
        AggregateDerivationProofVerificationInput,
        'proofBytesHex'
    >;
    readonly proofParameterSet: AggregateDerivationProofParameterSet;
    readonly proofStatement: AggregateDerivationProofStatement;
    readonly secretState: {
        readonly sourceWitnessCoefficients: readonly DensePolynomial[];
    };
};
