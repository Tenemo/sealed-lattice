import type { ProtocolHash, VerificationResult } from '@sealed-lattice/types';

export type BgvRnsParametersDescription = {
    readonly parameters: {
        readonly polynomialDegree: number;
        readonly plaintextModulus: number;
        readonly dataPrimes: readonly number[];
        readonly specialPrime: number;
        readonly scoreRange: {
            readonly minimum: number;
            readonly maximum: number;
        };
        readonly bucketCount: number;
        readonly coordinatesPerOption: number;
    };
    readonly bgvParametersHash: ProtocolHash;
};

export type BgvCollectiveSetupParametersDescription = {
    readonly setupParametersHash: ProtocolHash;
    readonly participantCount: number;
    readonly qShare: {
        readonly primes: readonly number[];
    };
    readonly evaluatorKeySchedule: {
        readonly objectType: 'EvaluatorKeySchedule';
        readonly relinearizationLevelSchedule: readonly {
            readonly level: number;
        }[];
        readonly requiredGaloisKeySchedule: readonly {
            readonly rotation: number;
            readonly level: number;
        }[];
    };
    readonly boundedDomainEvaluator: {
        readonly objectType: 'BoundedDomainEvaluatorParameters';
        readonly scoreDifferenceBound: number;
        readonly directComparisonOutputLevel: number;
    };
};

export type BgvCollectiveSetupVerification = VerificationResult<void>;

export type BgvPrivateVssShareEnvelopeVerification = VerificationResult<{
    readonly privateEnvelopeHash: ProtocolHash;
}>;

type BgvTrusteeEvaluationKeyStatementKeyCommon = {
    readonly level: number;
    readonly componentMaterialBytesHex: string;
};

// One key share inside a key-bearing setup proof statement. Component material
// is supplied only as canonical binary transport bytes; round-two keys also
// carry the recomputed public round-one aggregate diagonals.
export type BgvTrusteeEvaluationKeyStatementKey =
    | (BgvTrusteeEvaluationKeyStatementKeyCommon & {
          readonly proofFamily: 'relinearization-round-one';
      })
    | (BgvTrusteeEvaluationKeyStatementKeyCommon & {
          readonly proofFamily: 'relinearization-round-two';
          readonly roundOneAggregateDiagonal: readonly (readonly number[])[];
      })
    | (BgvTrusteeEvaluationKeyStatementKeyCommon & {
          readonly proofFamily: 'galois-rotation';
          readonly rotation: number;
      })
    | (BgvTrusteeEvaluationKeyStatementKeyCommon & {
          readonly proofFamily: 'public-key-share';
      });

export type BgvSuccinctSetupProofContext = {
    readonly setupContextHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
};

export type BgvTrusteeEvaluationKeyStatementContext =
    BgvSuccinctSetupProofContext & {
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
    };

export type BgvPublicKeyShareStatementContext = BgvSuccinctSetupProofContext;

export type BgvTrusteeEvaluationKeySameSecretLinkage = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly commitments: readonly unknown[];
};

export type BgvTrusteeEvaluationKeySameSecretBridge = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetConstantCommitments: readonly unknown[];
};

export type BgvTrusteeEvaluationKeyProofGeneration = {
    readonly proofBytesHash: ProtocolHash;
};

type BgvSetupCommitmentValue = {
    readonly objectType: 'SetupCommitment';
    readonly sourceRnsLimbIndex: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
    readonly commitmentLimbs: readonly {
        readonly commitmentModulusIndex: number;
        readonly modulus: number;
        readonly rows: readonly (readonly number[])[];
    }[];
};

export type BgvSetupCommitmentOpeningComputation = {
    readonly commitment: BgvSetupCommitmentValue;
};

export type BgvVssCommittedMaterialCommitmentComputation = {
    readonly commitment: Record<string, unknown>;
    readonly openingRoot: ProtocolHash;
};
