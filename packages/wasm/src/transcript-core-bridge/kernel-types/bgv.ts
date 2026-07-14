import type {
    BgvTargetDecryptionShareProofMaterial,
    ProtocolHash,
} from '@sealed-lattice/types';

type BgvJsonRecord = Readonly<Record<string, unknown>>;

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
        readonly objectType: 'QSharePrimeList';
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

export type BgvCollectiveSetupVerification = Readonly<
    {
        readonly refusedObjects: readonly {
            readonly reasonCode: string;
            readonly message: string;
            readonly objectPath: string;
        }[];
    } & (
        | {
              readonly isValid: true;
              readonly acceptedSetupHandle: number;
          }
        | {
              readonly isValid: false;
          }
    )
>;

export type BgvPrivateVssShareEnvelopeVerification = {
    readonly isValid: boolean;
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly limbVerifications: readonly {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
    }[];
    readonly refusedObjects: readonly {
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath: string;
    }[];
};

export type BgvPrivateVssShareProofGeneration = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly shareValuesHash: ProtocolHash;
    readonly privateVssShareProof: Record<string, unknown>;
};

type BgvTrusteeEvaluationKeyStatementKeyCommon = {
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
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

// The kernel derives the key-bearing proof family from the key list. Trustee
// evaluation-key statements bind their schedule and exact source constant;
// public-key statements bind the separately verified bridge statement and
// proof record.
export type BgvTrusteeEvaluationKeyStatementContext = {
    readonly setupContextHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
} & (
    | {
          readonly evaluatorKeyScheduleRoot: ProtocolHash;
          readonly sourceConstantCoefficientCommitmentRoot: ProtocolHash;
      }
    | {
          readonly sameSecretBridgeStatementRoot: ProtocolHash;
          readonly sameSecretBridgeProofRecordRoot: ProtocolHash;
      }
);

export type BgvTrusteeEvaluationKeySameSecretLinkage = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly commitments: readonly unknown[];
};

export type BgvTrusteeEvaluationKeySameSecretBridge = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly bridgeRnsPrimes: readonly number[];
    readonly targetConstantCommitmentRoots: readonly ProtocolHash[];
    readonly targetConstantCommitments: readonly unknown[];
};

export type BgvVssShareLinkageProofContext = {
    readonly setupContextHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareLinkageStatementRoot: ProtocolHash;
};

export type BgvSameSecretBridgeProofContext = {
    readonly setupContextHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
};

export type BgvTrusteeEvaluationKeyProofGeneration = {
    readonly statementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

// The proof family and canonical statement hash of a key-bearing setup
// statement, computed without proving it.
export type BgvTrusteeEvaluationKeyStatementDescription = {
    readonly proofFamily: 'trustee-evaluation-key' | 'public-key-share';
    readonly statementHash: ProtocolHash;
};

type BgvSetupCommitmentValue = {
    readonly objectType: 'SetupCommitment';
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
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
    readonly commitmentRoot: ProtocolHash;
};

export type BgvVssCommittedMaterialCommitmentComputation = {
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
    readonly commitmentContextHash: ProtocolHash;
};

export type BgvVssShareLinkageProofGeneration = {
    readonly statementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvSameSecretBridgeProofGeneration = {
    readonly statementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvLocalTrusteeSetupStateVerification = {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly localStateRoot: ProtocolHash;
};

export type BgvTargetDecryptionShare = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'BgvTargetDecryptionShare';
        readonly targetDecryptionShareHash: ProtocolHash;
        readonly shareRoot: ProtocolHash;
    }
>;

export type { BgvTargetDecryptionShareProofMaterial };

export type BgvTargetDecryptionResultReleaseBegin = {
    readonly requiredShareCount: number;
};

export type BgvTargetDecryptionResultReleaseShareEvidence = {
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly interpolationPoint: number;
    readonly targetDecryptionShareHash: ProtocolHash;
    readonly proofStatementRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
};

export type BgvTargetDecryptionResultReleaseCompletion = {
    readonly targetResultHash: ProtocolHash;
    readonly targetIdByOption: readonly number[];
    readonly targetOrderByOption: readonly number[];
    readonly topCount: number;
    readonly shareEvidence: readonly BgvTargetDecryptionResultReleaseShareEvidence[];
};
