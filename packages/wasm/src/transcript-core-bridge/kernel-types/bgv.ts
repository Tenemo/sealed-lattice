import type {
    BgvTargetDecryptionShareProofMaterial,
    ProtocolHash,
} from '@sealed-lattice/types';

type BgvJsonRecord = Readonly<Record<string, unknown>>;

type BgvTransportedMaterialObject<ObjectType extends string> = Readonly<
    BgvJsonRecord & {
        readonly objectType: ObjectType;
    }
>;

type BgvTransportedSetupProofMaterialSet<ObjectType extends string = string> =
    BgvTransportedMaterialObject<ObjectType> &
        Readonly<{
            readonly proofFamily: string;
            readonly proofMaterials: readonly BgvJsonRecord[];
        }>;

type BgvTransportedPublicKeyShareMaterial =
    BgvTransportedMaterialObject<'SetupTransportedPublicKeyShareMaterial'> &
        Readonly<{
            readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        }>;

type BgvTransportedEvaluationKeyShareComponentMaterialSet =
    BgvTransportedMaterialObject<'SetupTransportedEvaluationKeyShareComponentMaterialSet'> &
        Readonly<{
            readonly componentMaterials: readonly BgvJsonRecord[];
        }>;

type BgvTransportedPublicEvaluationKeyMaterialSet =
    BgvTransportedMaterialObject<'SetupTransportedPublicEvaluationKeyMaterialSet'> &
        Readonly<{
            readonly publicEvaluationKeyMaterials: readonly BgvJsonRecord[];
            readonly componentMaterials?: readonly BgvJsonRecord[];
        }>;

export type BgvCollectiveSetupTransportCompanions = Readonly<{
    readonly transportedPublicKeyShareMaterial?: BgvTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedPublicKeyShareProofMaterialSet'>;
    readonly transportedEvaluationKeyShareProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedEvaluationKeyShareProofMaterialSet'>;
    readonly transportedVssShareLinkageProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedVssShareLinkageProofMaterialSet'>;
    readonly transportedSameSecretBridgeProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedSameSecretBridgeProofMaterialSet'>;
    readonly transportedEvaluationKeyShareComponentMaterial?: BgvTransportedEvaluationKeyShareComponentMaterialSet;
    readonly transportedPublicEvaluationKeyMaterial?: BgvTransportedPublicEvaluationKeyMaterialSet;
}>;

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

export type BgvObjectValidation = {
    readonly isValid: boolean;
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly bgvParametersHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly plaintextRoot?: ProtocolHash;
    readonly ciphertextRoot?: ProtocolHash;
};

export type BgvBatchPlaintextEncoding = {
    readonly bgvParametersHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly plaintextRoot: ProtocolHash;
    readonly sampledSlots: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly sampledCoefficientsModPlaintext: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly canonicalBytesHex?: string;
};

export type BgvPassiveSetupParticipantInput =
    | string
    | {
          readonly trusteeIdentity: string;
          readonly rosterPosition?: number;
          readonly recoveryEpoch?: number;
          readonly deviceEpoch?: number;
      };

export type BgvPassiveSetupPackage = {
    readonly objectType: 'BgvPassiveSetupPackage';
    readonly setupPackageHash: ProtocolHash;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdParametersHash: ProtocolHash;
        readonly setupSeedHash: string;
    };
    readonly bgvParametersHash: ProtocolHash;
    readonly participants: readonly unknown[];
    readonly collectivePublicKey: {
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
        readonly bgvPublicKeyRoot: ProtocolHash;
        readonly record: unknown;
        readonly coefficientMaterial: unknown;
    };
    readonly thresholdVerificationMaterial: Readonly<Record<string, unknown>>;
    readonly evaluationKeys: {
        readonly evaluationKeyRoot: ProtocolHash;
        readonly record: BgvJsonRecord & {
            readonly rotSetHash: ProtocolHash;
        };
        readonly rotSet: unknown;
    };
    readonly targetDecryptionParametersHash: ProtocolHash;
};

export type BgvCollectiveSetupParametersDescription = {
    readonly setupParametersHash: ProtocolHash;
    readonly canonicalTargetBasisHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSetupComplete: number;
    readonly qBallotRelease: number;
    readonly qFinal: number;
    readonly qDec: number;
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
        readonly requiredGaloisSetHash: ProtocolHash;
    };
    readonly boundedDomainEvaluator: {
        readonly objectType: 'BoundedDomainEvaluatorParameters';
        readonly scoreDifferenceBound: number;
        readonly directComparisonOutputLevel: number;
        readonly tiePolicy: string;
    };
    readonly phaseOrder: readonly string[];
    readonly phaseOrderHash: ProtocolHash;
};

export type BgvCollectiveSetupVerification = {
    readonly isValid: boolean;
    readonly refusedObjects: readonly {
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }[];
};

export type BgvPrivateVssShareEnvelopeVerification = {
    readonly isValid: boolean;
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly ringDegree?: number;
    readonly limbVerifications: readonly {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly proofStatementRoot: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
    }[];
    readonly refusedObjects: readonly {
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
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

// One key share inside a trustee evaluation-key proof statement. The
// component material is supplied either as embedded coefficient matrices or
// as canonical binary component-material bytes; round-two keys also carry the
// recomputed public round-one aggregate diagonals.
export type BgvTrusteeEvaluationKeyStatementKey = {
    readonly proofFamily:
        | 'relinearization-round-one'
        | 'relinearization-round-two'
        | 'galois-rotation'
        | 'public-key-share';
    readonly rotation?: number;
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly componentBByDigit?: readonly (readonly (readonly number[])[])[];
    readonly componentMaterialBytesHex?: string;
    readonly roundOneAggregateDiagonal?: readonly (readonly number[])[];
};

// The kernel derives the key-bearing proof family from the key list. Trustee
// evaluation-key statements bind their schedule and exact source constant;
// public-key statements bind the separately verified bridge statement and
// proof record.
export type BgvTrusteeEvaluationKeyStatementContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
} & (
    | {
          readonly requiredGaloisSetHash: ProtocolHash;
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
    readonly setupParametersHash: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly bridgeRnsPrimes: readonly number[];
    readonly targetConstantCommitmentRoots: readonly ProtocolHash[];
    readonly targetConstantCommitments: readonly unknown[];
};

export type BgvVssShareLinkageProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly shareLinkageStatementRoot: ProtocolHash;
};

export type BgvSameSecretBridgeProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
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
    readonly trusteePoint: number;
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

// Release context derived from a caller-supplied setup package. This record is
// not an authority capability. It is round-tripped byte-for-byte as the begin
// command's releaseSetupContext input; only objectType and
// releaseSetupContextHash are consumed on the TypeScript side, while the
// remaining context fields are recomputed by the kernel.
export type BgvTargetDecryptionReleaseSetupContext = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'BgvTargetDecryptionReleaseSetupContext';
        readonly releaseSetupContextHash: ProtocolHash;
    }
>;

export type BgvTargetDecryptionResultReleaseBegin = {
    readonly releaseVerificationId: string;
    readonly requiredShareCount: number;
};

export type BgvTargetDecryptionResultReleaseShareAbsorption = {
    readonly absorbedShareCount: number;
    readonly requiredShareCount: number;
    readonly rosterPosition: number;
    readonly targetDecryptionShareHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvTargetDecryptionResultReleaseShareEvidence = {
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly interpolationPoint: number;
    readonly targetDecryptionShareHash: ProtocolHash;
    readonly proofStatementRoot: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvTargetDecryptionResultReleaseCompletion = {
    readonly targetResultHash: ProtocolHash;
    readonly targetIdByOption: readonly number[];
    readonly targetOrderByOption: readonly number[];
    readonly topCount: number;
    readonly shareEvidence: readonly BgvTargetDecryptionResultReleaseShareEvidence[];
};
