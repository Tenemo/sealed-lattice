import type { ProtocolHash } from '@sealed-lattice/types';

export type BgvRnsProfileDescription = {
    readonly profile: {
        readonly profileId: string;
        readonly backendProfileId: string;
        readonly polynomialDegree: number;
        readonly plaintextModulus: number;
        readonly dataBasisId: string;
        readonly extendedBasisId: string;
        readonly specialBasisId: string;
        readonly dataPrimes: readonly number[];
        readonly specialPrime: number;
        readonly dataPrimeBitLength: number;
        readonly dataLevels: number;
        readonly extendedLevels: number;
        readonly aggregateShareLayoutId: string;
        readonly batchEncoderId: string;
        readonly canonicalCiphertextConventionId: string;
    };
    readonly profileHash: ProtocolHash;
    readonly backendProfileHash: ProtocolHash;
    readonly batchEncoderHash: ProtocolHash;
    readonly encryptedBallotAggregateLayoutHash: ProtocolHash;
    readonly batchLayoutBinding: unknown;
    readonly batchLayoutBindingHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly encryptedBallotLayoutHash: ProtocolHash;
    readonly encryptedBallotAggregateProfileHash: ProtocolHash;
    readonly directAggregateLayoutHash: ProtocolHash;
    readonly directComparisonProfileHash: ProtocolHash;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly allowedEvaluatorOpsHash: ProtocolHash;
    readonly securityEstimatorInputHash: string;
};

export type BgvObjectValidation = {
    readonly ok: boolean;
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutHash: ProtocolHash;
    readonly plaintextRoot?: ProtocolHash;
    readonly ciphertextRoot?: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly statusLabels: readonly string[];
};

export type BgvCanonicalObjectAnalysis = {
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutHash: ProtocolHash;
    readonly statusLabels: readonly string[];
};

export type BgvProfileRejection = {
    readonly ok: false;
    readonly operation: string;
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly {
        readonly code: 'BGVProfileRejected';
        readonly reasonCode: string;
        readonly message: string;
        readonly objectHash?: ProtocolHash;
    }[];
    readonly unresolvedReason: 'BGVProfileRejected';
    readonly statusLabels: readonly string[];
};

export type BgvEvaluatorOperationValidation =
    | {
          readonly ok: true;
          readonly operation: 'validateBgvEvaluatorOperation';
          readonly acceptedOperation: string;
          readonly allowedEvaluatorOpsHash: ProtocolHash;
          readonly statusLabels: readonly string[];
      }
    | BgvProfileRejection;

export type BgvBatchPlaintextEncoding = {
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly plaintextRoot: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly batchLayoutBindingHash: ProtocolHash;
    readonly sampledSlots: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly sampledCoefficientsModPlaintext: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly validation: BgvObjectValidation;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type BgvReferenceOracleRejection = {
    readonly ok: false;
    readonly artifactKind: string;
    readonly acceptedAsProtocolEvidence: false;
    readonly statusLabels: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
};

export type BgvCiphertextConventionFixture = {
    readonly profileHash: ProtocolHash;
    readonly ciphertextRoot: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly componentCount: number;
    readonly validation: BgvObjectValidation;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type BgvBaseConversionFixture = {
    readonly sourcePlaintextRoot: ProtocolHash;
    readonly convertedPlaintextRoot: ProtocolHash;
    readonly sourceCanonicalBytesHash512: string;
    readonly convertedCanonicalBytesHash512: string;
    readonly sourceBasisId: string;
    readonly convertedBasisId: string;
    readonly convertedModulusCount: number;
    readonly sampledConvertedResidues: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly statusLabels: readonly string[];
};

export type BgvPassiveSetupParticipantInput =
    | string
    | {
          readonly trusteeIdentity: string;
          readonly rosterPosition?: number;
          readonly boardPosition?: number;
          readonly recoveryEpoch?: number;
          readonly deviceEpoch?: number;
      };

export type BgvPassiveSetupPackage = {
    readonly objectType: 'BgvPassiveSetupPackage';
    readonly objectVersion: 1;
    readonly setupProfileId: string;
    readonly setupMode: string;
    readonly setupPackageHash: ProtocolHash;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdProfileHash: ProtocolHash;
        readonly participantCount: number;
        readonly participantIdentities: readonly string[];
        readonly setupSeedHash: string;
    };
    readonly profileBindings: Readonly<Record<string, unknown>>;
    readonly participants: readonly unknown[];
    readonly collectivePublicKey: {
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
        readonly bgvPublicKeyRoot: ProtocolHash;
        readonly statusLabels: readonly string[];
        readonly record: unknown;
        readonly coefficientMaterial: unknown;
    };
    readonly thresholdVerificationMaterial: Readonly<Record<string, unknown>>;
    readonly evaluationKeys: {
        readonly rotSetHash: ProtocolHash;
        readonly evaluationKeyRoot: ProtocolHash;
        readonly relinearizationKeyRoot: ProtocolHash;
        readonly keySwitchKeyRoot: ProtocolHash;
        readonly keySwitchDecompositionHash: ProtocolHash;
        readonly rotationKeyRoots: readonly unknown[];
        readonly statusLabels: readonly string[];
        readonly record: unknown;
        readonly rotSet: unknown;
    };
    readonly developmentEncryptionFixture: Readonly<Record<string, unknown>>;
    readonly certificates: Readonly<Record<string, unknown>>;
    readonly trustedDealerBoundary: Readonly<Record<string, unknown>>;
    readonly targetDecryptionStatus: {
        readonly targetDecryptionProfileId: string;
        readonly targetDecryptionProfileHash: ProtocolHash;
        readonly targetDecryptionProfileBindingHash: ProtocolHash;
        readonly setupMaterialMatchesTargetDecryption: boolean;
        readonly targetPartDecImplemented: boolean;
        readonly targetC1C4StatusAccepted: boolean;
    };
    readonly statusLabels: readonly string[];
    readonly nonClaims: readonly string[];
};

export type BgvPassiveSetupVerification = {
    readonly ok: boolean;
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly statusLabels: readonly string[];
};
