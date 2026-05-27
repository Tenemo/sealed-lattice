import type { ProtocolDigest } from '@sealed-lattice/types';

export type BgvRnsProfileReport = {
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
    readonly profileDigest: ProtocolDigest;
    readonly backendProfileDigest: ProtocolDigest;
    readonly batchEncoderDigest: ProtocolDigest;
    readonly encryptedAggregateInputLayoutDigest: ProtocolDigest;
    readonly batchLayoutBinding: unknown;
    readonly batchLayoutBindingDigest: ProtocolDigest;
    readonly ballotScoreEncodingProfileDigest: ProtocolDigest;
    readonly ballotShareLayoutProfileDigest: ProtocolDigest;
    readonly aggregateInputEncodingProfileDigest: ProtocolDigest;
    readonly encodedAggregateLayoutDigest: ProtocolDigest;
    readonly topKEvaluatorInputLayoutDigest: ProtocolDigest;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly allowedEvaluatorOpsDigest: ProtocolDigest;
    readonly securityEstimatorInputDigest: string;
    readonly bigIntegerReferenceVectors: unknown;
    readonly bigIntegerReferenceVectorRoot: ProtocolDigest;
    readonly basisReports: readonly unknown[];
    readonly statusLabels: readonly string[];
    readonly nonClaims: readonly string[];
};

export type BgvObjectValidation = {
    readonly ok: boolean;
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutDigest: ProtocolDigest;
    readonly plaintextRoot?: ProtocolDigest;
    readonly ciphertextRoot?: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly statusLabels: readonly string[];
};

export type BgvCanonicalObjectAnalysis = {
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutDigest: ProtocolDigest;
    readonly statusLabels: readonly string[];
};

export type BgvProfileRejection = {
    readonly ok: false;
    readonly operation: string;
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly {
        readonly code: 'BGVProfileRejected';
        readonly reasonCode: string;
        readonly message: string;
        readonly objectDigest?: ProtocolDigest;
    }[];
    readonly unresolvedReason: 'BGVProfileRejected';
    readonly statusLabels: readonly string[];
};

export type BgvEvaluatorOperationValidation =
    | {
          readonly ok: true;
          readonly operation: 'validateBgvEvaluatorOperation';
          readonly acceptedOperation: string;
          readonly allowedEvaluatorOpsDigest: ProtocolDigest;
          readonly statusLabels: readonly string[];
      }
    | BgvProfileRejection;

export type BgvBatchPlaintextEncoding = {
    readonly profileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly plaintextRoot: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly batchLayoutBindingDigest: ProtocolDigest;
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
    readonly profileDigest: ProtocolDigest;
    readonly ciphertextRoot: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly componentCount: number;
    readonly validation: BgvObjectValidation;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type BgvBaseConversionFixture = {
    readonly sourcePlaintextRoot: ProtocolDigest;
    readonly convertedPlaintextRoot: ProtocolDigest;
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
    readonly setupPackageDigest: ProtocolDigest;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestDigest: ProtocolDigest;
        readonly rosterDigest: ProtocolDigest;
        readonly thresholdProfileDigest: ProtocolDigest;
        readonly participantCount: number;
        readonly participantIdentities: readonly string[];
        readonly setupSeedDigest: string;
    };
    readonly profileBindings: Readonly<Record<string, unknown>>;
    readonly participants: readonly unknown[];
    readonly collectivePublicKey: {
        readonly collectivePublicKeyRoot: ProtocolDigest;
        readonly bgvPublicKeyRoot: ProtocolDigest;
        readonly statusLabels: readonly string[];
        readonly record: unknown;
    };
    readonly thresholdVerificationMaterial: Readonly<Record<string, unknown>>;
    readonly evaluationKeys: {
        readonly rotSetDigest: ProtocolDigest;
        readonly evaluationKeyRoot: ProtocolDigest;
        readonly relinearizationKeyRoot: ProtocolDigest;
        readonly keySwitchKeyRoot: ProtocolDigest;
        readonly keySwitchDecompositionDigest: ProtocolDigest;
        readonly rotationKeyRoots: readonly unknown[];
        readonly statusLabels: readonly string[];
        readonly record: unknown;
        readonly rotSet: unknown;
    };
    readonly developmentEncryptionFixture: Readonly<Record<string, unknown>>;
    readonly certificates: Readonly<Record<string, unknown>>;
    readonly trustedDealerBoundary: Readonly<Record<string, unknown>>;
    readonly kllpsCompatibility: {
        readonly thresholdDecryptionProfileId: string;
        readonly thresholdDecryptionProfileDigest: ProtocolDigest;
        readonly kllpsTargetDecryptionProfileDigest: ProtocolDigest;
        readonly setupMaterialCompatibleWithKLLPS: boolean;
        readonly KLLPSPartDecImplemented: boolean;
        readonly KLLPSC1C4Certified: boolean;
    };
    readonly statusLabels: readonly string[];
    readonly nonClaims: readonly string[];
};

export type BgvPassiveSetupVerification = {
    readonly ok: boolean;
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly statusLabels: readonly string[];
};
