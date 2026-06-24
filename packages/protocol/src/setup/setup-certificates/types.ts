import type { ProtocolHash } from '@sealed-lattice/types';

import type { setupTransportedObjectLoadingPolicy } from './constants.js';

export type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupProfileForCertificates = Readonly<
    JsonRecord & {
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProfileHash: ProtocolHash;
        readonly participantCount: number;
        readonly qDec: number;
        readonly qShare: Readonly<
            JsonRecord & {
                readonly primes: readonly number[];
            }
        >;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfile: Readonly<
            JsonRecord & {
                readonly messageEncoding: JsonRecord;
            }
        >;
        readonly commitmentProfileHash: ProtocolHash;
        readonly publicVssCommitmentMaterialSizeProfile: Readonly<
            JsonRecord & {
                readonly fullMaterialCoefficientBytes: number;
            }
        >;
        readonly setupProofProfile: JsonRecord;
        readonly setupProofProfileHash: ProtocolHash;
        readonly setupTransportProfile: JsonRecord;
        readonly setupTransportProfileHash: ProtocolHash;
        readonly acceptedCertificateTemplates?: JsonRecord;
        readonly evaluatorKeyScheduleProfile: Readonly<
            JsonRecord & {
                readonly relinearizationLevelSchedule: readonly Readonly<{
                    readonly level: number;
                }>[];
                readonly requiredGaloisKeySchedule: readonly Readonly<{
                    readonly level: number;
                }>[];
            }
        >;
        readonly evaluatorKeyScheduleProfileHash: ProtocolHash;
    }
>;

export type BgvRnsProfileForCertificates = Readonly<
    JsonRecord & {
        readonly profile: Readonly<
            JsonRecord & {
                readonly polynomialDegree: number;
                readonly plaintextModulus: number;
                readonly dataPrimes: readonly number[];
                readonly specialPrime: number;
            }
        >;
        readonly securityEstimatorInputHash: string;
    }
>;

export type SetupCertificateTransportedObjectInput = Readonly<{
    readonly objectName: string;
    readonly objectRole: string;
    readonly objectRoot: ProtocolHash;
    readonly byteLength: number;
    readonly fullObjectHash: ProtocolHash;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
}>;

export type SetupCertificateTransportInput = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly transportedObjects?: readonly SetupCertificateTransportedObjectInput[];
}>;

export type SetupCertificatesInput = Readonly<{
    readonly setupProfile:
        | CollectiveBgvSetupProfileForCertificates
        | JsonRecord;
    readonly bgvProfile: BgvRnsProfileForCertificates | JsonRecord;
    readonly vssCoefficientCommitmentMaterial: JsonRecord;
    readonly transport: SetupCertificateTransportInput;
    readonly sameSecretLinkageAnchorProofAccounting?: JsonRecord;
    readonly publicKeyShareProofAccounting?: JsonRecord;
    readonly trusteeEvaluationKeyProofAccounting?: JsonRecord;
}>;

export type SetupCommitmentSecurityCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupCommitmentSecurityCertificate';
        readonly objectVersion: 1;
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
    }
>;

export type SetupCommitmentSecurityCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupCommitmentSecurityCertificate';
        readonly objectVersion: 1;
    }
>;

export type SetupTransportCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportCertificate';
        readonly objectVersion: 1;
        readonly setupTransportCertificateHash: ProtocolHash;
    }
>;

export type SetupTransportCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportCertificate';
        readonly objectVersion: 1;
    }
>;

export type SetupProofAccountingCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupProofAccountingCertificate';
        readonly objectVersion: 1;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
    }
>;

export type SetupProofAccountingCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupProofAccountingCertificate';
        readonly objectVersion: 1;
    }
>;

export type BgvHeSecurityCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvHeSecurityCertificate';
        readonly objectVersion: 1;
        readonly heSecurityCertificateHash: ProtocolHash;
    }
>;

export type BgvHeSecurityCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvHeSecurityCertificate';
        readonly objectVersion: 1;
    }
>;

export type SetupCertificates = Readonly<{
    readonly setupCommitmentSecurityCertificate: SetupCommitmentSecurityCertificate;
    readonly setupTransportCertificate: SetupTransportCertificate;
    readonly setupProofAccountingCertificate: SetupProofAccountingCertificate;
    readonly heSecurityCertificate: BgvHeSecurityCertificate;
}>;

export type SetupTransportedObjectRecord = Readonly<{
    readonly objectType: 'SetupTransportedObject';
    readonly objectVersion: 1;
    readonly objectName: string;
    readonly objectRole: string;
    readonly objectRoot: ProtocolHash;
    readonly byteLength: number;
    readonly chunkStartIndex: number;
    readonly chunkCount: number;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
    readonly encoding: 'binary';
    readonly loadingPolicy: typeof setupTransportedObjectLoadingPolicy;
}>;
