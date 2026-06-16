import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type EvaluatorKeySchedule,
    type RelinearizationLevelScheduleEntry,
    type RequiredGaloisKeyScheduleEntry,
} from '../evaluator-key-schedule.js';
import { setupProofProfileId } from '../same-secret-consistency-records.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;
export type EvaluationKeyShareProofFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';

// Share records carry no proof fields: their correctness claim is the
// per-trustee succinct evaluation-key argument, so every record pins this
// status pair. Mirrors the kernel record statuses.
export const evaluationKeyShareRecordVerificationStatus =
    'share-records-bound-to-trustee-evaluation-key-argument';
export const trusteeEvaluationKeyProofModelStatus =
    'succinct-trustee-evaluation-key-argument-accounting-accepted';
export const trusteeEvaluationKeyProofVerificationStatus =
    'succinct-trustee-evaluation-key-argument-verified-with-accepted-proof-accounting';
export const trusteeEvaluationKeyProofFamily = 'trustee-evaluation-key';
export const publicEvaluationKeyAssemblyStatus =
    'assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate';
export const publicEvaluationKeyMaterialEncoding =
    'root-bound-public-key-switch-component-roots';
export const publicEvaluationKeyTransportMaterialEncoding =
    'binary-chunked-public-evaluation-key-root-manifest';
export const publicEvaluationKeyMaterialSource =
    'verified-relinearization-and-galois-proof-records';
export const publicEvaluationKeyMaterialTransportSetObjectType =
    'SetupTransportedPublicEvaluationKeyMaterialSet';
export const publicEvaluationKeyMaterialTransportObjectType =
    'SetupTransportedPublicEvaluationKeyMaterial';
export const evaluationKeyShareProofTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterialSet';
export const evaluationKeyShareProofTransportObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterial';
export const evaluationKeyShareComponentMaterialTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterialSet';
export const evaluationKeyShareComponentMaterialTransportObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterial';
export const evaluationKeyShareComponentMaterialEncoding =
    'binary-chunked-key-switch-component-vectors';
export const setupProofMaterialTransportEncoding = 'binary-chunked-proof-bytes';
export const evaluationKeyShareComponentVectorHashDomain =
    'sealed-lattice-bgv-rns/evaluation-key-share-component-vector-v1';
export const evaluationKeyShareComponentMaterialFullObjectHashDomain =
    'sealed-lattice/setup/evaluation-key-share/component-material/full-object-v1';
export const evaluationKeyShareComponentMaterialChunkHashDomain =
    'sealed-lattice/setup/evaluation-key-share/component-material/chunk-v1';
export const trusteeEvaluationKeyProofBytesHashDomain =
    'sealed-lattice/setup/trustee-evaluation-key/proof-bytes-v1';
export const evaluationKeyShareComponentMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x31,
]);
export const publicEvaluationKeyMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x50, 0x4d, 0x56, 0x31,
]);
export const textEncoder = new TextEncoder();

export const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

export type SameSecretProofReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
}>;

export type KeySwitchComponentVectorEntry = Readonly<JsonRecord>;

export type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors';
    readonly keySwitchComponentVectors: readonly KeySwitchComponentVectorEntry[];
}>;

export type EvaluationKeyShareTransportedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: typeof evaluationKeyShareComponentMaterialEncoding;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
    readonly keySwitchComponentChunkSizeBytes: number;
    readonly keySwitchComponentChunkCount: number;
    readonly keySwitchComponentTotalByteLength: number;
    readonly keySwitchComponentFullObjectHash: ProtocolHash;
    readonly keySwitchComponentChunkRoot: ProtocolHash;
    readonly keySwitchComponentChunkHashes: readonly ProtocolHash[];
}>;

export type EvaluationKeyShareKeySwitchComponentMaterial =
    | EvaluationKeyShareEmbeddedKeySwitchComponentMaterial
    | EvaluationKeyShareTransportedKeySwitchComponentMaterial;

// The public key-switch component material one trustee publishes for one
// scheduled key: the runtime key share itself, either embedded as canonical
// component vector entries or referenced as binary chunked transport.
export type EvaluationKeyShareMaterial = Readonly<{
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly ringDegree: number;
    readonly keySwitchComponentVectorRoot: ProtocolHash;
}> &
    EvaluationKeyShareKeySwitchComponentMaterial;

export type RelinearizationRoundOneContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundOneShareRoot: ProtocolHash;
    readonly shareMaterial: EvaluationKeyShareMaterial;
}>;

export type RelinearizationRoundTwoContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundTwoShareRoot: ProtocolHash;
    readonly shareMaterial: EvaluationKeyShareMaterial;
}>;

export type GaloisKeyShareContribution = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly galoisKeyShareRoot: ProtocolHash;
    readonly shareMaterial: EvaluationKeyShareMaterial;
}>;

export type GaloisKeyShareBatchContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShares: readonly GaloisKeyShareContribution[];
}>;

export type RelinearizationKeyShareRoundOneRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundOne';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof evaluationKeyShareRecordVerificationStatus;
        readonly proofModelStatus: typeof trusteeEvaluationKeyProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial
>;

export type RelinearizationKeyShareRoundTwoRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundTwo';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof evaluationKeyShareRecordVerificationStatus;
        readonly proofModelStatus: typeof trusteeEvaluationKeyProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
        readonly roundOneAggregateRoot: ProtocolHash;
        readonly roundTwoShareRoot: ProtocolHash;
        readonly roundTwoRecordRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial
>;

export type RelinearizationKeyShareRounds = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRounds';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof evaluationKeyShareRecordVerificationStatus;
        readonly proofModelStatus: typeof trusteeEvaluationKeyProofModelStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly roundOneAggregateRoots: readonly {
            readonly level: number;
            readonly roundOneAggregateRoot: ProtocolHash;
        }[];
        readonly roundOneRecords: readonly RelinearizationKeyShareRoundOneRecord[];
        readonly roundTwoAggregateRoots: readonly {
            readonly level: number;
            readonly roundTwoAggregateRoot: ProtocolHash;
        }[];
        readonly roundTwoRecords: readonly RelinearizationKeyShareRoundTwoRecord[];
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
    }
>;

export type GaloisKeyShareRootReference = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly galoisKeyShareRoot: ProtocolHash;
}>;

export type GaloisKeyShareMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareMaterial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'galois-key-share';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly rotation: number;
        readonly level: number;
        readonly galoisKeyShareRoot: ProtocolHash;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial
>;

export type GaloisKeyShareBatch = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareBatch';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'galois-key-share';
        readonly proofVerificationStatus: typeof evaluationKeyShareRecordVerificationStatus;
        readonly proofModelStatus: typeof trusteeEvaluationKeyProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareRoots: readonly GaloisKeyShareRootReference[];
        readonly galoisKeyShareMaterialRecords: readonly GaloisKeyShareMaterialRecord[];
        readonly galoisKeyShareBatchRoot: ProtocolHash;
    }
>;

export type TrusteeEvaluationKeyEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type TrusteeEvaluationKeyTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: typeof setupProofMaterialTransportEncoding;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type TrusteeEvaluationKeyProofRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'TrusteeEvaluationKeyProof';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
        readonly proofVerificationStatus: typeof trusteeEvaluationKeyProofVerificationStatus;
        readonly proofModelStatus: typeof trusteeEvaluationKeyProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly statementHash: ProtocolHash;
        readonly keyCount: number;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
        readonly trusteeEvaluationKeyProofRoot: ProtocolHash;
    } & (
            | TrusteeEvaluationKeyEmbeddedProofBytes
            | TrusteeEvaluationKeyTransportedProofBytes
        )
>;

export type TrusteeEvaluationKeyProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'TrusteeEvaluationKeyProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
        readonly proofVerificationStatus: typeof trusteeEvaluationKeyProofVerificationStatus;
        readonly proofModelStatus: typeof trusteeEvaluationKeyProofModelStatus;
        readonly proofAccountingHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly keySwitchDecompositionHash: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly galoisKeyShareBatchRoots: readonly {
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly galoisKeyShareBatchRoot: ProtocolHash;
        }[];
        readonly proofRecords: readonly TrusteeEvaluationKeyProofRecord[];
        readonly trusteeEvaluationKeyProofSetRoot: ProtocolHash;
    }
>;

// Statement key descriptors for the kernel trustee evaluation-key proof
// commands: relinearization round-one and round-two keys plus Galois rotation
// keys, each with the full public component-b material. The round-two keys
// additionally carry the recomputed public round-one aggregate diagonal.
export type TrusteeEvaluationKeyStatementKey = Readonly<{
    readonly proofFamily:
        | 'relinearization-round-one'
        | 'relinearization-round-two'
        | 'galois-rotation';
    readonly rotation?: number;
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly componentBByDigit: readonly (readonly (readonly number[])[])[];
    readonly roundOneAggregateDiagonal?: readonly (readonly number[])[];
}>;

export type TrusteeEvaluationKeyStatementContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly requiredGaloisSetHash: ProtocolHash;
    readonly evaluatorKeyScheduleRoot: ProtocolHash;
    readonly keySwitchDecompositionHash: ProtocolHash;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
}>;

export type TrusteeEvaluationKeyProofGenerationOutput = Readonly<{
    readonly ok: true;
    readonly operation: 'generateTrusteeEvaluationKeyProof';
    readonly proofModelStatus: string;
    readonly proofAccountingHash: ProtocolHash;
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly keyCount: number;
    readonly sameSecretLinkageIncluded: boolean;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
    readonly proofRandomness: Readonly<{
        readonly source: string;
        readonly binding?: string;
        readonly nonceHash?: ProtocolHash;
        readonly retention: string;
    }>;
}>;

export type TrusteeEvaluationKeyProofGenerator = (
    input: Readonly<{
        readonly context: TrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly TrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage: Readonly<{
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly commitments: readonly JsonRecord[];
        }>;
        readonly secretCoefficients: readonly number[];
        readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
        readonly negativeIndicatorCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSource: string;
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }>,
) => TrusteeEvaluationKeyProofGenerationOutput;

// One trustee's private witness for its batched evaluation-key statement: the
// shared ternary secret, per-key centered-binomial errors in statement key
// order (relinearization round-one levels ascending, round-two levels
// ascending, then the frozen Galois schedule), the negative-coefficient
// indicator, the BDLOP opening randomness, and the same-secret constant
// commitments the linkage opens.
export type TrusteeEvaluationKeyWitnessInput = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly secretCoefficients: readonly number[];
    readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
    readonly constantCommitments: readonly JsonRecord[];
}>;

export type RelinearizationKeyRootReference = Readonly<{
    readonly level: number;
    readonly decompositionDigitCount: number;
    readonly rnsLimbCount: number;
    readonly roundOneAggregateRoot: ProtocolHash;
    readonly roundTwoAggregateRoot: ProtocolHash;
    readonly relinearizationKeyRoot: ProtocolHash;
}>;

export type GaloisKeyShareBatchRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareBatchRoot: ProtocolHash;
}>;

export type GaloisKeyContributingShareRoot = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareRoot: ProtocolHash;
}>;

export type GaloisKeyRootReference = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly decompositionDigitCount: number;
    readonly rnsLimbCount: number;
    readonly galoisKeyRoot: ProtocolHash;
    readonly contributingShareRoots: readonly GaloisKeyContributingShareRoot[];
}>;

export type PublicEvaluationKeySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicEvaluationKeySet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly assemblyStatus: typeof publicEvaluationKeyAssemblyStatus;
        readonly materialEncoding: typeof publicEvaluationKeyMaterialEncoding;
        readonly materialSource: typeof publicEvaluationKeyMaterialSource;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly relinearizationKeyRoots: readonly RelinearizationKeyRootReference[];
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareBatchRoots: readonly GaloisKeyShareBatchRootReference[];
        readonly galoisKeyRoots: readonly GaloisKeyRootReference[];
        readonly genericKeySwitchKeyRoots: readonly ProtocolHash[];
        readonly rawKeyBytesEmbedded: false;
        readonly verifierGeneratedKeyMaterial: false;
        readonly publicEvaluationKeyMaterialEncoding?: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
        readonly publicEvaluationKeyMaterialChunkSizeBytes?: number;
        readonly publicEvaluationKeyMaterialChunkCount?: number;
        readonly publicEvaluationKeyMaterialTotalByteLength?: number;
        readonly publicEvaluationKeyMaterialFullObjectHash?: ProtocolHash;
        readonly publicEvaluationKeyMaterialChunkRoot?: ProtocolHash;
        readonly publicEvaluationKeyMaterialChunkHashes?: readonly ProtocolHash[];
        readonly evaluationKeySetHash: ProtocolHash;
    }
>;

export type PublicEvaluationKeyMaterialReference = Readonly<{
    readonly publicEvaluationKeyMaterialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
    readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
    readonly publicEvaluationKeyMaterialChunkSizeBytes: number;
    readonly publicEvaluationKeyMaterialChunkCount: number;
    readonly publicEvaluationKeyMaterialTotalByteLength: number;
    readonly publicEvaluationKeyMaterialFullObjectHash: ProtocolHash;
    readonly publicEvaluationKeyMaterialChunkRoot: ProtocolHash;
    readonly publicEvaluationKeyMaterialChunkHashes: readonly ProtocolHash[];
}>;

export type TransportedEvaluationKeyShareProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareProofTransportSetObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
        readonly proofMaterials: readonly JsonRecord[];
    }
>;

export type TransportedEvaluationKeyShareComponentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareComponentMaterialTransportSetObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly componentMaterials: readonly JsonRecord[];
    }
>;

export type TransportedPublicEvaluationKeyMaterial = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly materialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
        readonly chunkSizeBytes: number;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkRoot: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunks: readonly {
            readonly chunkIndex: number;
            readonly bytesHex: string;
        }[];
    }
>;

export type TransportedPublicEvaluationKeyMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportSetObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly materialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly publicEvaluationKeyMaterials: readonly TransportedPublicEvaluationKeyMaterial[];
        readonly componentMaterials?: readonly JsonRecord[];
    }
>;

export type BinaryChunkedPublicEvaluationKeyMaterialTransport = Readonly<{
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly publicEvaluationKeyMaterialReference: PublicEvaluationKeyMaterialReference;
    readonly transportedPublicEvaluationKeyMaterial: TransportedPublicEvaluationKeyMaterialSet;
}>;

export type BinaryChunkedEvaluationKeyShareMaterialTransport = Readonly<{
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly transportedEvaluationKeyShareComponentMaterial: TransportedEvaluationKeyShareComponentMaterialSet;
}>;

export type EvaluationKeyShareMaterialTransportInput = Readonly<{
    readonly sameSecretProofReferences: readonly Pick<
        SameSecretProofReference,
        'trusteeIdentity' | 'trusteeRosterPosition'
    >[];
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
}>;

export type EvaluationKeyProofCommonInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly sameSecretProofSetRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    readonly sameSecretProofReferences: readonly SameSecretProofReference[];
}>;

export type RelinearizationKeyShareRoundsInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly roundOneContributions: readonly RelinearizationRoundOneContribution[];
        readonly roundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    }>;

export type GaloisKeyShareBatchesInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly batchContributions: readonly GaloisKeyShareBatchContribution[];
    }>;

export type TrusteeEvaluationKeyProofsInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly keySwitchDecompositionHash: ProtocolHash;
        readonly trusteeWitnesses: readonly TrusteeEvaluationKeyWitnessInput[];
        readonly trusteeEvaluationKeyProofGenerator: TrusteeEvaluationKeyProofGenerator;
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    }>;

export type PublicEvaluationKeySetInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly publicEvaluationKeyMaterialReference?: PublicEvaluationKeyMaterialReference;
    }>;

export type PublicEvaluationKeyMaterialTransportInput = Omit<
    PublicEvaluationKeySetInput,
    'publicEvaluationKeyMaterialReference'
> &
    Readonly<{
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    }>;
