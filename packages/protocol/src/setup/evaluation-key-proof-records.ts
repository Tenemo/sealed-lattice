import {
    canonicalJson,
    deriveProtocolHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { BinaryChunkWriter } from './binary-chunk-writer.js';
import {
    type EvaluatorKeySchedule,
    type RelinearizationLevelScheduleEntry,
    type RequiredGaloisKeyScheduleEntry,
} from './evaluator-key-schedule.js';
import { setupProofProfileId } from './same-secret-consistency-records.js';
import {
    setupProofChunkManifestRoot,
    setupProofMaterialChunkHash,
    setupProofTransportChunkSizeBytes,
} from './setup-proof-material-transport.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;
type EvaluationKeyShareProofFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';

// Share records carry no proof fields: their correctness claim is the
// per-trustee succinct evaluation-key argument, so every record pins this
// status pair. Mirrors the kernel record statuses.
export const evaluationKeyShareRecordVerificationStatus =
    'share-records-bound-to-trustee-evaluation-key-argument';
export const trusteeEvaluationKeyProofModelStatus =
    'succinct-trustee-evaluation-key-argument-accounting-pending';
export const trusteeEvaluationKeyProofVerificationStatus =
    'succinct-trustee-evaluation-key-argument-verified-with-open-proof-accounting';
export const trusteeEvaluationKeyProofFamily = 'trustee-evaluation-key';
const publicEvaluationKeyAssemblyStatus =
    'assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate';
const publicEvaluationKeyMaterialEncoding =
    'root-bound-public-key-switch-component-roots';
const publicEvaluationKeyTransportMaterialEncoding =
    'binary-chunked-public-evaluation-key-root-manifest';
const publicEvaluationKeyMaterialSource =
    'verified-relinearization-and-galois-proof-records';
const publicEvaluationKeyMaterialTransportSetObjectType =
    'SetupTransportedPublicEvaluationKeyMaterialSet';
const publicEvaluationKeyMaterialTransportObjectType =
    'SetupTransportedPublicEvaluationKeyMaterial';
const evaluationKeyShareProofTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterialSet';
const evaluationKeyShareProofTransportObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterial';
const evaluationKeyShareComponentMaterialTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterialSet';
const evaluationKeyShareComponentMaterialTransportObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterial';
export const evaluationKeyShareComponentMaterialEncoding =
    'binary-chunked-key-switch-component-vectors';
const setupProofMaterialTransportEncoding = 'binary-chunked-proof-bytes';
const evaluationKeyShareComponentVectorHashDomain =
    'sealed-lattice-bgv-rns/evaluation-key-share-component-vector-v1';
const evaluationKeyShareComponentMaterialFullObjectHashDomain =
    'sealed-lattice/setup/evaluation-key-share/component-material/full-object-v1';
const evaluationKeyShareComponentMaterialChunkHashDomain =
    'sealed-lattice/setup/evaluation-key-share/component-material/chunk-v1';
const trusteeEvaluationKeyProofBytesHashDomain =
    'sealed-lattice/setup/trustee-evaluation-key/proof-bytes-v1';
const evaluationKeyShareComponentMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x31,
]);
const publicEvaluationKeyMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x50, 0x4d, 0x56, 0x31,
]);
const textEncoder = new TextEncoder();

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
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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
    readonly proofRandomnessSource:
        | 'fresh-csprng'
        | 'development-deterministic-fixture';
    readonly proofRandomnessSeedHex: string;
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
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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
    readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
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

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^[0-9a-f]+$/u;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertLowercaseHex = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex.`);
    }
};

const assertJsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (value === null || Array.isArray(value) || typeof value !== 'object') {
        throw new TypeError(`${fieldName} must be a JSON object.`);
    }

    return value as JsonRecord;
};

const stringRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const value = record[fieldName];
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return value;
};

const nonNegativeIntegerRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const value = record[fieldName];
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const appendVaruint = (outputBytes: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'binary varuint value must be a non-negative safe integer.',
        );
    }
    let remainingValue = value;
    do {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        outputBytes.push(byte);
    } while (remainingValue !== 0);
};

const varUintBytes = (value: number): Uint8Array => {
    const outputBytes: number[] = [];
    appendVaruint(outputBytes, value);

    return Uint8Array.from(outputBytes);
};

const coefficientVectorFromLittleEndianHex = (
    coefficientsLeHex: string,
    expectedCoefficientCount: number,
    fieldName: string,
): readonly number[] => {
    const coefficientBytes = bytesFromHex(coefficientsLeHex, fieldName);
    if (coefficientBytes.byteLength !== expectedCoefficientCount * 8) {
        throw new Error(`${fieldName} byte length must match ringDegree.`);
    }

    return Array.from(
        { length: expectedCoefficientCount },
        (_unused, coefficientIndex) => {
            let coefficient = 0n;
            for (let byteOffset = 7; byteOffset >= 0; byteOffset -= 1) {
                coefficient <<= 8n;
                coefficient |= BigInt(
                    coefficientBytes[coefficientIndex * 8 + byteOffset] ?? 0,
                );
            }
            if (coefficient > BigInt(Number.MAX_SAFE_INTEGER)) {
                throw new Error(
                    `${fieldName} contains a coefficient outside the JavaScript safe integer range.`,
                );
            }

            return Number(coefficient);
        },
    );
};

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (!Number.isSafeInteger(coefficient) || coefficient < 0) {
            throw new TypeError(
                'evaluation-key component coefficient must be a non-negative safe integer.',
            );
        }
        let remainingValue = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(
                remainingValue & 0xffn,
            );
            remainingValue >>= 8n;
        }
    });

    return bytes;
};

export const evaluationKeyShareComponentVectorHash = (
    coefficients: readonly number[],
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const u64LittleEndianBytes = (value: number, fieldName: string): Uint8Array => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);

    return bytes;
};

export const evaluationKeyShareComponentVectorRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    level: number,
    ringDegree: number,
    componentVectors: readonly JsonRecord[],
): ProtocolHash =>
    deriveProtocolHash('EvaluationKeyShareComponentVectorRoot', {
        objectType: 'EvaluationKeyShareComponentVectorSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        componentVectors,
    });

const evaluationKeyShareComponentMaterialFullObjectHash = (
    proofFamily: EvaluationKeyShareProofFamily,
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentMaterialFullObjectHashDomain, [
        textEncoder.encode(proofFamily),
        varUintBytes(totalByteLength),
        ...chunks,
    ]);

const evaluationKeyShareComponentMaterialChunkHash = (
    proofFamily: EvaluationKeyShareProofFamily,
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentMaterialChunkHashDomain, [
        textEncoder.encode(proofFamily),
        textEncoder.encode(fullObjectHash),
        varUintBytes(chunkIndex),
        chunk,
    ]);

type ComponentMaterialTransportHashes = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}>;

const evaluationKeyShareComponentMaterialTransportHashes = (
    proofFamily: EvaluationKeyShareProofFamily,
    chunks: readonly Uint8Array[],
): ComponentMaterialTransportHashes => {
    const totalByteLength = chunks.reduce(
        (byteLength, chunk) => byteLength + chunk.byteLength,
        0,
    );
    const fullObjectHash = evaluationKeyShareComponentMaterialFullObjectHash(
        proofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        evaluationKeyShareComponentMaterialChunkHash(
            proofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const chunkRoot = deriveProtocolHash(
        'EvaluationKeyShareComponentMaterialChunkRoot',
        {
            objectType: 'EvaluationKeyShareComponentMaterialChunkManifest',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily,
            keySwitchMaterialEncoding:
                evaluationKeyShareComponentMaterialEncoding,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    );

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const evaluationKeyShareComponentMaterialReferenceRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    shareMaterial: EvaluationKeyShareMaterial,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
    transportHashes: ComponentMaterialTransportHashes,
): ProtocolHash =>
    deriveProtocolHash('EvaluationKeyShareComponentMaterialRoot', {
        objectType: 'EvaluationKeyShareComponentMaterialReference',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        trusteeIdentity,
        trusteeRosterPosition,
        keySwitchDomain: shareMaterial.keySwitchDomain,
        keySwitchSeedHex: shareMaterial.keySwitchSeedHex,
        level,
        ringDegree: shareMaterial.ringDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        keySwitchComponentVectorRoot:
            shareMaterial.keySwitchComponentVectorRoot,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: transportHashes.chunkHashes.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkRoot: transportHashes.chunkRoot,
        chunkHashes: transportHashes.chunkHashes,
    });

const assertEmbeddedComponentMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    fieldName: string,
): EvaluationKeyShareMaterial &
    EvaluationKeyShareEmbeddedKeySwitchComponentMaterial => {
    if (
        shareMaterial.keySwitchMaterialEncoding !==
        'embedded-full-key-switch-component-vectors'
    ) {
        throw new Error(
            `${fieldName}.keySwitchMaterialEncoding must embed full key-switch component vectors.`,
        );
    }
    if (shareMaterial.keySwitchComponentVectors.length === 0) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectors must be non-empty.`,
        );
    }

    return shareMaterial;
};

const assertShareMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    expectedComponentVectorRoot: ProtocolHash,
    fieldName: string,
): void => {
    assertNonEmptyString(
        shareMaterial.keySwitchDomain,
        `${fieldName}.keySwitchDomain`,
    );
    assertNonEmptyString(
        shareMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertLowercaseHex(
        shareMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertPositiveSafeInteger(
        shareMaterial.ringDegree,
        `${fieldName}.ringDegree`,
    );
    assertProtocolHash(
        shareMaterial.keySwitchComponentVectorRoot,
        `${fieldName}.keySwitchComponentVectorRoot`,
    );
    if (
        shareMaterial.keySwitchComponentVectorRoot !==
        expectedComponentVectorRoot
    ) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectorRoot must match the share root.`,
        );
    }
    if (
        shareMaterial.keySwitchMaterialEncoding ===
        'embedded-full-key-switch-component-vectors'
    ) {
        if (shareMaterial.keySwitchComponentVectors.length === 0) {
            throw new Error(
                `${fieldName}.keySwitchComponentVectors must be non-empty.`,
            );
        }
        shareMaterial.keySwitchComponentVectors.forEach(
            (componentVector, vectorIndex) => {
                assertJsonRecord(
                    componentVector,
                    `${fieldName}.keySwitchComponentVectors.${String(vectorIndex)}`,
                );
            },
        );
    } else if (
        shareMaterial.keySwitchMaterialEncoding ===
        evaluationKeyShareComponentMaterialEncoding
    ) {
        for (const [hashFieldName, hashValue] of [
            [
                'keySwitchComponentMaterialRoot',
                shareMaterial.keySwitchComponentMaterialRoot,
            ],
            [
                'keySwitchComponentFullObjectHash',
                shareMaterial.keySwitchComponentFullObjectHash,
            ],
            [
                'keySwitchComponentChunkRoot',
                shareMaterial.keySwitchComponentChunkRoot,
            ],
        ] as const) {
            assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
        }
        assertPositiveSafeInteger(
            shareMaterial.keySwitchComponentChunkSizeBytes,
            `${fieldName}.keySwitchComponentChunkSizeBytes`,
        );
        assertPositiveSafeInteger(
            shareMaterial.keySwitchComponentChunkCount,
            `${fieldName}.keySwitchComponentChunkCount`,
        );
        assertPositiveSafeInteger(
            shareMaterial.keySwitchComponentTotalByteLength,
            `${fieldName}.keySwitchComponentTotalByteLength`,
        );
        if (
            shareMaterial.keySwitchComponentChunkHashes.length !==
            shareMaterial.keySwitchComponentChunkCount
        ) {
            throw new Error(
                `${fieldName}.keySwitchComponentChunkHashes must match keySwitchComponentChunkCount.`,
            );
        }
        shareMaterial.keySwitchComponentChunkHashes.forEach(
            (chunkHash, chunkIndex) => {
                assertProtocolHash(
                    chunkHash,
                    `${fieldName}.keySwitchComponentChunkHashes.${String(chunkIndex)}`,
                );
            },
        );
    } else {
        throw new TypeError(
            `${fieldName}.keySwitchMaterialEncoding must be embedded-full-key-switch-component-vectors or ${evaluationKeyShareComponentMaterialEncoding}.`,
        );
    }
};

const shareMaterialRecordFields = (
    shareMaterial: EvaluationKeyShareMaterial,
): JsonRecord => ({
    keySwitchDomain: shareMaterial.keySwitchDomain,
    keySwitchSeedHex: shareMaterial.keySwitchSeedHex,
    ringDegree: shareMaterial.ringDegree,
    keySwitchComponentVectorRoot: shareMaterial.keySwitchComponentVectorRoot,
    ...(shareMaterial.keySwitchMaterialEncoding ===
    'embedded-full-key-switch-component-vectors'
        ? {
              keySwitchMaterialEncoding:
                  shareMaterial.keySwitchMaterialEncoding,
              keySwitchComponentVectors:
                  shareMaterial.keySwitchComponentVectors,
          }
        : {
              keySwitchMaterialEncoding:
                  shareMaterial.keySwitchMaterialEncoding,
              keySwitchComponentMaterialRoot:
                  shareMaterial.keySwitchComponentMaterialRoot,
              keySwitchComponentChunkSizeBytes:
                  shareMaterial.keySwitchComponentChunkSizeBytes,
              keySwitchComponentChunkCount:
                  shareMaterial.keySwitchComponentChunkCount,
              keySwitchComponentTotalByteLength:
                  shareMaterial.keySwitchComponentTotalByteLength,
              keySwitchComponentFullObjectHash:
                  shareMaterial.keySwitchComponentFullObjectHash,
              keySwitchComponentChunkRoot:
                  shareMaterial.keySwitchComponentChunkRoot,
              keySwitchComponentChunkHashes:
                  shareMaterial.keySwitchComponentChunkHashes,
          }),
});

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

const relinearizationKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): ProtocolHash =>
    deriveProtocolHash('RelinearizationKeyShareSeed', {
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: evaluatorKeySchedule.relinearizationCrpRoot,
        round,
        level,
    });

const galoisKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): ProtocolHash =>
    deriveProtocolHash('GaloisKeyShareSeed', {
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
        rotation,
        level,
    });

const assertRelinearizationKeySwitchSampleBinding = (
    shareMaterial: EvaluationKeyShareMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
    fieldName: string,
): void => {
    if (shareMaterial.keySwitchDomain !== 'relinearization') {
        throw new Error(
            `${fieldName}.keySwitchDomain must be relinearization.`,
        );
    }
    const expectedSeed = relinearizationKeySwitchSeed(
        evaluatorKeySchedule,
        round,
        level,
    );
    if (shareMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled relinearization level and round.`,
        );
    }
};

const assertGaloisKeySwitchSampleBinding = (
    shareMaterial: EvaluationKeyShareMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
    fieldName: string,
): void => {
    const expectedDomain = `galois-${String(rotation)}`;
    if (shareMaterial.keySwitchDomain !== expectedDomain) {
        throw new Error(
            `${fieldName}.keySwitchDomain must match the scheduled Galois rotation.`,
        );
    }
    const expectedSeed = galoisKeySwitchSeed(
        evaluatorKeySchedule,
        rotation,
        level,
    );
    if (shareMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled Galois rotation and level.`,
        );
    }
};

const sortedSameSecretProofReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        'participantCount' | 'sameSecretProofReferences'
    >,
): SameSecretProofReference[] => {
    const references = [...input.sameSecretProofReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofReferences must contain one proof per participant.',
        );
    }
    references.forEach((reference, expectedRosterPosition) => {
        assertNonEmptyString(reference.trusteeIdentity, 'trusteeIdentity');
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            'trusteeRosterPosition',
        );
        if (reference.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofReferences roster positions must be contiguous from zero.',
            );
        }
        for (const [fieldName, hashValue] of [
            ['sameSecretStatementRoot', reference.sameSecretStatementRoot],
            [
                'trusteeSecretCommitmentRoot',
                reference.trusteeSecretCommitmentRoot,
            ],
            ['sameSecretProofRoot', reference.sameSecretProofRoot],
        ] as const) {
            assertProtocolHash(hashValue, fieldName);
        }
    });

    return references;
};

const validateCommonInput = (
    input: EvaluationKeyProofCommonInput,
): SameSecretProofReference[] => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.evaluatorKeySchedule,
        'evaluatorKeySchedule',
    );
    if (
        input.evaluatorKeySchedule.participantCount !==
            input.participantCount ||
        input.evaluatorKeySchedule.rnsLimbCount !== input.qSharePrimes.length
    ) {
        throw new Error(
            'evaluatorKeySchedule must match participant and RNS limb counts.',
        );
    }
    for (const [fieldName, hashValue] of [
        [
            'evaluatorKeyScheduleRoot',
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        ],
        [
            'sameSecretConsistencyRoot',
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        ],
        ['sameSecretProofSetRoot', input.sameSecretProofSetRoot],
        [
            'sameSecretProofFamilyBindingRoot',
            input.sameSecretProofFamilyBindingRoot,
        ],
        [
            'publicKeyShareSetRoot',
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        ['publicKeyShareLnpProofSetRoot', input.publicKeyShareLnpProofSetRoot],
        [
            'relinearizationCrpRoot',
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        ],
        ['galoisKeyCrpRoot', input.evaluatorKeySchedule.galoisKeyCrpRoot],
        [
            'requiredGaloisSetHash',
            input.evaluatorKeySchedule.requiredGaloisSetHash,
        ],
    ] as const) {
        assertProtocolHash(hashValue, fieldName);
    }

    return sortedSameSecretProofReferences(input);
};

const contributionMap = <
    Contribution extends {
        readonly trusteeRosterPosition: number;
        readonly level: number;
    },
>(
    contributions: readonly Contribution[],
    fieldName: string,
): ReadonlyMap<string, Contribution> => {
    const byKey = new Map<string, Contribution>();
    contributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            `${fieldName}.trusteeRosterPosition`,
        );
        assertNonNegativeSafeInteger(contribution.level, `${fieldName}.level`);
        const key = contributionKey(
            contribution.level,
            contribution.trusteeRosterPosition,
        );
        if (byKey.has(key)) {
            throw new Error(
                `${fieldName} must not repeat a trustee and level.`,
            );
        }
        byKey.set(key, contribution);
    });

    return byKey;
};

export const createRelinearizationKeyShareRounds = (
    input: RelinearizationKeyShareRoundsInput,
): RelinearizationKeyShareRounds => {
    const sameSecretProofReferences = validateCommonInput(input);
    const roundOneContributions = contributionMap(
        input.roundOneContributions,
        'roundOneContributions',
    );
    const roundTwoContributions = contributionMap(
        input.roundTwoContributions,
        'roundTwoContributions',
    );
    const levels = input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
        (entry) => entry.level,
    );
    const roundOneRecords: RelinearizationKeyShareRoundOneRecord[] = [];
    const roundOneShareRoots = new Map<string, ProtocolHash>();
    const roundOneRecordRoots = new Map<string, ProtocolHash>();
    const roundOneAggregateRootByLevel = new Map<number, ProtocolHash>();
    const roundOneAggregateRoots = levels.map((level) => {
        const roundOneRecordRootsForLevel = sameSecretProofReferences.map(
            (proofReference) => {
                const key = contributionKey(
                    level,
                    proofReference.trusteeRosterPosition,
                );
                const contribution = roundOneContributions.get(key);
                if (contribution === undefined) {
                    throw new Error(
                        'roundOneContributions is missing a scheduled trustee and level.',
                    );
                }
                assertProtocolHash(
                    contribution.roundOneShareRoot,
                    'roundOneShareRoot',
                );
                assertShareMaterial(
                    contribution.shareMaterial,
                    contribution.roundOneShareRoot,
                    'roundOneContributions.shareMaterial',
                );
                assertRelinearizationKeySwitchSampleBinding(
                    contribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    'round-one',
                    level,
                    'roundOneContributions.shareMaterial',
                );
                const recordWithoutRoot = {
                    objectType: 'RelinearizationKeyShareRoundOne',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'relinearization-key-share',
                    proofVerificationStatus:
                        evaluationKeyShareRecordVerificationStatus,
                    proofModelStatus: trusteeEvaluationKeyProofModelStatus,
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot: contribution.roundOneShareRoot,
                    ...shareMaterialRecordFields(contribution.shareMaterial),
                } as JsonRecord;
                const roundOneRecordRoot = deriveProtocolHash(
                    'RelinearizationRoundOneRecordRoot',
                    recordWithoutRoot,
                );
                roundOneShareRoots.set(key, contribution.roundOneShareRoot);
                roundOneRecordRoots.set(key, roundOneRecordRoot);
                roundOneRecords.push({
                    ...recordWithoutRoot,
                    roundOneRecordRoot,
                } as RelinearizationKeyShareRoundOneRecord);

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundOneRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = deriveProtocolHash(
            'RelinearizationRoundOneAggregateRoot',
            {
                objectType: 'RelinearizationRoundOneAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneRecordRoots: roundOneRecordRootsForLevel,
            },
        );
        roundOneAggregateRootByLevel.set(level, roundOneAggregateRoot);

        return {
            level,
            roundOneAggregateRoot,
        };
    });

    const roundTwoRecords: RelinearizationKeyShareRoundTwoRecord[] = [];
    const roundTwoAggregateRoots = levels.map((level) => {
        const roundTwoRecordRootsForLevel = sameSecretProofReferences.map(
            (proofReference) => {
                const key = contributionKey(
                    level,
                    proofReference.trusteeRosterPosition,
                );
                const contribution = roundTwoContributions.get(key);
                const roundOneShareRoot = roundOneShareRoots.get(key);
                const roundOneRecordRoot = roundOneRecordRoots.get(key);
                const roundOneAggregateRoot =
                    roundOneAggregateRootByLevel.get(level);
                if (
                    contribution === undefined ||
                    roundOneShareRoot === undefined ||
                    roundOneRecordRoot === undefined ||
                    roundOneAggregateRoot === undefined
                ) {
                    throw new Error(
                        'roundTwoContributions is missing a scheduled trustee and level.',
                    );
                }
                assertProtocolHash(
                    contribution.roundTwoShareRoot,
                    'roundTwoShareRoot',
                );
                assertShareMaterial(
                    contribution.shareMaterial,
                    contribution.roundTwoShareRoot,
                    'roundTwoContributions.shareMaterial',
                );
                assertRelinearizationKeySwitchSampleBinding(
                    contribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    'round-two',
                    level,
                    'roundTwoContributions.shareMaterial',
                );
                const recordWithoutRoot = {
                    objectType: 'RelinearizationKeyShareRoundTwo',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'relinearization-key-share',
                    proofVerificationStatus:
                        evaluationKeyShareRecordVerificationStatus,
                    proofModelStatus: trusteeEvaluationKeyProofModelStatus,
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot,
                    roundOneRecordRoot,
                    roundOneAggregateRoot,
                    roundTwoShareRoot: contribution.roundTwoShareRoot,
                    ...shareMaterialRecordFields(contribution.shareMaterial),
                } as JsonRecord;
                const roundTwoRecordRoot = deriveProtocolHash(
                    'RelinearizationRoundTwoRecordRoot',
                    recordWithoutRoot,
                );
                roundTwoRecords.push({
                    ...recordWithoutRoot,
                    roundTwoRecordRoot,
                } as RelinearizationKeyShareRoundTwoRecord);

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundTwoRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = roundOneAggregateRootByLevel.get(level);
        if (roundOneAggregateRoot === undefined) {
            throw new Error(
                'roundTwoContributions is missing a scheduled round-one aggregate root.',
            );
        }
        const roundTwoAggregateRoot = deriveProtocolHash(
            'RelinearizationRoundTwoAggregateRoot',
            {
                objectType: 'RelinearizationRoundTwoAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneAggregateRoot,
                roundTwoRecordRoots: roundTwoRecordRootsForLevel,
            },
        );

        return {
            level,
            roundTwoAggregateRoot,
        };
    });

    const roundsWithoutRoot = {
        objectType: 'RelinearizationKeyShareRounds',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        proofVerificationStatus: evaluationKeyShareRecordVerificationStatus,
        proofModelStatus: trusteeEvaluationKeyProofModelStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        sameSecretConsistencyRoot:
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
        relinearizationCrpRoot:
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        relinearizationLevelSchedule:
            input.evaluatorKeySchedule.relinearizationLevelSchedule,
        roundOneAggregateRoots,
        roundOneRecords,
        roundTwoAggregateRoots,
        roundTwoRecords,
    } as const satisfies Omit<
        RelinearizationKeyShareRounds,
        'relinearizationKeyShareRoundsRoot'
    >;

    return {
        ...roundsWithoutRoot,
        relinearizationKeyShareRoundsRoot: deriveProtocolHash(
            'RelinearizationKeyShareRoundsRoot',
            roundsWithoutRoot,
        ),
    } satisfies RelinearizationKeyShareRounds;
};

export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => {
    const sameSecretProofReferences = validateCommonInput(input);
    const contributionsByRosterPosition = new Map<
        number,
        GaloisKeyShareBatchContribution
    >();
    input.batchContributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            'batchContributions.trusteeRosterPosition',
        );
        if (
            contributionsByRosterPosition.has(
                contribution.trusteeRosterPosition,
            )
        ) {
            throw new Error(
                'batchContributions must not repeat a trustee roster position.',
            );
        }
        contributionsByRosterPosition.set(
            contribution.trusteeRosterPosition,
            contribution,
        );
    });

    return sameSecretProofReferences.map((proofReference) => {
        const contribution = contributionsByRosterPosition.get(
            proofReference.trusteeRosterPosition,
        );
        if (contribution === undefined) {
            throw new Error(
                'batchContributions must contain one batch per participant.',
            );
        }
        if (
            contribution.galoisKeyShares.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                'galoisKeyShares must contain one share per required Galois key.',
            );
        }
        const galoisKeyShareMaterialRecords = contribution.galoisKeyShares.map(
            (shareContribution, index) => {
                const expectedScheduleEntry =
                    input.evaluatorKeySchedule.requiredGaloisKeySchedule[index];
                if (
                    shareContribution.rotation !==
                        expectedScheduleEntry.rotation ||
                    shareContribution.level !== expectedScheduleEntry.level
                ) {
                    throw new Error(
                        'galoisKeyShares must follow the frozen Galois key schedule.',
                    );
                }
                assertProtocolHash(
                    shareContribution.galoisKeyShareRoot,
                    'galoisKeyShareRoot',
                );
                assertShareMaterial(
                    shareContribution.shareMaterial,
                    shareContribution.galoisKeyShareRoot,
                    'galoisKeyShares.shareMaterial',
                );
                assertGaloisKeySwitchSampleBinding(
                    shareContribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    shareContribution.rotation,
                    shareContribution.level,
                    'galoisKeyShares.shareMaterial',
                );

                return {
                    objectType: 'GaloisKeyShareMaterial',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'galois-key-share',
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    rotation: shareContribution.rotation,
                    level: shareContribution.level,
                    galoisKeyShareRoot: shareContribution.galoisKeyShareRoot,
                    ...shareMaterialRecordFields(
                        shareContribution.shareMaterial,
                    ),
                } as GaloisKeyShareMaterialRecord;
            },
        );
        const galoisKeyShareRoots = contribution.galoisKeyShares.map(
            (shareContribution) => ({
                rotation: shareContribution.rotation,
                level: shareContribution.level,
                galoisKeyShareRoot: shareContribution.galoisKeyShareRoot,
            }),
        );
        const batchWithoutRoot = {
            objectType: 'GaloisKeyShareBatch',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: 'galois-key-share',
            proofVerificationStatus: evaluationKeyShareRecordVerificationStatus,
            proofModelStatus: trusteeEvaluationKeyProofModelStatus,
            ...contextFields(input.setupContext),
            trusteeIdentity: proofReference.trusteeIdentity,
            trusteeRosterPosition: proofReference.trusteeRosterPosition,
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            sameSecretConsistencyRoot:
                input.evaluatorKeySchedule.sameSecretConsistencyRoot,
            sameSecretProofSetRoot: input.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                input.sameSecretProofFamilyBindingRoot,
            publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
            sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                proofReference.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: proofReference.sameSecretProofRoot,
            galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
            requiredGaloisSetHash:
                input.evaluatorKeySchedule.requiredGaloisSetHash,
            requiredGaloisKeySchedule:
                input.evaluatorKeySchedule.requiredGaloisKeySchedule,
            galoisKeyShareRoots,
            galoisKeyShareMaterialRecords,
        } as const satisfies Omit<
            GaloisKeyShareBatch,
            'galoisKeyShareBatchRoot'
        >;

        return {
            ...batchWithoutRoot,
            galoisKeyShareBatchRoot: deriveProtocolHash(
                'GaloisKeyShareBatchRoot',
                batchWithoutRoot,
            ),
        } satisfies GaloisKeyShareBatch;
    });
};

// Decode one record's full public component-b material, mirroring the kernel
// decoder: from embedded canonical component vector entries, or from the
// binary chunked transport referenced by keySwitchComponentMaterialRoot.
const componentBVectorsFromMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    record: JsonRecord,
    qSharePrimes: readonly number[],
    transportedComponentMaterial:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    objectPath: string,
): number[][][] => {
    const level = nonNegativeIntegerRecordField(record, 'level', objectPath);
    const ringDegree = nonNegativeIntegerRecordField(
        record,
        'ringDegree',
        objectPath,
    );
    const digitCount = level + 1;
    if (digitCount > qSharePrimes.length) {
        throw new Error(`${objectPath}.level is outside the Q_share basis.`);
    }
    const materialEncoding = stringRecordField(
        record,
        'keySwitchMaterialEncoding',
        objectPath,
    );
    if (materialEncoding === 'embedded-full-key-switch-component-vectors') {
        const entriesValue = record.keySwitchComponentVectors;
        if (!Array.isArray(entriesValue)) {
            throw new TypeError(
                `${objectPath}.keySwitchComponentVectors must be an array.`,
            );
        }
        if (entriesValue.length !== digitCount * digitCount) {
            throw new Error(
                `${objectPath}.keySwitchComponentVectors must contain one vector per digit and RNS limb.`,
            );
        }
        const componentBByDigit: number[][][] = Array.from(
            { length: digitCount },
            () => Array.from({ length: digitCount }, () => [] as number[]),
        );
        entriesValue.forEach((entryValue, entryIndex) => {
            const entry = assertJsonRecord(
                entryValue,
                `${objectPath}.keySwitchComponentVectors.${String(entryIndex)}`,
            );
            const entryPath = `${objectPath}.keySwitchComponentVectors.${String(entryIndex)}`;
            const digitIndex = nonNegativeIntegerRecordField(
                entry,
                'digitIndex',
                entryPath,
            );
            const rnsLimbIndex = nonNegativeIntegerRecordField(
                entry,
                'rnsLimbIndex',
                entryPath,
            );
            if (digitIndex >= digitCount || rnsLimbIndex >= digitCount) {
                throw new Error(
                    `${entryPath} component vector index is outside the proof level.`,
                );
            }
            if (
                nonNegativeIntegerRecordField(entry, 'rnsPrime', entryPath) !==
                    qSharePrimes[rnsLimbIndex] ||
                entry.component !== 'b' ||
                nonNegativeIntegerRecordField(
                    entry,
                    'coefficientByteLength',
                    entryPath,
                ) !==
                    ringDegree * 8
            ) {
                throw new Error(
                    `${entryPath} component vector metadata does not match the proof level.`,
                );
            }
            if (componentBByDigit[digitIndex][rnsLimbIndex].length !== 0) {
                throw new Error(
                    `${entryPath} repeats a digit and RNS limb component vector.`,
                );
            }
            const coefficients = coefficientVectorFromLittleEndianHex(
                stringRecordField(entry, 'coefficientsLeHex', entryPath),
                ringDegree,
                `${entryPath}.coefficientsLeHex`,
            );
            if (
                coefficients.some(
                    (coefficient) => coefficient >= qSharePrimes[rnsLimbIndex],
                )
            ) {
                throw new Error(
                    `${entryPath} contains non-canonical Q_share residues.`,
                );
            }
            if (
                stringRecordField(
                    entry,
                    'coefficientVectorHash512',
                    entryPath,
                ) !== evaluationKeyShareComponentVectorHash(coefficients)
            ) {
                throw new Error(
                    `${entryPath} coefficient hash does not match coefficientsLeHex.`,
                );
            }
            componentBByDigit[digitIndex][rnsLimbIndex] = [...coefficients];
        });
        const expectedRoot = evaluationKeyShareComponentVectorRoot(
            proofFamily,
            stringRecordField(record, 'keySwitchDomain', objectPath),
            stringRecordField(record, 'keySwitchSeedHex', objectPath),
            level,
            ringDegree,
            entriesValue as JsonRecord[],
        );
        if (
            stringRecordField(
                record,
                'keySwitchComponentVectorRoot',
                objectPath,
            ) !== expectedRoot
        ) {
            throw new Error(
                `${objectPath}.keySwitchComponentVectorRoot does not match the embedded public material.`,
            );
        }

        return componentBByDigit;
    }
    if (materialEncoding !== evaluationKeyShareComponentMaterialEncoding) {
        throw new Error(
            `${objectPath}.keySwitchMaterialEncoding is not accepted.`,
        );
    }
    if (transportedComponentMaterial === undefined) {
        throw new Error(
            `${objectPath} uses binary component material but no transportedEvaluationKeyShareComponentMaterial was supplied.`,
        );
    }
    const expectedMaterialRoot = stringRecordField(
        record,
        'keySwitchComponentMaterialRoot',
        objectPath,
    );
    const matchingMaterials =
        transportedComponentMaterial.componentMaterials.filter(
            (componentMaterial) =>
                componentMaterial.keySwitchComponentMaterialRoot ===
                expectedMaterialRoot,
        );
    if (matchingMaterials.length !== 1) {
        throw new Error(
            `${objectPath} transported component material must match exactly one keySwitchComponentMaterialRoot.`,
        );
    }
    const componentMaterial = assertJsonRecord(
        matchingMaterials[0],
        'componentMaterial',
    );
    const chunksValue = componentMaterial.chunks;
    if (!Array.isArray(chunksValue) || chunksValue.length === 0) {
        throw new Error(
            `${objectPath} transported component material chunks must be a non-empty array.`,
        );
    }
    const materialBytesParts = chunksValue.map((chunkValue, chunkIndex) => {
        const chunk = assertJsonRecord(
            chunkValue,
            `componentMaterial.chunks.${String(chunkIndex)}`,
        );
        if (chunk.chunkIndex !== chunkIndex) {
            throw new Error(
                'transported component material chunks must be in ascending chunk-index order.',
            );
        }

        return bytesFromHex(
            stringRecordField(
                chunk,
                'bytesHex',
                `componentMaterial.chunks.${String(chunkIndex)}`,
            ),
            'componentMaterial.chunks.bytesHex',
        );
    });
    const totalByteLength = materialBytesParts.reduce(
        (byteLength, part) => byteLength + part.byteLength,
        0,
    );
    const materialBytes = new Uint8Array(totalByteLength);
    let writeOffset = 0;
    for (const part of materialBytesParts) {
        materialBytes.set(part, writeOffset);
        writeOffset += part.byteLength;
    }
    const view = new DataView(
        materialBytes.buffer,
        materialBytes.byteOffset,
        materialBytes.byteLength,
    );
    let cursor = 0;
    const readWord = (): number => {
        if (cursor + 8 > materialBytes.byteLength) {
            throw new Error(
                'transported component material ended unexpectedly.',
            );
        }
        const word = view.getBigUint64(cursor, true);
        cursor += 8;
        if (word > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(
                'transported component material contains a value outside the JavaScript safe integer range.',
            );
        }

        return Number(word);
    };
    for (
        let magicIndex = 0;
        magicIndex < evaluationKeyShareComponentMaterialMagic.length;
        magicIndex += 1
    ) {
        if (
            materialBytes[magicIndex] !==
            evaluationKeyShareComponentMaterialMagic[magicIndex]
        ) {
            throw new Error(
                'transported component material has the wrong format marker.',
            );
        }
    }
    cursor = evaluationKeyShareComponentMaterialMagic.length;
    const decodedLevel = readWord();
    const decodedRingDegree = readWord();
    const decodedDigitCount = readWord();
    const decodedLimbCount = readWord();
    if (
        decodedLevel !== level ||
        decodedRingDegree !== ringDegree ||
        decodedDigitCount !== digitCount ||
        decodedLimbCount !== digitCount
    ) {
        throw new Error(
            'transported component material shape does not match the share record.',
        );
    }
    const componentBByDigit: number[][][] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        const componentBByLimb: number[][] = [];
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            if (
                readWord() !== digitIndex ||
                readWord() !== rnsLimbIndex ||
                readWord() !== qSharePrimes[rnsLimbIndex] ||
                readWord() !== ringDegree
            ) {
                throw new Error(
                    'transported component material record order or metadata is invalid.',
                );
            }
            const coefficients: number[] = [];
            for (
                let coefficientIndex = 0;
                coefficientIndex < ringDegree;
                coefficientIndex += 1
            ) {
                const coefficient = readWord();
                if (coefficient >= qSharePrimes[rnsLimbIndex]) {
                    throw new Error(
                        'transported component material contains non-canonical Q_share residues.',
                    );
                }
                coefficients.push(coefficient);
            }
            componentBByLimb.push(coefficients);
        }
        componentBByDigit.push(componentBByLimb);
    }
    if (cursor !== materialBytes.byteLength) {
        throw new Error('transported component material has trailing bytes.');
    }

    return componentBByDigit;
};

const relinearizationRecordForTrusteeAndLevel = (
    records: readonly JsonRecord[],
    trusteeRosterPosition: number,
    level: number,
    recordFieldName: string,
): JsonRecord => {
    const matchingRecords = records.filter(
        (record) =>
            record.trusteeRosterPosition === trusteeRosterPosition &&
            record.level === level,
    );
    if (matchingRecords.length !== 1) {
        throw new Error(
            `${recordFieldName} must contain exactly one record per scheduled trustee and level.`,
        );
    }

    return matchingRecords[0];
};

// The public round-one aggregate diagonal per scheduled level: for digit j,
// the sum over every trustee of its round-one component b at (digit j, limb j)
// mod the j-th Q_share prime. Mirrors the kernel recomputation so the prover
// statement matches the verifier-rebuilt statement.
const roundOnePublicAggregateDiagonals = (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
    qSharePrimes: readonly number[],
    participantCount: number,
    transportedComponentMaterial:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
): ReadonlyMap<number, number[][]> => {
    const aggregatesByLevel = new Map<
        number,
        { aggregate: number[][]; contributionCount: number }
    >();
    relinearizationKeyShareRounds.roundOneRecords.forEach((record) => {
        const recordFields = record as JsonRecord;
        const level = nonNegativeIntegerRecordField(
            recordFields,
            'level',
            'roundOneRecords',
        );
        const digitCount = level + 1;
        const components = componentBVectorsFromMaterial(
            'relinearization-key-share',
            recordFields,
            qSharePrimes,
            transportedComponentMaterial,
            'roundOneRecords',
        );
        const ringDegree = components[0]?.[0]?.length ?? 0;
        if (ringDegree === 0) {
            throw new Error(
                'round-one component material does not cover the aggregate diagonal.',
            );
        }
        let aggregateEntry = aggregatesByLevel.get(level);
        if (aggregateEntry === undefined) {
            aggregateEntry = {
                aggregate: Array.from({ length: digitCount }, () =>
                    Array.from({ length: ringDegree }, () => 0),
                ),
                contributionCount: 0,
            };
            aggregatesByLevel.set(level, aggregateEntry);
        }
        for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
            const modulus = qSharePrimes[digitIndex];
            const diagonal = components[digitIndex]?.[digitIndex];
            if (diagonal?.length !== ringDegree) {
                throw new Error(
                    'round-one component material does not cover the aggregate diagonal.',
                );
            }
            const accumulated = aggregateEntry.aggregate[digitIndex];
            for (
                let coefficientIndex = 0;
                coefficientIndex < ringDegree;
                coefficientIndex += 1
            ) {
                accumulated[coefficientIndex] =
                    (accumulated[coefficientIndex] +
                        diagonal[coefficientIndex]) %
                    modulus;
            }
        }
        aggregateEntry.contributionCount += 1;
    });
    const aggregateDiagonalsByLevel = new Map<number, number[][]>();
    for (const [level, aggregateEntry] of aggregatesByLevel) {
        if (aggregateEntry.contributionCount !== participantCount) {
            throw new Error(
                'round-one aggregate requires one component contribution per trustee.',
            );
        }
        aggregateDiagonalsByLevel.set(level, aggregateEntry.aggregate);
    }

    return aggregateDiagonalsByLevel;
};

export const createTrusteeEvaluationKeyProofs = (
    input: TrusteeEvaluationKeyProofsInput,
): TrusteeEvaluationKeyProofSet => {
    const sameSecretProofReferences = validateCommonInput(input);
    assertProtocolHash(
        input.keySwitchDecompositionHash,
        'keySwitchDecompositionHash',
    );
    assertContextMatches(
        input.setupContext,
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRounds',
    );
    if (
        input.relinearizationKeyShareRounds.evaluatorKeyScheduleRoot !==
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
        input.relinearizationKeyShareRounds.sameSecretProofSetRoot !==
            input.sameSecretProofSetRoot ||
        input.relinearizationKeyShareRounds.publicKeyShareLnpProofSetRoot !==
            input.publicKeyShareLnpProofSetRoot
    ) {
        throw new Error(
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding.',
        );
    }
    const sortedGaloisBatches = [...input.galoisKeyShareBatches].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (sortedGaloisBatches.length !== input.participantCount) {
        throw new Error(
            'galoisKeyShareBatches must contain one batch per participant.',
        );
    }
    sortedGaloisBatches.forEach((batch, expectedRosterPosition) => {
        assertContextMatches(input.setupContext, batch, 'galoisKeyShareBatch');
        if (batch.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'galoisKeyShareBatches roster positions must be contiguous from zero.',
            );
        }
    });
    const witnessesByRosterPosition = new Map<
        number,
        TrusteeEvaluationKeyWitnessInput
    >();
    input.trusteeWitnesses.forEach((witness) => {
        assertNonNegativeSafeInteger(
            witness.trusteeRosterPosition,
            'trusteeWitnesses.trusteeRosterPosition',
        );
        if (witnessesByRosterPosition.has(witness.trusteeRosterPosition)) {
            throw new Error(
                'trusteeWitnesses must not repeat a trustee roster position.',
            );
        }
        witnessesByRosterPosition.set(witness.trusteeRosterPosition, witness);
    });

    const scheduledLevels =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (entry) => entry.level,
        );
    const aggregateDiagonalsByLevel = roundOnePublicAggregateDiagonals(
        input.relinearizationKeyShareRounds,
        input.qSharePrimes,
        input.participantCount,
        input.transportedEvaluationKeyShareComponentMaterial,
    );

    let proofAccountingHash: ProtocolHash | undefined;
    const proofRecords = sameSecretProofReferences.map((proofReference) => {
        const witness = witnessesByRosterPosition.get(
            proofReference.trusteeRosterPosition,
        );
        if (witness === undefined) {
            throw new Error(
                'trusteeWitnesses must contain one witness per participant.',
            );
        }
        const statementKeys: TrusteeEvaluationKeyStatementKey[] = [];
        let ringDegree: number | undefined;
        const recordRingDegree = (record: JsonRecord): void => {
            const observed = nonNegativeIntegerRecordField(
                record,
                'ringDegree',
                'evaluationKeyShareRecord',
            );
            if (ringDegree === undefined) {
                ringDegree = observed;
            } else if (ringDegree !== observed) {
                throw new Error(
                    'evaluation-key share records must agree on one ring degree.',
                );
            }
        };
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds.roundOneRecords,
                proofReference.trusteeRosterPosition,
                level,
                'roundOneRecords',
            );
            recordRingDegree(record);
            statementKeys.push({
                proofFamily: 'relinearization-round-one',
                level,
                keySwitchDomain: stringRecordField(
                    record,
                    'keySwitchDomain',
                    'roundOneRecords',
                ),
                keySwitchSeedHex: stringRecordField(
                    record,
                    'keySwitchSeedHex',
                    'roundOneRecords',
                ),
                componentBByDigit: componentBVectorsFromMaterial(
                    'relinearization-key-share',
                    record,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    'roundOneRecords',
                ),
            });
        }
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds.roundTwoRecords,
                proofReference.trusteeRosterPosition,
                level,
                'roundTwoRecords',
            );
            recordRingDegree(record);
            const aggregateDiagonal = aggregateDiagonalsByLevel.get(level);
            if (aggregateDiagonal === undefined) {
                throw new Error(
                    'round-one public aggregate diagonal is missing for a scheduled level.',
                );
            }
            statementKeys.push({
                proofFamily: 'relinearization-round-two',
                level,
                keySwitchDomain: stringRecordField(
                    record,
                    'keySwitchDomain',
                    'roundTwoRecords',
                ),
                keySwitchSeedHex: stringRecordField(
                    record,
                    'keySwitchSeedHex',
                    'roundTwoRecords',
                ),
                componentBByDigit: componentBVectorsFromMaterial(
                    'relinearization-key-share',
                    record,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    'roundTwoRecords',
                ),
                roundOneAggregateDiagonal: aggregateDiagonal,
            });
        }
        const batch = sortedGaloisBatches[proofReference.trusteeRosterPosition];
        for (const scheduleEntry of input.evaluatorKeySchedule
            .requiredGaloisKeySchedule) {
            const materialRecords = batch.galoisKeyShareMaterialRecords.filter(
                (materialRecord) =>
                    materialRecord.rotation === scheduleEntry.rotation &&
                    materialRecord.level === scheduleEntry.level,
            );
            if (materialRecords.length !== 1) {
                throw new Error(
                    'galoisKeyShareMaterialRecords must contain exactly one record per scheduled rotation and level.',
                );
            }
            const materialRecord = materialRecords[0] as JsonRecord;
            recordRingDegree(materialRecord);
            statementKeys.push({
                proofFamily: 'galois-rotation',
                rotation: scheduleEntry.rotation,
                level: scheduleEntry.level,
                keySwitchDomain: stringRecordField(
                    materialRecord,
                    'keySwitchDomain',
                    'galoisKeyShareMaterialRecords',
                ),
                keySwitchSeedHex: stringRecordField(
                    materialRecord,
                    'keySwitchSeedHex',
                    'galoisKeyShareMaterialRecords',
                ),
                componentBByDigit: componentBVectorsFromMaterial(
                    'galois-key-share',
                    materialRecord,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    'galoisKeyShareMaterialRecords',
                ),
            });
        }
        if (ringDegree === undefined) {
            throw new Error(
                'trustee evaluation-key statement requires at least one share record.',
            );
        }
        if (witness.errorCoefficientsByKey.length !== statementKeys.length) {
            throw new Error(
                'trusteeWitnesses.errorCoefficientsByKey must contain one error vector set per statement key.',
            );
        }
        witness.constantCommitments.forEach((commitment, commitmentIndex) =>
            assertJsonRecord(
                commitment,
                `trusteeWitnesses.constantCommitments.${String(commitmentIndex)}`,
            ),
        );
        if (
            witness.proofRandomnessSource !== 'fresh-csprng' &&
            witness.proofRandomnessSource !==
                'development-deterministic-fixture'
        ) {
            throw new TypeError(
                'trusteeWitnesses.proofRandomnessSource must be fresh-csprng or development-deterministic-fixture.',
            );
        }
        assertProtocolHash(
            witness.proofRandomnessSeedHex,
            'trusteeWitnesses.proofRandomnessSeedHex',
        );
        const generatedProof = input.trusteeEvaluationKeyProofGenerator({
            context: {
                ceremonyId: input.setupContext.ceremonyId,
                manifestHash: input.setupContext.manifestHash,
                rosterHash: input.setupContext.rosterHash,
                trusteeIdentity: proofReference.trusteeIdentity,
                trusteeRosterPosition: proofReference.trusteeRosterPosition,
                setupEpoch: input.setupContext.setupEpoch,
                requiredGaloisSetHash:
                    input.evaluatorKeySchedule.requiredGaloisSetHash,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                keySwitchDecompositionHash: input.keySwitchDecompositionHash,
                sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
                sameSecretProofRoot: proofReference.sameSecretProofRoot,
            },
            ringDegree,
            keys: statementKeys,
            sameSecretLinkage: {
                publicMatrixSeedHash:
                    input.evaluatorKeySchedule.publicMatrixSeedHash,
                commitments: witness.constantCommitments,
            },
            secretCoefficients: witness.secretCoefficients,
            errorCoefficientsByKey: witness.errorCoefficientsByKey,
            negativeIndicatorCoefficients:
                witness.negativeIndicatorCoefficients,
            openingRandomnessByLimb: witness.openingRandomnessByLimb,
            proofRandomnessSource: witness.proofRandomnessSource,
            proofRandomnessSeedHex: witness.proofRandomnessSeedHex,
        });
        if (
            generatedProof.ok !== true ||
            generatedProof.operation !== 'generateTrusteeEvaluationKeyProof'
        ) {
            throw new Error(
                'trusteeEvaluationKeyProofGenerator returned the wrong operation.',
            );
        }
        if (
            generatedProof.proofModelStatus !==
            trusteeEvaluationKeyProofModelStatus
        ) {
            throw new Error(
                'trusteeEvaluationKeyProofGenerator returned an unexpected proof model status.',
            );
        }
        assertProtocolHash(
            generatedProof.proofAccountingHash,
            'generatedProof.proofAccountingHash',
        );
        if (proofAccountingHash === undefined) {
            proofAccountingHash = generatedProof.proofAccountingHash;
        } else if (proofAccountingHash !== generatedProof.proofAccountingHash) {
            throw new Error(
                'trustee evaluation-key proofs must pin one proof accounting hash.',
            );
        }
        assertProtocolHash(
            generatedProof.statementHash,
            'generatedProof.statementHash',
        );
        if (generatedProof.keyCount !== statementKeys.length) {
            throw new Error(
                'generatedProof.keyCount must match the frozen key schedule.',
            );
        }
        if (generatedProof.sameSecretLinkageIncluded !== true) {
            throw new Error(
                'generatedProof must include the same-secret linkage.',
            );
        }
        assertNonEmptyString(
            generatedProof.proofBytesHex,
            'generatedProof.proofBytesHex',
        );
        assertLowercaseHex(
            generatedProof.proofBytesHex,
            'generatedProof.proofBytesHex',
        );
        if (
            generatedProof.proofBytesHex.length !==
            generatedProof.proofByteLength * 2
        ) {
            throw new Error(
                'generatedProof.proofBytesHex length must match proofByteLength.',
            );
        }
        const proofBytes = bytesFromHex(
            generatedProof.proofBytesHex,
            'generatedProof.proofBytesHex',
        );
        const recordWithoutRoot = {
            objectType: 'TrusteeEvaluationKeyProof',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: trusteeEvaluationKeyProofFamily,
            proofVerificationStatus:
                trusteeEvaluationKeyProofVerificationStatus,
            proofModelStatus: trusteeEvaluationKeyProofModelStatus,
            ...contextFields(input.setupContext),
            trusteeIdentity: proofReference.trusteeIdentity,
            trusteeRosterPosition: proofReference.trusteeRosterPosition,
            sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                proofReference.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: proofReference.sameSecretProofRoot,
            statementHash: generatedProof.statementHash,
            keyCount: statementKeys.length,
            proofSizeBytes: proofBytes.byteLength,
            proofBytesHash: hash512Hex(
                trusteeEvaluationKeyProofBytesHashDomain,
                [proofBytes],
            ),
            proofBytesHex: generatedProof.proofBytesHex,
        } as JsonRecord;

        return {
            ...recordWithoutRoot,
            trusteeEvaluationKeyProofRoot: deriveProtocolHash(
                'TrusteeEvaluationKeyProofRoot',
                recordWithoutRoot,
            ),
        } as TrusteeEvaluationKeyProofRecord;
    });
    if (proofAccountingHash === undefined) {
        throw new Error(
            'trustee evaluation-key proofs require at least one participant.',
        );
    }

    const galoisKeyShareBatchRoots = sortedGaloisBatches.map((batch) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: batch.galoisKeyShareBatchRoot,
    }));
    const proofSetWithoutRoot = {
        objectType: 'TrusteeEvaluationKeyProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: trusteeEvaluationKeyProofFamily,
        proofVerificationStatus: trusteeEvaluationKeyProofVerificationStatus,
        proofModelStatus: trusteeEvaluationKeyProofModelStatus,
        proofAccountingHash,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        requiredGaloisSetHash: input.evaluatorKeySchedule.requiredGaloisSetHash,
        keySwitchDecompositionHash: input.keySwitchDecompositionHash,
        sameSecretConsistencyRoot:
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
        relinearizationCrpRoot:
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
        publicMatrixSeedHash: input.evaluatorKeySchedule.publicMatrixSeedHash,
        relinearizationKeyShareRoundsRoot:
            input.relinearizationKeyShareRounds
                .relinearizationKeyShareRoundsRoot,
        galoisKeyShareBatchRoots,
        proofRecords,
    } as const satisfies Omit<
        TrusteeEvaluationKeyProofSet,
        'trusteeEvaluationKeyProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        trusteeEvaluationKeyProofSetRoot: deriveProtocolHash(
            'TrusteeEvaluationKeyProofSetRoot',
            proofSetWithoutRoot,
        ),
    } satisfies TrusteeEvaluationKeyProofSet;
};

export type TrusteeEvaluationKeyProofMaterialTransport = Readonly<{
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
}>;

// Move every trustee proof's embedded bytes into binary chunked transport and
// rebind the record and set roots, mirroring the kernel terminal-transport
// flow: the proof record keeps the transport reference, the chunks travel in
// the request-side transported proof material set.
export const transportTrusteeEvaluationKeyProofSet = (
    proofSet: TrusteeEvaluationKeyProofSet,
): TrusteeEvaluationKeyProofMaterialTransport => {
    const transportedProofMaterials: JsonRecord[] = [];
    const transportedProofRecords = proofSet.proofRecords.map((proofRecord) => {
        const recordFields = proofRecord as JsonRecord;
        const proofBytesHex = stringRecordField(
            recordFields,
            'proofBytesHex',
            'proofRecords',
        );
        const proofBytes = bytesFromHex(
            proofBytesHex,
            'proofRecords.proofBytesHex',
        );
        if (
            hash512Hex(trusteeEvaluationKeyProofBytesHashDomain, [
                proofBytes,
            ]) !== proofRecord.proofBytesHash
        ) {
            throw new Error(
                'proofRecords.proofBytesHash must match proofBytesHex before transport.',
            );
        }
        const chunks: Uint8Array[] = [];
        for (
            let chunkStart = 0;
            chunkStart < proofBytes.byteLength;
            chunkStart += setupProofTransportChunkSizeBytes
        ) {
            chunks.push(
                proofBytes.slice(
                    chunkStart,
                    Math.min(
                        chunkStart + setupProofTransportChunkSizeBytes,
                        proofBytes.byteLength,
                    ),
                ),
            );
        }
        if (chunks.length === 0) {
            throw new Error(
                'proofRecords.proofBytesHex must produce at least one transported chunk.',
            );
        }
        const totalByteLength = proofBytes.byteLength;
        const fullObjectHash = setupProofMaterialFullObjectHashHex(
            trusteeEvaluationKeyProofFamily,
            totalByteLength,
            chunks,
        );
        const chunkHashes = chunks.map((chunk, chunkIndex) =>
            setupProofMaterialChunkHash(
                trusteeEvaluationKeyProofFamily,
                fullObjectHash,
                chunkIndex,
                chunk,
            ),
        );
        const chunkRoot = setupProofChunkManifestRoot(
            trusteeEvaluationKeyProofFamily,
            chunkHashes,
            fullObjectHash,
            totalByteLength,
        );
        const proofMaterialRoot = deriveProtocolHash(
            'TrusteeEvaluationKeyProofMaterialRoot',
            {
                objectType: 'TrusteeEvaluationKeyProofMaterialReference',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: trusteeEvaluationKeyProofFamily,
                trusteeIdentity: proofRecord.trusteeIdentity,
                trusteeRosterPosition: proofRecord.trusteeRosterPosition,
                statementHash: proofRecord.statementHash,
                proofSizeBytes: proofRecord.proofSizeBytes,
                proofBytesHash: proofRecord.proofBytesHash,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: chunkHashes.length,
                totalByteLength,
                fullObjectHash,
                chunkRoot,
                chunkHashes,
            },
        );
        transportedProofMaterials.push({
            objectType: evaluationKeyShareProofTransportObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: trusteeEvaluationKeyProofFamily,
            proofBytesEncoding: setupProofMaterialTransportEncoding,
            proofMaterialRoot,
            proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
            proofChunkCount: chunkHashes.length,
            proofTotalByteLength: totalByteLength,
            proofFullObjectHash: fullObjectHash,
            proofChunkRoot: chunkRoot,
            proofChunkHashes: chunkHashes,
            chunks: chunks.map((chunk, chunkIndex) => ({
                chunkIndex,
                bytesHex: bytesToHex(chunk),
            })),
        });
        const transportedRecordWithoutRoot = {
            ...recordFields,
            proofBytesEncoding: setupProofMaterialTransportEncoding,
            proofMaterialRoot,
            proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
            proofChunkCount: chunkHashes.length,
            proofTotalByteLength: totalByteLength,
            proofFullObjectHash: fullObjectHash,
            proofChunkRoot: chunkRoot,
            proofChunkHashes: chunkHashes,
        } as JsonRecord;
        delete transportedRecordWithoutRoot.proofBytesHex;
        delete transportedRecordWithoutRoot.trusteeEvaluationKeyProofRoot;

        return {
            ...transportedRecordWithoutRoot,
            trusteeEvaluationKeyProofRoot: deriveProtocolHash(
                'TrusteeEvaluationKeyProofRoot',
                transportedRecordWithoutRoot,
            ),
        } as TrusteeEvaluationKeyProofRecord;
    });
    const proofSetWithoutRoot: JsonRecord = {
        ...(proofSet as JsonRecord),
        proofRecords: transportedProofRecords,
    };
    delete proofSetWithoutRoot.trusteeEvaluationKeyProofSetRoot;

    return {
        trusteeEvaluationKeyProofs: {
            ...proofSetWithoutRoot,
            trusteeEvaluationKeyProofSetRoot: deriveProtocolHash(
                'TrusteeEvaluationKeyProofSetRoot',
                proofSetWithoutRoot,
            ),
        } as TrusteeEvaluationKeyProofSet,
        transportedEvaluationKeyShareProofMaterial: {
            objectType: evaluationKeyShareProofTransportSetObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: trusteeEvaluationKeyProofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};

type EvaluationKeyShareTransportWorkItem = Readonly<{
    readonly proofFamily: EvaluationKeyShareProofFamily;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly shareMaterial: EvaluationKeyShareMaterial &
        EvaluationKeyShareEmbeddedKeySwitchComponentMaterial;
}>;

const trusteeIdentityByRosterPosition = (
    sameSecretProofReferences: readonly Pick<
        SameSecretProofReference,
        'trusteeIdentity' | 'trusteeRosterPosition'
    >[],
): ReadonlyMap<number, string> => {
    const identities = new Map<number, string>();
    sameSecretProofReferences.forEach((reference, referenceIndex) => {
        assertNonEmptyString(
            reference.trusteeIdentity,
            `sameSecretProofReferences.${String(referenceIndex)}.trusteeIdentity`,
        );
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            `sameSecretProofReferences.${String(referenceIndex)}.trusteeRosterPosition`,
        );
        if (identities.has(reference.trusteeRosterPosition)) {
            throw new Error(
                'sameSecretProofReferences must not repeat trusteeRosterPosition.',
            );
        }
        identities.set(
            reference.trusteeRosterPosition,
            reference.trusteeIdentity,
        );
    });

    return identities;
};

const trusteeIdentityForContribution = (
    identities: ReadonlyMap<number, string>,
    trusteeRosterPosition: number,
    fieldName: string,
): string => {
    const trusteeIdentity = identities.get(trusteeRosterPosition);
    if (trusteeIdentity === undefined) {
        throw new Error(
            `${fieldName} references a trustee roster position without a same-secret proof reference.`,
        );
    }

    return trusteeIdentity;
};

const encodeEvaluationKeyShareComponentMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    shareMaterial: EvaluationKeyShareMaterial &
        EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    level: number,
): readonly Uint8Array[] => {
    const digitCount = level + 1;
    if (shareMaterial.keySwitchComponentVectors.length !== digitCount ** 2) {
        throw new Error(
            'evaluation-key component material must contain one vector per scheduled digit and RNS limb.',
        );
    }
    const writer = new BinaryChunkWriter({
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        emptyErrorMessage:
            'evaluation-key component material transport requires bytes.',
    });
    writer.writeBytes(evaluationKeyShareComponentMaterialMagic);
    writer.writeU64LittleEndian(level, 'evaluation-key level');
    writer.writeU64LittleEndian(
        shareMaterial.ringDegree,
        'evaluation-key ringDegree',
    );
    writer.writeU64LittleEndian(digitCount, 'evaluation-key digitCount');
    writer.writeU64LittleEndian(digitCount, 'evaluation-key rnsLimbCount');
    const canonicalComponentVectors: JsonRecord[] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            const componentVector = assertJsonRecord(
                shareMaterial.keySwitchComponentVectors[
                    digitIndex * digitCount + rnsLimbIndex
                ],
                'keySwitchComponentVectors',
            );
            const vectorPath = `keySwitchComponentVectors.${String(
                digitIndex,
            )}.${String(rnsLimbIndex)}`;
            if (
                nonNegativeIntegerRecordField(
                    componentVector,
                    'digitIndex',
                    vectorPath,
                ) !== digitIndex ||
                nonNegativeIntegerRecordField(
                    componentVector,
                    'rnsLimbIndex',
                    vectorPath,
                ) !== rnsLimbIndex ||
                componentVector.component !== 'b'
            ) {
                throw new Error(
                    'evaluation-key component material vectors must be ordered by digit and RNS limb.',
                );
            }
            const rnsPrime = nonNegativeIntegerRecordField(
                componentVector,
                'rnsPrime',
                vectorPath,
            );
            const coefficientByteLength = nonNegativeIntegerRecordField(
                componentVector,
                'coefficientByteLength',
                vectorPath,
            );
            if (coefficientByteLength !== shareMaterial.ringDegree * 8) {
                throw new Error(
                    'evaluation-key component material coefficientByteLength must match ringDegree.',
                );
            }
            const coefficientsLeHex = stringRecordField(
                componentVector,
                'coefficientsLeHex',
                vectorPath,
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientsLeHex,
                shareMaterial.ringDegree,
                `${vectorPath}.coefficientsLeHex`,
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'evaluation-key component material coefficients must be canonical residues.',
                );
            }
            const coefficientVectorHash =
                evaluationKeyShareComponentVectorHash(coefficients);
            if (
                stringRecordField(
                    componentVector,
                    'coefficientVectorHash512',
                    vectorPath,
                ) !== coefficientVectorHash
            ) {
                throw new Error(
                    'evaluation-key component material coefficient hash must match coefficientsLeHex.',
                );
            }
            canonicalComponentVectors.push({
                digitIndex,
                rnsLimbIndex,
                rnsPrime,
                component: 'b',
                coefficientByteLength,
                coefficientVectorHash512: coefficientVectorHash,
                coefficientsLeHex,
            });
            writer.writeU64LittleEndian(
                digitIndex,
                'evaluation-key component digitIndex',
            );
            writer.writeU64LittleEndian(
                rnsLimbIndex,
                'evaluation-key component rnsLimbIndex',
            );
            writer.writeU64LittleEndian(
                rnsPrime,
                'evaluation-key component rnsPrime',
            );
            writer.writeU64LittleEndian(
                shareMaterial.ringDegree,
                'evaluation-key component coefficientCount',
            );
            coefficients.forEach((coefficient) =>
                writer.writeU64LittleEndian(
                    coefficient,
                    'evaluation-key component coefficient',
                ),
            );
        }
    }
    const componentVectorRoot = evaluationKeyShareComponentVectorRoot(
        proofFamily,
        shareMaterial.keySwitchDomain,
        shareMaterial.keySwitchSeedHex,
        level,
        shareMaterial.ringDegree,
        canonicalComponentVectors,
    );
    if (componentVectorRoot !== shareMaterial.keySwitchComponentVectorRoot) {
        throw new Error(
            'evaluation-key component material root must match keySwitchComponentVectorRoot before transport.',
        );
    }

    return writer.finish();
};

const transportEvaluationKeyShareComponentMaterial = (
    workItem: EvaluationKeyShareTransportWorkItem,
): Readonly<{
    readonly shareMaterial: EvaluationKeyShareMaterial;
    readonly componentMaterial: JsonRecord;
}> => {
    const chunks = encodeEvaluationKeyShareComponentMaterial(
        workItem.proofFamily,
        workItem.shareMaterial,
        workItem.level,
    );
    const transportHashes = evaluationKeyShareComponentMaterialTransportHashes(
        workItem.proofFamily,
        chunks,
    );
    const keySwitchComponentMaterialRoot =
        evaluationKeyShareComponentMaterialReferenceRoot(
            workItem.proofFamily,
            workItem.shareMaterial,
            workItem.trusteeIdentity,
            workItem.trusteeRosterPosition,
            workItem.level,
            transportHashes,
        );
    const shareMaterial: EvaluationKeyShareMaterial = {
        keySwitchDomain: workItem.shareMaterial.keySwitchDomain,
        keySwitchSeedHex: workItem.shareMaterial.keySwitchSeedHex,
        ringDegree: workItem.shareMaterial.ringDegree,
        keySwitchComponentVectorRoot:
            workItem.shareMaterial.keySwitchComponentVectorRoot,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        keySwitchComponentMaterialRoot,
        keySwitchComponentChunkSizeBytes: setupProofTransportChunkSizeBytes,
        keySwitchComponentChunkCount: transportHashes.chunkHashes.length,
        keySwitchComponentTotalByteLength: transportHashes.totalByteLength,
        keySwitchComponentFullObjectHash: transportHashes.fullObjectHash,
        keySwitchComponentChunkRoot: transportHashes.chunkRoot,
        keySwitchComponentChunkHashes: transportHashes.chunkHashes,
    };

    return {
        shareMaterial,
        componentMaterial: {
            objectType: evaluationKeyShareComponentMaterialTransportObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: workItem.proofFamily,
            keySwitchMaterialEncoding:
                evaluationKeyShareComponentMaterialEncoding,
            trusteeIdentity: workItem.trusteeIdentity,
            trusteeRosterPosition: workItem.trusteeRosterPosition,
            keySwitchDomain: workItem.shareMaterial.keySwitchDomain,
            keySwitchSeedHex: workItem.shareMaterial.keySwitchSeedHex,
            level: workItem.level,
            ringDegree: workItem.shareMaterial.ringDegree,
            digitCount: workItem.level + 1,
            rnsLimbCount: workItem.level + 1,
            keySwitchComponentVectorRoot:
                workItem.shareMaterial.keySwitchComponentVectorRoot,
            keySwitchComponentMaterialRoot,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: transportHashes.chunkHashes.length,
            totalByteLength: transportHashes.totalByteLength,
            fullObjectHash: transportHashes.fullObjectHash,
            chunkRoot: transportHashes.chunkRoot,
            chunkHashes: transportHashes.chunkHashes,
            chunks: chunks.map((chunk, chunkIndex) => ({
                chunkIndex,
                bytesHex: bytesToHex(chunk),
            })),
        },
    };
};

export const createBinaryChunkedEvaluationKeyShareMaterialTransport = (
    input: EvaluationKeyShareMaterialTransportInput,
): BinaryChunkedEvaluationKeyShareMaterialTransport => {
    const identities = trusteeIdentityByRosterPosition(
        input.sameSecretProofReferences,
    );
    const componentMaterials: JsonRecord[] = [];
    const componentRoots = new Set<string>();
    const transportShareMaterial = (
        workItem: EvaluationKeyShareTransportWorkItem,
    ): EvaluationKeyShareMaterial => {
        const componentTransport =
            transportEvaluationKeyShareComponentMaterial(workItem);
        const componentMaterialRoot = stringRecordField(
            componentTransport.componentMaterial,
            'keySwitchComponentMaterialRoot',
            'componentMaterial',
        );
        if (componentRoots.has(componentMaterialRoot)) {
            throw new Error(
                'transported evaluation-key component material contains duplicate roots.',
            );
        }
        componentRoots.add(componentMaterialRoot);
        componentMaterials.push(componentTransport.componentMaterial);

        return componentTransport.shareMaterial;
    };

    const relinearizationRoundOneContributions =
        input.relinearizationRoundOneContributions.map((contribution) => ({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            roundOneShareRoot: contribution.roundOneShareRoot,
            shareMaterial: transportShareMaterial({
                proofFamily: 'relinearization-key-share',
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    'relinearizationRoundOneContributions',
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                shareMaterial: assertEmbeddedComponentMaterial(
                    contribution.shareMaterial,
                    'relinearizationRoundOneContributions.shareMaterial',
                ),
            }),
        }));
    const relinearizationRoundTwoContributions =
        input.relinearizationRoundTwoContributions.map((contribution) => ({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            roundTwoShareRoot: contribution.roundTwoShareRoot,
            shareMaterial: transportShareMaterial({
                proofFamily: 'relinearization-key-share',
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    'relinearizationRoundTwoContributions',
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                shareMaterial: assertEmbeddedComponentMaterial(
                    contribution.shareMaterial,
                    'relinearizationRoundTwoContributions.shareMaterial',
                ),
            }),
        }));
    const galoisKeyShareBatchContributions =
        input.galoisKeyShareBatchContributions.map((batchContribution) => {
            const trusteeIdentity = trusteeIdentityForContribution(
                identities,
                batchContribution.trusteeRosterPosition,
                'galoisKeyShareBatchContributions',
            );

            return {
                trusteeRosterPosition: batchContribution.trusteeRosterPosition,
                galoisKeyShares: batchContribution.galoisKeyShares.map(
                    (shareContribution) => ({
                        rotation: shareContribution.rotation,
                        level: shareContribution.level,
                        galoisKeyShareRoot:
                            shareContribution.galoisKeyShareRoot,
                        shareMaterial: transportShareMaterial({
                            proofFamily: 'galois-key-share',
                            trusteeIdentity,
                            trusteeRosterPosition:
                                batchContribution.trusteeRosterPosition,
                            level: shareContribution.level,
                            shareMaterial: assertEmbeddedComponentMaterial(
                                shareContribution.shareMaterial,
                                'galoisKeyShares.shareMaterial',
                            ),
                        }),
                    }),
                ),
            };
        });

    return {
        relinearizationRoundOneContributions,
        relinearizationRoundTwoContributions,
        galoisKeyShareBatchContributions,
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                evaluationKeyShareComponentMaterialTransportSetObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            componentMaterials,
        },
    };
};

const galoisShareMaterialForSchedule = (
    batch: GaloisKeyShareBatch,
    rotation: number,
    level: number,
): GaloisKeyShareMaterialRecord => {
    const materialRecords = batch.galoisKeyShareMaterialRecords.filter(
        (materialRecord) =>
            materialRecord.rotation === rotation &&
            materialRecord.level === level,
    );
    if (materialRecords.length !== 1) {
        throw new Error(
            'galoisKeyShareBatches is missing a scheduled material record.',
        );
    }

    return materialRecords[0];
};

export function createPublicEvaluationKeySet(
    input: PublicEvaluationKeySetInput,
): PublicEvaluationKeySet {
    validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRounds',
    );
    if (
        input.relinearizationKeyShareRounds.evaluatorKeyScheduleRoot !==
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
        input.relinearizationKeyShareRounds.sameSecretProofFamilyBindingRoot !==
            input.sameSecretProofFamilyBindingRoot ||
        input.relinearizationKeyShareRounds.publicKeyShareLnpProofSetRoot !==
            input.publicKeyShareLnpProofSetRoot
    ) {
        throw new Error(
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding.',
        );
    }
    const roundOneAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundOneAggregateRoots.map(
            (entry) => [entry.level, entry.roundOneAggregateRoot] as const,
        ),
    );
    const roundTwoAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundTwoAggregateRoots.map(
            (entry) => [entry.level, entry.roundTwoAggregateRoot] as const,
        ),
    );
    const relinearizationKeyRoots =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (scheduleEntry) => {
                const { level } = scheduleEntry;
                const roundOneAggregateRoot =
                    roundOneAggregateRootByLevel.get(level);
                const roundTwoAggregateRoot =
                    roundTwoAggregateRootByLevel.get(level);
                if (
                    roundOneAggregateRoot === undefined ||
                    roundTwoAggregateRoot === undefined
                ) {
                    throw new Error(
                        'relinearizationKeyShareRounds is missing a scheduled aggregate root.',
                    );
                }
                const decompositionDigitCount = level + 1;
                const relinearizationKeyRoot = deriveProtocolHash(
                    'RelinearizationKeyRoot',
                    {
                        objectType: 'RelinearizationKeyAggregate',
                        objectVersion: 1,
                        setupProfileId: 'CollectiveBgvSetup-v1',
                        setupProofProfileId,
                        assemblyStatus: publicEvaluationKeyAssemblyStatus,
                        materialEncoding: publicEvaluationKeyMaterialEncoding,
                        materialSource: publicEvaluationKeyMaterialSource,
                        evaluatorKeyScheduleRoot:
                            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                        sameSecretProofFamilyBindingRoot:
                            input.sameSecretProofFamilyBindingRoot,
                        publicKeyShareLnpProofSetRoot:
                            input.publicKeyShareLnpProofSetRoot,
                        relinearizationKeyShareRoundsRoot:
                            input.relinearizationKeyShareRounds
                                .relinearizationKeyShareRoundsRoot,
                        level,
                        decompositionDigitCount,
                        rnsLimbCount: decompositionDigitCount,
                        roundOneAggregateRoot,
                        roundTwoAggregateRoot,
                    },
                );

                return {
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    roundOneAggregateRoot,
                    roundTwoAggregateRoot,
                    relinearizationKeyRoot,
                } satisfies RelinearizationKeyRootReference;
            },
        );

    const sortedGaloisBatches = [...input.galoisKeyShareBatches].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (sortedGaloisBatches.length !== input.participantCount) {
        throw new Error(
            'galoisKeyShareBatches must contain one batch per participant.',
        );
    }
    sortedGaloisBatches.forEach((batch, expectedRosterPosition) => {
        assertContextMatches(input.setupContext, batch, 'galoisKeyShareBatch');
        if (batch.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'galoisKeyShareBatches roster positions must be contiguous from zero.',
            );
        }
        if (
            batch.evaluatorKeyScheduleRoot !==
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
            batch.sameSecretProofFamilyBindingRoot !==
                input.sameSecretProofFamilyBindingRoot ||
            batch.publicKeyShareLnpProofSetRoot !==
                input.publicKeyShareLnpProofSetRoot ||
            batch.requiredGaloisSetHash !==
                input.evaluatorKeySchedule.requiredGaloisSetHash
        ) {
            throw new Error(
                'galoisKeyShareBatches must match the accepted evaluation-key binding.',
            );
        }
    });
    const galoisKeyShareBatchRoots = sortedGaloisBatches.map((batch) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: batch.galoisKeyShareBatchRoot,
    })) satisfies GaloisKeyShareBatchRootReference[];
    const galoisKeyRoots =
        input.evaluatorKeySchedule.requiredGaloisKeySchedule.map(
            (scheduleEntry) => {
                const { rotation, level } = scheduleEntry;
                const decompositionDigitCount = level + 1;
                const contributingShareRoots = sortedGaloisBatches.map(
                    (batch) => {
                        const materialRecord = galoisShareMaterialForSchedule(
                            batch,
                            rotation,
                            level,
                        );

                        return {
                            trusteeIdentity: batch.trusteeIdentity,
                            trusteeRosterPosition: batch.trusteeRosterPosition,
                            galoisKeyShareRoot:
                                materialRecord.galoisKeyShareRoot,
                        } satisfies GaloisKeyContributingShareRoot;
                    },
                );
                const galoisKeyRoot = deriveProtocolHash('RotationKeyRoot', {
                    objectType: 'GaloisKeyAggregate',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    assemblyStatus: publicEvaluationKeyAssemblyStatus,
                    materialEncoding: publicEvaluationKeyMaterialEncoding,
                    materialSource: publicEvaluationKeyMaterialSource,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    galoisKeyCrpRoot:
                        input.evaluatorKeySchedule.galoisKeyCrpRoot,
                    requiredGaloisSetHash:
                        input.evaluatorKeySchedule.requiredGaloisSetHash,
                    rotation,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    contributingShareRoots,
                });

                return {
                    rotation,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    galoisKeyRoot,
                    contributingShareRoots,
                } satisfies GaloisKeyRootReference;
            },
        );
    if (input.publicEvaluationKeyMaterialReference !== undefined) {
        const reference = input.publicEvaluationKeyMaterialReference;
        if (
            reference.publicEvaluationKeyMaterialEncoding !==
            publicEvaluationKeyTransportMaterialEncoding
        ) {
            throw new Error(
                'publicEvaluationKeyMaterialReference uses an unsupported material encoding.',
            );
        }
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialRoot,
            'publicEvaluationKeyMaterialRoot',
        );
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialFullObjectHash,
            'publicEvaluationKeyMaterialFullObjectHash',
        );
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialChunkRoot,
            'publicEvaluationKeyMaterialChunkRoot',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialChunkSizeBytes,
            'publicEvaluationKeyMaterialChunkSizeBytes',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialChunkCount,
            'publicEvaluationKeyMaterialChunkCount',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialTotalByteLength,
            'publicEvaluationKeyMaterialTotalByteLength',
        );
        if (
            reference.publicEvaluationKeyMaterialChunkHashes.length !==
            reference.publicEvaluationKeyMaterialChunkCount
        ) {
            throw new Error(
                'publicEvaluationKeyMaterialChunkHashes must match publicEvaluationKeyMaterialChunkCount.',
            );
        }
        reference.publicEvaluationKeyMaterialChunkHashes.forEach(
            (chunkHash, chunkIndex) => {
                assertProtocolHash(
                    chunkHash,
                    `publicEvaluationKeyMaterialChunkHashes[${chunkIndex}]`,
                );
            },
        );
    }

    const evaluationKeysWithoutHash = {
        objectType: 'PublicEvaluationKeySet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        assemblyStatus: publicEvaluationKeyAssemblyStatus,
        materialEncoding: publicEvaluationKeyMaterialEncoding,
        materialSource: publicEvaluationKeyMaterialSource,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
        relinearizationKeyShareRoundsRoot:
            input.relinearizationKeyShareRounds
                .relinearizationKeyShareRoundsRoot,
        relinearizationLevelSchedule:
            input.evaluatorKeySchedule.relinearizationLevelSchedule,
        relinearizationKeyRoots,
        requiredGaloisSetHash: input.evaluatorKeySchedule.requiredGaloisSetHash,
        requiredGaloisKeySchedule:
            input.evaluatorKeySchedule.requiredGaloisKeySchedule,
        galoisKeyShareBatchRoots,
        galoisKeyRoots,
        genericKeySwitchKeyRoots: [],
        rawKeyBytesEmbedded: false,
        verifierGeneratedKeyMaterial: false,
        ...(input.publicEvaluationKeyMaterialReference ?? {}),
    } as const satisfies Omit<PublicEvaluationKeySet, 'evaluationKeySetHash'>;

    return {
        ...evaluationKeysWithoutHash,
        evaluationKeySetHash: deriveProtocolHash(
            'EvaluationKeySetHash',
            evaluationKeysWithoutHash,
        ),
    } satisfies PublicEvaluationKeySet;
}

const relinearizationShareMaterialManifest = (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
): readonly JsonRecord[] => {
    const entries: {
        readonly level: number;
        readonly roundOrder: number;
        readonly trusteeRosterPosition: number;
        readonly entry: JsonRecord;
    }[] = [];
    const recordGroups = [
        {
            round: 'round-one',
            roundOrder: 0,
            records: relinearizationKeyShareRounds.roundOneRecords,
            shareRootFieldName: 'roundOneShareRoot',
            recordRootFieldName: 'roundOneRecordRoot',
        },
        {
            round: 'round-two',
            roundOrder: 1,
            records: relinearizationKeyShareRounds.roundTwoRecords,
            shareRootFieldName: 'roundTwoShareRoot',
            recordRootFieldName: 'roundTwoRecordRoot',
        },
    ] as const;

    recordGroups.forEach((group) => {
        group.records.forEach((record) => {
            const recordFields = record as JsonRecord;
            entries.push({
                level: record.level,
                roundOrder: group.roundOrder,
                trusteeRosterPosition: record.trusteeRosterPosition,
                entry: {
                    round: group.round,
                    trusteeIdentity: record.trusteeIdentity,
                    trusteeRosterPosition: record.trusteeRosterPosition,
                    level: record.level,
                    keySwitchMaterialEncoding: record.keySwitchMaterialEncoding,
                    keySwitchDomain: record.keySwitchDomain,
                    keySwitchSeedHex: record.keySwitchSeedHex,
                    keySwitchComponentVectorRoot:
                        record.keySwitchComponentVectorRoot,
                    keySwitchComponentMaterialRoot:
                        recordFields.keySwitchComponentMaterialRoot ?? null,
                    shareRoot: recordFields[group.shareRootFieldName],
                    recordRoot: recordFields[group.recordRootFieldName],
                },
            });
        });
    });

    return entries
        .sort(
            (left, right) =>
                left.level - right.level ||
                left.roundOrder - right.roundOrder ||
                left.trusteeRosterPosition - right.trusteeRosterPosition,
        )
        .map((entry) => entry.entry);
};

const galoisShareMaterialManifest = (
    galoisKeyShareBatches: readonly GaloisKeyShareBatch[],
): readonly JsonRecord[] => {
    const entries: {
        readonly rotation: number;
        readonly level: number;
        readonly trusteeRosterPosition: number;
        readonly entry: JsonRecord;
    }[] = [];
    galoisKeyShareBatches.forEach((batch) => {
        batch.galoisKeyShareMaterialRecords.forEach((materialRecord) => {
            const materialFields = materialRecord as JsonRecord;
            entries.push({
                rotation: materialRecord.rotation,
                level: materialRecord.level,
                trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                entry: {
                    trusteeIdentity: materialRecord.trusteeIdentity,
                    trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                    rotation: materialRecord.rotation,
                    level: materialRecord.level,
                    keySwitchMaterialEncoding:
                        materialRecord.keySwitchMaterialEncoding,
                    keySwitchDomain: materialRecord.keySwitchDomain,
                    keySwitchSeedHex: materialRecord.keySwitchSeedHex,
                    keySwitchComponentVectorRoot:
                        materialRecord.keySwitchComponentVectorRoot,
                    keySwitchComponentMaterialRoot:
                        materialFields.keySwitchComponentMaterialRoot ?? null,
                    galoisKeyShareRoot: materialRecord.galoisKeyShareRoot,
                },
            });
        });
    });

    return entries
        .sort(
            (left, right) =>
                left.rotation - right.rotation ||
                left.level - right.level ||
                left.trusteeRosterPosition - right.trusteeRosterPosition,
        )
        .map((entry) => entry.entry);
};

const publicEvaluationKeyMaterialManifest = (
    input: PublicEvaluationKeyMaterialTransportInput,
    evaluationKeys: PublicEvaluationKeySet,
): JsonRecord => ({
    objectType: 'PublicEvaluationKeyMaterialManifest',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    assemblyStatus: publicEvaluationKeyAssemblyStatus,
    materialEncoding: publicEvaluationKeyMaterialEncoding,
    materialTransportEncoding: publicEvaluationKeyTransportMaterialEncoding,
    materialSource: publicEvaluationKeyMaterialSource,
    ...contextFields(input.setupContext),
    participantCount: input.participantCount,
    rnsLimbCount: input.qSharePrimes.length,
    evaluatorKeyScheduleRoot: evaluationKeys.evaluatorKeyScheduleRoot,
    sameSecretProofFamilyBindingRoot:
        evaluationKeys.sameSecretProofFamilyBindingRoot,
    publicKeyShareLnpProofSetRoot: evaluationKeys.publicKeyShareLnpProofSetRoot,
    relinearizationKeyShareRoundsRoot:
        evaluationKeys.relinearizationKeyShareRoundsRoot,
    relinearizationLevelSchedule: evaluationKeys.relinearizationLevelSchedule,
    relinearizationKeyRoots: evaluationKeys.relinearizationKeyRoots,
    relinearizationShareMaterialRoots: relinearizationShareMaterialManifest(
        input.relinearizationKeyShareRounds,
    ),
    requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
    requiredGaloisKeySchedule: evaluationKeys.requiredGaloisKeySchedule,
    galoisKeyShareBatchRoots: evaluationKeys.galoisKeyShareBatchRoots,
    galoisKeyRoots: evaluationKeys.galoisKeyRoots,
    galoisShareMaterialRoots: galoisShareMaterialManifest(
        input.galoisKeyShareBatches,
    ),
    genericKeySwitchKeyRoots: evaluationKeys.genericKeySwitchKeyRoots,
    rawKeyBytesEmbedded: false,
    verifierGeneratedKeyMaterial: false,
});

const encodePublicEvaluationKeyMaterialManifest = (
    manifest: JsonRecord,
): Uint8Array => {
    const manifestBytes = textEncoder.encode(canonicalJson(manifest));
    const materialBytes = new Uint8Array(
        publicEvaluationKeyMaterialMagic.byteLength + manifestBytes.byteLength,
    );
    materialBytes.set(publicEvaluationKeyMaterialMagic, 0);
    materialBytes.set(manifestBytes, publicEvaluationKeyMaterialMagic.length);

    return materialBytes;
};

const publicEvaluationKeyMaterialChunks = (
    materialBytes: Uint8Array,
): readonly Uint8Array[] => {
    if (materialBytes.byteLength === 0) {
        throw new Error(
            'public evaluation-key material transport requires bytes.',
        );
    }
    const chunks: Uint8Array[] = [];
    for (
        let byteOffset = 0;
        byteOffset < materialBytes.byteLength;
        byteOffset += setupProofTransportChunkSizeBytes
    ) {
        chunks.push(
            materialBytes.slice(
                byteOffset,
                byteOffset + setupProofTransportChunkSizeBytes,
            ),
        );
    }

    return chunks;
};

const publicEvaluationKeyMaterialFullObjectHash = (
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash =>
    hash512Hex(
        'sealed-lattice/setup/public-evaluation-key-material/full-object-v1',
        [u64LittleEndianBytes(totalByteLength, 'totalByteLength'), ...chunks],
    );

const publicEvaluationKeyMaterialChunkHash = (
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex('sealed-lattice/setup/public-evaluation-key-material/chunk-v1', [
        textEncoder.encode(fullObjectHash),
        u64LittleEndianBytes(chunkIndex, 'chunkIndex'),
        chunk,
    ]);

const publicEvaluationKeyMaterialTransportHashes = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'public evaluation-key material transport requires at least one chunk.',
        );
    }
    const totalByteLength = chunks.reduce((byteLength, chunk, chunkIndex) => {
        if (chunk.byteLength === 0) {
            throw new Error(
                'public evaluation-key material chunks must be non-empty.',
            );
        }
        if (chunk.byteLength > setupProofTransportChunkSizeBytes) {
            throw new Error(
                'public evaluation-key material chunk exceeds the accepted chunk size.',
            );
        }
        if (
            chunkIndex + 1 < chunks.length &&
            chunk.byteLength !== setupProofTransportChunkSizeBytes
        ) {
            throw new Error(
                'public evaluation-key material contains a short non-final chunk.',
            );
        }

        return byteLength + chunk.byteLength;
    }, 0);
    const fullObjectHash = publicEvaluationKeyMaterialFullObjectHash(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        publicEvaluationKeyMaterialChunkHash(fullObjectHash, chunkIndex, chunk),
    );
    const chunkRoot = deriveProtocolHash(
        'PublicEvaluationKeyMaterialChunkRoot',
        {
            objectType: 'PublicEvaluationKeyMaterialChunkManifest',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    );

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const publicEvaluationKeyMaterialReferenceRoot = (
    evaluationKeys: PublicEvaluationKeySet,
    expectedMaterialManifest: JsonRecord,
    transportHashes: ReturnType<
        typeof publicEvaluationKeyMaterialTransportHashes
    >,
): ProtocolHash =>
    deriveProtocolHash('PublicEvaluationKeyMaterialRoot', {
        objectType: 'PublicEvaluationKeyMaterialReference',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        assemblyStatus: publicEvaluationKeyAssemblyStatus,
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        materialSource: publicEvaluationKeyMaterialSource,
        ceremonyId: evaluationKeys.ceremonyId,
        manifestHash: evaluationKeys.manifestHash,
        rosterHash: evaluationKeys.rosterHash,
        setupProfileHash: evaluationKeys.setupProfileHash,
        qShareHash: evaluationKeys.qShareHash,
        carryAwareVssShareRelationProfileHash:
            evaluationKeys.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: evaluationKeys.commitmentProfileHash,
        setupEpoch: evaluationKeys.setupEpoch,
        evaluatorKeyScheduleRoot: evaluationKeys.evaluatorKeyScheduleRoot,
        sameSecretProofFamilyBindingRoot:
            evaluationKeys.sameSecretProofFamilyBindingRoot,
        publicKeyShareLnpProofSetRoot:
            evaluationKeys.publicKeyShareLnpProofSetRoot,
        relinearizationKeyShareRoundsRoot:
            evaluationKeys.relinearizationKeyShareRoundsRoot,
        requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
        expectedMaterialManifest,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: transportHashes.chunkHashes.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkRoot: transportHashes.chunkRoot,
        chunkHashes: transportHashes.chunkHashes,
    });

const expectedPublicEvaluationKeyComponentMaterialRoots = (
    input: PublicEvaluationKeyMaterialTransportInput,
): ReadonlySet<ProtocolHash> => {
    const roots = new Set<ProtocolHash>();
    const collectRoot = (record: JsonRecord): void => {
        if (
            record.keySwitchMaterialEncoding !==
            evaluationKeyShareComponentMaterialEncoding
        ) {
            return;
        }
        const root = record.keySwitchComponentMaterialRoot;
        if (typeof root !== 'string') {
            throw new TypeError(
                'binary evaluation-key share records must carry keySwitchComponentMaterialRoot.',
            );
        }
        assertProtocolHash(root, 'keySwitchComponentMaterialRoot');
        roots.add(root);
    };

    input.relinearizationKeyShareRounds.roundOneRecords.forEach((record) =>
        collectRoot(record),
    );
    input.relinearizationKeyShareRounds.roundTwoRecords.forEach((record) =>
        collectRoot(record),
    );
    input.galoisKeyShareBatches.forEach((batch) =>
        batch.galoisKeyShareMaterialRecords.forEach((materialRecord) =>
            collectRoot(materialRecord),
        ),
    );

    return roots;
};

const assertPublicEvaluationKeyComponentMaterialCoverage = (
    input: PublicEvaluationKeyMaterialTransportInput,
): void => {
    const expectedRoots =
        expectedPublicEvaluationKeyComponentMaterialRoots(input);
    const componentMaterials =
        input.transportedEvaluationKeyShareComponentMaterial
            ?.componentMaterials ?? [];
    if (expectedRoots.size === 0) {
        if (componentMaterials.length !== 0) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial must not be supplied when evaluation-key records do not use binary component material.',
            );
        }

        return;
    }
    if (componentMaterials.length === 0) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial is required for binary evaluation-key component material.',
        );
    }

    const suppliedRoots = new Set<ProtocolHash>();
    componentMaterials.forEach((componentMaterial, componentIndex) => {
        const materialRoot = componentMaterial.keySwitchComponentMaterialRoot;
        if (typeof materialRoot !== 'string') {
            throw new TypeError(
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot must be a protocol hash.`,
            );
        }
        assertProtocolHash(
            materialRoot,
            `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot`,
        );
        if (suppliedRoots.has(materialRoot)) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial contains duplicate key-switch component material roots.',
            );
        }
        suppliedRoots.add(materialRoot);
    });
    if (
        suppliedRoots.size !== expectedRoots.size ||
        [...expectedRoots].some(
            (expectedRoot) => !suppliedRoots.has(expectedRoot),
        )
    ) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial must cover every binary evaluation-key component material root.',
        );
    }
};

export const createBinaryChunkedPublicEvaluationKeyMaterialTransport = (
    input: PublicEvaluationKeyMaterialTransportInput,
): BinaryChunkedPublicEvaluationKeyMaterialTransport => {
    const evaluationKeysWithoutMaterialReference =
        createPublicEvaluationKeySet(input);
    const manifest = publicEvaluationKeyMaterialManifest(
        input,
        evaluationKeysWithoutMaterialReference,
    );
    const materialBytes = encodePublicEvaluationKeyMaterialManifest(manifest);
    const chunks = publicEvaluationKeyMaterialChunks(materialBytes);
    const transportHashes = publicEvaluationKeyMaterialTransportHashes(chunks);
    const publicEvaluationKeyMaterialRoot =
        publicEvaluationKeyMaterialReferenceRoot(
            evaluationKeysWithoutMaterialReference,
            manifest,
            transportHashes,
        );
    const publicEvaluationKeyMaterialReference = {
        publicEvaluationKeyMaterialEncoding:
            publicEvaluationKeyTransportMaterialEncoding,
        publicEvaluationKeyMaterialRoot,
        publicEvaluationKeyMaterialChunkSizeBytes:
            setupProofTransportChunkSizeBytes,
        publicEvaluationKeyMaterialChunkCount:
            transportHashes.chunkHashes.length,
        publicEvaluationKeyMaterialTotalByteLength:
            transportHashes.totalByteLength,
        publicEvaluationKeyMaterialFullObjectHash:
            transportHashes.fullObjectHash,
        publicEvaluationKeyMaterialChunkRoot: transportHashes.chunkRoot,
        publicEvaluationKeyMaterialChunkHashes: transportHashes.chunkHashes,
    } satisfies PublicEvaluationKeyMaterialReference;
    const evaluationKeys = createPublicEvaluationKeySet({
        ...input,
        publicEvaluationKeyMaterialReference,
    });
    assertPublicEvaluationKeyComponentMaterialCoverage(input);
    const transportedPublicEvaluationKeyMaterial = {
        objectType: publicEvaluationKeyMaterialTransportSetObjectType,
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        publicEvaluationKeyMaterials: [
            {
                objectType: publicEvaluationKeyMaterialTransportObjectType,
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
                ...contextFields(input.setupContext),
                evaluationKeySetHash: evaluationKeys.evaluationKeySetHash,
                publicEvaluationKeyMaterialRoot,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: transportHashes.chunkHashes.length,
                totalByteLength: transportHashes.totalByteLength,
                fullObjectHash: transportHashes.fullObjectHash,
                chunkRoot: transportHashes.chunkRoot,
                chunkHashes: transportHashes.chunkHashes,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            },
        ],
    } satisfies TransportedPublicEvaluationKeyMaterialSet;

    return {
        evaluationKeys,
        publicEvaluationKeyMaterialReference,
        transportedPublicEvaluationKeyMaterial,
    };
};
