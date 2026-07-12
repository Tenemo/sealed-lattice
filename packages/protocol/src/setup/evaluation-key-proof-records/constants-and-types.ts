import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type EvaluatorKeySchedule,
    type RelinearizationLevelScheduleEntry,
    type RequiredGaloisKeyScheduleEntry,
} from '../evaluator-key-schedule.js';
import type {
    CanonicalGeneratedSetupProofMaterial,
    CanonicalProofMaterialChunkPull,
} from '../setup-proof-material-transport.js';
import type { VssSameSecretBridgeStatementSet } from '../vss-commitments/linkage-and-bridge.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;
export type EvaluationKeyShareProofFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';

export const trusteeEvaluationKeyProofFamily = 'trustee-evaluation-key';
export const publicEvaluationKeyMaterialEncoding =
    'root-bound-public-key-switch-component-roots';
export const publicEvaluationKeyTransportMaterialEncoding =
    'binary-chunked-public-evaluation-key-root-manifest';
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
export const evaluationKeyAggregateBindingSetObjectType =
    'EvaluationKeyAggregateBindingSet';
export const evaluationKeyAggregateBindingKeyGroupObjectType =
    'EvaluationKeyAggregateBindingKeyGroup';
export const evaluationKeyAggregateBindingOpeningSetObjectType =
    'SetupTransportedEvaluationKeyAggregateBindingOpeningSet';
export const evaluationKeyShareComponentMaterialEncoding =
    'binary-chunked-key-switch-component-vectors';
export const setupProofMaterialTransportEncoding = 'binary-chunked-proof-bytes';
export const evaluationKeyShareComponentVectorHashDomain =
    'sealed-lattice-bgv-rns/evaluation-key-share-component-vector';
export const evaluationKeyShareComponentMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x31,
]);
export const publicEvaluationKeyMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x50, 0x4d, 0x56, 0x31,
]);
export const textEncoder = new TextEncoder();

export type EvaluationKeyTrusteeReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}>;

export type KeySwitchComponentVectorEntry = Readonly<JsonRecord>;

export type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors';
    readonly keySwitchComponentVectors: readonly KeySwitchComponentVectorEntry[];
}>;

export type EvaluationKeyShareTransportedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: typeof evaluationKeyShareComponentMaterialEncoding;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
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
        readonly proofFamily: 'relinearization-key-share';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
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
        readonly proofFamily: 'relinearization-key-share';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
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
        readonly proofFamily: 'relinearization-key-share';
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
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
        readonly proofFamily: 'galois-key-share';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareMaterialRecords: readonly GaloisKeyShareMaterialRecord[];
        readonly galoisKeyShareBatchRoot: ProtocolHash;
    }
>;

export type TrusteeEvaluationKeyCanonicalProofReference = Readonly<{
    readonly proofBytesEncoding: typeof setupProofMaterialTransportEncoding;
    readonly proofMaterialRoot: ProtocolHash;
}>;

export type TrusteeEvaluationKeyProofRecord = Readonly<
    JsonRecord &
        TrusteeEvaluationKeyCanonicalProofReference & {
            readonly objectType: 'TrusteeEvaluationKeyProof';
            readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly statementHash: ProtocolHash;
            readonly proofBytesHash: ProtocolHash;
            readonly trusteeEvaluationKeyProofRoot: ProtocolHash;
        }
>;

export type TrusteeEvaluationKeyProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'TrusteeEvaluationKeyProofSet';
        readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly keySwitchDecompositionHash: ProtocolHash;
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
    readonly sourceConstantCoefficientCommitmentRoot: ProtocolHash;
}>;

export type TrusteeEvaluationKeyProofGenerationOutput = Readonly<{
    readonly operation: 'generateTrusteeEvaluationKeyProof';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly proofBytesEncoding: typeof setupProofMaterialTransportEncoding;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
    readonly canonicalMaterial: CanonicalGeneratedSetupProofMaterial;
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
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }>,
) => Promise<TrusteeEvaluationKeyProofGenerationOutput>;

// One trustee's private witness for its batched evaluation-key statement: the
// shared ternary secret, per-key centered-binomial errors in statement key
// order (relinearization round-one levels ascending, round-two levels
// ascending, then the frozen Galois schedule), the binary negative-coefficient
// indicator, and the five ternary opening-randomness columns for the original
// source-limb-zero BDLOP constant commitment the schedule opens.
export type TrusteeEvaluationKeyWitnessInput = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly secretCoefficients: readonly number[];
    readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
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

// One trustee's committed-material root inside an aggregate-binding key group,
// in roster order. The material root is a fixed-width atom-proof Merkle digest
// in lowercase hexadecimal, narrower than the 128-character canonical object
// hashes, so it is a plain hexadecimal string rather than a ProtocolHash.
export type EvaluationKeyAggregateBindingTrusteeMaterialRoot = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly materialRoot: string;
}>;

// One scheduled key group's committed-material aggregate-binding record: the
// runtime key group it binds (level, an optional rotation for Galois keys, the
// consecutive limb span, and the full ring degree), the per-coefficient wrap
// multiples the aggregate identity accepts as signed integers indexed by digit
// then coefficient, and each trustee's committed-material root.
export type EvaluationKeyAggregateBindingKeyGroup = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyAggregateBindingKeyGroupObjectType;
        readonly level: number;
        readonly rotation?: number;
        readonly groupStartLimb: number;
        readonly groupLimbCount: number;
        readonly ringDegree: number;
        readonly wrapMultiples: readonly (readonly number[])[];
        readonly trusteeMaterialRoots: readonly EvaluationKeyAggregateBindingTrusteeMaterialRoot[];
    }
>;

// The optional committed-material aggregate-binding set the accepted-setup
// evaluation-key verification consumes when the package publishes it. Absent by
// default so existing packages and verification are unchanged; when present, the
// kernel binds each published runtime key group to the trustee-committed
// material through the atom material roots plus the transported openings.
export type EvaluationKeyAggregateBindingSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyAggregateBindingSetObjectType;
        readonly keyGroups: readonly EvaluationKeyAggregateBindingKeyGroup[];
    }
>;

// One transported batched linear-evaluation opening, content-addressed by the
// atom-proof material root it opens. The opening bytes are the family backend's
// opening codec output in lowercase hexadecimal.
export type TransportedEvaluationKeyAggregateBindingOpening = Readonly<{
    readonly materialRoot: string;
    readonly openingBytesHex: string;
}>;

// The transported opening set the verification request carries alongside the
// package aggregate binding: one opening per trustee-committed material root the
// aggregate-binding key groups reference. Absent by default; the kernel skips
// the aggregate-binding check when the package does not publish it.
export type TransportedEvaluationKeyAggregateBindingOpeningSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyAggregateBindingOpeningSetObjectType;
        readonly openings: readonly TransportedEvaluationKeyAggregateBindingOpening[];
    }
>;

export type PublicEvaluationKeySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicEvaluationKeySet';
        readonly materialEncoding: typeof publicEvaluationKeyMaterialEncoding;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly relinearizationKeyRoots: readonly RelinearizationKeyRootReference[];
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareBatchRoots: readonly GaloisKeyShareBatchRootReference[];
        readonly galoisKeyRoots: readonly GaloisKeyRootReference[];
        readonly publicEvaluationKeyMaterialEncoding?: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
        readonly aggregateBinding?: EvaluationKeyAggregateBindingSet;
        readonly evaluationKeySetHash: ProtocolHash;
    }
>;

export type PublicEvaluationKeyMaterialReference = Readonly<{
    readonly publicEvaluationKeyMaterialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
    readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
}>;

export type TransportedEvaluationKeyShareProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareProofTransportSetObjectType;
        readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
        readonly proofMaterials: readonly Readonly<
            JsonRecord & {
                readonly objectType: typeof evaluationKeyShareProofTransportObjectType;
                readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
                readonly proofMaterialRoot: ProtocolHash;
                readonly descriptorBytes: Uint8Array;
            }
        >[];
    }
>;

export type TransportedEvaluationKeyShareComponentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareComponentMaterialTransportSetObjectType;
        readonly componentMaterials: readonly JsonRecord[];
    }
>;

// A repeatable bounded source for one transported evaluation-key component
// material. The canonical descriptor remains on the component sidecar while
// the source supplies one requested chunk at a time.
export type EvaluationKeyShareComponentMaterialChunkSource = Readonly<{
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
    readonly proofFamily: EvaluationKeyShareProofFamily;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type EvaluationKeyShareComponentMaterialWriter = (
    input: Readonly<{
        readonly keySwitchComponentMaterialRoot: ProtocolHash;
        readonly proofFamily: EvaluationKeyShareProofFamily;
        readonly totalByteLength: number;
        readonly pullChunk: CanonicalProofMaterialChunkPull;
    }>,
) => Promise<Uint8Array>;

// A repeatable bounded source for one canonical public evaluation-key
// material stream. The descriptor remains on the transported reference while
// the source is supplied separately to verification.
export type PublicEvaluationKeyMaterialChunkSource = Readonly<{
    readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type PublicEvaluationKeyMaterialWriter = (
    input: Readonly<{
        readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
        readonly totalByteLength: number;
        readonly pullChunk: CanonicalProofMaterialChunkPull;
    }>,
) => Promise<Uint8Array>;

export type TransportedPublicEvaluationKeyMaterial = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportObjectType;
        readonly materialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
        readonly descriptorBytes: Uint8Array;
    }
>;

export type TransportedPublicEvaluationKeyMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportSetObjectType;
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
    readonly trusteeReferences: readonly EvaluationKeyTrusteeReference[];
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly writeEvaluationKeyShareComponentMaterial: EvaluationKeyShareComponentMaterialWriter;
}>;

export type EvaluationKeyProofCommonInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    readonly trusteeReferences: readonly EvaluationKeyTrusteeReference[];
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
        readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
        readonly trusteeEvaluationKeyProofGenerator: TrusteeEvaluationKeyProofGenerator;
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
        // Bounded component sources supplied out of band so the prover can
        // reconstruct transported public component vectors without retaining a
        // second whole-material byte representation.
        readonly evaluationKeyShareComponentMaterialChunkSources?: readonly EvaluationKeyShareComponentMaterialChunkSource[];
    }>;

export type PublicEvaluationKeySetInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly publicEvaluationKeyMaterialReference?: PublicEvaluationKeyMaterialReference;
        // Optional committed-material aggregate binding, carried through into the
        // assembled evaluation-key set verbatim and included in the canonical
        // evaluationKeySetHash. Absent by default so existing assembly output is
        // unchanged.
        readonly aggregateBinding?: EvaluationKeyAggregateBindingSet;
    }>;

export type PublicEvaluationKeyMaterialTransportInput = Omit<
    PublicEvaluationKeySetInput,
    'publicEvaluationKeyMaterialReference'
> &
    Readonly<{
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
        readonly writePublicEvaluationKeyMaterial: PublicEvaluationKeyMaterialWriter;
    }>;
