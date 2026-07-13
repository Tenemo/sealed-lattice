import type { ProtocolHash } from './protocol-hash.js';

/** Closed semantic refusal taxonomy shared by every protocol verifier. */
export const refusalReasons = Object.freeze([
    'malformedEncoding',
    'unsupportedVersionOrSuite',
    'outsideSupportedProfile',
    'wrongContext',
    'wrongTypeOrLength',
    'wrongHashOrRoot',
    'invalidSignature',
    'duplicateIdentity',
    'equivocation',
    'missingPrerequisite',
    'invalidProof',
    'invalidArithmeticRelation',
    'consumedState',
] as const);

/** A verifier refusal whose name has the same meaning in Rust, Node, and WASM. */
export type RefusalReason = (typeof refusalReasons)[number];

/** Canonical numeric encodings for refusal reasons. Zero and unassigned values refuse. */
export const refusalReasonCodes: Readonly<Record<RefusalReason, number>> =
    Object.freeze({
        malformedEncoding: 0x0001,
        unsupportedVersionOrSuite: 0x0002,
        outsideSupportedProfile: 0x0003,
        wrongContext: 0x0004,
        wrongTypeOrLength: 0x0005,
        wrongHashOrRoot: 0x0006,
        invalidSignature: 0x0007,
        duplicateIdentity: 0x0008,
        equivocation: 0x0009,
        missingPrerequisite: 0x000a,
        invalidProof: 0x000b,
        invalidArithmeticRelation: 0x000c,
        consumedState: 0x000d,
    });

/** The only result shape returned by cryptographic and protocol verifiers. */
export type VerificationResult<VerifiedValue> =
    | {
          readonly isValid: true;
          readonly value: VerifiedValue;
      }
    | {
          readonly isValid: false;
          readonly refusalReason: RefusalReason;
      };

declare const participantIdentityBrand: unique symbol;

/** A lowercase canonical participant identity derived from a roster ML-DSA-65 verification key. */
export type ParticipantIdentity = ProtocolHash & {
    readonly [participantIdentityBrand]: 'ParticipantIdentity';
};

const participantIdentityPattern = /^[0-9a-f]{128}$/u;

export const isParticipantIdentity = (
    value: unknown,
): value is ParticipantIdentity =>
    typeof value === 'string' && participantIdentityPattern.test(value);

/** Parses the sole canonical string representation of a participant identity. */
export const parseParticipantIdentity = (
    value: unknown,
): ParticipantIdentity => {
    if (!isParticipantIdentity(value)) {
        throw new TypeError(
            'participant identity must contain exactly 128 lowercase hexadecimal characters.',
        );
    }

    return value;
};

/** Fixed public parameters of the first supported foundation profile. */
export const foundationProfile = Object.freeze({
    protocolName: 'sealed-lattice',
    protocolVersion: 1,
    participantCount: 10,
    activeFaultBound: 3,
    reconstructionThreshold: 4,
    finalityQuorum: 7,
    stateWitnessQuorum: 7,
    optionCount: 20,
    minimumScore: 1,
    maximumScore: 10,
    maximumIdentifierByteLength: 128,
    streamChunkByteLength: 1_048_576,
    maximumResidentStreamChunkCount: 2,
    maximumCopiedBufferByteLength: 1_572_864,
    maximumWasmMemoryByteLength: 402_653_184,
    maximumAdditionalJavaScriptHeapByteLength: 134_217_728,
    maximumAdditionalBrowserProcessByteLength: 671_088_640,
} as const);

/** Canonical tuple item identifiers. */
export const canonicalItemTypes = Object.freeze({
    rawBytes: 0x01,
    ascii: 0x02,
    unsigned16: 0x03,
    unsigned32: 0x04,
    unsigned64: 0x05,
    hash512: 0x06,
    participantIdentity: 0x07,
    fieldElement: 0x08,
    nestedTuple: 0x09,
    unsigned8: 0x0a,
    boolean: 0x0b,
    displayText: 0x0c,
    optional: 0x0d,
    homogeneousList: 0x0e,
    challengeExtensionElement: 0x0f,
} as const);

/** Canonical foundation schema identifiers. */
export const foundationSchemaIdentifiers = Object.freeze({
    hashInput: 0x0001,
    objectEnvelope: 0x0100,
    signedCarrier: 0x0101,
    proofObjectHeader: 0x0102,
    proofMerkleTreeContext: 0x0103,
    proofOraclePhasePairLeaf: 0x0104,
    proofMerkleNode: 0x0105,
    proofAuthenticationNode: 0x0106,
    proofQueryOpeningRecord: 0x0107,
    proofAuthenticationFrontier: 0x0108,
    manifest: 0x0110,
    optionDefinition: 0x0111,
    actionDefinition: 0x0112,
    boardPolicy: 0x0113,
    rosterEntry: 0x0114,
    roster: 0x0115,
    distributionRecord: 0x0116,
    artifactReference: 0x0117,
    suiteRecord: 0x0118,
    mailboxKeyScheduleInput: 0x0200,
    mailboxAssociatedData: 0x0201,
    signedMailboxEnvelope: 0x0202,
    deviceWrappingAssociatedData: 0x0300,
    localRecordAssociatedData: 0x0301,
    storageRootRecoveryValue: 0x0302,
    storageRootCommitmentPayload: 0x0303,
    localRecordKeyInput: 0x0304,
    deviceWrappedStorageRoot: 0x0305,
    localRecordEnvelope: 0x0306,
    localRecordAuthenticatorInput: 0x0307,
    actionStorageDerivationInput: 0x0308,
    privateRandomBlockInput: 0x0400,
    actionRandomnessDerivationInput: 0x0402,
    stateReservationIntent: 0x1610,
    stateOutputIntent: 0x1611,
    stateWitnessVote: 0x1612,
    stateCertificate: 0x1613,
    stateRecoveryTransition: 0x1614,
    streamDescriptor: 0x1800,
    runtimeAssetReference: 0x1801,
    runtimeBuildManifest: 0x1802,
    randomCursor: 0x1804,
    checkpointManifest: 0x1805,
    checkpointRandomUseProfile: 0x1806,
    checkpointBoundaryProfile: 0x1807,
    runtimeOperationProfile: 0x1808,
    mobileRuntimeProfile: 0x1809,
    proofProfileSet: 0x2200,
    proofFieldProfile: 0x2201,
    proofFamilyProfile: 0x2202,
    proofFieldSchedule: 0x2203,
    collectivePublicKeyAggregateStatement: 0x1213,
    relationPlan: 0x2204,
    relationPlanVariant: 0x2205,
} as const);

/** Public context bound into the participant-local storage key hierarchy. */
export type ActionStorageDerivationInput = Readonly<{
    protocolVersion: number;
    suiteId: ProtocolHash;
    ceremonyContextHash: ProtocolHash;
    actionContextHash: ProtocolHash;
    participantId: ParticipantIdentity;
}>;

/** Public context bound into the participant-private randomness key hierarchy. */
export type ActionRandomnessDerivationInput = Readonly<{
    protocolVersion: number;
    suiteId: ProtocolHash;
    ceremonyContextHash: ProtocolHash;
    actionContextHash: ProtocolHash;
    participantId: ParticipantIdentity;
}>;

/** Public inputs bound by the collective public-key aggregation proof header. */
export type CollectivePublicKeyAggregateStatement = Readonly<{
    setupProofContextHash: ProtocolHash;
    orderedPublicKeyShareRoots: readonly ProtocolHash[];
    collectivePublicKeyRoot: ProtocolHash;
    collectivePublicKeyFullObjectDigest: ProtocolHash;
}>;

/** Fixed capability-kind assignments for non-forking state authorization. */
export const stateCapabilityKinds = Object.freeze({
    ballotCandidateList: 1,
    finalitySignature: 2,
    targetRelease: 3,
    setupActionRandomnessRoot: 4,
    setupPublicSeedBranch: 5,
    setupDealerSetBranch: 6,
    setupRkgRoundOneBranch: 7,
    setupTerminalPackage: 8,
} as const);

export type StateCapabilityKind =
    (typeof stateCapabilityKinds)[keyof typeof stateCapabilityKinds];

/** Object-family identifiers selected by the verifier, never by proof bytes. */
export const foundationObjectTypes = Object.freeze({
    publicRandomnessCommitment: 0x0001,
    publicRandomnessReveal: 0x0002,
    publicRandomnessLock: 0x0003,
    setupIntent: 0x0010,
    privateShareAcceptance: 0x0011,
    complaint: 0x0012,
    publicSetupRecord: 0x0013,
    ballotPackage: 0x0020,
    ballotCandidateList: 0x0021,
    aggregate: 0x0030,
    evaluatorReplay: 0x0040,
    finalitySignature: 0x0050,
    stateReservation: 0x0051,
    stateOutputIntent: 0x0052,
    stateWitnessVote: 0x0053,
    recoveryTransition: 0x0054,
    targetDecryptionShare: 0x0060,
    storageRootCommitment: 0x0070,
} as const);

/** Assigned distribution encodings for the first foundation suite profile. */
export const distributionKinds = Object.freeze({
    ternary: 1,
    centeredBinomial: 2,
} as const);

export type DistributionKind =
    (typeof distributionKinds)[keyof typeof distributionKinds];

/** One suite-owned private-randomness distribution assignment. */
export type DistributionRecord = Readonly<{
    purpose: number;
    kind: DistributionKind;
    parameter: bigint;
}>;

/** Assigned suite artifact roles. */
export const artifactKinds = Object.freeze({
    encoderAndBallotLayout: 1,
    verifiableSecretSharingProfile: 2,
    latticeCommitmentProfile: 3,
    proofProfileSet: 4,
    evaluatorProgramSet: 5,
    targetDecryptionProfile: 6,
} as const);

export type ArtifactKind = (typeof artifactKinds)[keyof typeof artifactKinds];

/** A suite artifact expectation whose hash must be recomputed from canonical bytes. */
export type ArtifactReference = Readonly<{
    artifactKind: ArtifactKind;
    byteLength: bigint;
    artifactHash: ProtocolHash;
}>;

/** External manifest input before canonical encoding and verification. */
export type ManifestInput = Readonly<{
    manifestVersion: 1;
    displayTitle: string;
    options: readonly OptionDefinitionInput[];
}>;

/** One externally supplied option before canonical encoding and verification. */
export type OptionDefinitionInput = Readonly<{
    optionIndex: number;
    optionIdentifier: string;
    displayLabel: string;
}>;

/** External action policy before canonical encoding and verification. */
export type ActionDefinitionInput = Readonly<{
    actionDefinitionVersion: 1;
    actionKind: 1;
    optionCount: 20;
    minimumScore: 1;
    maximumScore: 10;
    topCount: number;
    submissionCutoffUnixMilliseconds: bigint;
}>;

/** External board policy before canonical encoding and verification. */
export type BoardPolicyInput = Readonly<{
    boardPolicyVersion: 1;
    boardOriginIdentifier: string;
    candidateListPolicy: 1;
}>;

/** External participant entry. Cryptographic identity is derived from its signing key. */
export type RosterEntryInput = Readonly<{
    rosterPosition: number;
    role: 1;
    signingVerificationKey: Uint8Array;
    mailboxEncapsulationKey: Uint8Array;
}>;

/** Fixed external roster before canonical encoding and verification. */
export type RosterInput = Readonly<{
    rosterVersion: 1;
    entries: readonly RosterEntryInput[];
}>;

/** An untrusted canonical carrier. Its bytes confer no verification authority. */
export type UntrustedCanonicalCarrier = Readonly<{
    canonicalBytes: Uint8Array;
}>;

/** A canonical streamed value whose digests are recomputed by the verifier. */
export type StreamDescriptor = Readonly<{
    totalByteLength: bigint;
    orderedChunkDigests: readonly Uint8Array[];
    fullObjectDigest: Uint8Array;
}>;
