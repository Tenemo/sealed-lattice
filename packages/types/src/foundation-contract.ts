import type { ProtocolHash } from './protocol-hash.js';

/** Canonical numeric encodings for refusal reasons. Zero and unassigned values refuse. */
export const refusalReasonCodes = Object.freeze({
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
} as const);

/** A verifier refusal whose name has the same meaning in Rust, Node, and WASM. */
export type RefusalReason = keyof typeof refusalReasonCodes;

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
    maximumCopiedBufferByteLength: 1_572_864,
    maximumWasmMemoryByteLength: 402_653_184,
} as const);

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

export const stateIntentKinds = Object.freeze({
    output: 'output',
    recovery: 'recovery',
    reservation: 'reservation',
} as const);

export type StateIntentKind =
    (typeof stateIntentKinds)[keyof typeof stateIntentKinds];
