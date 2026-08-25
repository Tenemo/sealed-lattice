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

/** Canonical payload assignment for one replicated-key component opening. */
export const replicatedKeyComponentOpeningMailboxPayloadType = 0x0002;

export type MailboxPayloadType =
    typeof replicatedKeyComponentOpeningMailboxPayloadType;

/** Canonical public inputs that bind one authenticated-mailbox key schedule. */
export type MailboxKeyScheduleInput = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly recipientParticipantId: string;
    readonly producerSequence: string;
    readonly envelopeAttemptIdentifierHex: string;
    readonly payloadType: MailboxPayloadType;
    readonly statementHash: ProtocolHash;
    readonly orderedMaterialRoots: readonly ProtocolHash[];
}>;

/** Canonical associated data authenticated by one mailbox envelope. */
export type MailboxAssociatedData = MailboxKeyScheduleInput;

/** The reset-safe setup uniqueness slot before attempt and ciphertext derivation. */
export type SetupMailboxSlot = Omit<
    MailboxKeyScheduleInput,
    'envelopeAttemptIdentifierHex'
>;

/** Canonical streamed ciphertext commitment carried by a mailbox envelope. */
export type MailboxCiphertextDescriptor = Readonly<{
    readonly totalByteLength: string;
    readonly orderedChunkDigests: readonly ProtocolHash[];
    readonly fullObjectDigest: ProtocolHash;
}>;

/** Canonical mailbox envelope fields covered by its source signature. */
export type UnsignedMailboxEnvelope = Readonly<{
    readonly associatedData: MailboxAssociatedData;
    readonly kemCiphertextHex: string;
    readonly ciphertextDescriptor: MailboxCiphertextDescriptor;
    readonly gcmTagHex: string;
}>;

/** Canonical signed mailbox envelope. */
export type SignedMailboxEnvelope = Readonly<
    UnsignedMailboxEnvelope & {
        readonly sourceSignatureHex: string;
    }
>;

/** Roster sizes for which protocol parameters can be derived. */
export const configurableParticipantCountRange = Object.freeze({
    minimum: 3,
    maximum: 20,
} as const);

/** Option counts for which canonical structure and formulas are defined. */
export const configurableOptionCountRange = Object.freeze({
    minimum: 2,
    maximum: 20,
} as const);

export type FoundationRosterParameters = Readonly<{
    participantCount: number;
    activeFaultBound: number;
    reconstructionThreshold: number;
    candidateViewQuorum: number;
    finalityQuorum: number;
    stateWitnessQuorum: number;
}>;

/**
 * Derives roster-dependent protocol parameters without claiming support or
 * evidence for that roster size.
 */
export const deriveFoundationRosterParameters = (
    participantCount: number,
): FoundationRosterParameters => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < configurableParticipantCountRange.minimum ||
        participantCount > configurableParticipantCountRange.maximum
    ) {
        throw new RangeError(
            'participant count must be an integer from 3 through 20.',
        );
    }

    const activeFaultBound = Math.floor((participantCount - 1) / 3);
    const quorum = Math.floor((participantCount + activeFaultBound) / 2) + 1;
    return Object.freeze({
        participantCount,
        activeFaultBound,
        reconstructionThreshold: Math.floor(participantCount / 3) + 1,
        candidateViewQuorum: quorum,
        finalityQuorum: quorum,
        stateWitnessQuorum: quorum,
    });
};

/** The sole selected and evidence-gated prototype roster size. */
const prototypeParticipantCount = 10;

const prototypeRosterParameters = deriveFoundationRosterParameters(
    prototypeParticipantCount,
);

/** Fixed public parameters and absolute runtime safety bounds for the selected prototype. */
export const foundationProfile = Object.freeze({
    protocolName: 'sealed-lattice',
    protocolVersion: 1,
    ...prototypeRosterParameters,
    optionCount: 10,
    minimumScore: 1,
    maximumScore: 10,
    maximumIdentifierByteLength: 128,
    streamChunkByteLength: 1_048_576,
    // A canonical raw-byte item uses four of its u32-framed bytes for the payload length.
    maximumCanonicalStreamByteLength: 4_294_967_291,
    maximumCopiedBufferByteLength: 8_388_608,
    maximumWasmMemoryByteLength: 671_088_640,
} as const);
