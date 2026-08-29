export type ProtocolHash = string;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const isProtocolHash = (value: unknown): value is ProtocolHash =>
    typeof value === 'string' && protocolHashPattern.test(value);

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

export type RefusalReason = keyof typeof refusalReasonCodes;

export type VerificationResult<VerifiedValue> =
    | {
          readonly isValid: true;
          readonly value: VerifiedValue;
      }
    | {
          readonly isValid: false;
          readonly refusalReason: RefusalReason;
      };

export const configurableParticipantCountRange = Object.freeze({
    minimum: 3,
    maximum: 20,
} as const);

export const configurableOptionCountRange = Object.freeze({
    minimum: 2,
    maximum: 20,
} as const);

export type FoundationRosterParameters = Readonly<{
    participantCount: number;
    activeFaultBound: number;
    reconstructionThreshold: number;
    selectedSetQuorum: number;
    finalityQuorum: number;
    stateWitnessQuorum: number;
}>;

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
        selectedSetQuorum: quorum,
        finalityQuorum: quorum,
        stateWitnessQuorum: quorum,
    });
};

const prototypeRosterParameters = deriveFoundationRosterParameters(10);

export const foundationProfile = Object.freeze({
    protocolName: 'sealed-lattice',
    protocolVersion: 1,
    ...prototypeRosterParameters,
    optionCount: 10,
    minimumScore: 1,
    maximumScore: 10,
    maximumIdentifierByteLength: 128,
    maximumCopiedBufferByteLength: 8_388_608,
    maximumWasmMemoryByteLength: 671_088_640,
} as const);

export const canonicalErrorCodeValues = [
    'ComponentMismatch',
    'DuplicateField',
    'InvalidEnum',
    'InvalidProtocolObject',
    'InvalidHex',
    'InvalidUtf8',
    'MalformedLength',
    'MalformedMagic',
    'MalformedVarUint',
    'NonCanonicalVarUint',
    'TrailingBytes',
    'UnsupportedObjectVersion',
] as const;

export type CanonicalErrorCode = (typeof canonicalErrorCodeValues)[number];

export type CanonicalError = {
    readonly code: CanonicalErrorCode;
    readonly message: string;
};
