import type {
    ParticipantIdentity,
    ProtocolHash,
    RosterEntryInput,
} from '@sealed-lattice/types';
import { isParticipantIdentity } from '@sealed-lattice/types';

const mlDsa65VerificationKeyByteLength = 1_952;
const mlKem768EncapsulationKeyByteLength = 1_184;
const protocolHashPattern = /^[0-9a-f]{128}$/u;
const maximumCapabilityIdentifierCharacterLength = 256;
const signingSelfTestMessage = new TextEncoder().encode(
    'sealed-lattice external-key-provider ML-DSA-65 pairwise self-test v1',
);
const signingSelfTestContext = new TextEncoder().encode(
    'sealed-lattice/key-provider-self-test/v1',
);

const participantSigningHandleBrand: unique symbol = Symbol(
    'sealed-lattice participant signing handle',
);
const participantMailboxHandleBrand: unique symbol = Symbol(
    'sealed-lattice participant mailbox handle',
);

export type BrowserLocalParticipantKeyProviderErrorCode =
    | 'CapabilityLost'
    | 'CapabilityPurposeMismatch'
    | 'CapabilityPurposeReuse'
    | 'CapabilityReplaced'
    | 'CapabilityRevoked'
    | 'CapabilityUnavailable'
    | 'GenericHiddenRandomnessProviderRejected'
    | 'InvalidActionBinding'
    | 'InvalidRosterBinding'
    | 'MailboxSelfTestFailed'
    | 'PrivateHandlePublicKeyMismatch'
    | 'ProviderFailure'
    | 'RemoteProviderRejected'
    | 'SessionClosed'
    | 'SigningSelfTestFailed';

export class BrowserLocalParticipantKeyProviderError extends Error {
    public readonly code: BrowserLocalParticipantKeyProviderErrorCode;

    public constructor(
        code: BrowserLocalParticipantKeyProviderErrorCode,
        message: string,
    ) {
        super(message);
        this.name = 'BrowserLocalParticipantKeyProviderError';
        this.code = code;
    }
}

/**
 * Public keys selected from one externally accepted, frozen canonical roster.
 * Canonical key decoding remains the roster verifier's responsibility; this
 * boundary checks the exact bytes again when it resolves each private handle.
 */
export type ExternallyAcceptedParticipantKeyBinding = Readonly<{
    participantIdentity: ParticipantIdentity;
    rosterEntry: RosterEntryInput;
}>;

export type ParticipantKeyCapabilityState =
    | Readonly<{
          state: 'available';
          publicKey: Uint8Array;
      }>
    | Readonly<{
          state: 'lost' | 'replaced' | 'revoked' | 'unavailable';
      }>;

export type SigningCapabilityPairwiseSelfTestInput = Readonly<{
    actionContextHash: ProtocolHash;
    participantIdentity: ParticipantIdentity;
    expectedVerificationKey: Uint8Array;
    message: Uint8Array;
    context: Uint8Array;
}>;

export type MailboxCapabilityPairwiseSelfTestInput = Readonly<{
    actionContextHash: ProtocolHash;
    participantIdentity: ParticipantIdentity;
    expectedEncapsulationKey: Uint8Array;
}>;

/**
 * A purpose-specific provider capability. Its implementation owns the private
 * key and performs the dedicated sign-and-verify self-test without exporting
 * either the private key or a general signing operation.
 */
export type BrowserLocalSigningProviderCapability = Readonly<{
    capabilityIdentifier: string;
    capabilityPurpose: 'participant-signing';
    readState():
        | ParticipantKeyCapabilityState
        | Promise<ParticipantKeyCapabilityState>;
    performPairwiseSelfTest(
        input: SigningCapabilityPairwiseSelfTestInput,
    ): boolean | Promise<boolean>;
}>;

/**
 * A purpose-specific provider capability. Its implementation encapsulates to
 * the expected public key, decapsulates locally, and compares both shared
 * secrets without returning a secret or exposing encapsulation coins.
 */
export type BrowserLocalMailboxProviderCapability = Readonly<{
    capabilityIdentifier: string;
    capabilityPurpose: 'participant-mailbox';
    readState():
        | ParticipantKeyCapabilityState
        | Promise<ParticipantKeyCapabilityState>;
    performPairwiseSelfTest(
        input: MailboxCapabilityPairwiseSelfTestInput,
    ): boolean | Promise<boolean>;
}>;

export type BrowserLocalParticipantKeyProvider = Readonly<{
    executionLocation: 'browser-local' | 'remote';
    operationInterface:
        | 'sealed-lattice-closed-operations'
        | 'generic-hidden-randomness-only';
    resolveSigningCapability(input: {
        actionContextHash: ProtocolHash;
        participantIdentity: ParticipantIdentity;
    }):
        | BrowserLocalSigningProviderCapability
        | undefined
        | Promise<BrowserLocalSigningProviderCapability | undefined>;
    resolveMailboxCapability(input: {
        actionContextHash: ProtocolHash;
        participantIdentity: ParticipantIdentity;
    }):
        | BrowserLocalMailboxProviderCapability
        | undefined
        | Promise<BrowserLocalMailboxProviderCapability | undefined>;
}>;

/**
 * An opaque participant-private token. It carries no signing operation and is
 * not authority by itself; a closed operation must re-enter the owning
 * provider session so loss, revocation, or replacement is checked at use time.
 */
export type ParticipantSigningHandle = Readonly<{
    capabilityKind: 'participant-signing';
    [participantSigningHandleBrand]: true;
}>;

/**
 * An opaque participant-private token. It carries no decapsulation operation
 * and is not authority by itself; a closed operation must re-enter the owning
 * provider session so loss, revocation, or replacement is checked at use time.
 */
export type ParticipantMailboxHandle = Readonly<{
    capabilityKind: 'participant-mailbox';
    [participantMailboxHandleBrand]: true;
}>;

export type BrowserLocalParticipantKeySession = Readonly<{
    actionContextHash: ProtocolHash;
    participantIdentity: ParticipantIdentity;
    requireSigningHandle(): Promise<ParticipantSigningHandle>;
    requireMailboxHandle(): Promise<ParticipantMailboxHandle>;
    assertAvailable(): Promise<void>;
    close(): void;
}>;

type NormalizedSigningCapability = Readonly<{
    capabilityIdentifier: string;
    capabilityPurpose: string;
    readState(): Promise<ParticipantKeyCapabilityState>;
    performPairwiseSelfTest(
        input: SigningCapabilityPairwiseSelfTestInput,
    ): Promise<boolean>;
}>;

type NormalizedMailboxCapability = Readonly<{
    capabilityIdentifier: string;
    capabilityPurpose: string;
    readState(): Promise<ParticipantKeyCapabilityState>;
    performPairwiseSelfTest(
        input: MailboxCapabilityPairwiseSelfTestInput,
    ): Promise<boolean>;
}>;

const providerError = (
    code: BrowserLocalParticipantKeyProviderErrorCode,
    message: string,
): BrowserLocalParticipantKeyProviderError =>
    new BrowserLocalParticipantKeyProviderError(code, message);

const assertProtocolHash = (value: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw providerError(
            'InvalidActionBinding',
            'actionContextHash must be a canonical protocol hash.',
        );
    }
};

const copyPublicKey = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== expectedByteLength
    ) {
        throw providerError(
            'InvalidRosterBinding',
            `${label} has the wrong byte length for the supported profile.`,
        );
    }

    return value.slice();
};

const publicKeysEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }

    return difference === 0;
};

const assertCapabilityIdentifier = (value: unknown): string => {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length > maximumCapabilityIdentifierCharacterLength
    ) {
        throw providerError(
            'ProviderFailure',
            'The key provider returned an invalid private-handle identifier.',
        );
    }

    return value;
};

const normalizeSigningCapability = (
    capability: BrowserLocalSigningProviderCapability,
): NormalizedSigningCapability => {
    if (
        typeof capability !== 'object' ||
        capability === null ||
        typeof capability.readState !== 'function' ||
        typeof capability.performPairwiseSelfTest !== 'function'
    ) {
        throw providerError(
            'ProviderFailure',
            'The key provider returned a malformed signing capability.',
        );
    }
    const readState = capability.readState.bind(capability);
    const performPairwiseSelfTest =
        capability.performPairwiseSelfTest.bind(capability);

    return Object.freeze({
        capabilityIdentifier: assertCapabilityIdentifier(
            capability.capabilityIdentifier,
        ),
        capabilityPurpose: capability.capabilityPurpose,
        readState: async () => readState(),
        performPairwiseSelfTest: async (input) =>
            performPairwiseSelfTest(input),
    });
};

const normalizeMailboxCapability = (
    capability: BrowserLocalMailboxProviderCapability,
): NormalizedMailboxCapability => {
    if (
        typeof capability !== 'object' ||
        capability === null ||
        typeof capability.readState !== 'function' ||
        typeof capability.performPairwiseSelfTest !== 'function'
    ) {
        throw providerError(
            'ProviderFailure',
            'The key provider returned a malformed mailbox capability.',
        );
    }
    const readState = capability.readState.bind(capability);
    const performPairwiseSelfTest =
        capability.performPairwiseSelfTest.bind(capability);

    return Object.freeze({
        capabilityIdentifier: assertCapabilityIdentifier(
            capability.capabilityIdentifier,
        ),
        capabilityPurpose: capability.capabilityPurpose,
        readState: async () => readState(),
        performPairwiseSelfTest: async (input) =>
            performPairwiseSelfTest(input),
    });
};

const readCapabilityState = async (
    capability: NormalizedSigningCapability | NormalizedMailboxCapability,
): Promise<ParticipantKeyCapabilityState> => {
    let state: ParticipantKeyCapabilityState;
    try {
        state = await capability.readState();
    } catch {
        throw providerError(
            'ProviderFailure',
            'The key provider could not inspect a private capability.',
        );
    }
    if (typeof state !== 'object' || state === null) {
        throw providerError(
            'ProviderFailure',
            'The key provider returned a malformed capability state.',
        );
    }

    return state;
};

const assertCapabilityAvailable = async (input: {
    capability: NormalizedSigningCapability | NormalizedMailboxCapability;
    expectedPublicKey: Uint8Array;
    established: boolean;
}): Promise<void> => {
    const state = await readCapabilityState(input.capability);
    switch (state.state) {
        case 'lost':
            throw providerError(
                'CapabilityLost',
                'A required participant private capability is lost.',
            );
        case 'revoked':
            throw providerError(
                'CapabilityRevoked',
                'A required participant private capability is revoked.',
            );
        case 'replaced':
            throw providerError(
                'CapabilityReplaced',
                'A required participant private capability was replaced.',
            );
        case 'unavailable':
            throw providerError(
                'CapabilityUnavailable',
                'A required participant private capability is unavailable.',
            );
        case 'available':
            if (
                !(state.publicKey instanceof Uint8Array) ||
                !publicKeysEqual(state.publicKey, input.expectedPublicKey)
            ) {
                throw providerError(
                    input.established
                        ? 'CapabilityReplaced'
                        : 'PrivateHandlePublicKeyMismatch',
                    input.established
                        ? 'A participant private capability no longer matches the frozen roster key.'
                        : 'A participant private capability does not match the frozen roster key.',
                );
            }
            return;
        default:
            throw providerError(
                'ProviderFailure',
                'The key provider returned an unknown capability state.',
            );
    }
};

const performSigningSelfTest = async (input: {
    actionContextHash: ProtocolHash;
    capability: NormalizedSigningCapability;
    expectedVerificationKey: Uint8Array;
    participantIdentity: ParticipantIdentity;
}): Promise<void> => {
    let passed: boolean;
    try {
        passed = await input.capability.performPairwiseSelfTest({
            actionContextHash: input.actionContextHash,
            participantIdentity: input.participantIdentity,
            expectedVerificationKey: input.expectedVerificationKey.slice(),
            message: signingSelfTestMessage.slice(),
            context: signingSelfTestContext.slice(),
        });
    } catch {
        throw providerError(
            'ProviderFailure',
            'The browser-local key provider failed while running the signing pairwise self-test.',
        );
    }
    if (passed !== true) {
        throw providerError(
            'SigningSelfTestFailed',
            'The participant signing capability failed its local pairwise self-test.',
        );
    }
};

const performMailboxSelfTest = async (input: {
    actionContextHash: ProtocolHash;
    capability: NormalizedMailboxCapability;
    expectedEncapsulationKey: Uint8Array;
    participantIdentity: ParticipantIdentity;
}): Promise<void> => {
    let passed: boolean;
    try {
        passed = await input.capability.performPairwiseSelfTest({
            actionContextHash: input.actionContextHash,
            participantIdentity: input.participantIdentity,
            expectedEncapsulationKey: input.expectedEncapsulationKey.slice(),
        });
    } catch {
        throw providerError(
            'ProviderFailure',
            'The browser-local key provider failed while running the mailbox pairwise self-test.',
        );
    }
    if (passed !== true) {
        throw providerError(
            'MailboxSelfTestFailed',
            'The participant mailbox capability failed its local pairwise self-test.',
        );
    }
};

const createSigningHandle = (): ParticipantSigningHandle =>
    Object.freeze({
        capabilityKind: 'participant-signing' as const,
        [participantSigningHandleBrand]: true as const,
    });

const createMailboxHandle = (): ParticipantMailboxHandle =>
    Object.freeze({
        capabilityKind: 'participant-mailbox' as const,
        [participantMailboxHandleBrand]: true as const,
    });

export const openBrowserLocalParticipantKeySession = async (input: {
    actionContextHash: ProtocolHash;
    participantKeyBinding: ExternallyAcceptedParticipantKeyBinding;
    provider: BrowserLocalParticipantKeyProvider;
}): Promise<BrowserLocalParticipantKeySession> => {
    assertProtocolHash(input.actionContextHash);
    if (
        !isParticipantIdentity(input.participantKeyBinding.participantIdentity)
    ) {
        throw providerError(
            'InvalidRosterBinding',
            'participantIdentity must be a canonical roster identity.',
        );
    }
    const rosterEntry = input.participantKeyBinding.rosterEntry;
    if (
        typeof rosterEntry !== 'object' ||
        rosterEntry === null ||
        !Number.isSafeInteger(rosterEntry.rosterPosition) ||
        rosterEntry.rosterPosition < 0 ||
        rosterEntry.role !== 1
    ) {
        throw providerError(
            'InvalidRosterBinding',
            'The participant roster entry is outside the supported profile.',
        );
    }
    const expectedSigningVerificationKey = copyPublicKey(
        rosterEntry.signingVerificationKey,
        mlDsa65VerificationKeyByteLength,
        'signingVerificationKey',
    );
    const expectedMailboxEncapsulationKey = copyPublicKey(
        rosterEntry.mailboxEncapsulationKey,
        mlKem768EncapsulationKeyByteLength,
        'mailboxEncapsulationKey',
    );

    if (input.provider.executionLocation !== 'browser-local') {
        throw providerError(
            'RemoteProviderRejected',
            'Participant private capabilities must execute in the browser-local provider.',
        );
    }
    if (
        input.provider.operationInterface !== 'sealed-lattice-closed-operations'
    ) {
        throw providerError(
            'GenericHiddenRandomnessProviderRejected',
            'A generic hidden-randomness-only provider cannot implement the required closed protocol operations.',
        );
    }

    const resolutionInput = Object.freeze({
        actionContextHash: input.actionContextHash,
        participantIdentity: input.participantKeyBinding.participantIdentity,
    });
    let resolvedSigningCapability:
        | BrowserLocalSigningProviderCapability
        | undefined;
    let resolvedMailboxCapability:
        | BrowserLocalMailboxProviderCapability
        | undefined;
    try {
        resolvedSigningCapability =
            await input.provider.resolveSigningCapability(resolutionInput);
        resolvedMailboxCapability =
            await input.provider.resolveMailboxCapability(resolutionInput);
    } catch {
        throw providerError(
            'ProviderFailure',
            'The browser-local key provider failed while resolving participant capabilities.',
        );
    }
    if (resolvedSigningCapability === undefined) {
        throw providerError(
            'CapabilityUnavailable',
            'The participant signing capability is unavailable.',
        );
    }
    if (resolvedMailboxCapability === undefined) {
        throw providerError(
            'CapabilityUnavailable',
            'The participant mailbox capability is unavailable.',
        );
    }

    const signingCapability = normalizeSigningCapability(
        resolvedSigningCapability,
    );
    const mailboxCapability = normalizeMailboxCapability(
        resolvedMailboxCapability,
    );
    if (signingCapability.capabilityPurpose !== 'participant-signing') {
        throw providerError(
            'CapabilityPurposeMismatch',
            'The resolved signing capability has the wrong purpose.',
        );
    }
    if (mailboxCapability.capabilityPurpose !== 'participant-mailbox') {
        throw providerError(
            'CapabilityPurposeMismatch',
            'The resolved mailbox capability has the wrong purpose.',
        );
    }
    if (
        signingCapability.capabilityIdentifier ===
        mailboxCapability.capabilityIdentifier
    ) {
        throw providerError(
            'CapabilityPurposeReuse',
            'Signing and mailbox operations must resolve distinct private capabilities.',
        );
    }

    await assertCapabilityAvailable({
        capability: signingCapability,
        expectedPublicKey: expectedSigningVerificationKey,
        established: false,
    });
    await assertCapabilityAvailable({
        capability: mailboxCapability,
        expectedPublicKey: expectedMailboxEncapsulationKey,
        established: false,
    });
    await performSigningSelfTest({
        actionContextHash: input.actionContextHash,
        capability: signingCapability,
        expectedVerificationKey: expectedSigningVerificationKey,
        participantIdentity: input.participantKeyBinding.participantIdentity,
    });
    await performMailboxSelfTest({
        actionContextHash: input.actionContextHash,
        capability: mailboxCapability,
        expectedEncapsulationKey: expectedMailboxEncapsulationKey,
        participantIdentity: input.participantKeyBinding.participantIdentity,
    });
    await assertCapabilityAvailable({
        capability: signingCapability,
        expectedPublicKey: expectedSigningVerificationKey,
        established: true,
    });
    await assertCapabilityAvailable({
        capability: mailboxCapability,
        expectedPublicKey: expectedMailboxEncapsulationKey,
        established: true,
    });

    const signingHandle = createSigningHandle();
    const mailboxHandle = createMailboxHandle();
    let sessionClosed = false;
    let activeSigningCapability: NormalizedSigningCapability | undefined =
        signingCapability;
    let activeMailboxCapability: NormalizedMailboxCapability | undefined =
        mailboxCapability;

    const requireOpenSession = (): void => {
        if (
            sessionClosed ||
            activeSigningCapability === undefined ||
            activeMailboxCapability === undefined
        ) {
            throw providerError(
                'SessionClosed',
                'The participant key-provider session is closed.',
            );
        }
    };
    const requireSigningHandle =
        async (): Promise<ParticipantSigningHandle> => {
            requireOpenSession();
            await assertCapabilityAvailable({
                capability: activeSigningCapability!,
                expectedPublicKey: expectedSigningVerificationKey,
                established: true,
            });

            return signingHandle;
        };
    const requireMailboxHandle =
        async (): Promise<ParticipantMailboxHandle> => {
            requireOpenSession();
            await assertCapabilityAvailable({
                capability: activeMailboxCapability!,
                expectedPublicKey: expectedMailboxEncapsulationKey,
                established: true,
            });

            return mailboxHandle;
        };
    const assertAvailable = async (): Promise<void> => {
        requireOpenSession();
        await assertCapabilityAvailable({
            capability: activeSigningCapability!,
            expectedPublicKey: expectedSigningVerificationKey,
            established: true,
        });
        await assertCapabilityAvailable({
            capability: activeMailboxCapability!,
            expectedPublicKey: expectedMailboxEncapsulationKey,
            established: true,
        });
    };

    return Object.freeze({
        actionContextHash: input.actionContextHash,
        participantIdentity: input.participantKeyBinding.participantIdentity,
        requireSigningHandle,
        requireMailboxHandle,
        assertAvailable,
        close: () => {
            sessionClosed = true;
            activeSigningCapability = undefined;
            activeMailboxCapability = undefined;
        },
    });
};
