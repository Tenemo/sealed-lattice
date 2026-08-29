import {
    type CanonicalFoundationActionDefinition,
    type CanonicalFoundationBoardPolicy,
    type CanonicalFoundationManifest,
    type FoundationActionContextVerification,
    type FoundationActionDefinitionVerification,
    type FoundationBoardPolicyVerification,
    type FoundationCeremonyContextVerification,
    type FoundationManifestVerification,
    type ProtocolHash,
} from '@sealed-lattice/wasm/published-sdk';

import { loadFoundationCeremonyRuntime } from './kernel.js';
import {
    foundationManifestInputFromPollSpec,
    type PollSpec,
    type PollSpecValidation,
    validatePollSpec as validatePollSpecInternal,
} from './poll-spec.js';

export type {
    PollSpec,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
} from './poll-spec.js';
export type {
    ProtocolHash,
    RefusalReason,
    VerificationResult,
} from '@sealed-lattice/wasm/published-sdk';
export type {
    CanonicalFoundationActionDefinition,
    CanonicalFoundationBoardPolicy,
    CanonicalFoundationManifest,
    FoundationActionContextVerification,
    FoundationActionDefinitionVerification,
    FoundationBoardPolicyVerification,
    FoundationCeremonyContextVerification,
    FoundationManifestVerification,
};
export const validatePollSpec = (input: unknown): PollSpecValidation =>
    validatePollSpecInternal(input);

export const createCanonicalManifest = async (
    input: PollSpec,
): Promise<CanonicalFoundationManifest> => {
    const validation = validatePollSpecInternal(input);
    if (!validation.isValid) {
        throw new TypeError(
            validation.errors.map((error) => error.message).join(' '),
        );
    }
    const runtime = await loadFoundationCeremonyRuntime();
    return runtime.encodeManifest(
        foundationManifestInputFromPollSpec(validation.normalized),
    );
};

export const verifyCanonicalManifest = async (
    canonicalBytes: Uint8Array,
): Promise<FoundationManifestVerification> =>
    (await loadFoundationCeremonyRuntime()).verifyManifest(canonicalBytes);

export const createCanonicalActionDefinition = async (input: {
    readonly submissionCutoffUnixMilliseconds: bigint;
    readonly topCount: number;
}): Promise<CanonicalFoundationActionDefinition> =>
    (await loadFoundationCeremonyRuntime()).encodeActionDefinition(input);

export const verifyCanonicalActionDefinition = async (
    canonicalBytes: Uint8Array,
): Promise<FoundationActionDefinitionVerification> =>
    (await loadFoundationCeremonyRuntime()).verifyActionDefinition(
        canonicalBytes,
    );

export const createCanonicalBoardPolicy = async (input: {
    readonly boardOriginIdentifier: string;
}): Promise<CanonicalFoundationBoardPolicy> =>
    (await loadFoundationCeremonyRuntime()).encodeBoardPolicy(input);

export const verifyCanonicalBoardPolicy = async (
    canonicalBytes: Uint8Array,
): Promise<FoundationBoardPolicyVerification> =>
    (await loadFoundationCeremonyRuntime()).verifyBoardPolicy(canonicalBytes);

export const verifyCanonicalCeremonyContext = async (input: {
    readonly canonicalManifestBytes: Uint8Array;
    readonly canonicalRosterBytes: Uint8Array;
    readonly ceremonyIdentifier: string;
    readonly expectedSuiteId: ProtocolHash;
}): Promise<FoundationCeremonyContextVerification> =>
    (await loadFoundationCeremonyRuntime()).verifyCeremonyContext(input);

export const verifyCanonicalActionContext = async (input: {
    readonly actionIdentifier: string;
    readonly canonicalActionDefinitionBytes: Uint8Array;
    readonly canonicalBoardPolicyBytes: Uint8Array;
    readonly canonicalManifestBytes: Uint8Array;
    readonly canonicalRosterBytes: Uint8Array;
    readonly ceremonyIdentifier: string;
    readonly expectedCeremonyContextHash: ProtocolHash;
    readonly expectedSuiteId: ProtocolHash;
}): Promise<FoundationActionContextVerification> =>
    (await loadFoundationCeremonyRuntime()).verifyActionContext(input);
