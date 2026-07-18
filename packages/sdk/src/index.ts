import {
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    prepareFoundationManifestIngress,
    validatePollSpec as validatePollSpecInternal,
} from '@sealed-lattice/protocol';
import type { CollectiveBgvSetupRosterEntryInput as ProtocolCollectiveBgvSetupRosterEntryInput } from '@sealed-lattice/protocol';
import {
    type PollSpecInput,
    type PollSpecValidation,
    type ProtocolHash,
} from '@sealed-lattice/types';
import {
    openFoundationCeremonyRuntime,
    type CanonicalFoundationActionDefinition,
    type CanonicalFoundationBoardPolicy,
    type CanonicalFoundationManifest,
    type FoundationActionContextVerification,
    type FoundationActionDefinitionVerification,
    type FoundationBoardPolicyVerification,
    type FoundationCeremonyContextVerification,
    type FoundationManifestVerification,
    type FoundationSuiteRecordVerification,
} from '@sealed-lattice/wasm/published-sdk';

import { loadFreshTranscriptCoreKernel } from './kernel.js';

export type {
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    ProtocolHash,
    RefusalReason,
    VerificationResult,
} from '@sealed-lattice/types';
export type {
    CanonicalFoundationActionDefinition,
    CanonicalFoundationBoardPolicy,
    CanonicalFoundationManifest,
    FoundationActionContextVerification,
    FoundationActionDefinitionVerification,
    FoundationBoardPolicyVerification,
    FoundationCeremonyContextVerification,
    FoundationManifestVerification,
    FoundationSuiteRecordVerification,
};
export type CollectiveBgvSetupRosterEntryInput =
    ProtocolCollectiveBgvSetupRosterEntryInput;

export const deriveCollectiveBgvSetupRosterHash =
    deriveCollectiveBgvSetupRosterHashInternal;

export const validatePollSpec = (input: unknown): PollSpecValidation =>
    validatePollSpecInternal(input);

const loadFoundationCeremonyRuntime = async () =>
    openFoundationCeremonyRuntime(await loadFreshTranscriptCoreKernel());

export const createCanonicalManifest = async (
    input: PollSpecInput,
): Promise<CanonicalFoundationManifest> => {
    const validation = validatePollSpecInternal(input);
    if (!validation.isValid) {
        throw new TypeError(
            validation.errors.map((error) => error.message).join(' '),
        );
    }
    const runtime = await loadFoundationCeremonyRuntime();
    return runtime.encodeManifest(
        prepareFoundationManifestIngress(validation.normalized),
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

export const verifyCanonicalSuiteRecord = async (
    canonicalBytes: Uint8Array,
): Promise<FoundationSuiteRecordVerification> =>
    (await loadFoundationCeremonyRuntime()).verifySuiteRecord(canonicalBytes);

export const verifyCanonicalCeremonyContext = async (input: {
    readonly canonicalManifestBytes: Uint8Array;
    readonly canonicalRosterBytes: Uint8Array;
    readonly canonicalSuiteRecordBytes: Uint8Array;
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
    readonly canonicalSuiteRecordBytes: Uint8Array;
    readonly ceremonyIdentifier: string;
    readonly expectedCeremonyContextHash: ProtocolHash;
    readonly expectedSuiteId: ProtocolHash;
}): Promise<FoundationActionContextVerification> =>
    (await loadFoundationCeremonyRuntime()).verifyActionContext(input);
