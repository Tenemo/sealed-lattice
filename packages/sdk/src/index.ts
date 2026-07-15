import {
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    validatePollSpec as validatePollSpecInternal,
} from '@sealed-lattice/protocol';
import type { CollectiveBgvSetupRosterEntryInput as ProtocolCollectiveBgvSetupRosterEntryInput } from '@sealed-lattice/protocol';
import {
    isProtocolHash,
    type PollSpecInput,
    type PollSpecValidation,
    type ProtocolHash,
    type VerificationResult,
} from '@sealed-lattice/types';

import { loadFreshTranscriptCoreKernel } from './kernel.js';
import {
    prepareSnapshottedPrivateVssShareVerificationInputForKernel,
    prepareSnapshottedSetupPackageVerificationInputForKernel,
    snapshotPrivateVssShareVerificationInput,
    snapshotSetupPackageVerificationInput,
} from './setup-verification-input.js';

function assertProtocolHash(
    value: unknown,
    fieldName: string,
): asserts value is ProtocolHash {
    if (!isProtocolHash(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
}

const assertSetupPackageVerificationBindings = (
    input: VerifySetupPackageInput,
): void => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');
};

export type {
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    ProtocolHash,
    RefusalReason,
    SmallRosterPolicy,
    VerificationResult,
} from '@sealed-lattice/types';
export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly participantCount: number;
}>;

export type SetupMaterialStream = Readonly<{
    readonly descriptorBytes: Uint8Array;
    readonly pullChunk: (input: {
        readonly abortSignal?: AbortSignal;
        readonly chunkIndex: number;
        readonly expectedByteLength: number;
    }) => Promise<ArrayBuffer | undefined>;
}>;

export type SetupProofMaterialStreamSet = Readonly<{
    readonly proofMaterialStreams: readonly SetupMaterialStream[];
}>;

export type VerifyPrivateVssShareInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly privateEnvelope: unknown;
    readonly transportedPrivateVssShareProofMaterial?: SetupProofMaterialStreamSet;
    readonly expectedPrivateEnvelopeHash?: ProtocolHash;
}>;

export type PrivateVssShareVerification = VerificationResult<{
    readonly privateEnvelopeHash: ProtocolHash;
}>;

export type CollectiveBgvSetupRosterEntryInput =
    ProtocolCollectiveBgvSetupRosterEntryInput;

export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly publicKeyShareMaterialStream: SetupMaterialStream;
    readonly transportedPublicKeyShareProofMaterial: SetupProofMaterialStreamSet;
    readonly transportedVssShareLinkageProofMaterial: SetupProofMaterialStreamSet;
    readonly transportedSameSecretBridgeProofMaterial: SetupProofMaterialStreamSet;
    readonly transportedEvaluationKeyShareProofMaterial: SetupProofMaterialStreamSet;
    readonly evaluationKeyShareComponentMaterialStreams: readonly SetupMaterialStream[];
}>;

export type SetupPackageVerification = VerificationResult<void>;

export const deriveCollectiveBgvSetupRosterHash =
    deriveCollectiveBgvSetupRosterHashInternal;

export const derivePollSpecHash = derivePollSpecHashInternal;

export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecInternal(input);
}

export const verifyPrivateVssShare = async (
    input: VerifyPrivateVssShareInput,
): Promise<PrivateVssShareVerification> => {
    const verificationInputSnapshot =
        snapshotPrivateVssShareVerificationInput(input);
    const kernel = await loadFreshTranscriptCoreKernel();

    const verification = kernel.verifyPrivateVssShareEnvelope(
        await prepareSnapshottedPrivateVssShareVerificationInputForKernel(
            kernel,
            verificationInputSnapshot,
        ),
    );
    return verification;
};

export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    const verificationInputSnapshot =
        snapshotSetupPackageVerificationInput(input);
    assertSetupPackageVerificationBindings(verificationInputSnapshot);

    const kernel = await loadFreshTranscriptCoreKernel();
    const acceptedSetupSession = kernel.beginAcceptedSetupSession();
    try {
        const verificationInput =
            await prepareSnapshottedSetupPackageVerificationInputForKernel(
                kernel,
                verificationInputSnapshot,
                acceptedSetupSession,
            );

        const verification =
            acceptedSetupSession.verifyCollectiveBgvSetup(verificationInput);
        if (!verification.isValid) {
            return verification;
        }

        return {
            isValid: true,
            value: undefined,
        };
    } catch (error) {
        acceptedSetupSession.cancel();
        throw error;
    }
};
