import {
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    validatePollSpec as validatePollSpecInternal,
} from '@sealed-lattice/protocol';
import type {
    SetupProofMaterialStream as ProtocolSetupProofMaterialStream,
    SetupProofMaterialStreamSet as ProtocolSetupProofMaterialStreamSet,
    PublicKeyShareMaterialStream as ProtocolPublicKeyShareMaterialStream,
    EvaluationKeyShareComponentMaterialStream as ProtocolEvaluationKeyShareComponentMaterialStream,
    TransportedPublicKeyShareProofMaterialSet as ProtocolTransportedPublicKeyShareProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet as ProtocolTransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet as ProtocolTransportedSameSecretBridgeProofMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet as ProtocolTransportedEvaluationKeyShareProofMaterialSet,
    SetupPackage as ProtocolSetupPackage,
    CollectiveBgvSetupRosterEntryInput as ProtocolCollectiveBgvSetupRosterEntryInput,
} from '@sealed-lattice/protocol';
import type {
    PollSpecInput,
    PollSpecValidation,
    ProtocolHash,
    VerificationResult,
} from '@sealed-lattice/types';

import { loadFreshTranscriptCoreKernel } from './kernel.js';
import {
    prepareSnapshottedPrivateVssShareVerificationInputForKernel,
    prepareSnapshottedSetupPackageVerificationInputForKernel,
    snapshotPrivateVssShareVerificationInput,
    snapshotSetupPackageVerificationInput,
} from './setup-verification-input.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;

function assertProtocolHash(
    value: unknown,
    fieldName: string,
): asserts value is ProtocolHash {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
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
    CanonicalSignedRootObject,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RefusalReason,
    SignedObjectType,
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

export type SetupPackage = ProtocolSetupPackage;
export type CollectiveBgvSetupRosterEntryInput =
    ProtocolCollectiveBgvSetupRosterEntryInput;

export type PublicKeyShareMaterialStream = ProtocolPublicKeyShareMaterialStream;
export type TransportedPublicKeyShareProofMaterialSet =
    ProtocolTransportedPublicKeyShareProofMaterialSet;
export type TransportedVssShareLinkageProofMaterialSet =
    ProtocolTransportedVssShareLinkageProofMaterialSet;
export type TransportedSameSecretBridgeProofMaterialSet =
    ProtocolTransportedSameSecretBridgeProofMaterialSet;
export type TransportedEvaluationKeyShareProofMaterialSet =
    ProtocolTransportedEvaluationKeyShareProofMaterialSet;
export type EvaluationKeyShareComponentMaterialStream =
    ProtocolEvaluationKeyShareComponentMaterialStream;
export type SetupProofMaterialStream = ProtocolSetupProofMaterialStream;
export type SetupProofMaterialStreamSet = ProtocolSetupProofMaterialStreamSet;
export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly publicKeyShareMaterialStream: PublicKeyShareMaterialStream;
    readonly transportedPublicKeyShareProofMaterial: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
    readonly evaluationKeyShareComponentMaterialStreams: readonly EvaluationKeyShareComponentMaterialStream[];
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
