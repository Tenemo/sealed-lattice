import type { ProtocolDigest } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from './canonical-json.js';

const textEncoder = new TextEncoder();

export const protocolDigestNamespaceValues = [
    'BoardEntryDigest',
    'BoardRootDigest',
    'BoardPolicyDigest',
    'PollSpecDigest',
    'PublicKeyDigest',
    'RegistrationEntryDigest',
    'ReceiverKeyRegistrationDigest',
    'TrusteeSetupEntryDigest',
    'ElectionManifestDigest',
    'RosterDigest',
    'RosterExternalAcceptanceDigest',
    'BoardHeadDigest',
    'RecoveryEpochUpdateDigest',
    'ActionContextDigest',
    'BallotPackageDigest',
    'BallotSetDigest',
    'CastReceiptDigest',
    'CloseRecordDigest',
    'WitnessCheckpointDigest',
    'ConflictingHeadEvidenceDigest',
    'WitnessEquivocationEvidenceDigest',
    'InclusionProofDigest',
    'FirstValidOrderDigest',
    'DuplicateBallotPolicyDigest',
    'FirstValidPolicyDigest',
    'TargetFinalityPolicyDigest',
    'WitnessPolicyDigest',
    'RecoveryPolicyDigest',
    'SignedRootDigest',
    'ProtocolSignatureEnvelopeDigest',
    'ProviderBuildDigest',
    'ThresholdProfileDigest',
    'HEParamDigest',
    'BGVProfileDigest',
    'CiphertextRoot',
    'PlaintextRoot',
    'BGVPublicKeyRoot',
    'CollectivePublicKeyRoot',
    'EvalKeyRoot',
    'TopKCircuitDigest',
    'RotSetDigest',
    'TargetLayoutDigest',
    'PublicSlotMaskDigest',
    'AggregateDerivationComponentDigest',
    'AggregateContributionDigest',
    'AggregateReadyRecordDigest',
    'AggregateSelectionPolicyDigest',
    'PostVotingClosedContextDigest',
    'EvaluationContextDigest',
    'TopKEvaluationRecordDigest',
    'TargetProposalDigest',
    'TargetFinalityCheckpointDigest',
    'TargetFinalityRecordDigest',
    'EvaluationProofRecordDigest',
    'EvaluationProofProfileDigest',
    'TargetAcceptedRecordDigest',
    'TargetPreimageDigest',
    'TargetContextDigest',
    'LocalReplayRecordDigest',
    'MobileReplayCertDigest',
    'TopKDecryptionShareDigest',
    'VerifiedTopKResultDigest',
    'CPADProfileDigest',
    'CPADProfileVerificationDigest',
    'ThresholdDecryptionProfileDigest',
    'BGVAsyncThresholdCPADProfileDigest',
    'BridgeProofRecordDigest',
    'BridgeProofProfileDigest',
    'DirectQDataBridgeProfileDigest',
    'ActualAggregateCiphertextRoot',
    'CanonicalCiphertextConventionDigest',
    'BGVBatchEncoderDigest',
    'AppendixDProfileDigest',
    'HEEvaluationNoiseCertDigest',
    'AllowedEvaluatorOpsDigest',
    'BridgeLayoutDigest',
    'AggregateShareCommitmentDigest',
    'ShareCommitmentDigest',
    'ThresholdShareVerificationKeyRoot',
    'ThresholdShareVerificationKeyDigest',
    'TargetDecryptionPreparationRecordDigest',
    'TargetDecryptionCiphertextDigest',
    'QTargetDigest',
    'MobileProfileCertDigest',
    'BridgeMobileCertDigest',
    'BridgeBatchingCertDigest',
    'AggregateBridgeProverCertDigest',
    'EncryptedEnvelopeRoot',
] as const;

export type ProtocolDigestNamespace =
    (typeof protocolDigestNamespaceValues)[number];

const protocolDigestNamespaceSet = new Set<string>(
    protocolDigestNamespaceValues,
);

const pascalCaseToKebabCase = (value: string): string =>
    value
        .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1-$2')
        .replace(/([a-z0-9])([A-Z])/gu, '$1-$2')
        .toLowerCase();

const reservedProtocolDigestDomainSet = new Set(
    protocolDigestNamespaceValues.map(
        (reservedNamespace) =>
            `sealed-lattice-root/${pascalCaseToKebabCase(reservedNamespace)}-v1`,
    ),
);

export const resolveProtocolDigestDomain = (namespace: string): string => {
    if (protocolDigestNamespaceSet.has(namespace)) {
        return `sealed-lattice-root/${pascalCaseToKebabCase(namespace)}-v1`;
    }

    if (namespace.startsWith('sealed-lattice-root/')) {
        if (reservedProtocolDigestDomainSet.has(namespace)) {
            return namespace;
        }

        throw new TypeError(
            'Protocol digest namespace domain must be reserved in the transcript-core registry.',
        );
    }
    if (!/^[A-Z][A-Za-z0-9]*$/u.test(namespace)) {
        throw new TypeError(
            'Protocol digest namespace must be a reserved PascalCase name.',
        );
    }

    throw new TypeError(
        'Protocol digest namespace must be reserved in the transcript-core registry.',
    );
};

export const deriveProtocolDigest = (
    namespace: string,
    value: unknown,
): ProtocolDigest =>
    hash512Hex(resolveProtocolDigestDomain(namespace), [
        textEncoder.encode(canonicalJson(value)),
    ]);

export const derivePolicyDigest = (
    namespace: ProtocolDigestNamespace,
    policy: unknown,
): ProtocolDigest => deriveProtocolDigest(namespace, policy);
