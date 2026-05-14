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
    'BoardHeadDigest',
    'RecoveryEpochUpdateDigest',
    'ActionContextDigest',
    'BallotPackageDigest',
    'BallotSetDigest',
    'CastReceiptDigest',
    'CloseRecordDigest',
    'WitnessCheckpointDigest',
    'ConflictingHeadEvidenceDigest',
    'InclusionProofDigest',
    'FirstComeOrderDigest',
    'DuplicateBallotPolicyDigest',
    'FirstComePolicyDigest',
    'TargetFinalityPolicyDigest',
    'WitnessPolicyDigest',
    'RecoveryPolicyDigest',
    'SignedRootDigest',
    'ProtocolSignatureEnvelopeDigest',
    'ProviderBuildDigest',
    'ThresholdProfileDigest',
    'HEParamDigest',
    'CiphertextRoot',
    'PlaintextRoot',
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
    'TargetFinalityRecordDigest',
    'EvaluationReplayAttestationDigest',
    'TargetAcceptedRecordDigest',
    'TargetPreimageDigest',
    'TopKDecryptionShareDigest',
    'VerifiedTopKResultDigest',
    'EvaluationProofRoot',
    'CPADProfileDigest',
    'ThresholdDecryptionProfileDigest',
    'BridgeProofRecordDigest',
    'BridgeProofProfileId',
    'ProofPrimeParamDigest',
    'ProofPrimeCiphertextRoot',
    'ProofPrimePublicKeyRoot',
    'ProofPrimeToQDataKeyConsistencyDigest',
    'DerivedAggregateCiphertextRoot',
    'CanonicalCiphertextConventionDigest',
    'BFVBatchEncoderDigest',
    'BridgeLayoutDigest',
    'AggregateShareCommitmentDigest',
    'ShareCommitmentDigest',
    'BrakerskiProfileDigest',
    'BrakerskiDeltaDigest',
    'BrakerskiShareVerificationKeyRoot',
    'TargetDecryptionPreparationRecordDigest',
    'BrakerskiPreprocessRecordDigest',
    'BrakerskiPreprocessTokenDigest',
    'BrakerskiPreprocessUseRecordDigest',
    'QTargetDigest',
    'MobileProfileCertDigest',
    'BridgeMobileCertDigest',
    'BridgeBatchingCertDigest',
    'AggregateBridgeProverCertDigest',
    'EncryptedEnvelopeRoot',
] as const;

export type ProtocolDigestNamespace =
    (typeof protocolDigestNamespaceValues)[number];

const pascalCaseToKebabCase = (value: string): string =>
    value
        .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1-$2')
        .replace(/([a-z0-9])([A-Z])/gu, '$1-$2')
        .toLowerCase();

export const resolveProtocolDigestDomain = (namespace: string): string => {
    if (namespace.startsWith('sealed-lattice-root/')) {
        return namespace;
    }
    if (!/^[A-Z][A-Za-z0-9]*$/u.test(namespace)) {
        throw new TypeError(
            'Protocol digest namespace must be a reserved PascalCase name or an explicit sealed-lattice-root domain.',
        );
    }

    return `sealed-lattice-root/${pascalCaseToKebabCase(namespace)}-v1`;
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
