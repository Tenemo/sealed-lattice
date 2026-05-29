import { deriveProtocolHash } from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type BridgeProofRecord,
    type ProtocolHash,
} from '@sealed-lattice/types';

import {
    deriveBridgeProofProfileHash,
    deriveBridgeProofRecordHash,
    deriveBridgeProofStatementHash,
    deriveBridgeProofTargetContractHash,
} from '../hashes.js';

import {
    aggregateRelationChallengeHexPattern,
    bridgeProofByteLength,
    hash512HexPattern,
    requireMatchingSafeInteger,
    requireMatchingValue,
    requireProtocolHash,
    requireProtocolHashField,
    type BridgeEncryptionEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from './shared.js';

const derivePendingBridgeProofEncodingProfileHash = (input: {
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        ...input,
        purpose:
            'sealed-lattice-pending-bridge-proof-evidence-encoding-profile-v1',
    });

const derivePendingBridgeProofParameterSetHash = (input: {
    readonly bgvProfileHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        ...input,
        purpose: 'sealed-lattice-pending-bridge-proof-parameter-set-v1',
    });

const derivePendingBridgeProofPublicRandomnessHash = (input: {
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('ProofBytesHash', {
        ...input,
        purpose: 'sealed-lattice-pending-bridge-proof-public-randomness-v1',
    });

const deriveSampledPublicRelationCheckPolicyHash = (
    policy: BridgeEncryptionEvidence['sampledPublicRelationCheckPolicy'],
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        policy,
        purpose:
            'sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1',
    });

const bridgeRandomnessSourceValues = [
    'fresh-csprng',
    'development-deterministic-fixture',
] as const;

const requireBridgeRandomnessSource = (
    value: unknown,
    description: string,
): void => {
    if (
        !bridgeRandomnessSourceValues.some(
            (randomnessSource) => randomnessSource === value,
        )
    ) {
        throw new RangeError(
            `Bridge proof record evidence mismatch for ${description}.`,
        );
    }
};

export const createPendingBridgeProofRecordFromBridgeEvidence = (
    input: PendingBridgeProofRecordFromEvidenceInput,
): BridgeProofRecord => {
    const { aggregateDerivationComponent, bridgeEncryptionEvidence } = input;
    const { statement } = aggregateDerivationComponent;
    const { profileBindings } = input.setupPackage;
    const bridgeProofProfileHash = deriveBridgeProofProfileHash({
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofSubrelation:
            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        claimBearingBridgeEncryption: false,
        developmentKeyOnly: false,
        proofBackend: 'SealedLatticeBridgeRelation',
        thresholdDecryptable: false,
    });
    const profileHash = requireProtocolHashField(
        profileBindings,
        'profileHash',
        'setupPackage.profileBindings',
    );
    const rustBgvBackendProfileHash = requireProtocolHashField(
        profileBindings,
        'backendProfileHash',
        'setupPackage.profileBindings',
    );
    const canonicalCiphertextConventionHash = requireProtocolHashField(
        profileBindings,
        'canonicalCiphertextConventionHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateInputLayoutHash = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateInputLayoutHash',
        'setupPackage.profileBindings',
    );
    const aggregateInputEncodingProfileHash = requireProtocolHashField(
        profileBindings,
        'aggregateInputEncodingProfileHash',
        'setupPackage.profileBindings',
    );
    const ballotScoreEncodingProfileHash = requireProtocolHashField(
        profileBindings,
        'ballotScoreEncodingProfileHash',
        'setupPackage.profileBindings',
    );
    const ballotShareLayoutProfileHash = requireProtocolHashField(
        profileBindings,
        'ballotShareLayoutProfileHash',
        'setupPackage.profileBindings',
    );
    const bgvBatchEncoderHash = requireProtocolHashField(
        profileBindings,
        'batchEncoderHash',
        'setupPackage.profileBindings',
    );
    const encodedAggregateLayoutHash = requireProtocolHashField(
        profileBindings,
        'encodedAggregateLayoutHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateBridgeHash = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateBridgeHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateReconstructionHash = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateReconstructionHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateTargetBasisRoot = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateTargetBasisRoot',
        'setupPackage.profileBindings',
    );
    const topKEvaluatorInputLayoutHash = requireProtocolHashField(
        profileBindings,
        'topKEvaluatorInputLayoutHash',
        'setupPackage.profileBindings',
    );
    const sampledPublicRelationCheckPolicy =
        bridgeEncryptionEvidence.sampledPublicRelationCheckPolicy;
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.objectType,
        'AggregateBridgeSampledRelationCheckPolicy',
        'sampled public relation check policy object type',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.objectVersion,
        1,
        'sampled public relation check policy version',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.diagnosticOnly,
        true,
        'sampled public relation check diagnostic-only policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.acceptedForBridgeProofVerification,
        false,
        'sampled public relation check acceptance policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.fullBridgeProofRequired,
        true,
        'sampled public relation full-proof policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.sampledOnlyBridgeVerificationAccepted,
        false,
        'sampled-only bridge verification policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.relationCheckSource,
        'first-data-prime-diagnostic',
        'sampled public relation check source',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.sampledRelationCheckCount,
        bridgeEncryptionEvidence.sampledPublicRelationChecks.length,
        'sampled public relation check count',
    );
    const sampledPublicRelationCheckPolicyHash =
        deriveSampledPublicRelationCheckPolicyHash(
            sampledPublicRelationCheckPolicy,
        );
    const bridgeProofTargetContractHash = deriveBridgeProofTargetContractHash({
        aggregateQuotientCoordinateCount: statement.shareVectorWidth,
        aggregateReducedCoordinateCount: statement.shareVectorWidth,
    });
    const bridgeSharedWitnessProofHash = requireProtocolHash(
        bridgeEncryptionEvidence.bridgeSharedWitnessProofHash,
        'shared-witness proof hash',
    );
    const verifiedBridgeSharedWitnessProofHash = requireProtocolHash(
        input.bridgeEvidenceVerification.bridgeSharedWitnessProofHash,
        'verified shared-witness proof hash',
    );
    const sharedWitnessZeroKnowledgeStatusHash = requireProtocolHash(
        bridgeEncryptionEvidence.sharedWitnessZeroKnowledgeStatusHash,
        'shared-witness zero-knowledge status hash',
    );
    const verifiedSharedWitnessZeroKnowledgeStatusHash = requireProtocolHash(
        input.bridgeEvidenceVerification.sharedWitnessZeroKnowledgeStatusHash,
        'verified shared-witness zero-knowledge status hash',
    );
    const bgvRandomnessBoundProofStatusHash = requireProtocolHash(
        bridgeEncryptionEvidence.bgvRandomnessBoundProofStatusHash,
        'BGV randomness-bound status hash',
    );
    const verifiedBgvRandomnessBoundProofStatusHash = requireProtocolHash(
        input.bridgeEvidenceVerification.bgvRandomnessBoundProofStatusHash,
        'verified BGV randomness-bound status hash',
    );
    const encryptedAggregateInputRoot = requireProtocolHash(
        bridgeEncryptionEvidence.encryptedAggregateInputRoot,
        'encrypted aggregate input root',
    );
    requireMatchingValue(
        encryptedAggregateInputRoot,
        bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        'prototype encrypted aggregate input root',
    );
    const expectedBridgeProofStatementHash = deriveBridgeProofStatementHash({
        aggregateDerivationComponentHash:
            aggregateDerivationComponent.aggregateDerivationComponentHash,
        aggregateInputEncodingProfileHash,
        aggregateQuotientCoordinateCount: statement.shareVectorWidth,
        aggregateReducedCoordinateCount: statement.shareVectorWidth,
        aggregateSelectionPolicyHash: requireProtocolHash(
            input.aggregateSelectionPolicyHash,
            'aggregate selection policy hash',
        ),
        aggregateShareCommitmentHash:
            aggregateDerivationComponent.aggregateCommitment
                .aggregateShareCommitmentHash,
        aggregateToPlaintextBindingStatus:
            'AggregateToPlaintextModularBindingChecked',
        ballotScoreEncodingProfileHash,
        ballotSetHash: statement.ballotSetHash,
        ballotShareLayoutProfileHash,
        basisId: bridgeEncryptionEvidence.basisId,
        bgvBatchEncoderHash,
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
        bgvProfileHash: profileHash,
        bgvPublicKeyRoot:
            input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
        bgvRandomnessBoundProofStatus:
            'BgvRandomnessErrorSupportPolynomialChecked',
        bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
        bridgeLayoutHash: encryptedAggregateInputLayoutHash,
        bridgeProofTargetContractHash,
        bridgeWitnessPrivacyProfileHash: requireProtocolHash(
            input.bridgeWitnessPrivacyProfileHash,
            'bridge witness privacy profile hash',
        ),
        canonicalByteLength: bridgeEncryptionEvidence.canonicalByteLength,
        canonicalBytesHash512: bridgeEncryptionEvidence.canonicalBytesHash512,
        canonicalCiphertextConventionHash,
        ceremonyId: statement.ceremonyId,
        ciphertextRoot: bridgeEncryptionEvidence.ciphertextRoot,
        claimBearingBridgeEncryption: false,
        coefficientDomainCanonical: true,
        coefficientCount: bridgeEncryptionEvidence.coefficientCount,
        collectivePublicKeyRoot:
            input.setupPackage.collectivePublicKey.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            input.setupPackage.collectivePublicKey
                .collectivePublicKeyCoefficientRoot,
        contributorActionContextHash: statement.contributorActionContextHash,
        contributorIdentity: statement.contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            statement.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: statement.contributorRosterPosition,
        developmentKeyOnly: false,
        optionCount: statement.optionCount,
        participantCount: statement.participantCount,
        encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: statement.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash,
        encryptedAggregateInputRoot,
        encryptedAggregateReconstructionHash,
        encryptedAggregateShareCiphertextRoot:
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisRoot,
        heParamHash: requireProtocolHash(
            input.heParamHash,
            'HE parameter hash',
        ),
        hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
        level: bridgeEncryptionEvidence.level,
        manifestHash: statement.manifestHash,
        aggregateDerivationVerificationScope:
            'AggregateDerivationFullVerificationPreconditionNotBound',
        plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofMissing',
        plaintextRoot: bridgeEncryptionEvidence.plaintextRoot,
        pollSpecHash: statement.pollSpecHash,
        postVotingClosedContextHash: statement.postVotingClosedContextHash,
        proofProfileHash: bridgeProofProfileHash,
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
        rosterHash: statement.rosterHash,
        rustBgvBackendProfileHash,
        sampledPublicRelationCheckPolicyHash,
        sampledOnlyBridgeVerificationAccepted: false,
        setupPackageHash: requireProtocolHash(
            input.setupPackage.setupPackageHash,
            'setup package hash',
        ),
        shareCommitmentMessageBoundCertHash:
            statement.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: statement.shareVectorWidth,
        sharedWitnessBindingRequired: true,
        sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
        sharedWitnessChallengeBitsPerCheck: 64,
        sharedWitnessCheckCount: 2,
        sharedWitnessChallengeEntropyBits: 128,
        sharedWitnessRejectionAttemptLimit: 64,
        sharedWitnessGrindingDiscountBitsPerCheck: 6,
        sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor: 32,
        sharedWitnessEffectiveBindingSoundnessBitsFloor: 20,
        sharedWitnessWeakestRelation: 'BGVBatchEncode65537InverseNegacyclicNtt',
        sharedWitnessWeakestRelationModulus: 65_537,
        sharedWitnessZeroKnowledgeStatus:
            'SharedWitnessZeroKnowledgeResponseDistributionChecked',
        slotCount: bridgeEncryptionEvidence.slotCount,
        thresholdProfileHash: statement.thresholdProfileHash,
        thresholdDecryptable: false,
        topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: statement.votingClosedBoardHeadHash,
    });

    requireMatchingValue(
        input.bridgeEvidenceVerification.ok,
        true,
        'verified bridge evidence status',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofVerificationStatus,
        'BridgeProofRelationChecked',
        'checked bridge proof status',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bgvEncryptionKeyMaterialKind,
        'passive-transcript-derived-collective-public-key',
        'BGV encryption key material kind',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.developmentKeyOnly,
        false,
        'development key-only evidence flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.thresholdDecryptable,
        false,
        'threshold-decryptable evidence flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.claimBearingBridgeEncryption,
        false,
        'claim-bearing bridge encryption evidence flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationVerificationScope,
        'AggregateDerivationFullVerificationPreconditionNotBound',
        'aggregate derivation verification scope',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.plaintextCanonicalLiftProofStatus,
        'PlaintextCanonicalLiftProofMissing',
        'plaintext canonical lift proof status',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeEvidenceVerificationStatus,
        'BridgeProofEvidenceChecked',
        'bridge evidence verification label',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bgvEncryptionKeyMaterialKind,
        'passive-transcript-derived-collective-public-key',
        'verified BGV encryption key material kind',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.developmentKeyOnly,
        false,
        'verified development key-only flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.thresholdDecryptable,
        false,
        'verified threshold-decryptable flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.claimBearingBridgeEncryption,
        false,
        'verified claim-bearing bridge encryption flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.aggregateDerivationVerificationScope,
        'AggregateDerivationFullVerificationPreconditionNotBound',
        'verified aggregate derivation verification scope',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.plaintextCanonicalLiftProofStatus,
        'PlaintextCanonicalLiftProofMissing',
        'verified plaintext canonical lift proof status',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationComponentHash,
        aggregateDerivationComponent.aggregateDerivationComponentHash,
        'aggregate derivation component hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationStatementHash,
        statement.aggregateDerivationStatementHash,
        'aggregate derivation statement hash',
    );
    requireMatchingSafeInteger(
        bridgeEncryptionEvidence.aggregateReducedCoordinateCount,
        statement.shareVectorWidth,
        'aggregate reduced coordinate count',
    );
    requireMatchingSafeInteger(
        bridgeEncryptionEvidence.aggregateQuotientCoordinateCount,
        statement.shareVectorWidth,
        'aggregate quotient coordinate count',
    );
    if (
        !aggregateRelationChallengeHexPattern.test(
            bridgeEncryptionEvidence.aggregateRelationChallengeHex,
        )
    ) {
        throw new RangeError(
            'Aggregate relation challenge summary must be canonical lowercase hex.',
        );
    }
    requireProtocolHash(
        bridgeEncryptionEvidence.aggregateRelationCommitmentHash,
        'aggregate relation commitment hash',
    );
    if (
        !hash512HexPattern.test(bridgeEncryptionEvidence.canonicalBytesHash512)
    ) {
        throw new RangeError(
            'Canonical ciphertext bytes hash must be lowercase 512-bit hex.',
        );
    }
    if (
        !Number.isSafeInteger(bridgeEncryptionEvidence.canonicalByteLength) ||
        bridgeEncryptionEvidence.canonicalByteLength <= 0
    ) {
        throw new RangeError(
            'Canonical ciphertext byte length must be a positive safe integer.',
        );
    }
    if (
        !Number.isSafeInteger(
            bridgeEncryptionEvidence.aggregateRelationSubproofSizeBytes,
        ) ||
        bridgeEncryptionEvidence.aggregateRelationSubproofSizeBytes <= 0
    ) {
        throw new RangeError(
            'Aggregate relation subproof size must be a positive safe integer.',
        );
    }
    requireMatchingValue(
        aggregateDerivationComponent.aggregateCommitment
            .aggregateShareCommitmentHash,
        statement.aggregateShareCommitmentHash,
        'aggregate share commitment hash',
    );
    requireMatchingValue(
        aggregateDerivationComponent.shareCommitmentMessageBoundCert
            .shareCommitmentMessageBoundCertHash,
        statement.shareCommitmentMessageBoundCertHash,
        'share commitment message-bound certificate hash',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.ceremonyId,
        statement.ceremonyId,
        'ceremony id',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.manifestHash,
        statement.manifestHash,
        'manifest hash',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.rosterHash,
        statement.rosterHash,
        'roster hash',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.thresholdProfileHash,
        statement.thresholdProfileHash,
        'threshold profile hash',
    );
    requireMatchingSafeInteger(
        input.setupPackage.setupInputs.participantCount,
        statement.participantCount,
        'setup participant count',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.collectivePublicKeyRoot,
        input.setupPackage.collectivePublicKey.collectivePublicKeyRoot,
        'collective public key root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
        input.setupPackage.collectivePublicKey
            .collectivePublicKeyCoefficientRoot,
        'collective public key coefficient root',
    );
    requireBridgeRandomnessSource(
        bridgeEncryptionEvidence.proverRandomnessSource,
        'prover randomness source',
    );
    requireBridgeRandomnessSource(
        bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        'encryption randomness source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectType,
        'AggregateBridgeRandomnessSourceEvidence',
        'randomness source evidence object type',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectVersion,
        1,
        'randomness source evidence object version',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .proverRandomnessSource,
        bridgeEncryptionEvidence.proverRandomnessSource,
        'randomness source evidence prover source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .encryptionRandomnessSeedSource,
        bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        'randomness source evidence encryption source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .callerSuppliedDevelopmentRandomness,
        bridgeEncryptionEvidence.proverRandomnessSource ===
            'development-deterministic-fixture' ||
            bridgeEncryptionEvidence.encryptionRandomnessSeedSource ===
                'development-deterministic-fixture',
        'randomness source evidence development flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .claimBearingEntropyEvidence,
        false,
        'randomness source evidence claim-bearing entropy flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
        input.bridgeEvidenceVerification.collectivePublicKeyCoefficientRoot,
        'verified collective public key coefficient root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.proverRandomnessSource,
        input.bridgeEvidenceVerification.proverRandomnessSource,
        'verified prover randomness source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        input.bridgeEvidenceVerification.encryptionRandomnessSeedSource,
        'verified encryption randomness source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectType,
        input.bridgeEvidenceVerification.randomnessSourceEvidence.objectType,
        'verified randomness source evidence object type',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectVersion,
        input.bridgeEvidenceVerification.randomnessSourceEvidence.objectVersion,
        'verified randomness source evidence object version',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .proverRandomnessSource,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .proverRandomnessSource,
        'verified randomness source evidence prover source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .encryptionRandomnessSeedSource,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .encryptionRandomnessSeedSource,
        'verified randomness source evidence encryption source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .callerSuppliedDevelopmentRandomness,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .callerSuppliedDevelopmentRandomness,
        'verified randomness source evidence development flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .claimBearingEntropyEvidence,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .claimBearingEntropyEvidence,
        'verified randomness source evidence claim-bearing entropy flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bgvPublicKeyRoot,
        input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
        'BGV public key root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.profileHash,
        profileHash,
        'BGV profile hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.rustBgvBackendProfileHash,
        rustBgvBackendProfileHash,
        'Rust BGV backend profile hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.canonicalCiphertextConventionHash,
        canonicalCiphertextConventionHash,
        'canonical ciphertext convention hash',
    );
    for (const [description, bridgeValue, verificationValue] of [
        [
            'bridge proof profile hash',
            bridgeEncryptionEvidence.bridgeProofProfileHash,
            input.bridgeEvidenceVerification.bridgeProofProfileHash,
        ],
        [
            'bridge proof statement hash',
            bridgeEncryptionEvidence.bridgeProofStatementHash,
            input.bridgeEvidenceVerification.bridgeProofStatementHash,
        ],
        [
            'bridge proof target contract hash',
            bridgeEncryptionEvidence.bridgeProofTargetContractHash,
            input.bridgeEvidenceVerification.bridgeProofTargetContractHash,
        ],
        [
            'bridge proof bytes hash',
            bridgeEncryptionEvidence.bridgeProofBytesHash,
            input.bridgeEvidenceVerification.bridgeProofBytesHash,
        ],
        [
            'bridge proof root',
            bridgeEncryptionEvidence.bridgeProofRoot,
            input.bridgeEvidenceVerification.bridgeProofRoot,
        ],
        [
            'shared-witness proof hash',
            bridgeSharedWitnessProofHash,
            verifiedBridgeSharedWitnessProofHash,
        ],
        [
            'shared-witness zero-knowledge status hash',
            sharedWitnessZeroKnowledgeStatusHash,
            verifiedSharedWitnessZeroKnowledgeStatusHash,
        ],
        [
            'BGV randomness-bound status hash',
            bgvRandomnessBoundProofStatusHash,
            verifiedBgvRandomnessBoundProofStatusHash,
        ],
        [
            'encrypted aggregate-share ciphertext root',
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
            input.bridgeEvidenceVerification
                .encryptedAggregateShareCiphertextRoot,
        ],
        [
            'encrypted aggregate input root',
            bridgeEncryptionEvidence.encryptedAggregateInputRoot,
            input.bridgeEvidenceVerification.encryptedAggregateInputRoot,
        ],
        [
            'aggregate relation challenge summary',
            bridgeEncryptionEvidence.aggregateRelationChallengeHex,
            input.bridgeEvidenceVerification.aggregateRelationChallengeHex,
        ],
        [
            'aggregate relation commitment hash',
            bridgeEncryptionEvidence.aggregateRelationCommitmentHash,
            input.bridgeEvidenceVerification.aggregateRelationCommitmentHash,
        ],
    ] as const) {
        requireMatchingValue(bridgeValue, verificationValue, description);
    }
    for (const [description, bridgeValue, verificationValue] of [
        [
            'aggregate relation subproof size',
            bridgeEncryptionEvidence.aggregateRelationSubproofSizeBytes,
            input.bridgeEvidenceVerification.aggregateRelationSubproofSizeBytes,
        ],
        [
            'aggregate reduced coordinate count',
            bridgeEncryptionEvidence.aggregateReducedCoordinateCount,
            input.bridgeEvidenceVerification.aggregateReducedCoordinateCount,
        ],
        [
            'aggregate quotient coordinate count',
            bridgeEncryptionEvidence.aggregateQuotientCoordinateCount,
            input.bridgeEvidenceVerification.aggregateQuotientCoordinateCount,
        ],
    ] as const) {
        requireMatchingSafeInteger(bridgeValue, verificationValue, description);
    }
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofProfileHash,
        bridgeProofProfileHash,
        'canonical bridge proof profile hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofStatementHash,
        expectedBridgeProofStatementHash,
        'canonical bridge proof statement hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofTargetContractHash,
        bridgeProofTargetContractHash,
        'canonical bridge proof target contract hash',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeProofVerificationStatus,
        'BridgeProofRelationChecked',
        'verification bridge proof status',
    );

    const proofEncodingProfileHash = requireProtocolHash(
        input.proofEncodingProfileHash ??
            derivePendingBridgeProofEncodingProfileHash({
                bridgeProofBytesHash:
                    bridgeEncryptionEvidence.bridgeProofBytesHash,
                bridgeProofProfileHash,
                bridgeProofStatementHash: expectedBridgeProofStatementHash,
            }),
        'proof encoding profile hash',
    );
    const proofParameterSetHash = requireProtocolHash(
        input.proofParameterSetHash ??
            derivePendingBridgeProofParameterSetHash({
                bgvProfileHash: profileHash,
                bridgeProofProfileHash,
                bridgeProofStatementHash: expectedBridgeProofStatementHash,
                collectivePublicKeyRoot:
                    bridgeEncryptionEvidence.collectivePublicKeyRoot,
                collectivePublicKeyCoefficientRoot:
                    bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
            }),
        'proof parameter set hash',
    );
    const publicRandomnessHash = requireProtocolHash(
        input.publicRandomnessHash ??
            derivePendingBridgeProofPublicRandomnessHash({
                bridgeProofBytesHash:
                    bridgeEncryptionEvidence.bridgeProofBytesHash,
                bridgeProofStatementHash: expectedBridgeProofStatementHash,
            }),
        'public randomness hash',
    );
    const bridgeProofRecordPayload: Omit<
        BridgeProofRecord,
        'bridgeProofRecordHash'
    > = {
        aggregateDerivationComponentHash:
            aggregateDerivationComponent.aggregateDerivationComponentHash,
        aggregateSelectionPolicyHash: requireProtocolHash(
            input.aggregateSelectionPolicyHash,
            'aggregate selection policy hash',
        ),
        aggregateShareCommitmentHash:
            aggregateDerivationComponent.aggregateCommitment
                .aggregateShareCommitmentHash,
        aggregateInputEncodingProfileHash,
        ballotScoreEncodingProfileHash,
        ballotSetHash: statement.ballotSetHash,
        ballotShareLayoutProfileHash,
        bgvBatchEncoderHash,
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofSubrelation:
            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
        bgvProfileHash: profileHash,
        bgvPublicKeyRoot: bridgeEncryptionEvidence.bgvPublicKeyRoot,
        bridgeLayoutHash: encryptedAggregateInputLayoutHash,
        bridgeProofProfileHash,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofTargetContractHash,
        bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
        bridgeWitnessPrivacyProfileHash: requireProtocolHash(
            input.bridgeWitnessPrivacyProfileHash,
            'bridge witness privacy profile hash',
        ),
        claimBearingBridgeEncryption: false,
        canonicalCiphertextConventionHash,
        ceremonyId: statement.ceremonyId,
        collectivePublicKeyRoot:
            bridgeEncryptionEvidence.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
        contributorIdentity: statement.contributorIdentity,
        contributorActionContextHash: statement.contributorActionContextHash,
        contributorRosterExternalAcceptanceHash:
            statement.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: statement.contributorRosterPosition,
        developmentKeyOnly: false,
        encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: statement.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash,
        encryptedAggregateInputRoot,
        encryptedAggregateReconstructionHash,
        encryptedAggregateShareCiphertextRoot:
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisRoot,
        heParamHash: requireProtocolHash(
            input.heParamHash,
            'HE parameter hash',
        ),
        manifestHash: statement.manifestHash,
        objectType: 'BridgeProofRecord',
        objectVersion: 1,
        pollSpecHash: statement.pollSpecHash,
        postVotingClosedContextHash: statement.postVotingClosedContextHash,
        participantCount: statement.participantCount,
        optionCount: statement.optionCount,
        proofBackend: 'SealedLatticeBridgeRelation',
        proofBytesHash: bridgeEncryptionEvidence.bridgeProofBytesHash,
        proofEncodingProfileHash,
        proofParameterSetHash,
        proofRoot: bridgeEncryptionEvidence.bridgeProofRoot,
        proofSizeBytes: bridgeProofByteLength(
            bridgeEncryptionEvidence.bridgeProofBytesHex,
        ),
        proofStatementHash: expectedBridgeProofStatementHash,
        publicRandomnessHash,
        rosterHash: statement.rosterHash,
        rustBgvBackendProfileHash,
        setupPackageHash: requireProtocolHash(
            input.setupPackage.setupPackageHash,
            'setup package hash',
        ),
        shareCommitmentMessageBoundCertHash:
            statement.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: statement.shareVectorWidth,
        thresholdProfileHash: statement.thresholdProfileHash,
        thresholdDecryptable: false,
        topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: statement.votingClosedBoardHeadHash,
    };

    return {
        ...bridgeProofRecordPayload,
        bridgeProofRecordHash: deriveBridgeProofRecordHash(
            bridgeProofRecordPayload,
        ),
    };
};
