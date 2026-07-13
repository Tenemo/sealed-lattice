import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    CanonicalSignedRootObject,
    ManifestOpaqueBindings,
    ManifestPolicyHashes,
    ProtocolSignatureEnvelope,
    SignedObjectType,
    SignerRole,
} from '@sealed-lattice/types';

import {
    createMlDsaKeyPairFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';

export const deriveFixtureHash = (
    purpose: string,
    payload: Record<string, unknown>,
): string =>
    deriveCanonicalObjectHash({
        objectType: 'FixtureChallenge',
        payload,
        purpose,
    });

export const ceremonyId = 'ceremony-main';
// The single canonical BGV parameter-set identity returned by the kernel's
// describeBgvRnsParameters().bgvParametersHash. The manifest binds it opaquely
// and the trustee setup entry cross-binds the same value, so the fixture pins the
// kernel-computed object hash rather than re-deriving the parameter object here.
const bgvParametersHash =
    '48309604b3590d164a517d03139bb2d98eae62faeb043599402db3961bc0770bc5dd632ae09f03b0464597190c38d4e0159af40d1278f0490a7c9da966688825';
export const boardPolicyHash = deriveFixtureHash('fixture-board-policy', {
    policy: 'signed-head-chain',
});
export const contextHash = deriveCanonicalObjectHash({
    objectType: 'ActionContext',
    context: 'default',
});
const keyFixturesByHash = new Map<
    string,
    ReturnType<typeof createMlDsaKeyPairFixture>
>();
export const createKeyFixture = (
    seedLabel: string,
): ReturnType<typeof createMlDsaKeyPairFixture> => {
    const keyFixture = createMlDsaKeyPairFixture(seedLabel);
    keyFixturesByHash.set(keyFixture.publicKeyHash, keyFixture);

    return keyFixture;
};
const boardKeyFixture = createKeyFixture('board');
const organizerKeyFixture = createKeyFixture('organizer');
export const recoveryRootKeyFixture = createKeyFixture(
    'recovery-root:participant-1',
);
const getParticipantKeyFixture = (
    participantIdentity: string,
): ReturnType<typeof createMlDsaKeyPairFixture> =>
    createKeyFixture(`participant:${participantIdentity}`);
export const boardPublicKeyHash = boardKeyFixture.publicKeyHash;
export const organizerPublicKeyHash = organizerKeyFixture.publicKeyHash;
export const getParticipantSigningPublicKeyHash = (
    participantIdentity: string,
): string =>
    participantIdentity === 'organizer'
        ? organizerPublicKeyHash
        : getParticipantKeyFixture(participantIdentity).publicKeyHash;
const witnessIdentities = [
    'witness-1',
    'witness-2',
    'witness-3',
    'witness-4',
    'witness-5',
    'witness-6',
    'witness-7',
] as const;
const witnessPolicyHash = deriveCanonicalObjectHash({
    objectType: 'WitnessPolicy',
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
});
const targetFinalityPolicyHash = deriveCanonicalObjectHash({
    objectType: 'TargetFinalityPolicy',
    witnessQuorum: 5,
    totalWitnesses: 7,
});

export const manifestPolicyHashes: ManifestPolicyHashes = {
    aggregateSelectionPolicyHash: deriveFixtureHash(
        'fixture-aggregate-selection-policy',
        { policy: 'first-valid-aggregate-contributors' },
    ),
    duplicateBallotPolicyHash: deriveFixtureHash(
        'fixture-duplicate-ballot-policy',
        {
            policy: 'first-valid-before-close',
        },
    ),
    firstValidPolicyHash: deriveFixtureHash('fixture-first-valid-policy', {
        policy: 'canonical-signed-board-order-current-epoch',
    }),
    recoveryPolicyHash: deriveFixtureHash('fixture-recovery-policy', {
        policy: 'same-slot-recovery',
    }),
    targetFinalityPolicyHash,
    witnessPolicyHash,
};
export const manifestOpaqueBindings: ManifestOpaqueBindings = {
    bgvParametersHash,
    collectivePublicKeyRoot: deriveCanonicalObjectHash({
        objectType: 'CollectivePublicKeyRoot',
        key: 'bgv-collective',
    }),
    targetLayoutHash: deriveCanonicalObjectHash({
        objectType: 'TargetLayoutHash',
        layout: 'direct-sparse-target-layout',
    }),
    rotSetHash: deriveCanonicalObjectHash({
        objectType: 'RotSetHash',
        rotations: 'direct-encrypted-ballot-evaluator-replay',
    }),
    evaluationKeyRoot: deriveCanonicalObjectHash({
        objectType: 'EvalKeyRoot',
        keys: 'direct-encrypted-ballot-evaluator-replay',
    }),
    thresholdShareVerificationKeyRoot: deriveCanonicalObjectHash({
        objectType: 'ThresholdShareVerificationKeyRoot',
        setup: 'threshold-share-verification-key-set',
    }),
};

export const createSignature = (
    objectType: SignedObjectType,
    signerRole: SignerRole,
    signerIdentity: string,
    publicKeyHash: string,
    objectRoot: string,
    overrides: Partial<CanonicalSignedRootObject> = {},
): ProtocolSignatureEnvelope => {
    const keyFixture = keyFixturesByHash.get(publicKeyHash);
    if (keyFixture === undefined) {
        throw new Error(`Missing ML-DSA test key for ${publicKeyHash}.`);
    }

    return createProtocolSignatureFixture({
        publicKeyHash,
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            objectType,
            ceremonyId,
            manifestHash: null,
            boardHeadHash: null,
            objectRoot,
            chunkMerkleRoot: null,
            signerRole,
            signerIdentity,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            contextHash,
            ...overrides,
        },
    });
};

export const replaceSignatureBytes = (
    signature: ProtocolSignatureEnvelope,
    signatureBytesHex: string,
): ProtocolSignatureEnvelope => ({
    ...signature,
    signatureBytesHex,
});

export const replaceSignaturePublicKeyBytes = (
    signature: ProtocolSignatureEnvelope,
    publicKeyBytesHex: string,
): ProtocolSignatureEnvelope => ({
    ...signature,
    publicKeyBytesHex,
});
