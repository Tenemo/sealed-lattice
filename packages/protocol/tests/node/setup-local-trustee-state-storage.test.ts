import {
    canonicalJson,
    encryptLocalTrusteeSetupSealedMaterial,
    hash512Hex,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    collectForbiddenLocalTrusteeSetupStateFieldPaths,
    decryptLocalTrusteeSetupState,
    encryptLocalTrusteeSetupState,
    type LocalTrusteeSetupStateEncryptionInput,
} from '#packages/protocol/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-local-trustee-state-storage');
const textEncoder = new TextEncoder();

const setupContext = makeSetupContext(fixtureHash);

const storageInputBase = {
    setupContext,
    trusteeIdentity: 'trustee-3',
    trusteeRosterPosition: 3,
    thresholdShareCommitmentRecipientRoot: fixtureHash(
        'threshold-share-commitment-recipient',
    ),
    issuedVssAcceptanceRoot: fixtureHash('issued-vss-acceptance'),
    issuedVssComplaintRoots: [fixtureHash('issued-vss-complaint')],
    storageKeyBytesHex: '11'.repeat(32),
    aeadNonceBytesHex: '22'.repeat(12),
} as const;

type LocalStatePlaintextFixture = Readonly<{
    readonly plaintext: LocalTrusteeSetupStateEncryptionInput['localStatePlaintext'];
    readonly storageInput: Omit<
        LocalTrusteeSetupStateEncryptionInput,
        'localStatePlaintext'
    >;
}>;

const localStatePlaintext = async (): Promise<LocalStatePlaintextFixture> => {
    const sealedAggregateThresholdShare =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'aggregate-threshold-share-sealed',
            materialPlaintext: {
                objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
                objectVersion: 1,
                trusteeIdentity: storageInputBase.trusteeIdentity,
                trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
                thresholdShareCommitmentRecipientRoot:
                    storageInputBase.thresholdShareCommitmentRecipientRoot,
                shareValues: [7, 8, 9],
            },
            setupContext,
            trusteeIdentity: storageInputBase.trusteeIdentity,
            trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                storageInputBase.thresholdShareCommitmentRecipientRoot,
            storageKeyBytesHex: storageInputBase.storageKeyBytesHex,
            aeadNonceBytesHex: '33'.repeat(12),
        });
    const storageInput = {
        ...storageInputBase,
        aggregateThresholdShareRoot: sealedAggregateThresholdShare.materialRoot,
    } as const;
    const plaintext = {
        objectType: 'LocalTrusteeSetupStateSealedPayload',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupEpoch: setupContext.setupEpoch,
        trusteeIdentity: storageInputBase.trusteeIdentity,
        trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
        deviceEpoch: 0,
        thresholdShareCommitmentRecipientRoot:
            storageInput.thresholdShareCommitmentRecipientRoot,
        sealedAggregateThresholdShare:
            sealedAggregateThresholdShare.sealedMaterial,
        issuedVssAcceptanceRoots: [storageInput.issuedVssAcceptanceRoot],
        issuedVssComplaintRoots: storageInput.issuedVssComplaintRoots,
    } as const;

    return { plaintext, storageInput };
};

const rebindEncryptedLocalStateHash = (
    encryptedLocalState: Record<string, unknown>,
): Record<string, unknown> => {
    const envelopeWithoutHash = {
        ...encryptedLocalState,
    };
    delete envelopeWithoutHash.encryptedLocalStateHash;

    return {
        ...encryptedLocalState,
        encryptedLocalStateHash: hash512Hex(
            'sealed-lattice-local-trustee-state/envelope-hash-v1',
            [textEncoder.encode(canonicalJson(envelopeWithoutHash))],
        ),
    };
};

describe('local trustee setup state storage', () => {
    it('encrypts and restores protocol-built roots-only local state', async () => {
        const { plaintext, storageInput } = await localStatePlaintext();

        const encryptedState = await encryptLocalTrusteeSetupState({
            ...storageInput,
            localStatePlaintext: plaintext,
        });
        const decryptedState = await decryptLocalTrusteeSetupState({
            encryptedLocalState: encryptedState.encryptedLocalState,
            expectedLocalStateRoot:
                encryptedState.localStateCommitment.localStateRoot,
            setupContext,
            storageKeyBytesHex: storageInput.storageKeyBytesHex,
        });

        expect(
            collectForbiddenLocalTrusteeSetupStateFieldPaths(
                encryptedState.localStateCommitment,
            ),
        ).toEqual([]);
        expect(encryptedState.encryptedLocalState.localStateRoot).toBe(
            encryptedState.localStateCommitment.localStateRoot,
        );
        expect(encryptedState.localStateTransportEvidence).toMatchObject({
            objectType: 'LocalTrusteeSetupStateTransportEvidence',
            measurementKind:
                'static-encrypted-local-state-transport-accounting',
            transportEncoding: 'canonical-json-envelope-with-hex-ciphertext',
            chunkingStatus: 'single-envelope-not-chunked',
            localStateRoot: encryptedState.localStateCommitment.localStateRoot,
            localStateCommitmentHash:
                encryptedState.encryptedLocalState.localStateCommitmentHash,
            storageAadHash: encryptedState.storageAadHash,
            encryptedLocalStateHash:
                encryptedState.encryptedLocalState.encryptedLocalStateHash,
            ciphertextBytesHash:
                encryptedState.encryptedLocalState.ciphertextBytesHash,
            ciphertextByteLength:
                encryptedState.encryptedLocalState.ciphertextByteLength,
            plaintextByteLength:
                encryptedState.encryptedLocalState.plaintextByteLength,
            aeadTagLength: 128,
            transportedObjectCount: 1,
            runtimeMeasurementBoundary:
                'runtime-measurements-are-recorded-outside-this-local-state-transport-evidence',
            supportedPhoneBoundary:
                'supported-phone-runtime-evidence-is-deferred-and-not-required-by-this-local-state-evidence',
            profileScaleStatus:
                'single-trustee-local-state-envelope-bound-to-profile-shape',
        });
        expect(
            encryptedState.localStateTransportEvidence
                .localStateTransportEvidenceRoot,
        ).toMatch(/^[0-9a-f]{128}$/u);
        expect(
            JSON.stringify(encryptedState.localStateTransportEvidence),
        ).not.toMatch(/ciphertextBytesHex|shareValues|privateEnvelope/u);
        expect(
            encryptedState.encryptedLocalState.storageAad.localStateCommitment,
        ).toEqual(encryptedState.localStateCommitment);
        expect(decryptedState).toMatchObject({
            localStatePlaintext: plaintext,
            localStatePlaintextHash: encryptedState.localStatePlaintextHash,
            storageAadHash: encryptedState.storageAadHash,
        });
    });

    it('rejects raw local material, unknown fields, and setup-context rebinding', async () => {
        const { plaintext, storageInput } = await localStatePlaintext();
        const rawLocalMaterial = {
            coefficientMessage: [1, 2, 3],
        } as unknown as LocalTrusteeSetupStateEncryptionInput['localStatePlaintext'];

        await expect(
            encryptLocalTrusteeSetupState({
                ...storageInput,
                localStatePlaintext: rawLocalMaterial,
            }),
        ).rejects.toThrow(/forbidden raw local state fields/u);

        await expect(
            encryptLocalTrusteeSetupState({
                ...storageInput,
                localStatePlaintext: {
                    ...plaintext,
                    unrecognizedAggregateShareCopy: [1, 2, 3],
                },
            }),
        ).rejects.toThrow(/not allowed by the local trustee state schema/u);

        const encryptedState = await encryptLocalTrusteeSetupState({
            ...storageInput,
            localStatePlaintext: plaintext,
        });

        await expect(
            decryptLocalTrusteeSetupState({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
                storageKeyBytesHex: storageInput.storageKeyBytesHex,
            }),
        ).rejects.toThrow(/storageAad/u);
    });

    it('rejects encrypted local state transport metadata drift', async () => {
        const { plaintext, storageInput } = await localStatePlaintext();
        const encryptedState = await encryptLocalTrusteeSetupState({
            ...storageInput,
            localStatePlaintext: plaintext,
        });

        const driftedCiphertextByteLength = rebindEncryptedLocalStateHash({
            ...encryptedState.encryptedLocalState,
            ciphertextByteLength:
                encryptedState.encryptedLocalState.ciphertextByteLength + 1,
        });

        await expect(
            decryptLocalTrusteeSetupState({
                encryptedLocalState:
                    driftedCiphertextByteLength as typeof encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex: storageInput.storageKeyBytesHex,
            }),
        ).rejects.toThrow(/ciphertextByteLength/u);

        const driftedAeadTagLength = rebindEncryptedLocalStateHash({
            ...encryptedState.encryptedLocalState,
            aeadTagLength: 96,
        });

        await expect(
            decryptLocalTrusteeSetupState({
                encryptedLocalState:
                    driftedAeadTagLength as typeof encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex: storageInput.storageKeyBytesHex,
            }),
        ).rejects.toThrow(/aeadTagLength/u);
    });
});
