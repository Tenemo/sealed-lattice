import { expect } from 'vitest';

import { setupRequest } from '../../bgv-passive-setup-fixtures.js';
import {
    collectiveSetupRosterHash,
    setupTrusteeSignatureSeedLabel,
    textEncoder,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { canonicalJson } from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import type {
    BgvCollectiveSetupProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const canonicalByteLength = (value: unknown): number =>
    textEncoder.encode(canonicalJson(value)).byteLength;

function commonRandomnessSignatureContextHash(input: {
    readonly kernel: TranscriptCoreKernel;
    readonly objectType: 'CommonRandomnessCommit' | 'CommonRandomnessReveal';
    readonly purpose:
        | 'common-randomness-commit-signature-context'
        | 'common-randomness-reveal-signature-context';
    readonly payload: JsonRecord;
    readonly objectRoot: string;
}): string {
    return input.kernel.deriveProtocolHash({
        namespace: `${input.objectType}Hash`,
        value: {
            purpose: input.purpose,
            ceremonyId: input.payload.ceremonyId,
            manifestHash: input.payload.manifestHash,
            rosterHash: input.payload.rosterHash,
            setupProfileHash: input.payload.setupProfileHash,
            setupEpoch: input.payload.setupEpoch,
            trusteeIdentity: input.payload.trusteeIdentity,
            rosterPosition: input.payload.rosterPosition,
            objectRoot: input.objectRoot,
        },
    });
}

function commonRandomnessSignatureEnvelope(input: {
    readonly kernel: TranscriptCoreKernel;
    readonly objectType: 'CommonRandomnessCommit' | 'CommonRandomnessReveal';
    readonly purpose:
        | 'common-randomness-commit-signature-context'
        | 'common-randomness-reveal-signature-context';
    readonly payload: JsonRecord;
    readonly objectRoot: string;
    readonly trusteeIdentity: string;
}): JsonRecord {
    const keyFixture = createMlDsaKeyPairFixture(
        setupTrusteeSignatureSeedLabel(input.trusteeIdentity),
    );
    const signatureContextHash = commonRandomnessSignatureContextHash(input);

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyHash: keyFixture.publicKeyHash,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            objectType: input.objectType,
            objectVersion: 1,
            ceremonyId: String(input.payload.ceremonyId),
            manifestHash: String(input.payload.manifestHash),
            boardHeadHash: null,
            objectRoot: input.objectRoot,
            chunkMerkleRoot: null,
            byteLength: canonicalByteLength(input.payload),
            signerRole: 'Trustee',
            signerIdentity: input.trusteeIdentity,
            recoveryEpoch: Number(input.payload.recoveryEpoch),
            deviceEpoch: Number(input.payload.deviceEpoch),
            contextHash: signatureContextHash,
        },
    });
}

export function acceptedCommonRandomness(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const commitRecords: JsonRecord[] = [];
    const revealRecords: JsonRecord[] = [];
    const orderedRevealHashes: string[] = [];
    const rosterHash = collectiveSetupRosterHash((input) =>
        kernel.deriveProtocolHash(input),
    );
    for (let rosterPosition = 0; rosterPosition < 10; rosterPosition += 1) {
        const trusteeIdentity = `trustee-${String(rosterPosition)}`;
        const revealHex = kernel
            .deriveProtocolHash({
                namespace: 'CommonRandomnessRevealHash',
                value: {
                    fixture: 'common-randomness-reveal',
                    rosterPosition,
                },
            })
            .slice(0, 64);
        const revealPayload: JsonRecord = {
            objectType: 'CommonRandomnessReveal',
            objectVersion: 1,
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash,
            setupProfileHash: profile.setupProfileHash,
            setupEpoch: 'setup-epoch-1',
            signerRole: 'Trustee',
            trusteeIdentity,
            rosterPosition,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            revealHex,
        };
        const revealHash = kernel.deriveProtocolHash({
            namespace: 'CommonRandomnessRevealHash',
            value: revealPayload,
        });
        const revealSignatureEnvelope = commonRandomnessSignatureEnvelope({
            kernel,
            objectType: 'CommonRandomnessReveal',
            purpose: 'common-randomness-reveal-signature-context',
            payload: revealPayload,
            objectRoot: revealHash,
            trusteeIdentity,
        });
        const revealRecord: JsonRecord = {
            ...revealPayload,
            signatureEnvelopeHash: revealSignatureEnvelope.signatureHash,
            signatureEnvelope: revealSignatureEnvelope,
            revealHash,
        };
        revealRecords.push(revealRecord);
        orderedRevealHashes.push(revealHash);

        const commitPayload: JsonRecord = {
            objectType: 'CommonRandomnessCommit',
            objectVersion: 1,
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash,
            setupProfileHash: profile.setupProfileHash,
            setupEpoch: 'setup-epoch-1',
            signerRole: 'Trustee',
            trusteeIdentity,
            rosterPosition,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            revealHash,
        };
        const commitHash = kernel.deriveProtocolHash({
            namespace: 'CommonRandomnessCommitHash',
            value: commitPayload,
        });
        const commitSignatureEnvelope = commonRandomnessSignatureEnvelope({
            kernel,
            objectType: 'CommonRandomnessCommit',
            purpose: 'common-randomness-commit-signature-context',
            payload: commitPayload,
            objectRoot: commitHash,
            trusteeIdentity,
        });
        const commitRecord: JsonRecord = {
            ...commitPayload,
            signatureEnvelopeHash: commitSignatureEnvelope.signatureHash,
            signatureEnvelope: commitSignatureEnvelope,
            commitHash,
        };
        commitRecords.push(commitRecord);
    }

    const publicMatrixSeedHash = kernel.deriveProtocolHash({
        namespace: 'SetupPublicMatrixSeedHash',
        value: {
            setupProfileId: 'CollectiveBgvSetup-v1',
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash,
            setupProfileHash: String(profile.setupProfileHash),
            setupEpoch: 'setup-epoch-1',
            orderedRevealHashes,
        },
    });
    const publicDerivations = kernel.deriveCollectiveBgvSetupPublicDerivations({
        publicMatrixSeedHash,
    });
    expect(
        publicDerivations.publicMatrices.commitmentMatrix.sampledEntries[0]
            ?.coefficientValue,
    ).toEqual(expect.any(Number));
    const commonRandomness: JsonRecord = {
        objectType: 'SetupCommonRandomness',
        objectVersion: 1,
        ceremonyId: setupRequest.ceremonyId,
        manifestHash: setupRequest.manifestHash,
        rosterHash,
        setupProfileHash: profile.setupProfileHash,
        setupEpoch: 'setup-epoch-1',
        commitRecords,
        revealRecords,
        publicMatrixSeedHash,
        publicDerivations,
    };
    commonRandomness.commonRandomnessRoot = kernel.deriveProtocolHash({
        namespace: 'SetupCommonRandomnessRoot',
        value: commonRandomness,
    });

    return commonRandomness;
}

function publicPrivateVssEnvelopeCommitmentReference(
    envelopeReference: JsonRecord,
): JsonRecord {
    const {
        encryptedEnvelope: encryptedEnvelopeForRecipientTransport,
        transportedPrivateVssShareProofMaterial:
            transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...publicReference
    } = envelopeReference;
    void encryptedEnvelopeForRecipientTransport;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return publicReference;
}

export { publicPrivateVssEnvelopeCommitmentReference };

export function publicPrivateVssEnvelopeCommitmentSet(
    privateVssEnvelopeCommitments: JsonRecord,
): JsonRecord {
    return {
        ...privateVssEnvelopeCommitments,
        envelopeReferences: (
            privateVssEnvelopeCommitments.envelopeReferences as JsonRecord[]
        ).map(publicPrivateVssEnvelopeCommitmentReference),
    };
}
