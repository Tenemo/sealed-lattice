import { chunklessSetupProofMaterialSetForVerificationInput } from '../setup-proof-material-transport.js';

import {
    assertObjectRecord,
    assertProtocolHash,
    cloneJsonLike,
} from './constants-and-assertions.js';
import type {
    JsonRecord,
    SetupPackage,
    SetupPackageVerificationInput,
    SetupPackageVerificationInputSource,
} from './types.js';

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): SetupPackageVerificationInput => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');

    const transportedPublicKeyShareProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedPublicKeyShareProofMaterial,
        );
    const transportedEvaluationKeyShareProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareProofMaterial,
        );
    const transportedVssShareLinkageProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedVssShareLinkageProofMaterial,
        );
    const transportedSameSecretBridgeProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedSameSecretBridgeProofMaterial,
        );

    return {
        setupPackage: input.setupPackage,
        expectedManifestHash: input.expectedManifestHash,
        expectedRosterHash: input.expectedRosterHash,
        ...(input.transportedPublicKeyShareMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      input.transportedPublicKeyShareMaterial,
              }),
        ...(transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareProofMaterial:
                      transportedPublicKeyShareProofMaterial,
              }),
        ...(transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareProofMaterial:
                      transportedEvaluationKeyShareProofMaterial,
              }),
        ...(transportedVssShareLinkageProofMaterial === undefined
            ? {}
            : {
                  transportedVssShareLinkageProofMaterial:
                      transportedVssShareLinkageProofMaterial,
              }),
        ...(transportedSameSecretBridgeProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretBridgeProofMaterial:
                      transportedSameSecretBridgeProofMaterial,
              }),
        ...(input.transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      input.transportedEvaluationKeyShareComponentMaterial,
              }),
        ...(input.transportedEvaluationKeyAggregateBindingOpenings === undefined
            ? {}
            : {
                  transportedEvaluationKeyAggregateBindingOpenings:
                      input.transportedEvaluationKeyAggregateBindingOpenings,
              }),
        ...(input.transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      input.transportedPublicEvaluationKeyMaterial,
              }),
    };
};

const publicPrivateVssEnvelopeCommitmentReference = (
    envelopeReference: JsonRecord,
): JsonRecord => {
    const {
        encryptedEnvelope,
        encryptedEnvelopeForRecipientTransport,
        transportedPrivateVssShareProofMaterial,
        transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...publicReference
    } = envelopeReference;
    void encryptedEnvelope;
    void encryptedEnvelopeForRecipientTransport;
    void transportedPrivateVssShareProofMaterial;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return publicReference;
};

export const publicPrivateVssEnvelopeCommitmentSet = (
    privateVssEnvelopeCommitments: JsonRecord,
): JsonRecord => {
    const envelopeReferences = privateVssEnvelopeCommitments.envelopeReferences;
    if (!Array.isArray(envelopeReferences)) {
        throw new TypeError(
            'privateVssEnvelopeCommitments.envelopeReferences must be an array.',
        );
    }

    return {
        ...privateVssEnvelopeCommitments,
        envelopeReferences: envelopeReferences.map((envelopeReference) =>
            publicPrivateVssEnvelopeCommitmentReference(
                assertObjectRecord(
                    envelopeReference,
                    'privateVssEnvelopeCommitments.envelopeReferences',
                ),
            ),
        ),
    };
};

export const setupPackageHashInput = (
    setupPackage: Readonly<SetupPackage | JsonRecord>,
): JsonRecord => {
    const hashInput = cloneJsonLike(setupPackage) as JsonRecord;
    delete hashInput.setupPackageHash;
    const privateVssEnvelopeCommitments =
        hashInput.privateVssEnvelopeCommitments;
    if (privateVssEnvelopeCommitments !== undefined) {
        hashInput.privateVssEnvelopeCommitments =
            publicPrivateVssEnvelopeCommitmentSet(
                assertObjectRecord(
                    privateVssEnvelopeCommitments,
                    'privateVssEnvelopeCommitments',
                ),
            );
    }

    return hashInput;
};
