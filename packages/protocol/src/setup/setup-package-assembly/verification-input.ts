import type { CompactVssShareLinkageBinaryProofMaterialTransportLike } from '../compact-vss-commitments.js';
import { chunklessSetupProofMaterialSetForVerificationInput } from '../setup-proof-material-transport.js';
import type {
    SetupTransportedVssCoefficientCommitmentMaterial,
    SetupTransportedVssCoefficientCommitmentMaterialLike,
    VerifiedVssCoefficientCommitmentMaterial,
} from '../vss-coefficient-commitments.js';

import {
    assertObjectRecord,
    cloneJsonLike,
} from './constants-and-assertions.js';
import type {
    JsonRecord,
    SetupPackage,
    SetupPackageVerificationInput,
    SetupPackageVerificationInputSource,
} from './types.js';

const publicVssMaterialReferenceForVerificationInput = (
    transportedMaterial:
        | SetupTransportedVssCoefficientCommitmentMaterialLike
        | undefined,
    verifiedMaterial: VerifiedVssCoefficientCommitmentMaterial | undefined,
): SetupTransportedVssCoefficientCommitmentMaterialLike | undefined => {
    if (transportedMaterial === undefined) {
        return undefined;
    }
    if (
        verifiedMaterial === undefined ||
        !Object.prototype.hasOwnProperty.call(transportedMaterial, 'chunks')
    ) {
        return transportedMaterial;
    }

    const { chunks: omittedChunks, ...transportedMaterialReference } =
        transportedMaterial as SetupTransportedVssCoefficientCommitmentMaterial;
    void omittedChunks;

    return transportedMaterialReference;
};

const compactVssShareLinkageProofMaterialReferenceForVerificationInput = (
    transportedMaterial:
        | CompactVssShareLinkageBinaryProofMaterialTransportLike
        | undefined,
): CompactVssShareLinkageBinaryProofMaterialTransportLike | undefined => {
    if (
        transportedMaterial === undefined ||
        !Object.prototype.hasOwnProperty.call(transportedMaterial, 'chunks')
    ) {
        return transportedMaterial;
    }

    const { chunks: omittedChunks, ...transportedMaterialReference } =
        transportedMaterial;
    void omittedChunks;

    return transportedMaterialReference;
};

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): SetupPackageVerificationInput => {
    const transportedVssCoefficientCommitmentMaterial =
        publicVssMaterialReferenceForVerificationInput(
            input.transportedVssCoefficientCommitmentMaterial,
            input.verifiedVssCoefficientCommitmentMaterial,
        );
    const transportedSameSecretProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedSameSecretProofMaterial,
            input.verifiedSetupProofMaterials,
        );
    const transportedCompactVssShareLinkageProofMaterial =
        compactVssShareLinkageProofMaterialReferenceForVerificationInput(
            input.transportedCompactVssShareLinkageProofMaterial,
        );
    const transportedPublicKeyShareProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedPublicKeyShareProofMaterial,
            input.verifiedSetupProofMaterials,
        );
    const transportedEvaluationKeyShareProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareProofMaterial,
            input.verifiedSetupProofMaterials,
        );

    return {
        setupPackage: input.setupPackage,
        ...(transportedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  transportedVssCoefficientCommitmentMaterial,
              }),
        ...(input.verifiedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  verifiedVssCoefficientCommitmentMaterial:
                      input.verifiedVssCoefficientCommitmentMaterial,
              }),
        ...(transportedSameSecretProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretProofMaterial:
                      transportedSameSecretProofMaterial,
              }),
        ...(transportedCompactVssShareLinkageProofMaterial === undefined
            ? {}
            : {
                  transportedCompactVssShareLinkageProofMaterial:
                      transportedCompactVssShareLinkageProofMaterial,
              }),
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
        ...(input.transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      input.transportedEvaluationKeyShareComponentMaterial,
              }),
        ...(input.transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      input.transportedPublicEvaluationKeyMaterial,
              }),
        ...(input.verifiedSetupProofMaterials === undefined
            ? {}
            : {
                  verifiedSetupProofMaterials:
                      input.verifiedSetupProofMaterials,
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
