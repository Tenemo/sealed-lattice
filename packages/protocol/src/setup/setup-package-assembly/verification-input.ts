import {
    canonicalStreamTransportAccountingFromDescriptor,
    type CanonicalStreamTransportAccounting,
} from '../canonical-stream-descriptor.js';

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

type KernelTransportAccountingFieldNames = Readonly<{
    readonly totalByteLength: string;
    readonly fullObjectHash: string;
    readonly chunkRoot: string;
    readonly chunkHashes: string;
}>;

const directKernelTransportAccountingFieldNames: KernelTransportAccountingFieldNames =
    {
        totalByteLength: 'totalByteLength',
        fullObjectHash: 'fullObjectHash',
        chunkRoot: 'chunkRoot',
        chunkHashes: 'chunkHashes',
    };

const proofPrefixedKernelTransportAccountingFieldNames: KernelTransportAccountingFieldNames =
    {
        totalByteLength: 'proofTotalByteLength',
        fullObjectHash: 'proofFullObjectHash',
        chunkRoot: 'proofChunkRoot',
        chunkHashes: 'proofChunkHashes',
    };

const kernelTransportAccountingFields = (
    accounting: CanonicalStreamTransportAccounting,
    fieldNames: KernelTransportAccountingFieldNames,
): JsonRecord => ({
    [fieldNames.totalByteLength]: accounting.totalByteLength,
    [fieldNames.fullObjectHash]: accounting.fullObjectHash,
    [fieldNames.chunkRoot]: accounting.chunkRoot,
    [fieldNames.chunkHashes]: accounting.chunkHashes,
});

const descriptorBackedMaterialReferenceForVerificationInput = (
    materialValue: unknown,
    materialPath: string,
    accountingFieldNames?: KernelTransportAccountingFieldNames,
): JsonRecord => {
    const material = assertObjectRecord(materialValue, materialPath);
    const accounting = canonicalStreamTransportAccountingFromDescriptor(
        material.descriptorBytes,
        `${materialPath}.descriptorBytes`,
    );
    const { descriptorBytes: omittedDescriptorBytes, ...materialReference } =
        material;
    void omittedDescriptorBytes;

    return accountingFieldNames === undefined
        ? materialReference
        : {
              ...materialReference,
              ...kernelTransportAccountingFields(
                  accounting,
                  accountingFieldNames,
              ),
          };
};

const descriptorBackedMaterialSetForVerificationInput = (
    materialSetValue: unknown,
    materialSetPath: string,
    materialArrayFieldName: string,
    accountingFieldNames?: KernelTransportAccountingFieldNames,
): JsonRecord | undefined => {
    if (materialSetValue === undefined) {
        return undefined;
    }
    const materialSet = assertObjectRecord(materialSetValue, materialSetPath);
    const materials = materialSet[materialArrayFieldName];
    if (!Array.isArray(materials)) {
        throw new TypeError(
            `${materialSetPath}.${materialArrayFieldName} must be an array.`,
        );
    }

    return {
        ...materialSet,
        [materialArrayFieldName]: materials.map(
            (materialValue, materialIndex) =>
                descriptorBackedMaterialReferenceForVerificationInput(
                    materialValue,
                    `${materialSetPath}.${materialArrayFieldName}.${String(materialIndex)}`,
                    accountingFieldNames,
                ),
        ),
    };
};

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): SetupPackageVerificationInput => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');

    const transportedPublicKeyShareProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedPublicKeyShareProofMaterial,
            'transportedPublicKeyShareProofMaterial',
            'proofMaterials',
            directKernelTransportAccountingFieldNames,
        );
    const transportedEvaluationKeyShareProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareProofMaterial,
            'transportedEvaluationKeyShareProofMaterial',
            'proofMaterials',
            proofPrefixedKernelTransportAccountingFieldNames,
        );
    const transportedVssShareLinkageProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedVssShareLinkageProofMaterial,
            'transportedVssShareLinkageProofMaterial',
            'proofMaterials',
            directKernelTransportAccountingFieldNames,
        );
    const transportedSameSecretBridgeProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedSameSecretBridgeProofMaterial,
            'transportedSameSecretBridgeProofMaterial',
            'proofMaterials',
            directKernelTransportAccountingFieldNames,
        );
    const transportedPublicKeyShareMaterial =
        input.transportedPublicKeyShareMaterial === undefined
            ? undefined
            : descriptorBackedMaterialReferenceForVerificationInput(
                  input.transportedPublicKeyShareMaterial,
                  'transportedPublicKeyShareMaterial',
                  directKernelTransportAccountingFieldNames,
              );
    const transportedEvaluationKeyShareComponentMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareComponentMaterial,
            'transportedEvaluationKeyShareComponentMaterial',
            'componentMaterials',
            directKernelTransportAccountingFieldNames,
        );
    const transportedPublicEvaluationKeyMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedPublicEvaluationKeyMaterial,
            'transportedPublicEvaluationKeyMaterial',
            'publicEvaluationKeyMaterials',
            directKernelTransportAccountingFieldNames,
        );

    return {
        setupPackage: input.setupPackage,
        expectedManifestHash: input.expectedManifestHash,
        expectedRosterHash: input.expectedRosterHash,
        ...(transportedPublicKeyShareMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      transportedPublicKeyShareMaterial,
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
        ...(transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      transportedEvaluationKeyShareComponentMaterial,
              }),
        ...(transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      transportedPublicEvaluationKeyMaterial,
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
