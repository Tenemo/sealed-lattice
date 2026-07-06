import { createSetupPackageVerificationInput } from '@sealed-lattice/protocol';
import type {
    SetupPackageVerificationInputSource,
    TransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicKeyShareProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet,
    TransportedSameSecretProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet,
    VerifiedSetupProofMaterial,
    VerifiedSetupProofMaterialSet,
} from '@sealed-lattice/protocol';
import type { TranscriptCoreKernel } from '@sealed-lattice/wasm';

import type { VerifySetupPackageInput } from './index.js';

type JsonRecord = Record<string, unknown>;

type SetupProofMaterialTransportFieldName =
    | 'transportedSameSecretProofMaterial'
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportSet =
    | TransportedSameSecretProofMaterialSet
    | TransportedPublicKeyShareProofMaterialSet
    | TransportedVssShareLinkageProofMaterialSet
    | TransportedSameSecretBridgeProofMaterialSet
    | TransportedEvaluationKeyShareProofMaterialSet;

type SetupProofMaterialChunk = Readonly<{
    readonly chunkIndex: number;
    readonly bytesHex: string;
}>;

const setupProofMaterialTransportFieldNames = [
    'transportedSameSecretProofMaterial',
    'transportedPublicKeyShareProofMaterial',
    'transportedVssShareLinkageProofMaterial',
    'transportedSameSecretBridgeProofMaterial',
    'transportedEvaluationKeyShareProofMaterial',
] as const satisfies readonly SetupProofMaterialTransportFieldName[];

let setupProofMaterialVerificationSequence = 0;

// Verification ids are process-local kernel stream handles, not security bindings; the cryptographic binding is the full proof material root.
const setupProofMaterialVerificationId = (
    fieldName: SetupProofMaterialTransportFieldName,
    materialIndex: number,
    proofMaterial: JsonRecord,
): string => {
    setupProofMaterialVerificationSequence += 1;
    const proofMaterialRoot =
        typeof proofMaterial.proofMaterialRoot === 'string'
            ? proofMaterial.proofMaterialRoot.slice(0, 24)
            : 'unbound';

    return [
        'sdk-proof-material',
        String(setupProofMaterialVerificationSequence),
        fieldName,
        String(materialIndex),
        proofMaterialRoot,
    ].join('-');
};

const setupProofMaterialReference = (proofMaterial: JsonRecord): JsonRecord => {
    const { chunks: omittedChunks, ...reference } = proofMaterial;
    void omittedChunks;

    return reference;
};

const setupProofMaterialChunks = (
    proofMaterial: unknown,
): readonly SetupProofMaterialChunk[] | undefined => {
    if (
        proofMaterial === null ||
        typeof proofMaterial !== 'object' ||
        !Object.prototype.hasOwnProperty.call(proofMaterial, 'chunks')
    ) {
        return undefined;
    }

    const chunks = (proofMaterial as JsonRecord).chunks;

    return Array.isArray(chunks)
        ? (chunks as readonly SetupProofMaterialChunk[])
        : undefined;
};

const streamSetupProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialTransportSet | undefined,
): readonly VerifiedSetupProofMaterial[] => {
    if (
        materialSet === undefined ||
        !Array.isArray(materialSet.proofMaterials)
    ) {
        return [];
    }

    const verifiedMaterials: VerifiedSetupProofMaterial[] = [];
    materialSet.proofMaterials.forEach((proofMaterialValue, materialIndex) => {
        const chunks = setupProofMaterialChunks(proofMaterialValue);
        if (chunks === undefined) {
            return;
        }
        const proofMaterial = proofMaterialValue as JsonRecord;
        const proofMaterialReference =
            setupProofMaterialReference(proofMaterial);
        const verificationId = setupProofMaterialVerificationId(
            fieldName,
            materialIndex,
            proofMaterial,
        );
        kernel.beginSetupProofMaterialTransportStream({
            verificationId,
            transportedSetupProofMaterial: proofMaterialReference,
        });
        chunks.forEach((chunk) => {
            kernel.absorbSetupProofMaterialTransportStreamChunk({
                verificationId,
                chunkIndex: chunk.chunkIndex,
                bytesHex: chunk.bytesHex,
            });
        });
        const verification = kernel.finishSetupProofMaterialTransportStream({
            verificationId,
        });
        verifiedMaterials.push(
            verification.verifiedSetupProofMaterial as VerifiedSetupProofMaterial,
        );
    });

    return verifiedMaterials;
};

const setupPackageVerificationInput = (
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    const verificationInput = createSetupPackageVerificationInput(
        input as unknown as SetupPackageVerificationInputSource,
    ) as VerifySetupPackageInput;

    return input.expectedSetupPackageHash === undefined
        ? verificationInput
        : {
              ...verificationInput,
              expectedSetupPackageHash: input.expectedSetupPackageHash,
          };
};

export const prepareSetupPackageVerificationInputForKernel = (
    kernel: TranscriptCoreKernel,
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    if (input.verifiedSetupProofMaterials !== undefined) {
        return setupPackageVerificationInput(input);
    }

    const verifiedMaterials = setupProofMaterialTransportFieldNames.flatMap(
        (fieldName) =>
            streamSetupProofMaterialSet(kernel, fieldName, input[fieldName]),
    );
    if (verifiedMaterials.length === 0) {
        return input;
    }

    const verifiedSetupProofMaterials = {
        objectType: 'VerifiedSetupProofMaterialSet',
        objectVersion: 1,
        proofMaterials: verifiedMaterials,
    } as const satisfies VerifiedSetupProofMaterialSet;

    return setupPackageVerificationInput({
        ...input,
        verifiedSetupProofMaterials,
    });
};
