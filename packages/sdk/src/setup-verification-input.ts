import { createSetupPackageVerificationInput } from '@sealed-lattice/protocol';
import type {
    EvaluationKeyShareComponentMaterialChunkStream,
    SetupPackageVerificationInputSource,
    TransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicKeyShareProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet,
} from '@sealed-lattice/protocol';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    type BgvCanonicalStreamFamily,
    type BgvCanonicalStreamRuntime,
    type TranscriptCoreKernel,
} from '@sealed-lattice/wasm';

import type {
    VerifyPrivateVssShareInput,
    VerifySetupPackageInput,
} from './index.js';

type JsonRecord = Record<string, unknown>;

type SetupProofMaterialTransportFieldName =
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportSet =
    | TransportedPublicKeyShareProofMaterialSet
    | TransportedVssShareLinkageProofMaterialSet
    | TransportedSameSecretBridgeProofMaterialSet
    | TransportedEvaluationKeyShareProofMaterialSet;

const setupProofMaterialFamilies = Object.freeze({
    transportedEvaluationKeyShareProofMaterial:
        bgvCanonicalStreamFamilies.trusteeEvaluationKey,
    transportedPublicKeyShareProofMaterial:
        bgvCanonicalStreamFamilies.publicKeyShare,
    transportedSameSecretBridgeProofMaterial:
        bgvCanonicalStreamFamilies.sameSecretBridge,
    transportedVssShareLinkageProofMaterial:
        bgvCanonicalStreamFamilies.vssShareLinkage,
} as const satisfies Readonly<
    Record<SetupProofMaterialTransportFieldName, BgvCanonicalStreamFamily>
>);

const setupProofMaterialTransportFieldNames = Object.freeze(
    Object.keys(
        setupProofMaterialFamilies,
    ) as SetupProofMaterialTransportFieldName[],
);

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
    Object.prototype.toString.call(value) === '[object ArrayBuffer]';

const protocolHash = (value: unknown, fieldPath: string): string => {
    if (typeof value !== 'string' || !/^[0-9a-f]{128}$/u.test(value)) {
        throw new TypeError(`${fieldPath} must be a protocol hash.`);
    }
    return value;
};

const orderedBinaryChunks = (
    value: unknown,
    fieldPath: string,
): readonly ArrayBuffer[] | undefined => {
    if (value === undefined) {
        return undefined;
    }
    if (!Array.isArray(value) || value.length === 0) {
        throw new TypeError(`${fieldPath} must be a non-empty array.`);
    }
    return value.map((chunkValue, chunkIndex) => {
        if (chunkValue === null || typeof chunkValue !== 'object') {
            throw new TypeError(
                `${fieldPath}.${String(chunkIndex)} must be an object.`,
            );
        }
        const chunk = chunkValue as JsonRecord;
        if (chunk.chunkIndex !== chunkIndex || !isArrayBuffer(chunk.bytes)) {
            throw new TypeError(
                `${fieldPath}.${String(chunkIndex)} must carry the expected binary chunk.`,
            );
        }
        return chunk.bytes;
    });
};

const streamSetupProofMaterialSet = (
    runtime: BgvCanonicalStreamRuntime,
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialTransportSet | undefined,
): void => {
    if (materialSet === undefined) {
        return;
    }
    if (!Array.isArray(materialSet.proofMaterials)) {
        throw new TypeError(`${fieldName}.proofMaterials must be an array.`);
    }
    materialSet.proofMaterials.forEach((proofMaterialValue, materialIndex) => {
        const proofMaterial = proofMaterialValue as JsonRecord;
        const chunks = orderedBinaryChunks(
            proofMaterial.chunks,
            `${fieldName}.proofMaterials.${String(materialIndex)}.chunks`,
        );
        if (chunks === undefined) {
            return;
        }
        runtime.stage({
            chunks,
            family: setupProofMaterialFamilies[fieldName],
            materialRoot: protocolHash(
                proofMaterial.proofMaterialRoot,
                `${fieldName}.proofMaterials.${String(materialIndex)}.proofMaterialRoot`,
            ),
        });
    });
};

const componentFamily = (proofFamily: string): BgvCanonicalStreamFamily => {
    if (proofFamily === 'relinearization-key-share') {
        return bgvCanonicalStreamFamilies.relinearizationComponent;
    }
    if (proofFamily === 'galois-key-share') {
        return bgvCanonicalStreamFamilies.galoisComponent;
    }
    throw new TypeError(
        'An evaluation-key component material stream has an unsupported proof family.',
    );
};

const streamEvaluationKeyShareComponentMaterial = (
    runtime: BgvCanonicalStreamRuntime,
    transportedMaterialSet:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    chunkStreams:
        | readonly EvaluationKeyShareComponentMaterialChunkStream[]
        | undefined,
): void => {
    if (transportedMaterialSet === undefined || chunkStreams === undefined) {
        return;
    }
    if (!Array.isArray(transportedMaterialSet.componentMaterials)) {
        throw new TypeError(
            'transportedEvaluationKeyShareComponentMaterial.componentMaterials must be an array.',
        );
    }
    const referenceFamilyByRoot = new Map<string, string>();
    transportedMaterialSet.componentMaterials.forEach(
        (componentMaterialValue, componentIndex) => {
            const componentMaterial = componentMaterialValue as JsonRecord;
            const root = protocolHash(
                componentMaterial.keySwitchComponentMaterialRoot,
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot`,
            );
            if (typeof componentMaterial.proofFamily !== 'string') {
                throw new TypeError(
                    'An evaluation-key component material reference must carry its proof family.',
                );
            }
            if (referenceFamilyByRoot.has(root)) {
                throw new TypeError(
                    'Evaluation-key component material references must not repeat a root.',
                );
            }
            referenceFamilyByRoot.set(root, componentMaterial.proofFamily);
        },
    );

    chunkStreams.forEach((chunkStream, streamIndex) => {
        const root = protocolHash(
            chunkStream.keySwitchComponentMaterialRoot,
            `evaluationKeyShareComponentMaterialChunkStreams.${String(streamIndex)}.keySwitchComponentMaterialRoot`,
        );
        const referenceFamily = referenceFamilyByRoot.get(root);
        if (
            referenceFamily === undefined ||
            referenceFamily !== chunkStream.proofFamily
        ) {
            throw new TypeError(
                'An evaluation-key component chunk stream must match exactly one transported reference and proof family.',
            );
        }
        const chunks = orderedBinaryChunks(
            chunkStream.chunks,
            `evaluationKeyShareComponentMaterialChunkStreams.${String(streamIndex)}.chunks`,
        );
        if (chunks === undefined) {
            throw new TypeError(
                'An evaluation-key component chunk stream must carry binary chunks.',
            );
        }
        runtime.stage({
            chunks,
            family: componentFamily(referenceFamily),
            materialRoot: root,
        });
    });
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
    const runtime = openBgvCanonicalStreamRuntime({ kernel });
    streamEvaluationKeyShareComponentMaterial(
        runtime,
        input.transportedEvaluationKeyShareComponentMaterial,
        input.evaluationKeyShareComponentMaterialChunkStreams,
    );
    setupProofMaterialTransportFieldNames.forEach((fieldName) => {
        streamSetupProofMaterialSet(runtime, fieldName, input[fieldName]);
    });

    return setupPackageVerificationInput(input);
};

export const preparePrivateVssShareVerificationInputForKernel = (
    kernel: TranscriptCoreKernel,
    input: VerifyPrivateVssShareInput,
): VerifyPrivateVssShareInput => {
    const transportedMaterial = input.transportedPrivateVssShareProofMaterial;
    if (transportedMaterial === undefined) {
        return input;
    }
    if (
        transportedMaterial === null ||
        typeof transportedMaterial !== 'object' ||
        !Array.isArray((transportedMaterial as JsonRecord).proofMaterials)
    ) {
        throw new TypeError(
            'transportedPrivateVssShareProofMaterial.proofMaterials must be an array.',
        );
    }
    const materialSet = transportedMaterial as JsonRecord & {
        readonly proofMaterials: readonly unknown[];
    };
    const runtime = openBgvCanonicalStreamRuntime({ kernel });
    const proofMaterials = materialSet.proofMaterials.map(
        (proofMaterialValue, proofMaterialIndex) => {
            if (
                proofMaterialValue === null ||
                typeof proofMaterialValue !== 'object'
            ) {
                throw new TypeError(
                    'A transported private VSS proof material must be an object.',
                );
            }
            const proofMaterial = proofMaterialValue as JsonRecord;
            const chunks = orderedBinaryChunks(
                proofMaterial.chunks,
                `transportedPrivateVssShareProofMaterial.proofMaterials.${String(proofMaterialIndex)}.chunks`,
            );
            if (chunks !== undefined) {
                runtime.stage({
                    chunks,
                    family: bgvCanonicalStreamFamilies.vssOpeningCarry,
                    materialRoot: protocolHash(
                        proofMaterial.proofMaterialRoot,
                        `transportedPrivateVssShareProofMaterial.proofMaterials.${String(proofMaterialIndex)}.proofMaterialRoot`,
                    ),
                });
            }
            const { chunks: omittedChunks, ...reference } = proofMaterial;
            void omittedChunks;
            return reference;
        },
    );

    return {
        ...input,
        transportedPrivateVssShareProofMaterial: {
            ...materialSet,
            proofMaterials,
        },
    };
};
