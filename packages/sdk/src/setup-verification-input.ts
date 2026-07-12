import { createSetupPackageVerificationInput } from '@sealed-lattice/protocol';
import type {
    EvaluationKeyShareComponentMaterialChunkSource,
    PublicKeyShareMaterialChunkSource,
    PublicEvaluationKeyMaterialChunkSource,
    SetupProofMaterialChunkSource,
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

const canonicalDescriptorBytes = (
    value: unknown,
    fieldPath: string,
): Uint8Array => {
    if (
        !ArrayBuffer.isView(value) ||
        Object.prototype.toString.call(value) !== '[object Uint8Array]' ||
        value.byteLength === 0
    ) {
        throw new TypeError(`${fieldPath} must be a non-empty Uint8Array.`);
    }

    return value as Uint8Array;
};

const protocolHash = (value: unknown, fieldPath: string): string => {
    if (typeof value !== 'string' || !/^[0-9a-f]{128}$/u.test(value)) {
        throw new TypeError(`${fieldPath} must be a protocol hash.`);
    }
    return value;
};

const proofMaterialChunkSourcesByRoot = (
    sources: readonly SetupProofMaterialChunkSource[] | undefined,
    fieldPath: string,
): Map<string, SetupProofMaterialChunkSource['pullChunk']> => {
    if (sources === undefined) {
        return new Map();
    }
    const sourceCandidate: unknown = sources;
    if (!Array.isArray(sourceCandidate)) {
        throw new TypeError(`${fieldPath} must be a non-empty array.`);
    }
    const typedSources: readonly SetupProofMaterialChunkSource[] = sources;
    const sourcesByRoot = new Map<
        string,
        SetupProofMaterialChunkSource['pullChunk']
    >();
    typedSources.forEach((source, sourceIndex) => {
        if (source === null || typeof source !== 'object') {
            throw new TypeError(
                `${fieldPath}.${String(sourceIndex)} must be an object.`,
            );
        }
        const materialRoot = protocolHash(
            source.proofMaterialRoot,
            `${fieldPath}.${String(sourceIndex)}.proofMaterialRoot`,
        );
        if (
            typeof source.pullChunk !== 'function' ||
            sourcesByRoot.has(materialRoot)
        ) {
            throw new TypeError(
                `${fieldPath}.${String(sourceIndex)} must carry one unique chunk pull function.`,
            );
        }
        sourcesByRoot.set(materialRoot, source.pullChunk);
    });

    return sourcesByRoot;
};

const authenticateCanonicalProofMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    input: Readonly<{
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: SetupProofMaterialChunkSource['pullChunk'];
    }>,
): Promise<void> => {
    await runtime.readMaterial({
        descriptorBytes: input.descriptorBytes,
        family: input.family,
        materialRoot: input.materialRoot,
        pullChunk: input.pullChunk,
    });
};

const streamPublicKeyShareMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    transportedMaterial:
        | VerifySetupPackageInput['transportedPublicKeyShareMaterial']
        | undefined,
    chunkSource: PublicKeyShareMaterialChunkSource | undefined,
): Promise<void> => {
    if (transportedMaterial === undefined) {
        if (chunkSource !== undefined) {
            throw new TypeError(
                'publicKeyShareMaterialChunkSource requires a transported public-key share material descriptor.',
            );
        }
        return;
    }
    if (chunkSource === undefined) {
        throw new TypeError(
            'transportedPublicKeyShareMaterial requires publicKeyShareMaterialChunkSource.',
        );
    }
    const materialRoot = protocolHash(
        transportedMaterial.publicKeyShareMaterialSetRoot,
        'transportedPublicKeyShareMaterial.publicKeyShareMaterialSetRoot',
    );
    if (
        protocolHash(
            chunkSource.publicKeyShareMaterialSetRoot,
            'publicKeyShareMaterialChunkSource.publicKeyShareMaterialSetRoot',
        ) !== materialRoot
    ) {
        throw new TypeError(
            'publicKeyShareMaterialChunkSource must match the transported public-key share material root.',
        );
    }
    if (typeof chunkSource.pullChunk !== 'function') {
        throw new TypeError(
            'publicKeyShareMaterialChunkSource.pullChunk must be a function.',
        );
    }
    await runtime.readMaterial({
        descriptorBytes: canonicalDescriptorBytes(
            transportedMaterial.descriptorBytes,
            'transportedPublicKeyShareMaterial.descriptorBytes',
        ),
        family: bgvCanonicalStreamFamilies.publicKeyShareMaterial,
        materialRoot,
        pullChunk: chunkSource.pullChunk,
    });
};

const streamSetupProofMaterialSet = async (
    runtime: BgvCanonicalStreamRuntime,
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialTransportSet | undefined,
    chunkSourcesByRoot: Map<string, SetupProofMaterialChunkSource['pullChunk']>,
): Promise<void> => {
    if (materialSet === undefined) {
        return;
    }
    if (!Array.isArray(materialSet.proofMaterials)) {
        throw new TypeError(`${fieldName}.proofMaterials must be an array.`);
    }
    const proofMaterials: readonly unknown[] = materialSet.proofMaterials;
    for (
        let materialIndex = 0;
        materialIndex < proofMaterials.length;
        materialIndex += 1
    ) {
        const proofMaterialValue: unknown = proofMaterials[materialIndex];
        const proofMaterial = proofMaterialValue as JsonRecord;
        const materialRoot = protocolHash(
            proofMaterial.proofMaterialRoot,
            `${fieldName}.proofMaterials.${String(materialIndex)}.proofMaterialRoot`,
        );
        const pullChunk = chunkSourcesByRoot.get(materialRoot);
        if (pullChunk === undefined) {
            throw new TypeError(
                `${fieldName}.proofMaterials.${String(materialIndex)} has no canonical chunk source.`,
            );
        }
        await authenticateCanonicalProofMaterial(runtime, {
            descriptorBytes: canonicalDescriptorBytes(
                proofMaterial.descriptorBytes,
                `${fieldName}.proofMaterials.${String(materialIndex)}.descriptorBytes`,
            ),
            family: setupProofMaterialFamilies[fieldName],
            materialRoot,
            pullChunk,
        });
        chunkSourcesByRoot.delete(materialRoot);
    }
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

const streamEvaluationKeyShareComponentMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    transportedMaterialSet:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    chunkSources:
        | readonly EvaluationKeyShareComponentMaterialChunkSource[]
        | undefined,
): Promise<void> => {
    if (transportedMaterialSet === undefined) {
        if ((chunkSources?.length ?? 0) !== 0) {
            throw new TypeError(
                'evaluationKeyShareComponentMaterialChunkSources requires transported component material references.',
            );
        }
        return;
    }
    if (!Array.isArray(transportedMaterialSet.componentMaterials)) {
        throw new TypeError(
            'transportedEvaluationKeyShareComponentMaterial.componentMaterials must be an array.',
        );
    }
    const componentMaterials: readonly unknown[] =
        transportedMaterialSet.componentMaterials;
    const sourcesByRoot = new Map<
        string,
        EvaluationKeyShareComponentMaterialChunkSource
    >();
    for (const [sourceIndex, source] of (chunkSources ?? []).entries()) {
        const root = protocolHash(
            source.keySwitchComponentMaterialRoot,
            `evaluationKeyShareComponentMaterialChunkSources.${String(sourceIndex)}.keySwitchComponentMaterialRoot`,
        );
        if (typeof source.pullChunk !== 'function' || sourcesByRoot.has(root)) {
            throw new TypeError(
                'Evaluation-key component material sources must carry one unique pull function per root.',
            );
        }
        sourcesByRoot.set(root, source);
    }
    for (
        let componentIndex = 0;
        componentIndex < componentMaterials.length;
        componentIndex += 1
    ) {
        const componentMaterialValue: unknown =
            componentMaterials[componentIndex];
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
        const source = sourcesByRoot.get(root);
        if (source?.proofFamily !== componentMaterial.proofFamily) {
            throw new TypeError(
                'An evaluation-key component material source must match exactly one transported reference and proof family.',
            );
        }
        await runtime.readMaterial({
            descriptorBytes: canonicalDescriptorBytes(
                componentMaterial.descriptorBytes,
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.descriptorBytes`,
            ),
            family: componentFamily(componentMaterial.proofFamily),
            materialRoot: root,
            pullChunk: source.pullChunk,
        });
        sourcesByRoot.delete(root);
    }
    if (sourcesByRoot.size !== 0) {
        throw new TypeError(
            'evaluationKeyShareComponentMaterialChunkSources must match transported component material references exactly.',
        );
    }
};

const streamPublicEvaluationKeyMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    transportedMaterialSet:
        | VerifySetupPackageInput['transportedPublicEvaluationKeyMaterial']
        | undefined,
    chunkSources: readonly PublicEvaluationKeyMaterialChunkSource[] | undefined,
): Promise<void> => {
    if (transportedMaterialSet === undefined) {
        if ((chunkSources?.length ?? 0) !== 0) {
            throw new TypeError(
                'publicEvaluationKeyMaterialChunkSources requires transported public evaluation-key material references.',
            );
        }
        return;
    }
    if (!Array.isArray(transportedMaterialSet.publicEvaluationKeyMaterials)) {
        throw new TypeError(
            'transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials must be an array.',
        );
    }
    const sourcesByRoot = new Map<
        string,
        PublicEvaluationKeyMaterialChunkSource['pullChunk']
    >();
    for (const [sourceIndex, source] of (chunkSources ?? []).entries()) {
        const root = protocolHash(
            source.publicEvaluationKeyMaterialRoot,
            `publicEvaluationKeyMaterialChunkSources.${String(sourceIndex)}.publicEvaluationKeyMaterialRoot`,
        );
        if (typeof source.pullChunk !== 'function' || sourcesByRoot.has(root)) {
            throw new TypeError(
                'Public evaluation-key material sources must carry one unique pull function per root.',
            );
        }
        sourcesByRoot.set(root, source.pullChunk);
    }
    for (
        let materialIndex = 0;
        materialIndex <
        transportedMaterialSet.publicEvaluationKeyMaterials.length;
        materialIndex += 1
    ) {
        const material = transportedMaterialSet.publicEvaluationKeyMaterials[
            materialIndex
        ] as JsonRecord;
        const root = protocolHash(
            material.publicEvaluationKeyMaterialRoot,
            `transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials.${String(materialIndex)}.publicEvaluationKeyMaterialRoot`,
        );
        const pullChunk = sourcesByRoot.get(root);
        if (pullChunk === undefined) {
            throw new TypeError(
                'A public evaluation-key material reference has no matching canonical chunk source.',
            );
        }
        await runtime.readMaterial({
            descriptorBytes: canonicalDescriptorBytes(
                material.descriptorBytes,
                `transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials.${String(materialIndex)}.descriptorBytes`,
            ),
            family: bgvCanonicalStreamFamilies.publicEvaluationKeyMaterial,
            materialRoot: root,
            pullChunk,
        });
        sourcesByRoot.delete(root);
    }
    if (sourcesByRoot.size !== 0) {
        throw new TypeError(
            'publicEvaluationKeyMaterialChunkSources must match transported public evaluation-key material references exactly.',
        );
    }
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

export const prepareSetupPackageVerificationInputForKernel = async (
    kernel: TranscriptCoreKernel,
    input: VerifySetupPackageInput,
): Promise<VerifySetupPackageInput> => {
    const runtime = openBgvCanonicalStreamRuntime({ kernel });
    await streamPublicKeyShareMaterial(
        runtime,
        input.transportedPublicKeyShareMaterial,
        input.publicKeyShareMaterialChunkSource,
    );
    await streamEvaluationKeyShareComponentMaterial(
        runtime,
        input.transportedEvaluationKeyShareComponentMaterial,
        input.evaluationKeyShareComponentMaterialChunkSources,
    );
    await streamPublicEvaluationKeyMaterial(
        runtime,
        input.transportedPublicEvaluationKeyMaterial,
        input.publicEvaluationKeyMaterialChunkSources,
    );
    const chunkSourcesByRoot = proofMaterialChunkSourcesByRoot(
        input.setupProofMaterialChunkSources,
        'setupProofMaterialChunkSources',
    );
    for (const fieldName of setupProofMaterialTransportFieldNames) {
        await streamSetupProofMaterialSet(
            runtime,
            fieldName,
            input[fieldName],
            chunkSourcesByRoot,
        );
    }
    if (chunkSourcesByRoot.size !== 0) {
        throw new TypeError(
            'setupProofMaterialChunkSources must match transported proof material references exactly.',
        );
    }

    return setupPackageVerificationInput(input);
};

export const preparePrivateVssShareVerificationInputForKernel = async (
    kernel: TranscriptCoreKernel,
    input: VerifyPrivateVssShareInput,
): Promise<VerifyPrivateVssShareInput> => {
    const transportedMaterial = input.transportedPrivateVssShareProofMaterial;
    if (transportedMaterial === undefined) {
        if (
            (input.privateVssShareProofMaterialChunkSources?.length ?? 0) !== 0
        ) {
            throw new TypeError(
                'privateVssShareProofMaterialChunkSources requires transported private VSS proof material references.',
            );
        }
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
    const chunkSourcesByRoot = proofMaterialChunkSourcesByRoot(
        input.privateVssShareProofMaterialChunkSources,
        'privateVssShareProofMaterialChunkSources',
    );
    const proofMaterials: JsonRecord[] = [];
    for (
        let proofMaterialIndex = 0;
        proofMaterialIndex < materialSet.proofMaterials.length;
        proofMaterialIndex += 1
    ) {
        const proofMaterialValue =
            materialSet.proofMaterials[proofMaterialIndex];
        if (
            proofMaterialValue === null ||
            typeof proofMaterialValue !== 'object'
        ) {
            throw new TypeError(
                'A transported private VSS proof material must be an object.',
            );
        }
        const proofMaterial = proofMaterialValue as JsonRecord;
        const materialRoot = protocolHash(
            proofMaterial.proofMaterialRoot,
            `transportedPrivateVssShareProofMaterial.proofMaterials.${String(proofMaterialIndex)}.proofMaterialRoot`,
        );
        const pullChunk = chunkSourcesByRoot.get(materialRoot);
        if (pullChunk === undefined) {
            throw new TypeError(
                `transportedPrivateVssShareProofMaterial.proofMaterials.${String(proofMaterialIndex)} has no canonical chunk source.`,
            );
        }
        await authenticateCanonicalProofMaterial(runtime, {
            descriptorBytes: canonicalDescriptorBytes(
                proofMaterial.descriptorBytes,
                `transportedPrivateVssShareProofMaterial.proofMaterials.${String(proofMaterialIndex)}.descriptorBytes`,
            ),
            family: bgvCanonicalStreamFamilies.vssOpeningCarry,
            materialRoot,
            pullChunk,
        });
        chunkSourcesByRoot.delete(materialRoot);
        const { descriptorBytes: omittedDescriptorBytes, ...reference } =
            proofMaterial;
        void omittedDescriptorBytes;
        proofMaterials.push(reference);
    }
    if (chunkSourcesByRoot.size !== 0) {
        throw new TypeError(
            'privateVssShareProofMaterialChunkSources must match transported proof material references exactly.',
        );
    }

    return {
        ...input,
        transportedPrivateVssShareProofMaterial: {
            ...materialSet,
            proofMaterials,
        },
    };
};
