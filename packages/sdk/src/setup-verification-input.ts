import {
    copyCanonicalStreamDescriptor,
    createSetupPackageVerificationInput,
} from '@sealed-lattice/protocol';
import type {
    EvaluationKeyShareComponentMaterialChunkSource,
    PublicKeyShareMaterialChunkSource,
    PublicEvaluationKeyMaterialChunkSource,
    SetupProofMaterialChunkSource,
    SetupPackageVerificationInput,
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
    type AcceptedSetupSession,
    type BgvCanonicalStreamFamily,
    type BgvCanonicalStreamRuntime,
    type PublishedSdkKernel,
} from '@sealed-lattice/wasm/published-sdk';

import {
    chargeKernelJsonSnapshotValues,
    createKernelJsonSnapshotState,
    dataPropertyValue,
    ordinaryArrayDescriptors,
    plainRecordDescriptors,
    snapshotKernelJsonValue,
    type KernelJsonSnapshotState,
} from './kernel-json-snapshot.js';

import type {
    VerifyPrivateVssShareInput,
    VerifySetupPackageInput,
} from './index.js';

type JsonRecord = Record<string, unknown>;

type KernelSetupPackageVerificationInput = Parameters<
    AcceptedSetupSession['verifyCollectiveBgvSetup']
>[0];

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

const ownedCanonicalDescriptorBytes = (
    value: unknown,
    fieldPath: string,
): Uint8Array => {
    if (
        !ArrayBuffer.isView(value) ||
        Object.prototype.toString.call(value) !== '[object Uint8Array]'
    ) {
        throw new TypeError(`${fieldPath} must be a Uint8Array.`);
    }

    return value as Uint8Array;
};

const snapshotJsonRecordWithoutProperties = (
    value: unknown,
    valuePath: string,
    omittedPropertyNames: ReadonlySet<string>,
    state: KernelJsonSnapshotState,
): JsonRecord => {
    const descriptors = plainRecordDescriptors(value, valuePath);
    const snapshotCandidate = Object.create(
        Reflect.getPrototypeOf(value as object),
    ) as JsonRecord;
    for (const propertyKey of Reflect.ownKeys(descriptors)) {
        if (
            typeof propertyKey === 'string' &&
            omittedPropertyNames.has(propertyKey)
        ) {
            continue;
        }
        const descriptor = descriptors[propertyKey];
        if (descriptor !== undefined) {
            Object.defineProperty(snapshotCandidate, propertyKey, descriptor);
        }
    }
    const snapshot = snapshotKernelJsonValue(
        snapshotCandidate,
        valuePath,
        state,
    );
    if (snapshot === null || typeof snapshot !== 'object') {
        throw new TypeError(`${valuePath} must be a plain object.`);
    }

    return snapshot as JsonRecord;
};

const descriptorBackedMaterialSnapshot = (
    materialValue: unknown,
    materialPath: string,
    state: KernelJsonSnapshotState,
): JsonRecord => {
    const descriptors = plainRecordDescriptors(materialValue, materialPath);
    const descriptorBytes = copyCanonicalStreamDescriptor(
        dataPropertyValue(
            descriptors,
            'descriptorBytes',
            `${materialPath}.descriptorBytes`,
        ),
        `${materialPath}.descriptorBytes`,
    );
    const materialSnapshot = snapshotJsonRecordWithoutProperties(
        materialValue,
        materialPath,
        new Set(['descriptorBytes']),
        state,
    );

    return { ...materialSnapshot, descriptorBytes };
};

const descriptorBackedMaterialSetSnapshot = (
    materialSetValue: unknown,
    materialSetPath: string,
    materialArrayFieldName: string,
    state: KernelJsonSnapshotState,
): JsonRecord | undefined => {
    if (materialSetValue === undefined) {
        return undefined;
    }
    const materialSetDescriptors = plainRecordDescriptors(
        materialSetValue,
        materialSetPath,
    );
    const materialsPath = `${materialSetPath}.${materialArrayFieldName}`;
    const { descriptors: materialDescriptors, length: materialCount } =
        ordinaryArrayDescriptors(
            dataPropertyValue(
                materialSetDescriptors,
                materialArrayFieldName,
                materialsPath,
            ),
            materialsPath,
        );
    chargeKernelJsonSnapshotValues(state, materialCount + 1);
    const materialSnapshots: JsonRecord[] = [];
    for (
        let materialIndex = 0;
        materialIndex < materialCount;
        materialIndex += 1
    ) {
        const materialDescriptor = materialDescriptors[String(materialIndex)];
        if (materialDescriptor === undefined) {
            throw new TypeError(`${materialsPath} cannot contain array holes.`);
        }
        if ('get' in materialDescriptor || 'set' in materialDescriptor) {
            throw new TypeError(
                `${materialsPath}.${String(materialIndex)} cannot be an accessor property.`,
            );
        }
        materialSnapshots.push(
            descriptorBackedMaterialSnapshot(
                materialDescriptor.value,
                `${materialsPath}.${String(materialIndex)}`,
                state,
            ),
        );
    }
    const materialSetSnapshot = snapshotJsonRecordWithoutProperties(
        materialSetValue,
        materialSetPath,
        new Set([materialArrayFieldName]),
        state,
    );

    return {
        ...materialSetSnapshot,
        [materialArrayFieldName]: materialSnapshots,
    };
};

const chunkSourceSnapshot = <ChunkSource extends object>(
    chunkSourceValue: unknown,
    fieldPath: string,
    jsonFieldNames: readonly string[],
    state: KernelJsonSnapshotState,
): ChunkSource | undefined => {
    if (chunkSourceValue === undefined) {
        return undefined;
    }
    const descriptors = plainRecordDescriptors(chunkSourceValue, fieldPath);
    const snapshot: JsonRecord = {};
    for (const jsonFieldName of jsonFieldNames) {
        snapshot[jsonFieldName] = snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                jsonFieldName,
                `${fieldPath}.${jsonFieldName}`,
            ),
            `${fieldPath}.${jsonFieldName}`,
            state,
        );
    }
    const pullChunk = dataPropertyValue(
        descriptors,
        'pullChunk',
        `${fieldPath}.pullChunk`,
    );
    if (typeof pullChunk !== 'function') {
        throw new TypeError(`${fieldPath}.pullChunk must be a function.`);
    }

    return { ...snapshot, pullChunk } as ChunkSource;
};

const chunkSourceCollectionSnapshot = <ChunkSource extends object>(
    chunkSourceCollectionValue: unknown,
    fieldPath: string,
    jsonFieldNames: readonly string[],
    state: KernelJsonSnapshotState,
): readonly ChunkSource[] | undefined => {
    if (chunkSourceCollectionValue === undefined) {
        return undefined;
    }
    const { descriptors, length } = ordinaryArrayDescriptors(
        chunkSourceCollectionValue,
        fieldPath,
    );
    chargeKernelJsonSnapshotValues(state, length + 1);
    const snapshots: ChunkSource[] = [];
    for (let sourceIndex = 0; sourceIndex < length; sourceIndex += 1) {
        const descriptor = descriptors[String(sourceIndex)];
        if (descriptor === undefined) {
            throw new TypeError(`${fieldPath} cannot contain array holes.`);
        }
        if ('get' in descriptor || 'set' in descriptor) {
            throw new TypeError(
                `${fieldPath}.${String(sourceIndex)} cannot be an accessor property.`,
            );
        }
        const snapshot = chunkSourceSnapshot<ChunkSource>(
            descriptor.value,
            `${fieldPath}.${String(sourceIndex)}`,
            jsonFieldNames,
            state,
        );
        if (snapshot === undefined) {
            throw new TypeError(
                `${fieldPath}.${String(sourceIndex)} must be an object.`,
            );
        }
        snapshots.push(snapshot);
    }

    return snapshots;
};

export const snapshotSetupPackageVerificationInput = (
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    const inputDescriptors = plainRecordDescriptors(input, 'input');
    const state = createKernelJsonSnapshotState();
    const setupPackage = snapshotKernelJsonValue(
        dataPropertyValue(inputDescriptors, 'setupPackage', 'setupPackage'),
        'setupPackage',
        state,
    );
    const expectedSetupPackageHash = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'expectedSetupPackageHash',
            'expectedSetupPackageHash',
        ),
        'expectedSetupPackageHash',
        state,
    ) as VerifySetupPackageInput['expectedSetupPackageHash'];
    const expectedManifestHash = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'expectedManifestHash',
            'expectedManifestHash',
        ),
        'expectedManifestHash',
        state,
    ) as VerifySetupPackageInput['expectedManifestHash'];
    const expectedRosterHash = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'expectedRosterHash',
            'expectedRosterHash',
        ),
        'expectedRosterHash',
        state,
    ) as VerifySetupPackageInput['expectedRosterHash'];
    const transportedPublicKeyShareMaterial =
        dataPropertyValue(
            inputDescriptors,
            'transportedPublicKeyShareMaterial',
            'transportedPublicKeyShareMaterial',
        ) === undefined
            ? undefined
            : descriptorBackedMaterialSnapshot(
                  dataPropertyValue(
                      inputDescriptors,
                      'transportedPublicKeyShareMaterial',
                      'transportedPublicKeyShareMaterial',
                  ),
                  'transportedPublicKeyShareMaterial',
                  state,
              );
    const transportedPublicKeyShareProofMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedPublicKeyShareProofMaterial',
                'transportedPublicKeyShareProofMaterial',
            ),
            'transportedPublicKeyShareProofMaterial',
            'proofMaterials',
            state,
        );
    const transportedVssShareLinkageProofMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedVssShareLinkageProofMaterial',
                'transportedVssShareLinkageProofMaterial',
            ),
            'transportedVssShareLinkageProofMaterial',
            'proofMaterials',
            state,
        );
    const transportedSameSecretBridgeProofMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedSameSecretBridgeProofMaterial',
                'transportedSameSecretBridgeProofMaterial',
            ),
            'transportedSameSecretBridgeProofMaterial',
            'proofMaterials',
            state,
        );
    const transportedEvaluationKeyShareProofMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedEvaluationKeyShareProofMaterial',
                'transportedEvaluationKeyShareProofMaterial',
            ),
            'transportedEvaluationKeyShareProofMaterial',
            'proofMaterials',
            state,
        );
    const transportedEvaluationKeyShareComponentMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedEvaluationKeyShareComponentMaterial',
                'transportedEvaluationKeyShareComponentMaterial',
            ),
            'transportedEvaluationKeyShareComponentMaterial',
            'componentMaterials',
            state,
        );
    const transportedPublicEvaluationKeyMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedPublicEvaluationKeyMaterial',
                'transportedPublicEvaluationKeyMaterial',
            ),
            'transportedPublicEvaluationKeyMaterial',
            'publicEvaluationKeyMaterials',
            state,
        );
    const publicKeyShareMaterialChunkSource =
        chunkSourceSnapshot<PublicKeyShareMaterialChunkSource>(
            dataPropertyValue(
                inputDescriptors,
                'publicKeyShareMaterialChunkSource',
                'publicKeyShareMaterialChunkSource',
            ),
            'publicKeyShareMaterialChunkSource',
            ['publicKeyShareMaterialSetRoot'],
            state,
        );
    const setupProofMaterialChunkSources =
        chunkSourceCollectionSnapshot<SetupProofMaterialChunkSource>(
            dataPropertyValue(
                inputDescriptors,
                'setupProofMaterialChunkSources',
                'setupProofMaterialChunkSources',
            ),
            'setupProofMaterialChunkSources',
            ['proofMaterialRoot'],
            state,
        );
    const evaluationKeyShareComponentMaterialChunkSources =
        chunkSourceCollectionSnapshot<EvaluationKeyShareComponentMaterialChunkSource>(
            dataPropertyValue(
                inputDescriptors,
                'evaluationKeyShareComponentMaterialChunkSources',
                'evaluationKeyShareComponentMaterialChunkSources',
            ),
            'evaluationKeyShareComponentMaterialChunkSources',
            ['keySwitchComponentMaterialRoot', 'proofFamily'],
            state,
        );
    const publicEvaluationKeyMaterialChunkSources =
        chunkSourceCollectionSnapshot<PublicEvaluationKeyMaterialChunkSource>(
            dataPropertyValue(
                inputDescriptors,
                'publicEvaluationKeyMaterialChunkSources',
                'publicEvaluationKeyMaterialChunkSources',
            ),
            'publicEvaluationKeyMaterialChunkSources',
            ['publicEvaluationKeyMaterialRoot'],
            state,
        );
    return {
        setupPackage,
        expectedManifestHash,
        expectedRosterHash,
        ...(expectedSetupPackageHash === undefined
            ? {}
            : { expectedSetupPackageHash }),
        ...(transportedPublicKeyShareMaterial === undefined
            ? {}
            : { transportedPublicKeyShareMaterial }),
        ...(transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : { transportedPublicKeyShareProofMaterial }),
        ...(transportedVssShareLinkageProofMaterial === undefined
            ? {}
            : { transportedVssShareLinkageProofMaterial }),
        ...(transportedSameSecretBridgeProofMaterial === undefined
            ? {}
            : { transportedSameSecretBridgeProofMaterial }),
        ...(transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : { transportedEvaluationKeyShareProofMaterial }),
        ...(transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : { transportedEvaluationKeyShareComponentMaterial }),
        ...(transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : { transportedPublicEvaluationKeyMaterial }),
        ...(publicKeyShareMaterialChunkSource === undefined
            ? {}
            : { publicKeyShareMaterialChunkSource }),
        ...(setupProofMaterialChunkSources === undefined
            ? {}
            : { setupProofMaterialChunkSources }),
        ...(evaluationKeyShareComponentMaterialChunkSources === undefined
            ? {}
            : { evaluationKeyShareComponentMaterialChunkSources }),
        ...(publicEvaluationKeyMaterialChunkSources === undefined
            ? {}
            : { publicEvaluationKeyMaterialChunkSources }),
    } as unknown as VerifySetupPackageInput;
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
        descriptorBytes: ownedCanonicalDescriptorBytes(
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
            descriptorBytes: ownedCanonicalDescriptorBytes(
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
            descriptorBytes: ownedCanonicalDescriptorBytes(
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
            descriptorBytes: ownedCanonicalDescriptorBytes(
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
): KernelSetupPackageVerificationInput => {
    const verificationInput = createSetupPackageVerificationInput(
        input as unknown as SetupPackageVerificationInputSource,
    );

    const verificationInputWithExpectedPackageHash:
        | SetupPackageVerificationInput
        | (SetupPackageVerificationInput & {
              readonly expectedSetupPackageHash: string;
          }) =
        input.expectedSetupPackageHash === undefined
            ? verificationInput
            : {
                  ...verificationInput,
                  expectedSetupPackageHash: input.expectedSetupPackageHash,
              };

    return verificationInputWithExpectedPackageHash as KernelSetupPackageVerificationInput;
};

export const prepareSnapshottedSetupPackageVerificationInputForKernel = async (
    kernel: PublishedSdkKernel,
    input: VerifySetupPackageInput,
    acceptedSetupSession: AcceptedSetupSession,
): Promise<KernelSetupPackageVerificationInput> => {
    const descriptorSnapshotInput = input;
    const runtime = openBgvCanonicalStreamRuntime({
        acceptedSetupSession,
        kernel,
    });
    await streamPublicKeyShareMaterial(
        runtime,
        descriptorSnapshotInput.transportedPublicKeyShareMaterial,
        descriptorSnapshotInput.publicKeyShareMaterialChunkSource,
    );
    await streamEvaluationKeyShareComponentMaterial(
        runtime,
        descriptorSnapshotInput.transportedEvaluationKeyShareComponentMaterial,
        descriptorSnapshotInput.evaluationKeyShareComponentMaterialChunkSources,
    );
    await streamPublicEvaluationKeyMaterial(
        runtime,
        descriptorSnapshotInput.transportedPublicEvaluationKeyMaterial,
        descriptorSnapshotInput.publicEvaluationKeyMaterialChunkSources,
    );
    const chunkSourcesByRoot = proofMaterialChunkSourcesByRoot(
        descriptorSnapshotInput.setupProofMaterialChunkSources,
        'setupProofMaterialChunkSources',
    );
    for (const fieldName of setupProofMaterialTransportFieldNames) {
        await streamSetupProofMaterialSet(
            runtime,
            fieldName,
            descriptorSnapshotInput[fieldName],
            chunkSourcesByRoot,
        );
    }
    if (chunkSourcesByRoot.size !== 0) {
        throw new TypeError(
            'setupProofMaterialChunkSources must match transported proof material references exactly.',
        );
    }

    return setupPackageVerificationInput(descriptorSnapshotInput);
};

export const prepareSetupPackageVerificationInputForKernel = (
    kernel: PublishedSdkKernel,
    acceptedSetupSession: AcceptedSetupSession,
    input: VerifySetupPackageInput,
): Promise<KernelSetupPackageVerificationInput> =>
    prepareSnapshottedSetupPackageVerificationInputForKernel(
        kernel,
        snapshotSetupPackageVerificationInput(input),
        acceptedSetupSession,
    );

export const snapshotPrivateVssShareVerificationInput = (
    input: VerifyPrivateVssShareInput,
): VerifyPrivateVssShareInput => {
    const inputDescriptors = plainRecordDescriptors(input, 'input');
    const state = createKernelJsonSnapshotState();
    const setupContext = snapshotKernelJsonValue(
        dataPropertyValue(inputDescriptors, 'setupContext', 'setupContext'),
        'setupContext',
        state,
    ) as VerifyPrivateVssShareInput['setupContext'];
    const publicMatrixSeedHash = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'publicMatrixSeedHash',
            'publicMatrixSeedHash',
        ),
        'publicMatrixSeedHash',
        state,
    ) as VerifyPrivateVssShareInput['publicMatrixSeedHash'];
    const sourceTrusteeCoefficientCommitmentRecord = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'sourceTrusteeCoefficientCommitmentRecord',
            'sourceTrusteeCoefficientCommitmentRecord',
        ),
        'sourceTrusteeCoefficientCommitmentRecord',
        state,
    );
    const sourceTrusteeCoefficientCommitmentMaterialRecords =
        snapshotKernelJsonValue(
            dataPropertyValue(
                inputDescriptors,
                'sourceTrusteeCoefficientCommitmentMaterialRecords',
                'sourceTrusteeCoefficientCommitmentMaterialRecords',
            ),
            'sourceTrusteeCoefficientCommitmentMaterialRecords',
            state,
        ) as VerifyPrivateVssShareInput['sourceTrusteeCoefficientCommitmentMaterialRecords'];
    const privateEnvelope = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'privateEnvelope',
            'privateEnvelope',
        ),
        'privateEnvelope',
        state,
    );
    const transportedPrivateVssShareProofMaterial =
        descriptorBackedMaterialSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedPrivateVssShareProofMaterial',
                'transportedPrivateVssShareProofMaterial',
            ),
            'transportedPrivateVssShareProofMaterial',
            'proofMaterials',
            state,
        );
    const privateVssShareProofMaterialChunkSources =
        chunkSourceCollectionSnapshot<SetupProofMaterialChunkSource>(
            dataPropertyValue(
                inputDescriptors,
                'privateVssShareProofMaterialChunkSources',
                'privateVssShareProofMaterialChunkSources',
            ),
            'privateVssShareProofMaterialChunkSources',
            ['proofMaterialRoot'],
            state,
        );
    const expectedPrivateEnvelopeHash = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'expectedPrivateEnvelopeHash',
            'expectedPrivateEnvelopeHash',
        ),
        'expectedPrivateEnvelopeHash',
        state,
    ) as VerifyPrivateVssShareInput['expectedPrivateEnvelopeHash'];
    const expectedLocalVerificationRoot = snapshotKernelJsonValue(
        dataPropertyValue(
            inputDescriptors,
            'expectedLocalVerificationRoot',
            'expectedLocalVerificationRoot',
        ),
        'expectedLocalVerificationRoot',
        state,
    ) as VerifyPrivateVssShareInput['expectedLocalVerificationRoot'];

    return {
        setupContext,
        publicMatrixSeedHash,
        sourceTrusteeCoefficientCommitmentRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords,
        privateEnvelope,
        ...(transportedPrivateVssShareProofMaterial === undefined
            ? {}
            : { transportedPrivateVssShareProofMaterial }),
        ...(privateVssShareProofMaterialChunkSources === undefined
            ? {}
            : { privateVssShareProofMaterialChunkSources }),
        ...(expectedPrivateEnvelopeHash === undefined
            ? {}
            : { expectedPrivateEnvelopeHash }),
        ...(expectedLocalVerificationRoot === undefined
            ? {}
            : { expectedLocalVerificationRoot }),
    };
};

export const prepareSnapshottedPrivateVssShareVerificationInputForKernel =
    async (
        kernel: PublishedSdkKernel,
        input: VerifyPrivateVssShareInput,
    ): Promise<VerifyPrivateVssShareInput> => {
        const transportedMaterial =
            input.transportedPrivateVssShareProofMaterial as
                | JsonRecord
                | undefined;
        if (transportedMaterial === undefined) {
            if (
                (input.privateVssShareProofMaterialChunkSources?.length ??
                    0) !== 0
            ) {
                throw new TypeError(
                    'privateVssShareProofMaterialChunkSources requires transported private VSS proof material references.',
                );
            }
            return input;
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
                descriptorBytes: ownedCanonicalDescriptorBytes(
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
