import {
    copyCanonicalStreamDescriptor,
    createSetupPackageVerificationInput,
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
    SetupMaterialStream,
    SetupProofMaterialStreamSet,
    VerifyPrivateVssShareInput,
    VerifySetupPackageInput,
} from './index.js';

type JsonRecord = Record<string, unknown>;

type KernelSetupPackageVerificationInput = Parameters<
    AcceptedSetupSession['verifyCollectiveBgvSetup']
>[0];

type KernelPrivateVssShareVerificationInput = Parameters<
    PublishedSdkKernel['verifyPrivateVssShareEnvelope']
>[0];

type SetupProofMaterialTransportFieldName =
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

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

const materialStreamSnapshot = (
    streamValue: unknown,
    streamPath: string,
): SetupMaterialStream => {
    const streamDescriptors = plainRecordDescriptors(streamValue, streamPath);
    const descriptorBytes = copyCanonicalStreamDescriptor(
        dataPropertyValue(
            streamDescriptors,
            'descriptorBytes',
            `${streamPath}.descriptorBytes`,
        ),
        `${streamPath}.descriptorBytes`,
    );
    const pullChunkValue = dataPropertyValue(
        streamDescriptors,
        'pullChunk',
        `${streamPath}.pullChunk`,
    );
    if (typeof pullChunkValue !== 'function') {
        throw new TypeError(`${streamPath}.pullChunk must be a function.`);
    }

    return {
        descriptorBytes,
        pullChunk: pullChunkValue as SetupMaterialStream['pullChunk'],
    };
};

const materialStreamCollectionSnapshot = (
    streamCollectionValue: unknown,
    fieldPath: string,
    state: KernelJsonSnapshotState,
): readonly SetupMaterialStream[] => {
    const { descriptors, length } = ordinaryArrayDescriptors(
        streamCollectionValue,
        fieldPath,
    );
    chargeKernelJsonSnapshotValues(state, length + 1);
    const snapshots: SetupMaterialStream[] = [];
    for (let streamIndex = 0; streamIndex < length; streamIndex += 1) {
        const streamDescriptor = descriptors[String(streamIndex)];
        if (streamDescriptor === undefined) {
            throw new TypeError(`${fieldPath} cannot contain array holes.`);
        }
        if ('get' in streamDescriptor || 'set' in streamDescriptor) {
            throw new TypeError(
                `${fieldPath}.${String(streamIndex)} cannot be an accessor property.`,
            );
        }
        snapshots.push(
            materialStreamSnapshot(
                streamDescriptor.value,
                `${fieldPath}.${String(streamIndex)}`,
            ),
        );
    }

    return snapshots;
};

const proofMaterialStreamSetSnapshot = (
    materialSetValue: unknown,
    materialSetPath: string,
    state: KernelJsonSnapshotState,
): SetupProofMaterialStreamSet => {
    const materialSetDescriptors = plainRecordDescriptors(
        materialSetValue,
        materialSetPath,
    );
    const streamsPath = `${materialSetPath}.proofMaterialStreams`;

    return {
        proofMaterialStreams: materialStreamCollectionSnapshot(
            dataPropertyValue(
                materialSetDescriptors,
                'proofMaterialStreams',
                streamsPath,
            ),
            streamsPath,
            state,
        ),
    };
};

const optionalProofMaterialStreamSetSnapshot = (
    materialSetValue: unknown,
    materialSetPath: string,
    state: KernelJsonSnapshotState,
): SetupProofMaterialStreamSet | undefined =>
    materialSetValue === undefined
        ? undefined
        : proofMaterialStreamSetSnapshot(
              materialSetValue,
              materialSetPath,
              state,
          );

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
    const publicKeyShareMaterialStream = materialStreamSnapshot(
        dataPropertyValue(
            inputDescriptors,
            'publicKeyShareMaterialStream',
            'publicKeyShareMaterialStream',
        ),
        'publicKeyShareMaterialStream',
    );
    const transportedPublicKeyShareProofMaterial =
        proofMaterialStreamSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedPublicKeyShareProofMaterial',
                'transportedPublicKeyShareProofMaterial',
            ),
            'transportedPublicKeyShareProofMaterial',
            state,
        );
    const transportedVssShareLinkageProofMaterial =
        proofMaterialStreamSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedVssShareLinkageProofMaterial',
                'transportedVssShareLinkageProofMaterial',
            ),
            'transportedVssShareLinkageProofMaterial',
            state,
        );
    const transportedSameSecretBridgeProofMaterial =
        proofMaterialStreamSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedSameSecretBridgeProofMaterial',
                'transportedSameSecretBridgeProofMaterial',
            ),
            'transportedSameSecretBridgeProofMaterial',
            state,
        );
    const transportedEvaluationKeyShareProofMaterial =
        proofMaterialStreamSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedEvaluationKeyShareProofMaterial',
                'transportedEvaluationKeyShareProofMaterial',
            ),
            'transportedEvaluationKeyShareProofMaterial',
            state,
        );
    const evaluationKeyShareComponentMaterialStreams =
        materialStreamCollectionSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'evaluationKeyShareComponentMaterialStreams',
                'evaluationKeyShareComponentMaterialStreams',
            ),
            'evaluationKeyShareComponentMaterialStreams',
            state,
        );
    return {
        setupPackage,
        expectedManifestHash,
        expectedRosterHash,
        ...(expectedSetupPackageHash === undefined
            ? {}
            : { expectedSetupPackageHash }),
        publicKeyShareMaterialStream,
        transportedPublicKeyShareProofMaterial,
        transportedVssShareLinkageProofMaterial,
        transportedSameSecretBridgeProofMaterial,
        transportedEvaluationKeyShareProofMaterial,
        evaluationKeyShareComponentMaterialStreams,
    };
};

const protocolHash = (value: unknown, fieldPath: string): string => {
    if (typeof value !== 'string' || !/^[0-9a-f]{128}$/u.test(value)) {
        throw new TypeError(`${fieldPath} must be a protocol hash.`);
    }
    return value;
};

const authenticateCanonicalProofMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    input: Readonly<{
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly proofBytesHash: string;
        readonly pullChunk: SetupMaterialStream['pullChunk'];
    }>,
): Promise<void> => {
    await runtime.readMaterial({
        descriptorBytes: input.descriptorBytes,
        family: input.family,
        materialRoot: input.proofBytesHash,
        pullChunk: input.pullChunk,
    });
};

const streamPublicKeyShareMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    setupPackage: VerifySetupPackageInput['setupPackage'],
    materialStream: SetupMaterialStream,
): Promise<void> => {
    const setupPackageRecord = evaluationKeyComponentRecord(
        setupPackage,
        'setupPackage',
        'SetupPackage',
    );
    const publicKeyShareMaterial = evaluationKeyComponentRecord(
        setupPackageRecord.publicKeyShareMaterial,
        'setupPackage.publicKeyShareMaterial',
        'PublicKeyShareMaterialSet',
    );
    const materialRoot = protocolHash(
        publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        'setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot',
    );
    if (typeof materialStream.pullChunk !== 'function') {
        throw new TypeError(
            'publicKeyShareMaterialStream.pullChunk must be a function.',
        );
    }
    await runtime.readMaterial({
        descriptorBytes: ownedCanonicalDescriptorBytes(
            materialStream.descriptorBytes,
            'publicKeyShareMaterialStream.descriptorBytes',
        ),
        family: bgvCanonicalStreamFamilies.publicKeyShareMaterial,
        materialRoot,
        pullChunk: materialStream.pullChunk,
    });
};

const proofBytesHashesFromArray = (
    record: JsonRecord,
    fieldName: string,
    fieldPath: string,
): readonly string[] =>
    Array.from(
        evaluationKeyComponentRecordArray(record, fieldName, fieldPath),
        (value, proofIndex) =>
            protocolHash(value, `${fieldPath}.${String(proofIndex)}`),
    );

const setupProofBytesHashesInCanonicalOrder = (
    setupPackage: VerifySetupPackageInput['setupPackage'],
    fieldName: SetupProofMaterialTransportFieldName,
): readonly string[] => {
    const setupPackageRecord = evaluationKeyComponentRecord(
        setupPackage,
        'setupPackage',
        'SetupPackage',
    );
    if (fieldName === 'transportedPublicKeyShareProofMaterial') {
        const proofSetPath = 'setupPackage.publicKeyShareSuccinctProofs';
        const proofSet = evaluationKeyComponentRecord(
            setupPackageRecord.publicKeyShareSuccinctProofs,
            proofSetPath,
            'PublicKeyShareSuccinctProofSet',
        );
        return proofBytesHashesFromArray(
            proofSet,
            'proofBytesHashes',
            `${proofSetPath}.proofBytesHashes`,
        );
    }
    if (fieldName === 'transportedVssShareLinkageProofMaterial') {
        const proofSetPath = 'setupPackage.vssShareLinkageProofMaterialSet';
        const proofSet = evaluationKeyComponentRecord(
            setupPackageRecord.vssShareLinkageProofMaterialSet,
            proofSetPath,
            'VssShareLinkageProofMaterialSet',
        );
        return Array.from(
            evaluationKeyComponentRecordArray(
                proofSet,
                'proofRecords',
                `${proofSetPath}.proofRecords`,
            ),
            (proofRecordValue, proofIndex) => {
                const proofRecordPath = `${proofSetPath}.proofRecords.${String(proofIndex)}`;
                const proofRecord = evaluationKeyComponentRecord(
                    proofRecordValue,
                    proofRecordPath,
                    'VssShareLinkageProofRecord',
                );
                return protocolHash(
                    proofRecord.proofBytesHash,
                    `${proofRecordPath}.proofBytesHash`,
                );
            },
        );
    }
    if (fieldName === 'transportedSameSecretBridgeProofMaterial') {
        const proofSetPath = 'setupPackage.sameSecretBridgeProofMaterialSet';
        const proofSet = evaluationKeyComponentRecord(
            setupPackageRecord.sameSecretBridgeProofMaterialSet,
            proofSetPath,
            'VssSameSecretBridgeProofMaterialSet',
        );
        return proofBytesHashesFromArray(
            proofSet,
            'proofBytesHashes',
            `${proofSetPath}.proofBytesHashes`,
        );
    }

    const proofSetPath = 'setupPackage.trusteeEvaluationKeyProofs';
    const proofSet = evaluationKeyComponentRecord(
        setupPackageRecord.trusteeEvaluationKeyProofs,
        proofSetPath,
        'TrusteeEvaluationKeyProofSet',
    );
    return proofBytesHashesFromArray(
        proofSet,
        'proofBytesHashes',
        `${proofSetPath}.proofBytesHashes`,
    );
};

const assertDistinctProofBytesHashes = (
    proofBytesHashes: readonly string[],
    fieldPath: string,
): void => {
    if (new Set(proofBytesHashes).size !== proofBytesHashes.length) {
        throw new TypeError(`${fieldPath} must not contain duplicate hashes.`);
    }
};

const streamSetupProofMaterialSet = async (
    runtime: BgvCanonicalStreamRuntime,
    setupPackage: VerifySetupPackageInput['setupPackage'],
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialStreamSet,
): Promise<void> => {
    if (!Array.isArray(materialSet.proofMaterialStreams)) {
        throw new TypeError(
            `${fieldName}.proofMaterialStreams must be an array.`,
        );
    }
    const proofBytesHashes = setupProofBytesHashesInCanonicalOrder(
        setupPackage,
        fieldName,
    );
    assertDistinctProofBytesHashes(proofBytesHashes, fieldName);
    const proofMaterialStreams: readonly unknown[] =
        materialSet.proofMaterialStreams;
    if (proofMaterialStreams.length !== proofBytesHashes.length) {
        throw new TypeError(
            `${fieldName}.proofMaterialStreams must contain one stream per authoritative setup-package proof hash in canonical order.`,
        );
    }
    for (const [materialIndex, proofBytesHash] of proofBytesHashes.entries()) {
        const streamPath = `${fieldName}.proofMaterialStreams.${String(materialIndex)}`;
        const proofMaterialStream = evaluationKeyComponentRecord(
            proofMaterialStreams[materialIndex],
            streamPath,
        );
        const pullChunkValue = proofMaterialStream.pullChunk;
        if (typeof pullChunkValue !== 'function') {
            throw new TypeError(`${streamPath}.pullChunk must be a function.`);
        }
        await authenticateCanonicalProofMaterial(runtime, {
            descriptorBytes: ownedCanonicalDescriptorBytes(
                proofMaterialStream.descriptorBytes,
                `${streamPath}.descriptorBytes`,
            ),
            family: setupProofMaterialFamilies[fieldName],
            proofBytesHash,
            pullChunk: pullChunkValue as SetupMaterialStream['pullChunk'],
        });
    }
};

type EvaluationKeyComponentReferenceFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';

const componentFamily = (
    proofFamily: EvaluationKeyComponentReferenceFamily,
): BgvCanonicalStreamFamily => {
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

const evaluationKeyComponentRecord = (
    value: unknown,
    fieldPath: string,
    expectedObjectType?: string,
): JsonRecord => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError(`${fieldPath} must be an object.`);
    }
    const record = value as JsonRecord;
    if (
        expectedObjectType !== undefined &&
        record.objectType !== expectedObjectType
    ) {
        throw new TypeError(
            `${fieldPath} must have objectType ${expectedObjectType}.`,
        );
    }

    return record;
};

const evaluationKeyComponentRecordArray = (
    record: JsonRecord,
    fieldName: string,
    fieldPath: string,
): readonly unknown[] => {
    const value = record[fieldName];
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldPath} must be an array.`);
    }

    return value;
};

type EvaluationKeyComponentReference = Readonly<{
    readonly root: string;
    readonly proofFamily: EvaluationKeyComponentReferenceFamily;
}>;

const evaluationKeyComponentReferencesInCanonicalOrder = (
    setupPackage: VerifySetupPackageInput['setupPackage'],
): readonly EvaluationKeyComponentReference[] => {
    const setupPackageRecord = evaluationKeyComponentRecord(
        setupPackage,
        'setupPackage',
        'SetupPackage',
    );
    const references: EvaluationKeyComponentReference[] = [];
    const referenceRoots = new Set<string>();
    const addReferences = (
        roots: readonly unknown[],
        fieldPath: string,
        referenceFamily: EvaluationKeyComponentReferenceFamily,
    ): void => {
        roots.forEach((rootValue, rootIndex) => {
            const rootPath = `${fieldPath}.${String(rootIndex)}`;
            const root = protocolHash(rootValue, rootPath);
            if (referenceRoots.has(root)) {
                throw new TypeError(
                    'Setup-package evaluation-key component references contain a duplicate material root.',
                );
            }
            referenceRoots.add(root);
            references.push({ root, proofFamily: referenceFamily });
        });
    };

    const relinearizationRounds = evaluationKeyComponentRecord(
        setupPackageRecord.relinearizationKeyShareRounds,
        'setupPackage.relinearizationKeyShareRounds',
        'RelinearizationKeyShareRounds',
    );
    addReferences(
        evaluationKeyComponentRecordArray(
            relinearizationRounds,
            'roundOneKeySwitchComponentMaterialRoots',
            'setupPackage.relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots',
        ),
        'setupPackage.relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots',
        'relinearization-key-share',
    );
    addReferences(
        evaluationKeyComponentRecordArray(
            relinearizationRounds,
            'roundTwoKeySwitchComponentMaterialRoots',
            'setupPackage.relinearizationKeyShareRounds.roundTwoKeySwitchComponentMaterialRoots',
        ),
        'setupPackage.relinearizationKeyShareRounds.roundTwoKeySwitchComponentMaterialRoots',
        'relinearization-key-share',
    );

    const galoisBatches = evaluationKeyComponentRecordArray(
        setupPackageRecord,
        'galoisKeyShareBatches',
        'setupPackage.galoisKeyShareBatches',
    );
    galoisBatches.forEach((batchValue, batchIndex) => {
        const batchPath = `setupPackage.galoisKeyShareBatches.${String(batchIndex)}`;
        const batch = evaluationKeyComponentRecord(
            batchValue,
            batchPath,
            'GaloisKeyShareBatch',
        );
        addReferences(
            evaluationKeyComponentRecordArray(
                batch,
                'keySwitchComponentMaterialRoots',
                `${batchPath}.keySwitchComponentMaterialRoots`,
            ),
            `${batchPath}.keySwitchComponentMaterialRoots`,
            'galois-key-share',
        );
    });

    return references;
};

const streamEvaluationKeyShareComponentMaterial = async (
    runtime: BgvCanonicalStreamRuntime,
    setupPackage: VerifySetupPackageInput['setupPackage'],
    componentMaterialStreams: readonly SetupMaterialStream[],
): Promise<void> => {
    const componentMaterialStreamValues: unknown = componentMaterialStreams;
    if (!Array.isArray(componentMaterialStreamValues)) {
        throw new TypeError(
            'evaluationKeyShareComponentMaterialStreams must be an array.',
        );
    }
    const references =
        evaluationKeyComponentReferencesInCanonicalOrder(setupPackage);
    if (componentMaterialStreamValues.length !== references.length) {
        throw new TypeError(
            'evaluationKeyShareComponentMaterialStreams must contain one stream per setup-package evaluation-key component reference in canonical order.',
        );
    }
    for (const [streamIndex, reference] of references.entries()) {
        const streamPath = `evaluationKeyShareComponentMaterialStreams.${String(streamIndex)}`;
        const componentMaterialStream = evaluationKeyComponentRecord(
            componentMaterialStreamValues[streamIndex],
            streamPath,
        );
        const pullChunkValue = componentMaterialStream.pullChunk;
        if (typeof pullChunkValue !== 'function') {
            throw new TypeError(
                `${streamPath} must carry descriptorBytes and a pullChunk function.`,
            );
        }
        const pullChunk = pullChunkValue as SetupMaterialStream['pullChunk'];
        await runtime.readMaterial({
            descriptorBytes: ownedCanonicalDescriptorBytes(
                componentMaterialStream.descriptorBytes,
                `${streamPath}.descriptorBytes`,
            ),
            family: componentFamily(reference.proofFamily),
            materialRoot: reference.root,
            pullChunk,
        });
    }
};

const setupPackageVerificationInput = (
    input: VerifySetupPackageInput,
): KernelSetupPackageVerificationInput => {
    const verificationInput = createSetupPackageVerificationInput(input);

    return {
        ...verificationInput,
        ...(input.expectedSetupPackageHash === undefined
            ? {}
            : { expectedSetupPackageHash: input.expectedSetupPackageHash }),
    };
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
        descriptorSnapshotInput.setupPackage,
        descriptorSnapshotInput.publicKeyShareMaterialStream,
    );
    await streamEvaluationKeyShareComponentMaterial(
        runtime,
        descriptorSnapshotInput.setupPackage,
        descriptorSnapshotInput.evaluationKeyShareComponentMaterialStreams,
    );
    for (const fieldName of setupProofMaterialTransportFieldNames) {
        await streamSetupProofMaterialSet(
            runtime,
            descriptorSnapshotInput.setupPackage,
            fieldName,
            descriptorSnapshotInput[fieldName],
        );
    }

    return setupPackageVerificationInput(descriptorSnapshotInput);
};

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
        optionalProofMaterialStreamSetSnapshot(
            dataPropertyValue(
                inputDescriptors,
                'transportedPrivateVssShareProofMaterial',
                'transportedPrivateVssShareProofMaterial',
            ),
            'transportedPrivateVssShareProofMaterial',
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

    return {
        setupContext,
        publicMatrixSeedHash,
        sourceTrusteeCoefficientCommitmentRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords,
        privateEnvelope,
        ...(transportedPrivateVssShareProofMaterial === undefined
            ? {}
            : { transportedPrivateVssShareProofMaterial }),
        ...(expectedPrivateEnvelopeHash === undefined
            ? {}
            : { expectedPrivateEnvelopeHash }),
    };
};

const privateVssProofBytesHashesInEnvelopeOrder = (
    privateEnvelope: VerifyPrivateVssShareInput['privateEnvelope'],
): readonly string[] => {
    const privateEnvelopeRecord = evaluationKeyComponentRecord(
        privateEnvelope,
        'privateEnvelope',
        'PrivateVssShareEnvelope',
    );
    const openingsPath = 'privateEnvelope.rnsShareOpenings';
    return Array.from(
        evaluationKeyComponentRecordArray(
            privateEnvelopeRecord,
            'rnsShareOpenings',
            openingsPath,
        ),
        (openingValue, openingIndex) => {
            const openingPath = `${openingsPath}.${String(openingIndex)}`;
            const opening = evaluationKeyComponentRecord(
                openingValue,
                openingPath,
                'PrivateVssShareLimbOpening',
            );
            return protocolHash(
                opening.privateVssShareProofBytesHash,
                `${openingPath}.privateVssShareProofBytesHash`,
            );
        },
    );
};

export const prepareSnapshottedPrivateVssShareVerificationInputForKernel =
    async (
        kernel: PublishedSdkKernel,
        input: VerifyPrivateVssShareInput,
    ): Promise<KernelPrivateVssShareVerificationInput> => {
        const transportedMaterial =
            input.transportedPrivateVssShareProofMaterial;
        if (transportedMaterial !== undefined) {
            const proofMaterialStreams: readonly unknown[] =
                transportedMaterial.proofMaterialStreams;
            if (!Array.isArray(proofMaterialStreams)) {
                throw new TypeError(
                    'transportedPrivateVssShareProofMaterial.proofMaterialStreams must be an array.',
                );
            }
            const proofBytesHashes = privateVssProofBytesHashesInEnvelopeOrder(
                input.privateEnvelope,
            );
            assertDistinctProofBytesHashes(
                proofBytesHashes,
                'privateEnvelope.rnsShareOpenings',
            );
            if (proofMaterialStreams.length !== proofBytesHashes.length) {
                throw new TypeError(
                    'transportedPrivateVssShareProofMaterial.proofMaterialStreams must contain one stream per private-envelope proof hash in opening order.',
                );
            }
            const runtime = openBgvCanonicalStreamRuntime({ kernel });
            for (const [
                proofMaterialIndex,
                proofBytesHash,
            ] of proofBytesHashes.entries()) {
                const streamPath = `transportedPrivateVssShareProofMaterial.proofMaterialStreams.${String(proofMaterialIndex)}`;
                const proofMaterialStream = evaluationKeyComponentRecord(
                    proofMaterialStreams[proofMaterialIndex],
                    streamPath,
                );
                const pullChunkValue = proofMaterialStream.pullChunk;
                if (typeof pullChunkValue !== 'function') {
                    throw new TypeError(
                        `${streamPath}.pullChunk must be a function.`,
                    );
                }
                await authenticateCanonicalProofMaterial(runtime, {
                    descriptorBytes: ownedCanonicalDescriptorBytes(
                        proofMaterialStream.descriptorBytes,
                        `${streamPath}.descriptorBytes`,
                    ),
                    family: bgvCanonicalStreamFamilies.vssOpeningCarry,
                    proofBytesHash,
                    pullChunk:
                        pullChunkValue as SetupMaterialStream['pullChunk'],
                });
            }
        }

        return {
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            sourceTrusteeCoefficientCommitmentRecord:
                input.sourceTrusteeCoefficientCommitmentRecord,
            sourceTrusteeCoefficientCommitmentMaterialRecords:
                input.sourceTrusteeCoefficientCommitmentMaterialRecords,
            privateEnvelope: input.privateEnvelope,
            expectedPrivateEnvelopeHash: input.expectedPrivateEnvelopeHash,
        };
    };
