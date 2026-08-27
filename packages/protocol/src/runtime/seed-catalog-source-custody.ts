import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';
import {
    isProductionSeedCatalogSourceCustodyKernel,
    type ProductionSeedCatalogSourceCustodyKernel,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    bytesEqual,
    copyExactBytes,
    mapStorageError,
    readRuntimeRecord,
    runtimeRecordEnvelopeOverheadByteLength,
    sampleRuntimeSecretBytes,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
} from './authenticated-runtime-record.js';
import { AuthenticatedStorageRecencyCoordinator } from './authenticated-storage-recency.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const sourceCustodyRecordMagic = Uint8Array.of(0x53, 0x4c, 0x43, 0x53);
const sourceCustodyRecordVersion = 1;
const reservedRecordKind = 1;
const retainedRecordKind = 2;
const hashByteLength = 64;
const preparationAttemptOrdinal = 0;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const sourceCustodyOperationDomain =
    'sealed-lattice/runtime/seed-catalog-source-custody-record/v1';

export type SeedCatalogSourceCustodyContext = Readonly<{
    actionContextIdentity: Uint8Array;
    catalogCompilerIdentity: Uint8Array;
    parameterIdentity: Uint8Array;
    participantCount: number;
    participantPosition: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    rosterIdentity: Uint8Array;
    statePredecessorIdentity: Uint8Array;
}>;

export type SeedCatalogSourceCustodyGeometry = Readonly<{
    commitmentSaltByteLength: number;
    deliverySourcePayloadByteLengths: readonly number[];
    inclusionProofByteLength: number;
    leafOpeningByteLengths: readonly number[];
    rootBodyByteLength: number;
    sourceContributionByteLength: number;
}>;

export type SeedCatalogSourceCustodyLimits = Readonly<{
    maximumCatalogLeafCount: number;
    maximumCommitmentSaltByteLength: number;
    maximumDeliverySourcePayloadByteLength: number;
    maximumInclusionProofByteLength: number;
    maximumLeafOpeningByteLength: number;
    maximumRootBodyByteLength: number;
    maximumSourceContributionByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

export type SeedCatalogSourceLeaf = Readonly<{
    commitmentSalt: Uint8Array;
    sourceContribution: Uint8Array;
}>;

export type SeedCatalogSourceInventory = readonly SeedCatalogSourceLeaf[];

export type RetainedLocalSeedCatalogEntry = Readonly<{
    inclusionProofBytes: Uint8Array;
    openingBytes: Uint8Array;
}>;

/**
 * Exact local catalog bytes durably retained before the root is returned.
 *
 * These bytes are inert local custody. They do not authorize root publication,
 * delivery, receipt, key combination, coin opening, burn, or preparation
 * continuation.
 */
export type RetainedLocalSeedCatalog = Readonly<{
    catalogIdentity: Uint8Array;
    entries: readonly RetainedLocalSeedCatalogEntry[];
    rootBodyBytes: Uint8Array;
}>;

/**
 * One exact precomputed delivery plaintext for a canonical recipient.
 *
 * This is neither an authenticated mailbox carrier nor a verified delivery.
 */
export type RetainedSeedCatalogDeliverySource = Readonly<{
    recipientPosition: number;
    sourcePayloadBytes: Uint8Array;
}>;

export type SeedCatalogProductionInput = Readonly<{
    context: SeedCatalogSourceCustodyContext;
    geometry: SeedCatalogSourceCustodyGeometry;
    sourceInventory: SeedCatalogSourceInventory;
}>;

export type SeedCatalogValidationInput = SeedCatalogProductionInput &
    Readonly<{
        catalog: RetainedLocalSeedCatalog;
    }>;

export type SeedCatalogDeliverySourceProductionInput =
    SeedCatalogValidationInput &
        Readonly<{
            recipientPosition: number;
        }>;

export type SeedCatalogDeliverySourceValidationInput =
    SeedCatalogDeliverySourceProductionInput &
        Readonly<{
            sourcePayloadBytes: Uint8Array;
        }>;

export type SeedCatalogSourceCustodyKernel = Readonly<{
    produceCatalog(
        input: SeedCatalogProductionInput,
    ): Promise<RetainedLocalSeedCatalog> | RetainedLocalSeedCatalog;
    produceDeliverySource(
        input: SeedCatalogDeliverySourceProductionInput,
    ):
        | Promise<RetainedSeedCatalogDeliverySource>
        | RetainedSeedCatalogDeliverySource;
    validateCatalog(input: SeedCatalogValidationInput): Promise<void> | void;
    validateDeliverySource(
        input: SeedCatalogDeliverySourceValidationInput,
    ): Promise<void> | void;
}>;

type SeedCatalogSourceCustodyRecordByteLengths = Readonly<{
    completedCiphertextByteLength: number;
    completedPlaintextByteLength: number;
    cumulativeCheckpointCiphertextWriteByteLength: number;
    deliveryCheckpointCiphertextByteLengths: readonly number[];
    deliveryCheckpointPlaintextByteLengths: readonly number[];
    maximumColdRestartReadByteLength: number;
    maximumCopyOnWriteCiphertextOverlapByteLength: number;
    maximumUncommittedProductionByteLength: number;
    maximumUncommittedDeliverySourceByteLength: number;
    reservationCiphertextByteLength: number;
    reservationPlaintextByteLength: number;
    rootCheckpointCiphertextByteLength: number;
    rootCheckpointPlaintextByteLength: number;
    rootProductionOutputByteLength: number;
}>;

type SeedCatalogSourceCustodyKernelByteLengths = Readonly<{
    catalogProductionRequestByteLength: number;
    catalogProductionResponseByteLength: number;
    catalogValidationRequestByteLength: number;
    coldValidationCumulativeRequestByteLength: number;
    coldValidationInvocationCount: number;
    deliveryProductionRequestByteLengths: readonly number[];
    deliveryProductionResponseByteLengths: readonly number[];
    deliveryValidationRequestByteLengths: readonly number[];
    maximumKernelInputByteLength: number;
    maximumKernelResponseByteLength: number;
    successPathCumulativeRequestByteLength: number;
    successPathCumulativeResponseByteLength: number;
    successPathInvocationCount: number;
    validationResponseByteLength: number;
}>;

type ReservedSeedCatalogSourceRecord = Readonly<{
    context: SeedCatalogSourceCustodyContext;
    geometry: SeedCatalogSourceCustodyGeometry;
    kind: 'reserved';
    sourceInventory: SeedCatalogSourceInventory;
}>;

type RetainedSeedCatalogSourceRecord = Readonly<{
    catalog: RetainedLocalSeedCatalog;
    context: SeedCatalogSourceCustodyContext;
    deliverySourcePayloads: readonly Uint8Array[];
    geometry: SeedCatalogSourceCustodyGeometry;
    kind: 'retained';
    sourceInventory: SeedCatalogSourceInventory;
}>;

type SeedCatalogSourceRecord =
    | ReservedSeedCatalogSourceRecord
    | RetainedSeedCatalogSourceRecord;

type OpenedSeedCatalogSourceRecord = Readonly<{
    record: SeedCatalogSourceRecord;
    sealedBytes: Uint8Array;
}>;

/**
 * Exact authenticated predecessor bytes admitted only for the local/global
 * master transition. The caller must erase both arrays after the transition.
 */
export type CompletedSeedCatalogSourceCustodyForMasterJoin = Readonly<{
    recordBytes: Uint8Array;
    recordKey: string;
    sealedBytes: Uint8Array;
}>;

export const snapshotSeedCatalogSourceCustodyLimitsForMasterJoin = (
    value: unknown,
): SeedCatalogSourceCustodyLimits => copyLimits(value);

const snapshotDataProperty = (
    container: unknown,
    propertyName: string,
    containerName: string,
): unknown => {
    if (
        container === null ||
        (typeof container !== 'object' && typeof container !== 'function')
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName} must be an object.`,
        );
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
        descriptor = Object.getOwnPropertyDescriptor(container, propertyName);
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must be an ordinary data property.`,
            error,
        );
    }
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const requireSafeInteger = (
    value: unknown,
    minimum: number,
    maximum: number,
    label: string,
    code: 'InvalidConfiguration' | 'InvalidInput' = 'InvalidInput',
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < minimum ||
        value > maximum
    ) {
        throw new AuthenticatedRuntimeRecordError(
            code,
            `${label} is outside the supported integer range.`,
        );
    }
    return value;
};

const checkedAdd = (left: number, right: number, label: string): number => {
    const result = left + right;
    if (!Number.isSafeInteger(result) || result > unsigned32Maximum) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the local record length range.`,
        );
    }
    return result;
};

const checkedMultiply = (
    left: number,
    right: number,
    label: string,
): number => {
    const result = left * right;
    if (!Number.isSafeInteger(result) || result > unsigned32Maximum) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the local record length range.`,
        );
    }
    return result;
};

const sumByteLengths = (
    byteLengths: readonly number[],
    label: string,
): number =>
    byteLengths.reduce(
        (total, byteLength) => checkedAdd(total, byteLength, label),
        0,
    );

const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const concatenateBytes = (
    parts: readonly Uint8Array[],
    expectedByteLength: number,
): Uint8Array => {
    const output = new Uint8Array(expectedByteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    if (offset !== expectedByteLength) {
        output.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Seed-catalog source custody encoded an unexpected byte length.',
        );
    }
    return output;
};

const copyNonzeroHash = (
    container: unknown,
    propertyName: string,
    containerName: string,
): Uint8Array => {
    const bytes = copyExactBytes(
        snapshotDataProperty(container, propertyName, containerName),
        hashByteLength,
        `${containerName}.${propertyName}`,
    );
    if (bytes.every((byte) => byte === 0)) {
        bytes.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must not be all zero.`,
        );
    }
    return bytes;
};

const copyContext = (value: unknown): SeedCatalogSourceCustodyContext => {
    const participantCount = requireSafeInteger(
        snapshotDataProperty(value, 'participantCount', 'context'),
        configurableParticipantCountRange.minimum,
        configurableParticipantCountRange.maximum,
        'context.participantCount',
        'InvalidConfiguration',
    );
    const participantPosition = requireSafeInteger(
        snapshotDataProperty(value, 'participantPosition', 'context'),
        0,
        participantCount - 1,
        'context.participantPosition',
        'InvalidConfiguration',
    );
    const attempt = requireSafeInteger(
        snapshotDataProperty(value, 'preparationAttemptOrdinal', 'context'),
        preparationAttemptOrdinal,
        preparationAttemptOrdinal,
        'context.preparationAttemptOrdinal',
        'InvalidConfiguration',
    );
    return Object.freeze({
        actionContextIdentity: copyNonzeroHash(
            value,
            'actionContextIdentity',
            'context',
        ),
        catalogCompilerIdentity: copyNonzeroHash(
            value,
            'catalogCompilerIdentity',
            'context',
        ),
        parameterIdentity: copyNonzeroHash(
            value,
            'parameterIdentity',
            'context',
        ),
        participantCount,
        participantPosition,
        preparationAttemptOrdinal: attempt,
        preparationContextIdentity: copyNonzeroHash(
            value,
            'preparationContextIdentity',
            'context',
        ),
        rosterIdentity: copyNonzeroHash(value, 'rosterIdentity', 'context'),
        statePredecessorIdentity: copyNonzeroHash(
            value,
            'statePredecessorIdentity',
            'context',
        ),
    });
};

const copyLimits = (value: unknown): SeedCatalogSourceCustodyLimits => {
    const readBufferLimit = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(value, propertyName, 'limits'),
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            `limits.${propertyName}`,
            'InvalidConfiguration',
        );
    const readSampledSecretLimit = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(value, propertyName, 'limits'),
            1,
            unsigned16Maximum,
            `limits.${propertyName}`,
            'InvalidConfiguration',
        );
    return Object.freeze({
        maximumCatalogLeafCount: requireSafeInteger(
            snapshotDataProperty(value, 'maximumCatalogLeafCount', 'limits'),
            1,
            unsigned16Maximum,
            'limits.maximumCatalogLeafCount',
            'InvalidConfiguration',
        ),
        maximumCommitmentSaltByteLength: readSampledSecretLimit(
            'maximumCommitmentSaltByteLength',
        ),
        maximumDeliverySourcePayloadByteLength: readBufferLimit(
            'maximumDeliverySourcePayloadByteLength',
        ),
        maximumInclusionProofByteLength: readBufferLimit(
            'maximumInclusionProofByteLength',
        ),
        maximumLeafOpeningByteLength: readBufferLimit(
            'maximumLeafOpeningByteLength',
        ),
        maximumRootBodyByteLength: readBufferLimit('maximumRootBodyByteLength'),
        maximumSourceContributionByteLength: readSampledSecretLimit(
            'maximumSourceContributionByteLength',
        ),
        transactionLifetimeMilliseconds: requireSafeInteger(
            snapshotDataProperty(
                value,
                'transactionLifetimeMilliseconds',
                'limits',
            ),
            1,
            Number.MAX_SAFE_INTEGER,
            'limits.transactionLifetimeMilliseconds',
            'InvalidConfiguration',
        ),
    });
};

const copyLengthArray = (input: {
    arrayName: string;
    maximumArrayLength: number;
    maximumByteLength: number;
    minimumArrayLength: number;
    value: unknown;
}): readonly number[] => {
    if (!Array.isArray(input.value)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${input.arrayName} must be an array.`,
        );
    }
    const arrayLength = requireSafeInteger(
        snapshotDataProperty(input.value, 'length', input.arrayName),
        input.minimumArrayLength,
        input.maximumArrayLength,
        `${input.arrayName}.length`,
    );
    return Object.freeze(
        Array.from({ length: arrayLength }, (_unused, arrayIndex) =>
            requireSafeInteger(
                snapshotDataProperty(
                    input.value,
                    String(arrayIndex),
                    input.arrayName,
                ),
                1,
                input.maximumByteLength,
                `${input.arrayName}[${arrayIndex}]`,
            ),
        ),
    );
};

const copyGeometry = (
    value: unknown,
    limits?: SeedCatalogSourceCustodyLimits,
): SeedCatalogSourceCustodyGeometry => {
    const maximumLeafCount =
        limits?.maximumCatalogLeafCount ?? unsigned16Maximum;
    const maximumBufferByteLength =
        foundationProfile.maximumCopiedBufferByteLength;
    const maximumSampledSecretByteLength = unsigned16Maximum;
    const leafOpeningByteLengths = copyLengthArray({
        arrayName: 'geometry.leafOpeningByteLengths',
        maximumArrayLength: maximumLeafCount,
        maximumByteLength:
            limits?.maximumLeafOpeningByteLength ?? maximumBufferByteLength,
        minimumArrayLength: 1,
        value: snapshotDataProperty(
            value,
            'leafOpeningByteLengths',
            'geometry',
        ),
    });
    const deliverySourcePayloadByteLengths = copyLengthArray({
        arrayName: 'geometry.deliverySourcePayloadByteLengths',
        maximumArrayLength: configurableParticipantCountRange.maximum - 1,
        maximumByteLength:
            limits?.maximumDeliverySourcePayloadByteLength ??
            maximumBufferByteLength,
        minimumArrayLength: configurableParticipantCountRange.minimum - 1,
        value: snapshotDataProperty(
            value,
            'deliverySourcePayloadByteLengths',
            'geometry',
        ),
    });
    return Object.freeze({
        commitmentSaltByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'commitmentSaltByteLength', 'geometry'),
            1,
            limits?.maximumCommitmentSaltByteLength ??
                maximumSampledSecretByteLength,
            'geometry.commitmentSaltByteLength',
        ),
        deliverySourcePayloadByteLengths,
        inclusionProofByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'inclusionProofByteLength', 'geometry'),
            1,
            limits?.maximumInclusionProofByteLength ?? maximumBufferByteLength,
            'geometry.inclusionProofByteLength',
        ),
        leafOpeningByteLengths,
        rootBodyByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'rootBodyByteLength', 'geometry'),
            1,
            limits?.maximumRootBodyByteLength ?? maximumBufferByteLength,
            'geometry.rootBodyByteLength',
        ),
        sourceContributionByteLength: requireSafeInteger(
            snapshotDataProperty(
                value,
                'sourceContributionByteLength',
                'geometry',
            ),
            1,
            limits?.maximumSourceContributionByteLength ??
                maximumSampledSecretByteLength,
            'geometry.sourceContributionByteLength',
        ),
    });
};

const geometryEquals = (
    left: SeedCatalogSourceCustodyGeometry,
    right: SeedCatalogSourceCustodyGeometry,
): boolean =>
    left.commitmentSaltByteLength === right.commitmentSaltByteLength &&
    left.inclusionProofByteLength === right.inclusionProofByteLength &&
    left.rootBodyByteLength === right.rootBodyByteLength &&
    left.sourceContributionByteLength === right.sourceContributionByteLength &&
    left.leafOpeningByteLengths.length ===
        right.leafOpeningByteLengths.length &&
    left.leafOpeningByteLengths.every(
        (byteLength, leafOrdinal) =>
            byteLength === right.leafOpeningByteLengths[leafOrdinal],
    ) &&
    left.deliverySourcePayloadByteLengths.length ===
        right.deliverySourcePayloadByteLengths.length &&
    left.deliverySourcePayloadByteLengths.every(
        (byteLength, deliveryIndex) =>
            byteLength ===
            right.deliverySourcePayloadByteLengths[deliveryIndex],
    );

export const deriveSeedCatalogSourceCustodyRecordByteLengths = (input: {
    geometry: SeedCatalogSourceCustodyGeometry;
}): SeedCatalogSourceCustodyRecordByteLengths => {
    const geometry = copyGeometry(
        snapshotDataProperty(input, 'geometry', 'input'),
    );
    const leafCount = geometry.leafOpeningByteLengths.length;
    const deliveryCount = geometry.deliverySourcePayloadByteLengths.length;
    const lengthTableByteLength = checkedMultiply(
        checkedAdd(leafCount, deliveryCount, 'Seed-catalog length-table count'),
        4,
        'Seed-catalog length tables',
    );
    const commonHeaderByteLength = sumByteLengths(
        [419, lengthTableByteLength],
        'Seed-catalog source-custody header',
    );
    const rawSourceInventoryByteLength = checkedMultiply(
        leafCount,
        checkedAdd(
            geometry.sourceContributionByteLength,
            geometry.commitmentSaltByteLength,
            'Seed-catalog raw leaf',
        ),
        'Seed-catalog raw source inventory',
    );
    const reservationPlaintextByteLength = checkedAdd(
        commonHeaderByteLength,
        rawSourceInventoryByteLength,
        'Seed-catalog source reservation',
    );
    const retainedEntryByteLength = sumByteLengths(
        geometry.leafOpeningByteLengths.map((openingByteLength) =>
            checkedAdd(
                openingByteLength,
                geometry.inclusionProofByteLength,
                'Seed-catalog retained entry',
            ),
        ),
        'Seed-catalog retained entry inventory',
    );
    const rootProductionOutputByteLength = sumByteLengths(
        [hashByteLength, geometry.rootBodyByteLength, retainedEntryByteLength],
        'Seed-catalog root production output',
    );
    const rootCheckpointPlaintextByteLength = sumByteLengths(
        [reservationPlaintextByteLength, rootProductionOutputByteLength, 2],
        'Seed-catalog root checkpoint',
    );
    const reservationCiphertextByteLength = checkedAdd(
        reservationPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-catalog source reservation ciphertext',
    );
    const rootCheckpointCiphertextByteLength = checkedAdd(
        rootCheckpointPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-catalog root-checkpoint ciphertext',
    );
    const deliveryCheckpointPlaintextByteLengths: number[] = [];
    let retainedDeliveryByteLength = 0;
    for (const deliverySourcePayloadByteLength of geometry.deliverySourcePayloadByteLengths) {
        retainedDeliveryByteLength = checkedAdd(
            retainedDeliveryByteLength,
            deliverySourcePayloadByteLength,
            'Seed-catalog retained delivery sources',
        );
        deliveryCheckpointPlaintextByteLengths.push(
            checkedAdd(
                rootCheckpointPlaintextByteLength,
                retainedDeliveryByteLength,
                'Seed-catalog delivery checkpoint',
            ),
        );
    }
    const deliveryCheckpointCiphertextByteLengths =
        deliveryCheckpointPlaintextByteLengths.map((plaintextByteLength) =>
            checkedAdd(
                plaintextByteLength,
                runtimeRecordEnvelopeOverheadByteLength,
                'Seed-catalog delivery-checkpoint ciphertext',
            ),
        );
    const completedPlaintextByteLength =
        deliveryCheckpointPlaintextByteLengths[
            deliveryCheckpointPlaintextByteLengths.length - 1
        ] ?? rootCheckpointPlaintextByteLength;
    const completedCiphertextByteLength =
        deliveryCheckpointCiphertextByteLengths[
            deliveryCheckpointCiphertextByteLengths.length - 1
        ] ?? rootCheckpointCiphertextByteLength;
    const checkpointCiphertextByteLengths = [
        reservationCiphertextByteLength,
        rootCheckpointCiphertextByteLength,
        ...deliveryCheckpointCiphertextByteLengths,
    ];
    let maximumCopyOnWriteCiphertextOverlapByteLength = 0;
    for (
        let checkpointIndex = 1;
        checkpointIndex < checkpointCiphertextByteLengths.length;
        checkpointIndex += 1
    ) {
        maximumCopyOnWriteCiphertextOverlapByteLength = Math.max(
            maximumCopyOnWriteCiphertextOverlapByteLength,
            checkedAdd(
                checkpointCiphertextByteLengths[checkpointIndex - 1] ?? 0,
                checkpointCiphertextByteLengths[checkpointIndex] ?? 0,
                'Seed-catalog copy-on-write ciphertext overlap',
            ),
        );
    }
    const maximumUncommittedDeliverySourceByteLength = Math.max(
        ...geometry.deliverySourcePayloadByteLengths,
    );
    return Object.freeze({
        completedCiphertextByteLength,
        completedPlaintextByteLength,
        cumulativeCheckpointCiphertextWriteByteLength: sumByteLengths(
            checkpointCiphertextByteLengths,
            'Seed-catalog cumulative checkpoint writes',
        ),
        deliveryCheckpointCiphertextByteLengths: Object.freeze(
            deliveryCheckpointCiphertextByteLengths,
        ),
        deliveryCheckpointPlaintextByteLengths: Object.freeze(
            deliveryCheckpointPlaintextByteLengths,
        ),
        maximumColdRestartReadByteLength: completedCiphertextByteLength,
        maximumCopyOnWriteCiphertextOverlapByteLength,
        maximumUncommittedDeliverySourceByteLength,
        maximumUncommittedProductionByteLength: Math.max(
            rootProductionOutputByteLength,
            maximumUncommittedDeliverySourceByteLength,
        ),
        reservationCiphertextByteLength,
        reservationPlaintextByteLength,
        rootCheckpointCiphertextByteLength,
        rootCheckpointPlaintextByteLength,
        rootProductionOutputByteLength,
    });
};

export const deriveSeedCatalogSourceCustodyKernelByteLengths = (input: {
    geometry: SeedCatalogSourceCustodyGeometry;
    preparationContextByteLength: number;
}): SeedCatalogSourceCustodyKernelByteLengths => {
    const preparationContextByteLength = requireSafeInteger(
        snapshotDataProperty(input, 'preparationContextByteLength', 'input'),
        1,
        4096,
        'input.preparationContextByteLength',
    );
    const geometry = copyGeometry(
        snapshotDataProperty(input, 'geometry', 'input'),
    );
    const recordByteLengths = deriveSeedCatalogSourceCustodyRecordByteLengths({
        geometry,
    });
    const requestContextOverheadByteLength = checkedAdd(
        4,
        preparationContextByteLength,
        'Seed-catalog kernel preparation-context wrapper',
    );
    const catalogProductionRequestByteLength = checkedAdd(
        recordByteLengths.reservationPlaintextByteLength,
        requestContextOverheadByteLength,
        'Seed-catalog production request',
    );
    const catalogValidationRequestByteLength = checkedAdd(
        catalogProductionRequestByteLength,
        recordByteLengths.rootProductionOutputByteLength,
        'Seed-catalog validation request',
    );
    const deliveryProductionRequestByteLengths =
        geometry.deliverySourcePayloadByteLengths.map(() =>
            checkedAdd(
                catalogValidationRequestByteLength,
                2,
                'Seed-catalog delivery production request',
            ),
        );
    const deliveryValidationRequestByteLengths =
        deliveryProductionRequestByteLengths.map(
            (requestByteLength, deliveryIndex) =>
                checkedAdd(
                    requestByteLength,
                    geometry.deliverySourcePayloadByteLengths[deliveryIndex] ??
                        0,
                    'Seed-catalog delivery validation request',
                ),
        );
    const responseHeaderByteLength = 4 + 2 + 1;
    const validationResponseByteLength = responseHeaderByteLength;
    const catalogProductionResponseByteLength = checkedAdd(
        responseHeaderByteLength,
        recordByteLengths.rootProductionOutputByteLength,
        'Seed-catalog production response',
    );
    const deliveryProductionResponseByteLengths =
        geometry.deliverySourcePayloadByteLengths.map((payloadByteLength) =>
            sumByteLengths(
                [responseHeaderByteLength, 2, payloadByteLength],
                'Seed-catalog delivery production response',
            ),
        );
    const deliveryCount = geometry.deliverySourcePayloadByteLengths.length;
    const catalogValidationInvocationCount = deliveryCount + 2;
    const deliveryValidationInvocationCounts = Array.from(
        { length: deliveryCount },
        (_unused, deliveryIndex) => deliveryCount + 1 - deliveryIndex,
    );
    const deliveryValidationCumulativeRequestByteLength =
        deliveryValidationRequestByteLengths.reduce(
            (total, requestByteLength, deliveryIndex) =>
                checkedAdd(
                    total,
                    checkedMultiply(
                        requestByteLength,
                        deliveryValidationInvocationCounts[deliveryIndex] ?? 0,
                        'Seed-catalog repeated delivery validation requests',
                    ),
                    'Seed-catalog cumulative delivery validation requests',
                ),
            0,
        );
    const successPathInvocationCount =
        1 +
        catalogValidationInvocationCount +
        deliveryCount +
        deliveryValidationInvocationCounts.reduce(
            (total, count) => total + count,
            0,
        );
    const successPathCumulativeRequestByteLength = sumByteLengths(
        [
            catalogProductionRequestByteLength,
            checkedMultiply(
                catalogValidationRequestByteLength,
                catalogValidationInvocationCount,
                'Seed-catalog repeated catalog validation requests',
            ),
            sumByteLengths(
                deliveryProductionRequestByteLengths,
                'Seed-catalog cumulative delivery production requests',
            ),
            deliveryValidationCumulativeRequestByteLength,
        ],
        'Seed-catalog success-path kernel requests',
    );
    const successPathCumulativeResponseByteLength = sumByteLengths(
        [
            catalogProductionResponseByteLength,
            sumByteLengths(
                deliveryProductionResponseByteLengths,
                'Seed-catalog cumulative delivery production responses',
            ),
            checkedMultiply(
                validationResponseByteLength,
                successPathInvocationCount - 1 - deliveryCount,
                'Seed-catalog validation responses',
            ),
        ],
        'Seed-catalog success-path kernel responses',
    );
    const coldValidationInvocationCount = 1 + deliveryCount;
    const coldValidationCumulativeRequestByteLength = sumByteLengths(
        [
            catalogValidationRequestByteLength,
            ...deliveryValidationRequestByteLengths,
        ],
        'Seed-catalog cold-validation kernel requests',
    );
    return Object.freeze({
        catalogProductionRequestByteLength,
        catalogProductionResponseByteLength,
        catalogValidationRequestByteLength,
        coldValidationCumulativeRequestByteLength,
        coldValidationInvocationCount,
        deliveryProductionRequestByteLengths: Object.freeze(
            deliveryProductionRequestByteLengths,
        ),
        deliveryProductionResponseByteLengths: Object.freeze(
            deliveryProductionResponseByteLengths,
        ),
        deliveryValidationRequestByteLengths: Object.freeze(
            deliveryValidationRequestByteLengths,
        ),
        maximumKernelInputByteLength: Math.max(
            catalogProductionRequestByteLength,
            catalogValidationRequestByteLength,
            ...deliveryProductionRequestByteLengths,
            ...deliveryValidationRequestByteLengths,
        ),
        maximumKernelResponseByteLength: Math.max(
            catalogProductionResponseByteLength,
            ...deliveryProductionResponseByteLengths,
            validationResponseByteLength,
        ),
        successPathCumulativeRequestByteLength,
        successPathCumulativeResponseByteLength,
        successPathInvocationCount,
        validationResponseByteLength,
    });
};

const copyGeometryValue = (
    geometry: SeedCatalogSourceCustodyGeometry,
): SeedCatalogSourceCustodyGeometry =>
    Object.freeze({
        commitmentSaltByteLength: geometry.commitmentSaltByteLength,
        deliverySourcePayloadByteLengths: Object.freeze([
            ...geometry.deliverySourcePayloadByteLengths,
        ]),
        inclusionProofByteLength: geometry.inclusionProofByteLength,
        leafOpeningByteLengths: Object.freeze([
            ...geometry.leafOpeningByteLengths,
        ]),
        rootBodyByteLength: geometry.rootBodyByteLength,
        sourceContributionByteLength: geometry.sourceContributionByteLength,
    });

const copyContextValue = (
    context: SeedCatalogSourceCustodyContext,
): SeedCatalogSourceCustodyContext =>
    Object.freeze({
        actionContextIdentity: context.actionContextIdentity.slice(),
        catalogCompilerIdentity: context.catalogCompilerIdentity.slice(),
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        participantPosition: context.participantPosition,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        rosterIdentity: context.rosterIdentity.slice(),
        statePredecessorIdentity: context.statePredecessorIdentity.slice(),
    });

const destroyContext = (
    context: SeedCatalogSourceCustodyContext | undefined,
): void => {
    context?.actionContextIdentity.fill(0);
    context?.catalogCompilerIdentity.fill(0);
    context?.parameterIdentity.fill(0);
    context?.preparationContextIdentity.fill(0);
    context?.rosterIdentity.fill(0);
    context?.statePredecessorIdentity.fill(0);
};

const contextEquals = (
    left: SeedCatalogSourceCustodyContext,
    right: SeedCatalogSourceCustodyContext,
): boolean =>
    left.participantCount === right.participantCount &&
    left.participantPosition === right.participantPosition &&
    left.preparationAttemptOrdinal === right.preparationAttemptOrdinal &&
    bytesEqual(left.actionContextIdentity, right.actionContextIdentity) &&
    bytesEqual(left.catalogCompilerIdentity, right.catalogCompilerIdentity) &&
    bytesEqual(left.parameterIdentity, right.parameterIdentity) &&
    bytesEqual(
        left.preparationContextIdentity,
        right.preparationContextIdentity,
    ) &&
    bytesEqual(left.rosterIdentity, right.rosterIdentity) &&
    bytesEqual(left.statePredecessorIdentity, right.statePredecessorIdentity);

const copySourceInventory = (
    sourceInventory: SeedCatalogSourceInventory,
): SeedCatalogSourceInventory => {
    const copiedLeaves: SeedCatalogSourceLeaf[] = [];
    let completed = false;
    try {
        for (const leaf of sourceInventory) {
            let commitmentSalt: Uint8Array | undefined;
            let sourceContribution: Uint8Array | undefined;
            try {
                sourceContribution = leaf.sourceContribution.slice();
                commitmentSalt = leaf.commitmentSalt.slice();
                copiedLeaves.push(
                    Object.freeze({ commitmentSalt, sourceContribution }),
                );
                commitmentSalt = undefined;
                sourceContribution = undefined;
            } finally {
                commitmentSalt?.fill(0);
                sourceContribution?.fill(0);
            }
        }
        const copied = Object.freeze(copiedLeaves);
        completed = true;
        return copied;
    } finally {
        if (!completed) {
            destroySourceInventory(copiedLeaves);
        }
    }
};

const destroySourceInventory = (
    sourceInventory: SeedCatalogSourceInventory | undefined,
): void => {
    sourceInventory?.forEach((leaf) => {
        leaf.commitmentSalt.fill(0);
        leaf.sourceContribution.fill(0);
    });
};

const sourceInventoriesEqual = (
    left: SeedCatalogSourceInventory,
    right: SeedCatalogSourceInventory,
): boolean =>
    left.length === right.length &&
    left.every(
        (leaf, leafOrdinal) =>
            bytesEqual(
                leaf.sourceContribution,
                right[leafOrdinal]?.sourceContribution ?? new Uint8Array(),
            ) &&
            bytesEqual(
                leaf.commitmentSalt,
                right[leafOrdinal]?.commitmentSalt ?? new Uint8Array(),
            ),
    );

const copyCatalog = (
    catalog: RetainedLocalSeedCatalog,
): RetainedLocalSeedCatalog => {
    let catalogIdentity: Uint8Array | undefined;
    let rootBodyBytes: Uint8Array | undefined;
    const entries: RetainedLocalSeedCatalogEntry[] = [];
    let completed = false;
    try {
        catalogIdentity = catalog.catalogIdentity.slice();
        rootBodyBytes = catalog.rootBodyBytes.slice();
        for (const entry of catalog.entries) {
            let inclusionProofBytes: Uint8Array | undefined;
            let openingBytes: Uint8Array | undefined;
            try {
                openingBytes = entry.openingBytes.slice();
                inclusionProofBytes = entry.inclusionProofBytes.slice();
                entries.push(
                    Object.freeze({ inclusionProofBytes, openingBytes }),
                );
                inclusionProofBytes = undefined;
                openingBytes = undefined;
            } finally {
                inclusionProofBytes?.fill(0);
                openingBytes?.fill(0);
            }
        }
        const copied = Object.freeze({
            catalogIdentity,
            entries: Object.freeze(entries),
            rootBodyBytes,
        });
        catalogIdentity = undefined;
        rootBodyBytes = undefined;
        completed = true;
        return copied;
    } finally {
        catalogIdentity?.fill(0);
        rootBodyBytes?.fill(0);
        if (!completed) {
            entries.forEach((entry) => {
                entry.inclusionProofBytes.fill(0);
                entry.openingBytes.fill(0);
            });
        }
    }
};

const destroyCatalog = (
    catalog: RetainedLocalSeedCatalog | undefined,
): void => {
    catalog?.catalogIdentity.fill(0);
    catalog?.rootBodyBytes.fill(0);
    catalog?.entries.forEach((entry) => {
        entry.inclusionProofBytes.fill(0);
        entry.openingBytes.fill(0);
    });
};

const catalogsEqual = (
    left: RetainedLocalSeedCatalog,
    right: RetainedLocalSeedCatalog,
): boolean =>
    bytesEqual(left.catalogIdentity, right.catalogIdentity) &&
    bytesEqual(left.rootBodyBytes, right.rootBodyBytes) &&
    left.entries.length === right.entries.length &&
    left.entries.every(
        (entry, leafOrdinal) =>
            bytesEqual(
                entry.openingBytes,
                right.entries[leafOrdinal]?.openingBytes ?? new Uint8Array(),
            ) &&
            bytesEqual(
                entry.inclusionProofBytes,
                right.entries[leafOrdinal]?.inclusionProofBytes ??
                    new Uint8Array(),
            ),
    );

const destroyDeliverySourcePayloads = (
    deliverySourcePayloads: readonly Uint8Array[] | undefined,
): void => {
    deliverySourcePayloads?.forEach((payload) => payload.fill(0));
};

const createReservedRecord = (input: {
    context: SeedCatalogSourceCustodyContext;
    geometry: SeedCatalogSourceCustodyGeometry;
    sourceInventory: SeedCatalogSourceInventory;
}): ReservedSeedCatalogSourceRecord => {
    let context: SeedCatalogSourceCustodyContext | undefined;
    let sourceInventory: SeedCatalogSourceInventory | undefined;
    try {
        context = copyContextValue(input.context);
        sourceInventory = copySourceInventory(input.sourceInventory);
        const record = Object.freeze({
            context,
            geometry: copyGeometryValue(input.geometry),
            kind: 'reserved' as const,
            sourceInventory,
        });
        context = undefined;
        sourceInventory = undefined;
        return record;
    } finally {
        destroyContext(context);
        destroySourceInventory(sourceInventory);
    }
};

const createRetainedRecord = (input: {
    catalog: RetainedLocalSeedCatalog;
    context: SeedCatalogSourceCustodyContext;
    deliverySourcePayloads: readonly Uint8Array[];
    geometry: SeedCatalogSourceCustodyGeometry;
    sourceInventory: SeedCatalogSourceInventory;
}): RetainedSeedCatalogSourceRecord => {
    let catalog: RetainedLocalSeedCatalog | undefined;
    let context: SeedCatalogSourceCustodyContext | undefined;
    let deliverySourcePayloads: Uint8Array[] | undefined;
    let sourceInventory: SeedCatalogSourceInventory | undefined;
    try {
        context = copyContextValue(input.context);
        sourceInventory = copySourceInventory(input.sourceInventory);
        catalog = copyCatalog(input.catalog);
        deliverySourcePayloads = [];
        for (const payload of input.deliverySourcePayloads) {
            deliverySourcePayloads.push(payload.slice());
        }
        const record = Object.freeze({
            catalog,
            context,
            deliverySourcePayloads: Object.freeze(deliverySourcePayloads),
            geometry: copyGeometryValue(input.geometry),
            kind: 'retained' as const,
            sourceInventory,
        });
        catalog = undefined;
        context = undefined;
        deliverySourcePayloads = undefined;
        sourceInventory = undefined;
        return record;
    } finally {
        destroyCatalog(catalog);
        destroyContext(context);
        destroyDeliverySourcePayloads(deliverySourcePayloads);
        destroySourceInventory(sourceInventory);
    }
};

const copyRecord = (
    record: SeedCatalogSourceRecord,
): SeedCatalogSourceRecord =>
    record.kind === 'reserved'
        ? createReservedRecord(record)
        : createRetainedRecord(record);

const destroyRecord = (record: SeedCatalogSourceRecord | undefined): void => {
    if (record === undefined) {
        return;
    }
    destroyContext(record.context);
    destroySourceInventory(record.sourceInventory);
    if (record.kind === 'retained') {
        destroyCatalog(record.catalog);
        destroyDeliverySourcePayloads(record.deliverySourcePayloads);
    }
};

const canonicalRecipientPositions = (
    context: SeedCatalogSourceCustodyContext,
): readonly number[] =>
    Object.freeze(
        Array.from(
            { length: context.participantCount },
            (_unused, participantPosition) => participantPosition,
        ).filter(
            (participantPosition) =>
                participantPosition !== context.participantPosition,
        ),
    );

const snapshotCatalog = (
    value: unknown,
    geometry: SeedCatalogSourceCustodyGeometry,
): RetainedLocalSeedCatalog => {
    let catalogIdentity: Uint8Array | undefined;
    let rootBodyBytes: Uint8Array | undefined;
    const entries: RetainedLocalSeedCatalogEntry[] = [];
    try {
        catalogIdentity = copyNonzeroHash(value, 'catalogIdentity', 'catalog');
        rootBodyBytes = copyExactBytes(
            snapshotDataProperty(value, 'rootBodyBytes', 'catalog'),
            geometry.rootBodyByteLength,
            'catalog.rootBodyBytes',
        );
        const entriesValue = snapshotDataProperty(value, 'entries', 'catalog');
        if (!Array.isArray(entriesValue)) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'catalog.entries must be an array.',
            );
        }
        const entryCount = requireSafeInteger(
            snapshotDataProperty(entriesValue, 'length', 'catalog.entries'),
            geometry.leafOpeningByteLengths.length,
            geometry.leafOpeningByteLengths.length,
            'catalog.entries.length',
        );
        for (let leafOrdinal = 0; leafOrdinal < entryCount; leafOrdinal += 1) {
            const entry = snapshotDataProperty(
                entriesValue,
                String(leafOrdinal),
                'catalog.entries',
            );
            let inclusionProofBytes: Uint8Array | undefined;
            let openingBytes: Uint8Array | undefined;
            try {
                inclusionProofBytes = copyExactBytes(
                    snapshotDataProperty(
                        entry,
                        'inclusionProofBytes',
                        `catalog.entries[${leafOrdinal}]`,
                    ),
                    geometry.inclusionProofByteLength,
                    `catalog.entries[${leafOrdinal}].inclusionProofBytes`,
                );
                openingBytes = copyExactBytes(
                    snapshotDataProperty(
                        entry,
                        'openingBytes',
                        `catalog.entries[${leafOrdinal}]`,
                    ),
                    geometry.leafOpeningByteLengths[leafOrdinal] ?? 0,
                    `catalog.entries[${leafOrdinal}].openingBytes`,
                );
                entries.push(
                    Object.freeze({
                        inclusionProofBytes,
                        openingBytes,
                    }),
                );
                inclusionProofBytes = undefined;
                openingBytes = undefined;
            } finally {
                inclusionProofBytes?.fill(0);
                openingBytes?.fill(0);
            }
        }
        const catalog = Object.freeze({
            catalogIdentity,
            entries: Object.freeze(entries),
            rootBodyBytes,
        });
        catalogIdentity = undefined;
        rootBodyBytes = undefined;
        return catalog;
    } finally {
        catalogIdentity?.fill(0);
        rootBodyBytes?.fill(0);
        if (catalogIdentity !== undefined || rootBodyBytes !== undefined) {
            entries.forEach((entry) => {
                entry.inclusionProofBytes.fill(0);
                entry.openingBytes.fill(0);
            });
        }
    }
};

const snapshotDeliverySource = (
    value: unknown,
    recipientPosition: number,
    expectedByteLength: number,
): RetainedSeedCatalogDeliverySource => {
    const outputRecipientPosition = requireSafeInteger(
        snapshotDataProperty(value, 'recipientPosition', 'deliverySource'),
        recipientPosition,
        recipientPosition,
        'deliverySource.recipientPosition',
    );
    let sourcePayloadBytes: Uint8Array | undefined;
    try {
        sourcePayloadBytes = copyExactBytes(
            snapshotDataProperty(value, 'sourcePayloadBytes', 'deliverySource'),
            expectedByteLength,
            'deliverySource.sourcePayloadBytes',
        );
        const output = Object.freeze({
            recipientPosition: outputRecipientPosition,
            sourcePayloadBytes,
        });
        sourcePayloadBytes = undefined;
        return output;
    } finally {
        sourcePayloadBytes?.fill(0);
    }
};

const logicalRecordKey = (context: SeedCatalogSourceCustodyContext): string =>
    `seed-catalog/source-custody/${context.preparationAttemptOrdinal
        .toString(10)
        .padStart(5, '0')}/${context.participantPosition
        .toString(10)
        .padStart(5, '0')}`;

const encodeCommonParts = (
    record: SeedCatalogSourceRecord,
): readonly Uint8Array[] => [
    sourceCustodyRecordMagic,
    unsigned16LittleEndian(sourceCustodyRecordVersion),
    Uint8Array.of(
        record.kind === 'reserved' ? reservedRecordKind : retainedRecordKind,
    ),
    record.context.parameterIdentity,
    record.context.rosterIdentity,
    record.context.actionContextIdentity,
    record.context.preparationContextIdentity,
    record.context.catalogCompilerIdentity,
    record.context.statePredecessorIdentity,
    unsigned16LittleEndian(record.context.preparationAttemptOrdinal),
    unsigned16LittleEndian(record.context.participantCount),
    unsigned16LittleEndian(record.context.participantPosition),
    unsigned32LittleEndian(record.geometry.leafOpeningByteLengths.length),
    unsigned32LittleEndian(record.geometry.sourceContributionByteLength),
    unsigned32LittleEndian(record.geometry.commitmentSaltByteLength),
    unsigned32LittleEndian(record.geometry.rootBodyByteLength),
    unsigned32LittleEndian(record.geometry.inclusionProofByteLength),
    unsigned16LittleEndian(
        record.geometry.deliverySourcePayloadByteLengths.length,
    ),
    ...record.geometry.leafOpeningByteLengths.map(unsigned32LittleEndian),
    ...record.geometry.deliverySourcePayloadByteLengths.map(
        unsigned32LittleEndian,
    ),
    ...record.sourceInventory.flatMap((leaf) => [
        leaf.sourceContribution,
        leaf.commitmentSalt,
    ]),
];

const encodeRecord = (record: SeedCatalogSourceRecord): Uint8Array => {
    const byteLengths = deriveSeedCatalogSourceCustodyRecordByteLengths({
        geometry: record.geometry,
    });
    const commonParts = encodeCommonParts(record);
    if (record.kind === 'reserved') {
        return concatenateBytes(
            commonParts,
            byteLengths.reservationPlaintextByteLength,
        );
    }
    const deliveryPrefixCount = record.deliverySourcePayloads.length;
    const expectedByteLength =
        deliveryPrefixCount === 0
            ? byteLengths.rootCheckpointPlaintextByteLength
            : (byteLengths.deliveryCheckpointPlaintextByteLengths[
                  deliveryPrefixCount - 1
              ] ?? 0);
    return concatenateBytes(
        [
            ...commonParts,
            record.catalog.catalogIdentity,
            record.catalog.rootBodyBytes,
            ...record.catalog.entries.flatMap((entry) => [
                entry.openingBytes,
                entry.inclusionProofBytes,
            ]),
            unsigned16LittleEndian(deliveryPrefixCount),
            ...record.deliverySourcePayloads,
        ],
        expectedByteLength,
    );
};

class BoundedRecordCursor {
    readonly #bytes: Uint8Array;
    #offset = 0;

    public constructor(bytes: Uint8Array) {
        this.#bytes = bytes;
    }

    public readExact(byteLength: number, label: string): Uint8Array {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > this.#bytes.byteLength - this.#offset
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `Seed-catalog source custody record ends within ${label}.`,
            );
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;
        return value;
    }

    public readUnsigned8(label: string): number {
        const bytes = this.readExact(1, label);
        try {
            return bytes[0] ?? 0;
        } finally {
            bytes.fill(0);
        }
    }

    public readUnsigned16(label: string): number {
        const bytes = this.readExact(2, label);
        try {
            return new DataView(
                bytes.buffer,
                bytes.byteOffset,
                bytes.byteLength,
            ).getUint16(0, true);
        } finally {
            bytes.fill(0);
        }
    }

    public readUnsigned32(label: string): number {
        const bytes = this.readExact(4, label);
        try {
            return new DataView(
                bytes.buffer,
                bytes.byteOffset,
                bytes.byteLength,
            ).getUint32(0, true);
        } finally {
            bytes.fill(0);
        }
    }

    public requireComplete(): void {
        if (this.#offset !== this.#bytes.byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-catalog source custody record has trailing bytes.',
            );
        }
    }
}

const decodeRecord = (
    plaintext: Uint8Array,
    limits: SeedCatalogSourceCustodyLimits,
): SeedCatalogSourceRecord => {
    if (
        plaintext.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Seed-catalog source custody record exceeds the absolute copied-buffer bound.',
        );
    }
    const cursor = new BoundedRecordCursor(plaintext);
    const magic = cursor.readExact(
        sourceCustodyRecordMagic.byteLength,
        'magic',
    );
    try {
        if (!bytesEqual(magic, sourceCustodyRecordMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-catalog source custody record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (cursor.readUnsigned16('version') !== sourceCustodyRecordVersion) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-catalog source custody record has the wrong version.',
        );
    }
    const recordKind = cursor.readUnsigned8('record kind');
    if (
        recordKind !== reservedRecordKind &&
        recordKind !== retainedRecordKind
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-catalog source custody record has an unknown kind.',
        );
    }
    let context: SeedCatalogSourceCustodyContext | undefined;
    let sourceInventory: SeedCatalogSourceLeaf[] | undefined;
    let catalog: RetainedLocalSeedCatalog | undefined;
    let deliverySourcePayloads: Uint8Array[] | undefined;
    try {
        const rawContext = Object.freeze({
            parameterIdentity: cursor.readExact(
                hashByteLength,
                'parameter identity',
            ),
            rosterIdentity: cursor.readExact(hashByteLength, 'roster identity'),
            actionContextIdentity: cursor.readExact(
                hashByteLength,
                'action-context identity',
            ),
            preparationContextIdentity: cursor.readExact(
                hashByteLength,
                'preparation-context identity',
            ),
            catalogCompilerIdentity: cursor.readExact(
                hashByteLength,
                'catalog-compiler identity',
            ),
            statePredecessorIdentity: cursor.readExact(
                hashByteLength,
                'state-predecessor identity',
            ),
            preparationAttemptOrdinal: cursor.readUnsigned16(
                'preparation-attempt ordinal',
            ),
            participantCount: cursor.readUnsigned16('participant count'),
            participantPosition: cursor.readUnsigned16('participant position'),
        });
        try {
            context = copyContext(rawContext);
        } catch (error) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-catalog source custody record has an invalid context.',
                error,
            );
        } finally {
            destroyContext(rawContext);
        }
        const leafCount = cursor.readUnsigned32('leaf count');
        const sourceContributionByteLength = cursor.readUnsigned32(
            'source-contribution byte length',
        );
        const commitmentSaltByteLength = cursor.readUnsigned32(
            'commitment-salt byte length',
        );
        const rootBodyByteLength = cursor.readUnsigned32(
            'root-body byte length',
        );
        const inclusionProofByteLength = cursor.readUnsigned32(
            'inclusion-proof byte length',
        );
        const deliveryCount = cursor.readUnsigned16('delivery count');
        if (
            leafCount < 1 ||
            leafCount > limits.maximumCatalogLeafCount ||
            deliveryCount !== context.participantCount - 1
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-catalog source custody record has noncanonical inventory counts.',
            );
        }
        const leafOpeningByteLengths = Array.from(
            { length: leafCount },
            (_unused, leafOrdinal) =>
                cursor.readUnsigned32(
                    `leaf-opening byte length ${leafOrdinal}`,
                ),
        );
        const deliverySourcePayloadByteLengths = Array.from(
            { length: deliveryCount },
            (_unused, deliveryIndex) =>
                cursor.readUnsigned32(
                    `delivery-source byte length ${deliveryIndex}`,
                ),
        );
        let geometry: SeedCatalogSourceCustodyGeometry;
        try {
            geometry = copyGeometry(
                {
                    commitmentSaltByteLength,
                    deliverySourcePayloadByteLengths,
                    inclusionProofByteLength,
                    leafOpeningByteLengths,
                    rootBodyByteLength,
                    sourceContributionByteLength,
                },
                limits,
            );
        } catch (error) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-catalog source custody record has invalid geometry.',
                error,
            );
        }
        const recordByteLengths =
            deriveSeedCatalogSourceCustodyRecordByteLengths({ geometry });
        if (
            recordByteLengths.completedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                'Seed-catalog source custody record geometry exceeds the absolute copied-buffer bound.',
            );
        }
        sourceInventory = [];
        for (let leafOrdinal = 0; leafOrdinal < leafCount; leafOrdinal += 1) {
            let sourceContribution: Uint8Array | undefined;
            let commitmentSalt: Uint8Array | undefined;
            try {
                sourceContribution = cursor.readExact(
                    geometry.sourceContributionByteLength,
                    `source contribution ${leafOrdinal}`,
                );
                commitmentSalt = cursor.readExact(
                    geometry.commitmentSaltByteLength,
                    `commitment salt ${leafOrdinal}`,
                );
                sourceInventory.push(
                    Object.freeze({ commitmentSalt, sourceContribution }),
                );
                sourceContribution = undefined;
                commitmentSalt = undefined;
            } finally {
                sourceContribution?.fill(0);
                commitmentSalt?.fill(0);
            }
        }
        if (recordKind === reservedRecordKind) {
            cursor.requireComplete();
            const reserved = Object.freeze({
                context,
                geometry,
                kind: 'reserved' as const,
                sourceInventory: Object.freeze(sourceInventory),
            });
            context = undefined;
            sourceInventory = undefined;
            return reserved;
        }
        let catalogIdentity: Uint8Array | undefined;
        let rootBodyBytes: Uint8Array | undefined;
        const entries: RetainedLocalSeedCatalogEntry[] = [];
        let catalogCompleted = false;
        try {
            catalogIdentity = cursor.readExact(
                hashByteLength,
                'catalog identity',
            );
            rootBodyBytes = cursor.readExact(
                geometry.rootBodyByteLength,
                'root-body bytes',
            );
            if (catalogIdentity.every((byte) => byte === 0)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-catalog source custody record has an all-zero catalog identity.',
                );
            }
            for (
                let leafOrdinal = 0;
                leafOrdinal < geometry.leafOpeningByteLengths.length;
                leafOrdinal += 1
            ) {
                let openingBytes: Uint8Array | undefined;
                let inclusionProofBytes: Uint8Array | undefined;
                try {
                    openingBytes = cursor.readExact(
                        geometry.leafOpeningByteLengths[leafOrdinal] ?? 0,
                        `opening ${leafOrdinal}`,
                    );
                    inclusionProofBytes = cursor.readExact(
                        geometry.inclusionProofByteLength,
                        `inclusion proof ${leafOrdinal}`,
                    );
                    entries.push(
                        Object.freeze({
                            inclusionProofBytes,
                            openingBytes,
                        }),
                    );
                    inclusionProofBytes = undefined;
                    openingBytes = undefined;
                } finally {
                    inclusionProofBytes?.fill(0);
                    openingBytes?.fill(0);
                }
            }
            catalog = Object.freeze({
                catalogIdentity,
                entries: Object.freeze(entries),
                rootBodyBytes,
            });
            catalogIdentity = undefined;
            rootBodyBytes = undefined;
            catalogCompleted = true;
        } finally {
            catalogIdentity?.fill(0);
            rootBodyBytes?.fill(0);
            if (!catalogCompleted) {
                entries.forEach((entry) => {
                    entry.inclusionProofBytes.fill(0);
                    entry.openingBytes.fill(0);
                });
            }
        }
        const retainedDeliveryCount = cursor.readUnsigned16(
            'retained-delivery count',
        );
        if (retainedDeliveryCount > deliveryCount) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-catalog source custody record retains a noncanonical delivery count.',
            );
        }
        deliverySourcePayloads = [];
        for (
            let deliveryIndex = 0;
            deliveryIndex < retainedDeliveryCount;
            deliveryIndex += 1
        ) {
            deliverySourcePayloads.push(
                cursor.readExact(
                    geometry.deliverySourcePayloadByteLengths[deliveryIndex] ??
                        0,
                    `delivery-source payload ${deliveryIndex}`,
                ),
            );
        }
        cursor.requireComplete();
        const retained = Object.freeze({
            catalog,
            context,
            deliverySourcePayloads: Object.freeze(deliverySourcePayloads),
            geometry,
            kind: 'retained' as const,
            sourceInventory: Object.freeze(sourceInventory),
        });
        catalog = undefined;
        context = undefined;
        deliverySourcePayloads = undefined;
        sourceInventory = undefined;
        return retained;
    } finally {
        destroyCatalog(catalog);
        destroyContext(context);
        destroyDeliverySourcePayloads(deliverySourcePayloads);
        destroySourceInventory(sourceInventory);
    }
};

const readRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: SeedCatalogSourceCustodyLimits,
): Promise<OpenedSeedCatalogSourceRecord | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: sourceCustodyOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    let record: SeedCatalogSourceRecord | undefined;
    try {
        record = decodeRecord(opened.plaintext, limits);
        const output = Object.freeze({
            record,
            sealedBytes: opened.sealedBytes.slice(),
        });
        record = undefined;
        return output;
    } finally {
        destroyRecord(record);
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

export const readCompletedSeedCatalogSourceCustodyForMasterJoin =
    async (input: {
        context: SeedCatalogSourceCustodyContext;
        limits: SeedCatalogSourceCustodyLimits;
        protection: RuntimeRecordProtection;
        store: UntrustedStorageTransactionStore;
    }): Promise<
        | CompletedSeedCatalogSourceCustodyForMasterJoin
        | 'incomplete'
        | undefined
    > => {
        const context = copyContext(input.context);
        const limits = copyLimits(input.limits);
        const recordKey = logicalRecordKey(context);
        const opened = await readRuntimeRecord({
            logicalRecordKey: recordKey,
            operationDomain: sourceCustodyOperationDomain,
            protection: input.protection,
            store: input.store,
        });
        if (opened === undefined) {
            destroyContext(context);
            return undefined;
        }
        let decoded: SeedCatalogSourceRecord | undefined;
        let canonicalRecordBytes: Uint8Array | undefined;
        try {
            decoded = decodeRecord(opened.plaintext, limits);
            if (!contextEquals(decoded.context, context)) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'The seed-catalog source predecessor is bound to a different context.',
                );
            }
            if (
                decoded.kind !== 'retained' ||
                decoded.deliverySourcePayloads.length !==
                    decoded.geometry.deliverySourcePayloadByteLengths.length
            ) {
                return 'incomplete';
            }
            canonicalRecordBytes = encodeRecord(decoded);
            if (!bytesEqual(canonicalRecordBytes, opened.plaintext)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'The seed-catalog source predecessor is not canonical.',
                );
            }
            return Object.freeze({
                recordBytes: opened.plaintext.slice(),
                recordKey,
                sealedBytes: opened.sealedBytes.slice(),
            });
        } finally {
            canonicalRecordBytes?.fill(0);
            destroyRecord(decoded);
            destroyContext(context);
            opened.plaintext.fill(0);
            opened.sealedBytes.fill(0);
        }
    };

const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationFailure: unknown,
): Promise<AuthenticatedRuntimeRecordError> => {
    const mappedOperationFailure = mapStorageError(operationFailure);
    try {
        await transaction.closeAfterFailure();
    } catch (closeFailure) {
        throw new AuthenticatedRuntimeRecordError(
            'CleanupFailed',
            'Seed-catalog source custody failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const commitRecord = async (input: {
    expectedCurrentSealedBytes: Uint8Array | null;
    limits: SeedCatalogSourceCustodyLimits;
    protection: RuntimeRecordProtection;
    record: SeedCatalogSourceRecord;
    recordKey: string;
    store: UntrustedStorageTransactionStore;
}): Promise<Uint8Array> => {
    const plaintext = encodeRecord(input.record);
    let transaction: UntrustedStorageTransaction | undefined;
    let stagedSealedBytes: Uint8Array | undefined;
    try {
        transaction = await input.store.beginTransaction({
            lifetimeMilliseconds: input.limits.transactionLifetimeMilliseconds,
        });
        stagedSealedBytes = await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: input.expectedCurrentSealedBytes,
            logicalRecordKey: input.recordKey,
            operationDomain: sourceCustodyOperationDomain,
            plaintext,
            protection: input.protection,
            transaction,
        });
        await transaction.commit();
        return stagedSealedBytes.slice();
    } catch (error) {
        if (transaction === undefined) {
            throw mapStorageError(error);
        }
        throw await closeTransactionAfterFailure(transaction, error);
    } finally {
        plaintext.fill(0);
        stagedSealedBytes?.fill(0);
    }
};

const errorHasCode = (error: unknown, code: string): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code;

const destroyProductionInput = (
    input: SeedCatalogProductionInput | undefined,
): void => {
    if (input === undefined) {
        return;
    }
    destroyContext(input.context);
    destroySourceInventory(input.sourceInventory);
};

const createProductionInput = (
    record: SeedCatalogSourceRecord,
): SeedCatalogProductionInput => {
    let context: SeedCatalogSourceCustodyContext | undefined;
    let sourceInventory: SeedCatalogSourceInventory | undefined;
    try {
        context = copyContextValue(record.context);
        sourceInventory = copySourceInventory(record.sourceInventory);
        const input = Object.freeze({
            context,
            geometry: copyGeometryValue(record.geometry),
            sourceInventory,
        });
        context = undefined;
        sourceInventory = undefined;
        return input;
    } finally {
        destroyContext(context);
        destroySourceInventory(sourceInventory);
    }
};

const createCatalogValidationInput = (
    record: SeedCatalogSourceRecord,
    retainedCatalog: RetainedLocalSeedCatalog,
): SeedCatalogValidationInput => {
    let productionInput: SeedCatalogProductionInput | undefined;
    let catalog: RetainedLocalSeedCatalog | undefined;
    try {
        productionInput = createProductionInput(record);
        catalog = copyCatalog(retainedCatalog);
        const input = Object.freeze({
            ...productionInput,
            catalog,
        });
        productionInput = undefined;
        catalog = undefined;
        return input;
    } finally {
        destroyCatalog(catalog);
        destroyProductionInput(productionInput);
    }
};

const createValidationInput = (
    record: RetainedSeedCatalogSourceRecord,
): SeedCatalogValidationInput =>
    createCatalogValidationInput(record, record.catalog);

const destroyValidationInput = (
    input: SeedCatalogValidationInput | undefined,
): void => {
    if (input === undefined) {
        return;
    }
    destroyCatalog(input.catalog);
    destroyProductionInput(input);
};

const destroyDeliveryProductionInput = (
    input: SeedCatalogDeliverySourceProductionInput | undefined,
): void => {
    destroyValidationInput(input);
};

const createDeliveryProductionInput = (
    record: RetainedSeedCatalogSourceRecord,
    recipientPosition: number,
): SeedCatalogDeliverySourceProductionInput => {
    let validationInput: SeedCatalogValidationInput | undefined;
    try {
        validationInput = createValidationInput(record);
        const input = Object.freeze({
            ...validationInput,
            recipientPosition,
        });
        validationInput = undefined;
        return input;
    } finally {
        destroyValidationInput(validationInput);
    }
};

const destroyDeliveryValidationInput = (
    input: SeedCatalogDeliverySourceValidationInput | undefined,
): void => {
    if (input === undefined) {
        return;
    }
    input.sourcePayloadBytes.fill(0);
    destroyDeliveryProductionInput(input);
};

const createDeliveryValidationInput = (
    record: RetainedSeedCatalogSourceRecord,
    recipientPosition: number,
    sourcePayloadBytes: Uint8Array,
): SeedCatalogDeliverySourceValidationInput => {
    let productionInput: SeedCatalogDeliverySourceProductionInput | undefined;
    let copiedSourcePayloadBytes: Uint8Array | undefined;
    try {
        productionInput = createDeliveryProductionInput(
            record,
            recipientPosition,
        );
        copiedSourcePayloadBytes = sourcePayloadBytes.slice();
        const input = Object.freeze({
            ...productionInput,
            sourcePayloadBytes: copiedSourcePayloadBytes,
        });
        productionInput = undefined;
        copiedSourcePayloadBytes = undefined;
        return input;
    } finally {
        copiedSourcePayloadBytes?.fill(0);
        destroyDeliveryProductionInput(productionInput);
    }
};

const recordsShareRetainedPrefix = (
    expectedPrefix: RetainedSeedCatalogSourceRecord,
    actual: RetainedSeedCatalogSourceRecord,
): boolean =>
    contextEquals(expectedPrefix.context, actual.context) &&
    geometryEquals(expectedPrefix.geometry, actual.geometry) &&
    sourceInventoriesEqual(
        expectedPrefix.sourceInventory,
        actual.sourceInventory,
    ) &&
    catalogsEqual(expectedPrefix.catalog, actual.catalog) &&
    actual.deliverySourcePayloads.length >=
        expectedPrefix.deliverySourcePayloads.length &&
    expectedPrefix.deliverySourcePayloads.every((payload, deliveryIndex) =>
        bytesEqual(
            payload,
            actual.deliverySourcePayloads[deliveryIndex] ?? new Uint8Array(),
        ),
    );

/**
 * Owns the one local, complete source catalog before any root bytes can leave
 * this boundary. It samples every contribution and salt internally, anchors a
 * reservation, persists the exact root and canonical local openings, and then
 * checkpoints each canonical recipient plaintext. A cold replay resumes from
 * the authenticated prefix and never resamples a retained action.
 *
 * The integrity-pinned scalar kernel is a generation and validation boundary
 * only. Returned bytes remain inert and provide no protocol acceptance or
 * continuation capability.
 */
export class SeedCatalogSourceCustody {
    readonly #context: SeedCatalogSourceCustodyContext;
    readonly #geometry: SeedCatalogSourceCustodyGeometry;
    readonly #kernel: ProductionSeedCatalogSourceCustodyKernel;
    readonly #limits: SeedCatalogSourceCustodyLimits;
    readonly #protection: RuntimeRecordProtection;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    readonly #recordKey: string;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        context: SeedCatalogSourceCustodyContext;
        geometry: SeedCatalogSourceCustodyGeometry;
        kernel: ProductionSeedCatalogSourceCustodyKernel;
        limits: SeedCatalogSourceCustodyLimits;
        protection: RuntimeRecordProtection;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    }) {
        if (!isProductionSeedCatalogSourceCustodyKernel(input.kernel)) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-catalog source custody requires an integrity-pinned production kernel.',
            );
        }
        if (
            !(
                input.recencyCoordinator instanceof
                AuthenticatedStorageRecencyCoordinator
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-catalog source custody requires an authenticated storage recency coordinator.',
            );
        }
        this.#context = copyContext(input.context);
        this.#limits = copyLimits(input.limits);
        this.#geometry = copyGeometry(input.geometry, this.#limits);
        if (
            this.#geometry.deliverySourcePayloadByteLengths.length !==
            this.#context.participantCount - 1
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-catalog source custody geometry has the wrong canonical recipient count.',
            );
        }
        const byteLengths = deriveSeedCatalogSourceCustodyRecordByteLengths({
            geometry: this.#geometry,
        });
        const kernelByteLengths =
            deriveSeedCatalogSourceCustodyKernelByteLengths({
                geometry: this.#geometry,
                preparationContextByteLength:
                    input.kernel.preparationContextByteLength,
            });
        if (
            Math.max(
                byteLengths.completedPlaintextByteLength,
                kernelByteLengths.maximumKernelInputByteLength,
                kernelByteLengths.maximumKernelResponseByteLength,
            ) > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-catalog source custody geometry or kernel operation exceeds the absolute copied-buffer bound.',
            );
        }
        this.#kernel = input.kernel;
        this.#protection = input.protection;
        this.#recencyCoordinator = input.recencyCoordinator;
        this.#recordKey = logicalRecordKey(this.#context);
    }

    public retainCatalogBeforeRootPublication(): Promise<RetainedLocalSeedCatalog> {
        const scheduled = this.#operationTail.then(async () => {
            const opened = await this.#completeRecord();
            try {
                return copyCatalog(opened.record.catalog);
            } finally {
                opened.sealedBytes.fill(0);
                destroyRecord(opened.record);
            }
        });
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    public loadRetainedDeliverySource(input: {
        recipientPosition: number;
    }): Promise<RetainedSeedCatalogDeliverySource> {
        const recipientPosition = requireSafeInteger(
            snapshotDataProperty(input, 'recipientPosition', 'input'),
            0,
            this.#context.participantCount - 1,
            'input.recipientPosition',
        );
        if (recipientPosition === this.#context.participantPosition) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'A local seed catalog has no delivery source for its owner.',
            );
        }
        const scheduled = this.#operationTail.then(async () => {
            const opened = await this.#completeRecord();
            try {
                const deliveryIndex = canonicalRecipientPositions(
                    opened.record.context,
                ).indexOf(recipientPosition);
                const sourcePayloadBytes =
                    opened.record.deliverySourcePayloads[deliveryIndex];
                if (deliveryIndex < 0 || sourcePayloadBytes === undefined) {
                    throw new AuthenticatedRuntimeRecordError(
                        'InvalidState',
                        'Completed seed-catalog source custody is missing a canonical delivery.',
                    );
                }
                return Object.freeze({
                    recipientPosition,
                    sourcePayloadBytes: sourcePayloadBytes.slice(),
                });
            } finally {
                opened.sealedBytes.fill(0);
                destroyRecord(opened.record);
            }
        });
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    async #readOpenedRecord(): Promise<
        OpenedSeedCatalogSourceRecord | undefined
    > {
        return this.#recencyCoordinator.runRead((store) =>
            readRecord(store, this.#protection, this.#recordKey, this.#limits),
        );
    }

    #requireConfiguredRecord(record: SeedCatalogSourceRecord): void {
        if (
            !contextEquals(record.context, this.#context) ||
            !geometryEquals(record.geometry, this.#geometry)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The seed-catalog source slot is durably bound to a different context or geometry.',
            );
        }
    }

    async #completeRecord(): Promise<
        OpenedSeedCatalogSourceRecord &
            Readonly<{ record: RetainedSeedCatalogSourceRecord }>
    > {
        let opened = await this.#readOpenedRecord();
        if (opened === undefined) {
            opened = await this.#reserve();
        }
        try {
            this.#requireConfiguredRecord(opened.record);
            if (opened.record.kind === 'reserved') {
                const retained = await this.#retainCatalog({
                    record: opened.record,
                    sealedBytes: opened.sealedBytes,
                });
                opened.sealedBytes.fill(0);
                destroyRecord(opened.record);
                opened = retained;
            }
            while (
                opened.record.kind === 'retained' &&
                opened.record.deliverySourcePayloads.length <
                    this.#geometry.deliverySourcePayloadByteLengths.length
            ) {
                this.#validateRetainedRecord(opened.record);
                const advanced = await this.#retainNextDelivery({
                    record: opened.record,
                    sealedBytes: opened.sealedBytes,
                });
                opened.sealedBytes.fill(0);
                destroyRecord(opened.record);
                opened = advanced;
            }
            if (opened.record.kind !== 'retained') {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Seed-catalog source custody did not reach a retained state.',
                );
            }
            this.#validateRetainedRecord(opened.record);
            return opened as OpenedSeedCatalogSourceRecord &
                Readonly<{ record: RetainedSeedCatalogSourceRecord }>;
        } catch (error) {
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
            throw error;
        }
    }

    async #reserve(): Promise<OpenedSeedCatalogSourceRecord> {
        const sampledInventory: SeedCatalogSourceLeaf[] = [];
        try {
            for (
                let leafOrdinal = 0;
                leafOrdinal < this.#geometry.leafOpeningByteLengths.length;
                leafOrdinal += 1
            ) {
                let sourceContribution: Uint8Array | undefined;
                let commitmentSalt: Uint8Array | undefined;
                try {
                    sourceContribution = sampleRuntimeSecretBytes(
                        this.#protection,
                        this.#geometry.sourceContributionByteLength,
                        `Seed-catalog source contribution ${leafOrdinal}`,
                    );
                    commitmentSalt = sampleRuntimeSecretBytes(
                        this.#protection,
                        this.#geometry.commitmentSaltByteLength,
                        `Seed-catalog commitment salt ${leafOrdinal}`,
                    );
                    sampledInventory.push(
                        Object.freeze({
                            commitmentSalt,
                            sourceContribution,
                        }),
                    );
                    sourceContribution = undefined;
                    commitmentSalt = undefined;
                } finally {
                    sourceContribution?.fill(0);
                    commitmentSalt?.fill(0);
                }
            }
            const reservation = createReservedRecord({
                context: this.#context,
                geometry: this.#geometry,
                sourceInventory: sampledInventory,
            });
            try {
                let sealedBytes: Uint8Array;
                try {
                    sealedBytes = await this.#recencyCoordinator.runMutation(
                        (store) =>
                            commitRecord({
                                expectedCurrentSealedBytes: null,
                                limits: this.#limits,
                                protection: this.#protection,
                                record: reservation,
                                recordKey: this.#recordKey,
                                store,
                            }),
                    );
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readOpenedRecord();
                    if (existing === undefined) {
                        throw error;
                    }
                    try {
                        this.#requireConfiguredRecord(existing.record);
                        return existing;
                    } catch (conflictError) {
                        existing.sealedBytes.fill(0);
                        destroyRecord(existing.record);
                        throw conflictError;
                    }
                }
                return Object.freeze({
                    record: copyRecord(reservation),
                    sealedBytes,
                });
            } finally {
                destroyRecord(reservation);
            }
        } finally {
            destroySourceInventory(sampledInventory);
        }
    }

    #produceCatalog(
        reservation: ReservedSeedCatalogSourceRecord,
    ): RetainedLocalSeedCatalog {
        const productionInput = createProductionInput(reservation);
        let productionFailed = false;
        let productionFailure: unknown;
        let produced: unknown;
        try {
            try {
                produced = this.#kernel.produceCatalog(productionInput);
            } catch (error) {
                productionFailed = true;
                productionFailure = error;
            }
            if (productionFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Seed-catalog production failed before root publication.',
                    productionFailure,
                );
            }
            return snapshotCatalog(produced, reservation.geometry);
        } finally {
            destroyProductionInput(productionInput);
        }
    }

    #validateCatalogForRecord(
        record: SeedCatalogSourceRecord,
        catalog: RetainedLocalSeedCatalog,
    ): void {
        const validationInput = createCatalogValidationInput(record, catalog);
        let validationFailed = false;
        let validationFailure: unknown;
        try {
            try {
                this.#kernel.validateCatalog(validationInput);
            } catch (error) {
                validationFailed = true;
                validationFailure = error;
            }
            if (validationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-catalog source custody failed catalog validation.',
                    validationFailure,
                );
            }
        } finally {
            destroyValidationInput(validationInput);
        }
    }

    async #retainCatalog(input: {
        record: ReservedSeedCatalogSourceRecord;
        sealedBytes: Uint8Array;
    }): Promise<OpenedSeedCatalogSourceRecord> {
        const catalog = this.#produceCatalog(input.record);
        try {
            this.#validateCatalogForRecord(input.record, catalog);
            const retainedRecord = createRetainedRecord({
                catalog,
                context: input.record.context,
                deliverySourcePayloads: [],
                geometry: input.record.geometry,
                sourceInventory: input.record.sourceInventory,
            });
            try {
                try {
                    const sealedBytes =
                        await this.#recencyCoordinator.runMutation((store) =>
                            commitRecord({
                                expectedCurrentSealedBytes: input.sealedBytes,
                                limits: this.#limits,
                                protection: this.#protection,
                                record: retainedRecord,
                                recordKey: this.#recordKey,
                                store,
                            }),
                        );
                    return Object.freeze({
                        record: copyRecord(retainedRecord),
                        sealedBytes,
                    });
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readOpenedRecord();
                    if (existing === undefined) {
                        throw error;
                    }
                    try {
                        this.#requireConfiguredRecord(existing.record);
                        if (
                            existing.record.kind !== 'retained' ||
                            !sourceInventoriesEqual(
                                input.record.sourceInventory,
                                existing.record.sourceInventory,
                            ) ||
                            !catalogsEqual(catalog, existing.record.catalog)
                        ) {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'Concurrent seed-catalog production selected different retained bytes.',
                            );
                        }
                        this.#validateRetainedRecord(existing.record);
                        return existing;
                    } catch (conflictError) {
                        existing.sealedBytes.fill(0);
                        destroyRecord(existing.record);
                        throw conflictError;
                    }
                }
            } finally {
                destroyRecord(retainedRecord);
            }
        } finally {
            destroyCatalog(catalog);
        }
    }

    #produceDeliverySource(
        record: RetainedSeedCatalogSourceRecord,
        deliveryIndex: number,
    ): RetainedSeedCatalogDeliverySource {
        const recipientPosition = canonicalRecipientPositions(record.context)[
            deliveryIndex
        ];
        const expectedByteLength =
            record.geometry.deliverySourcePayloadByteLengths[deliveryIndex];
        if (
            recipientPosition === undefined ||
            expectedByteLength === undefined
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Seed-catalog source custody selected a noncanonical delivery index.',
            );
        }
        const productionInput = createDeliveryProductionInput(
            record,
            recipientPosition,
        );
        let productionFailed = false;
        let productionFailure: unknown;
        let produced: unknown;
        try {
            try {
                produced = this.#kernel.produceDeliverySource(productionInput);
            } catch (error) {
                productionFailed = true;
                productionFailure = error;
            }
            if (productionFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Seed-catalog delivery-source production failed before publication.',
                    productionFailure,
                );
            }
            return snapshotDeliverySource(
                produced,
                recipientPosition,
                expectedByteLength,
            );
        } finally {
            destroyDeliveryProductionInput(productionInput);
        }
    }

    #validateDeliverySource(
        record: RetainedSeedCatalogSourceRecord,
        deliveryIndex: number,
        sourcePayloadBytes: Uint8Array,
    ): void {
        const recipientPosition = canonicalRecipientPositions(record.context)[
            deliveryIndex
        ];
        if (recipientPosition === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Seed-catalog source custody cannot validate a noncanonical delivery index.',
            );
        }
        const validationInput = createDeliveryValidationInput(
            record,
            recipientPosition,
            sourcePayloadBytes,
        );
        let validationFailed = false;
        let validationFailure: unknown;
        try {
            try {
                this.#kernel.validateDeliverySource(validationInput);
            } catch (error) {
                validationFailed = true;
                validationFailure = error;
            }
            if (validationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-catalog source custody failed delivery-source validation.',
                    validationFailure,
                );
            }
        } finally {
            destroyDeliveryValidationInput(validationInput);
        }
    }

    #validateRetainedRecord(record: RetainedSeedCatalogSourceRecord): void {
        this.#validateCatalogForRecord(record, record.catalog);
        for (
            let deliveryIndex = 0;
            deliveryIndex < record.deliverySourcePayloads.length;
            deliveryIndex += 1
        ) {
            const sourcePayloadBytes =
                record.deliverySourcePayloads[deliveryIndex];
            if (sourcePayloadBytes === undefined) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Seed-catalog source custody has a missing retained delivery prefix.',
                );
            }
            this.#validateDeliverySource(
                record,
                deliveryIndex,
                sourcePayloadBytes,
            );
        }
    }

    async #retainNextDelivery(input: {
        record: RetainedSeedCatalogSourceRecord;
        sealedBytes: Uint8Array;
    }): Promise<OpenedSeedCatalogSourceRecord> {
        const deliveryIndex = input.record.deliverySourcePayloads.length;
        const deliverySource = this.#produceDeliverySource(
            input.record,
            deliveryIndex,
        );
        try {
            this.#validateDeliverySource(
                input.record,
                deliveryIndex,
                deliverySource.sourcePayloadBytes,
            );
            const retainedRecord = createRetainedRecord({
                catalog: input.record.catalog,
                context: input.record.context,
                deliverySourcePayloads: [
                    ...input.record.deliverySourcePayloads,
                    deliverySource.sourcePayloadBytes,
                ],
                geometry: input.record.geometry,
                sourceInventory: input.record.sourceInventory,
            });
            try {
                try {
                    const sealedBytes =
                        await this.#recencyCoordinator.runMutation((store) =>
                            commitRecord({
                                expectedCurrentSealedBytes: input.sealedBytes,
                                limits: this.#limits,
                                protection: this.#protection,
                                record: retainedRecord,
                                recordKey: this.#recordKey,
                                store,
                            }),
                        );
                    return Object.freeze({
                        record: copyRecord(retainedRecord),
                        sealedBytes,
                    });
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readOpenedRecord();
                    if (existing === undefined) {
                        throw error;
                    }
                    try {
                        this.#requireConfiguredRecord(existing.record);
                        if (
                            existing.record.kind !== 'retained' ||
                            !recordsShareRetainedPrefix(
                                input.record,
                                existing.record,
                            ) ||
                            !bytesEqual(
                                deliverySource.sourcePayloadBytes,
                                existing.record.deliverySourcePayloads[
                                    deliveryIndex
                                ] ?? new Uint8Array(),
                            )
                        ) {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'Concurrent seed-catalog delivery production selected different retained bytes.',
                            );
                        }
                        this.#validateRetainedRecord(existing.record);
                        return existing;
                    } catch (conflictError) {
                        existing.sealedBytes.fill(0);
                        destroyRecord(existing.record);
                        throw conflictError;
                    }
                }
            } finally {
                destroyRecord(retainedRecord);
            }
        } finally {
            deliverySource.sourcePayloadBytes.fill(0);
        }
    }
}
