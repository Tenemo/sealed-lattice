import { foundationProfile } from '@sealed-lattice/types';

import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';

const requestMagic = Uint8Array.of(0x53, 0x4c, 0x53, 0x4b);
const responseMagic = Uint8Array.of(0x53, 0x4c, 0x53, 0x52);
const codecVersion = 1;
const produceCatalogOperation = 1;
const validateCatalogOperation = 2;
const produceDeliveryOperation = 3;
const validateDeliveryOperation = 4;
const failureStatus = 0;
const catalogStatus = 1;
const deliveryStatus = 2;
const validationStatus = 3;
const hashByteLength = 64;
const responseHeaderByteLength = responseMagic.byteLength + 2 + 1;
const failureResponseByteLength = responseHeaderByteLength + 2;
const maximumPreparationContextByteLength = 4096;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const seedCatalogSourceCustodyKernelBrand: unique symbol = Symbol(
    'seed-catalog-source-custody-kernel',
);

declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

type SeedCatalogSourceCustodyContext = Readonly<{
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

type SeedCatalogSourceCustodyGeometry = Readonly<{
    commitmentSaltByteLength: number;
    deliverySourcePayloadByteLengths: readonly number[];
    inclusionProofByteLength: number;
    leafOpeningByteLengths: readonly number[];
    rootBodyByteLength: number;
    sourceContributionByteLength: number;
}>;

type SeedCatalogSourceInventory = readonly Readonly<{
    commitmentSalt: Uint8Array;
    sourceContribution: Uint8Array;
}>[];

type RetainedLocalSeedCatalog = Readonly<{
    catalogIdentity: Uint8Array;
    entries: readonly Readonly<{
        inclusionProofBytes: Uint8Array;
        openingBytes: Uint8Array;
    }>[];
    rootBodyBytes: Uint8Array;
}>;

type SeedCatalogProductionInput = Readonly<{
    context: SeedCatalogSourceCustodyContext;
    geometry: SeedCatalogSourceCustodyGeometry;
    sourceInventory: SeedCatalogSourceInventory;
}>;

type SeedCatalogValidationInput = SeedCatalogProductionInput &
    Readonly<{ catalog: RetainedLocalSeedCatalog }>;

type SeedCatalogDeliverySourceProductionInput = SeedCatalogValidationInput &
    Readonly<{ recipientPosition: number }>;

type SeedCatalogDeliverySourceValidationInput =
    SeedCatalogDeliverySourceProductionInput &
        Readonly<{ sourcePayloadBytes: Uint8Array }>;

export type SeedCatalogSourceKernelErrorCode =
    | 'CatalogMismatch'
    | 'ContextMismatch'
    | 'DeliveryMismatch'
    | 'GeometryMismatch'
    | 'MalformedKernelResponse'
    | 'MalformedRequest'
    | 'ResourceLimit'
    | 'SourceGeneration';

export class SeedCatalogSourceKernelError extends Error {
    public readonly code: SeedCatalogSourceKernelErrorCode;

    public constructor(
        code: SeedCatalogSourceKernelErrorCode,
        message: string,
    ) {
        super(message);
        this.name = 'SeedCatalogSourceKernelError';
        this.code = code;
    }
}

/**
 * Integrity-pinned scalar Rust/WebAssembly source-production boundary. Its
 * outputs are inert local custody and grant no publication or continuation
 * authority.
 */
export type ProductionSeedCatalogSourceCustodyKernel = Readonly<{
    readonly [seedCatalogSourceCustodyKernelBrand]: true;
    readonly preparationContextByteLength: number;
    produceCatalog(input: SeedCatalogProductionInput): RetainedLocalSeedCatalog;
    produceDeliverySource(
        input: SeedCatalogDeliverySourceProductionInput,
    ): Readonly<{
        recipientPosition: number;
        sourcePayloadBytes: Uint8Array;
    }>;
    validateCatalog(input: SeedCatalogValidationInput): void;
    validateDeliverySource(
        input: SeedCatalogDeliverySourceValidationInput,
    ): void;
}>;

const productionKernels = new WeakSet<object>();

const responseCodeByNumber = new Map<
    number,
    Exclude<SeedCatalogSourceKernelErrorCode, 'MalformedKernelResponse'>
>([
    [1, 'MalformedRequest'],
    [2, 'ResourceLimit'],
    [3, 'ContextMismatch'],
    [4, 'GeometryMismatch'],
    [5, 'SourceGeneration'],
    [6, 'CatalogMismatch'],
    [7, 'DeliveryMismatch'],
]);

const malformedResponse = (detail: string): SeedCatalogSourceKernelError =>
    new SeedCatalogSourceKernelError(
        'MalformedKernelResponse',
        `The seed-catalog source kernel returned ${detail}.`,
    );

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const requireExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new TypeError(`${label} has the wrong exact byte length.`);
    }
    return value;
};

const requireInteger = (
    value: unknown,
    maximum: number,
    label: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > maximum
    ) {
        throw new TypeError(`${label} is outside its unsigned integer range.`);
    }
    return value;
};

const unsigned16LittleEndian = (value: number, label: string): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(
        0,
        requireInteger(value, unsigned16Maximum, label),
        true,
    );
    return bytes;
};

const unsigned32LittleEndian = (value: number, label: string): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(
        0,
        requireInteger(value, unsigned32Maximum, label),
        true,
    );
    return bytes;
};

const concatenateRequestParts = (parts: readonly Uint8Array[]): Uint8Array => {
    let byteLength = 0;
    for (const part of parts) {
        byteLength += part.byteLength;
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new SeedCatalogSourceKernelError(
                'ResourceLimit',
                'The seed-catalog source request exceeds the absolute copied-buffer bound.',
            );
        }
    }
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.byteLength;
    }
    return bytes;
};

const canonicalRecipientPositions = (
    context: SeedCatalogSourceCustodyContext,
): readonly number[] =>
    Array.from(
        { length: context.participantCount },
        (_unused, participantPosition) => participantPosition,
    ).filter(
        (participantPosition) =>
            participantPosition !== context.participantPosition,
    );

const encodeCommonRequestParts = (
    preparationContextBytes: Uint8Array,
    operation: number,
    input: SeedCatalogProductionInput,
): readonly Uint8Array[] => {
    const context = input.context;
    const geometry = input.geometry;
    const leafCount = requireInteger(
        geometry.leafOpeningByteLengths.length,
        unsigned32Maximum,
        'Seed-catalog leaf count',
    );
    const deliveryCount = requireInteger(
        geometry.deliverySourcePayloadByteLengths.length,
        unsigned16Maximum,
        'Seed-catalog delivery count',
    );
    if (input.sourceInventory.length !== leafCount) {
        throw new TypeError(
            'Seed-catalog source inventory has the wrong leaf count.',
        );
    }
    if (deliveryCount !== context.participantCount - 1) {
        throw new TypeError(
            'Seed-catalog delivery geometry has the wrong recipient count.',
        );
    }
    const sourceContributionByteLength = requireInteger(
        geometry.sourceContributionByteLength,
        unsigned32Maximum,
        'Seed-catalog source-contribution byte length',
    );
    const commitmentSaltByteLength = requireInteger(
        geometry.commitmentSaltByteLength,
        unsigned32Maximum,
        'Seed-catalog commitment-salt byte length',
    );
    const parts: Uint8Array[] = [
        requestMagic,
        unsigned16LittleEndian(codecVersion, 'Seed-catalog codec version'),
        Uint8Array.of(operation),
        unsigned32LittleEndian(
            preparationContextBytes.byteLength,
            'Preparation-context byte length',
        ),
        preparationContextBytes,
        requireExactBytes(
            context.parameterIdentity,
            hashByteLength,
            'Seed-catalog parameter identity',
        ),
        requireExactBytes(
            context.rosterIdentity,
            hashByteLength,
            'Seed-catalog roster identity',
        ),
        requireExactBytes(
            context.actionContextIdentity,
            hashByteLength,
            'Seed-catalog action-context identity',
        ),
        requireExactBytes(
            context.preparationContextIdentity,
            hashByteLength,
            'Seed-catalog preparation-context identity',
        ),
        requireExactBytes(
            context.catalogCompilerIdentity,
            hashByteLength,
            'Seed-catalog compiler identity',
        ),
        requireExactBytes(
            context.statePredecessorIdentity,
            hashByteLength,
            'Seed-catalog state-predecessor identity',
        ),
        unsigned16LittleEndian(
            context.preparationAttemptOrdinal,
            'Seed-catalog preparation-attempt ordinal',
        ),
        unsigned16LittleEndian(
            context.participantCount,
            'Seed-catalog participant count',
        ),
        unsigned16LittleEndian(
            context.participantPosition,
            'Seed-catalog participant position',
        ),
        unsigned32LittleEndian(leafCount, 'Seed-catalog leaf count'),
        unsigned32LittleEndian(
            sourceContributionByteLength,
            'Seed-catalog source-contribution byte length',
        ),
        unsigned32LittleEndian(
            commitmentSaltByteLength,
            'Seed-catalog commitment-salt byte length',
        ),
        unsigned32LittleEndian(
            geometry.rootBodyByteLength,
            'Seed-catalog root-body byte length',
        ),
        unsigned32LittleEndian(
            geometry.inclusionProofByteLength,
            'Seed-catalog inclusion-proof byte length',
        ),
        unsigned16LittleEndian(deliveryCount, 'Seed-catalog delivery count'),
        ...geometry.leafOpeningByteLengths.map((byteLength, leafOrdinal) =>
            unsigned32LittleEndian(
                byteLength,
                `Seed-catalog opening ${leafOrdinal} byte length`,
            ),
        ),
        ...geometry.deliverySourcePayloadByteLengths.map(
            (byteLength, deliveryIndex) =>
                unsigned32LittleEndian(
                    byteLength,
                    `Seed-catalog delivery ${deliveryIndex} byte length`,
                ),
        ),
    ];
    for (let leafOrdinal = 0; leafOrdinal < leafCount; leafOrdinal += 1) {
        const leaf = input.sourceInventory[leafOrdinal];
        if (leaf === undefined) {
            throw new TypeError('Seed-catalog source inventory is incomplete.');
        }
        parts.push(
            requireExactBytes(
                leaf.sourceContribution,
                sourceContributionByteLength,
                `Seed-catalog source contribution ${leafOrdinal}`,
            ),
            requireExactBytes(
                leaf.commitmentSalt,
                commitmentSaltByteLength,
                `Seed-catalog commitment salt ${leafOrdinal}`,
            ),
        );
    }
    return parts;
};

const encodeCatalogParts = (
    input: SeedCatalogValidationInput,
): readonly Uint8Array[] => {
    if (input.catalog.entries.length !== input.sourceInventory.length) {
        throw new TypeError('Seed-catalog output has the wrong entry count.');
    }
    const parts: Uint8Array[] = [
        requireExactBytes(
            input.catalog.catalogIdentity,
            hashByteLength,
            'Seed-catalog identity',
        ),
        requireExactBytes(
            input.catalog.rootBodyBytes,
            input.geometry.rootBodyByteLength,
            'Seed-catalog root body',
        ),
    ];
    for (
        let leafOrdinal = 0;
        leafOrdinal < input.catalog.entries.length;
        leafOrdinal += 1
    ) {
        const entry = input.catalog.entries[leafOrdinal];
        const openingByteLength =
            input.geometry.leafOpeningByteLengths[leafOrdinal];
        if (entry === undefined || openingByteLength === undefined) {
            throw new TypeError('Seed-catalog output is incomplete.');
        }
        parts.push(
            requireExactBytes(
                entry.openingBytes,
                openingByteLength,
                `Seed-catalog opening ${leafOrdinal}`,
            ),
            requireExactBytes(
                entry.inclusionProofBytes,
                input.geometry.inclusionProofByteLength,
                `Seed-catalog inclusion proof ${leafOrdinal}`,
            ),
        );
    }
    return parts;
};

const encodeRequest = (
    preparationContextBytes: Uint8Array,
    operation: number,
    input:
        | SeedCatalogProductionInput
        | SeedCatalogValidationInput
        | SeedCatalogDeliverySourceProductionInput
        | SeedCatalogDeliverySourceValidationInput,
): Uint8Array => {
    const parts = [
        ...encodeCommonRequestParts(preparationContextBytes, operation, input),
    ];
    if (operation !== produceCatalogOperation) {
        parts.push(...encodeCatalogParts(input as SeedCatalogValidationInput));
    }
    if (
        operation === produceDeliveryOperation ||
        operation === validateDeliveryOperation
    ) {
        const deliveryInput = input as SeedCatalogDeliverySourceProductionInput;
        parts.push(
            unsigned16LittleEndian(
                deliveryInput.recipientPosition,
                'Seed-catalog delivery recipient position',
            ),
        );
        if (operation === validateDeliveryOperation) {
            const recipients = canonicalRecipientPositions(input.context);
            const deliveryIndex = recipients.indexOf(
                deliveryInput.recipientPosition,
            );
            const expectedByteLength =
                input.geometry.deliverySourcePayloadByteLengths[deliveryIndex];
            if (deliveryIndex < 0 || expectedByteLength === undefined) {
                throw new TypeError(
                    'Seed-catalog delivery recipient is noncanonical.',
                );
            }
            parts.push(
                requireExactBytes(
                    (input as SeedCatalogDeliverySourceValidationInput)
                        .sourcePayloadBytes,
                    expectedByteLength,
                    'Seed-catalog delivery-source payload',
                ),
            );
        }
    }
    return concatenateRequestParts(parts);
};

const requireResponseHeader = (responseBytes: Uint8Array): number => {
    if (responseBytes.byteLength < responseHeaderByteLength) {
        throw malformedResponse('a truncated response header');
    }
    for (
        let magicBytePosition = 0;
        magicBytePosition < responseMagic.byteLength;
        magicBytePosition += 1
    ) {
        if (
            responseBytes[magicBytePosition] !==
            responseMagic[magicBytePosition]
        ) {
            throw malformedResponse('the wrong response magic');
        }
    }
    const responseView = new DataView(
        responseBytes.buffer,
        responseBytes.byteOffset,
        responseBytes.byteLength,
    );
    if (
        responseView.getUint16(responseMagic.byteLength, true) !== codecVersion
    ) {
        throw malformedResponse('an unsupported response version');
    }
    return responseBytes[responseHeaderByteLength - 1] ?? failureStatus;
};

const throwKernelFailure = (responseBytes: Uint8Array): never => {
    if (responseBytes.byteLength !== failureResponseByteLength) {
        throw malformedResponse('a malformed failure response');
    }
    const responseCode = new DataView(
        responseBytes.buffer,
        responseBytes.byteOffset,
        responseBytes.byteLength,
    ).getUint16(responseHeaderByteLength, true);
    const code = responseCodeByNumber.get(responseCode);
    if (code === undefined) {
        throw malformedResponse('an unknown failure code');
    }
    throw new SeedCatalogSourceKernelError(
        code,
        `The seed-catalog source kernel refused the request with ${code}.`,
    );
};

const parseCatalogResponse = (
    responseBytes: Uint8Array,
    input: SeedCatalogProductionInput,
): RetainedLocalSeedCatalog => {
    const status = requireResponseHeader(responseBytes);
    if (status === failureStatus) {
        throwKernelFailure(responseBytes);
    }
    const expectedByteLength =
        responseHeaderByteLength +
        hashByteLength +
        input.geometry.rootBodyByteLength +
        input.geometry.leafOpeningByteLengths.reduce(
            (total, openingByteLength) =>
                total +
                openingByteLength +
                input.geometry.inclusionProofByteLength,
            0,
        );
    if (
        status !== catalogStatus ||
        responseBytes.byteLength !== expectedByteLength
    ) {
        throw malformedResponse('an invalid catalog response');
    }
    let offset = responseHeaderByteLength;
    const catalogIdentity = responseBytes.slice(
        offset,
        offset + hashByteLength,
    );
    offset += hashByteLength;
    const rootBodyBytes = responseBytes.slice(
        offset,
        offset + input.geometry.rootBodyByteLength,
    );
    offset += input.geometry.rootBodyByteLength;
    const entries = input.geometry.leafOpeningByteLengths.map(
        (openingByteLength) => {
            const openingBytes = responseBytes.slice(
                offset,
                offset + openingByteLength,
            );
            offset += openingByteLength;
            const inclusionProofBytes = responseBytes.slice(
                offset,
                offset + input.geometry.inclusionProofByteLength,
            );
            offset += input.geometry.inclusionProofByteLength;
            return Object.freeze({ inclusionProofBytes, openingBytes });
        },
    );
    if (offset !== responseBytes.byteLength) {
        throw malformedResponse('trailing catalog response bytes');
    }
    return Object.freeze({
        catalogIdentity,
        entries: Object.freeze(entries),
        rootBodyBytes,
    });
};

const parseDeliveryResponse = (
    responseBytes: Uint8Array,
    input: SeedCatalogDeliverySourceProductionInput,
): Readonly<{
    recipientPosition: number;
    sourcePayloadBytes: Uint8Array;
}> => {
    const status = requireResponseHeader(responseBytes);
    if (status === failureStatus) {
        throwKernelFailure(responseBytes);
    }
    const recipients = canonicalRecipientPositions(input.context);
    const deliveryIndex = recipients.indexOf(input.recipientPosition);
    const expectedPayloadByteLength =
        input.geometry.deliverySourcePayloadByteLengths[deliveryIndex];
    if (deliveryIndex < 0 || expectedPayloadByteLength === undefined) {
        throw new TypeError('Seed-catalog delivery recipient is noncanonical.');
    }
    if (
        status !== deliveryStatus ||
        responseBytes.byteLength !==
            responseHeaderByteLength + 2 + expectedPayloadByteLength
    ) {
        throw malformedResponse('an invalid delivery response');
    }
    const returnedRecipientPosition = new DataView(
        responseBytes.buffer,
        responseBytes.byteOffset,
        responseBytes.byteLength,
    ).getUint16(responseHeaderByteLength, true);
    if (returnedRecipientPosition !== input.recipientPosition) {
        throw malformedResponse('a wrong delivery recipient');
    }
    return Object.freeze({
        recipientPosition: returnedRecipientPosition,
        sourcePayloadBytes: responseBytes.slice(responseHeaderByteLength + 2),
    });
};

const parseValidationResponse = (responseBytes: Uint8Array): void => {
    const status = requireResponseHeader(responseBytes);
    if (status === failureStatus) {
        throwKernelFailure(responseBytes);
    }
    if (
        status !== validationStatus ||
        responseBytes.byteLength !== responseHeaderByteLength
    ) {
        throw malformedResponse('an invalid validation response');
    }
};

const runOperation = <Result>(input: {
    operation: number;
    parseResponse(responseBytes: Uint8Array): Result;
    preparationContextBytes: Uint8Array;
    productionInput:
        | SeedCatalogProductionInput
        | SeedCatalogValidationInput
        | SeedCatalogDeliverySourceProductionInput
        | SeedCatalogDeliverySourceValidationInput;
    runtime: TranscriptCoreKernelCommandRuntime;
}): Result => {
    const requestBytes = encodeRequest(
        input.preparationContextBytes,
        input.operation,
        input.productionInput,
    );
    let responseBytes: Uint8Array | undefined;
    try {
        responseBytes = input.runtime.executeSeedCatalogSource(requestBytes);
        return input.parseResponse(responseBytes);
    } finally {
        requestBytes.fill(0);
        responseBytes?.fill(0);
    }
};

export const isProductionSeedCatalogSourceCustodyKernel = (
    value: unknown,
): value is ProductionSeedCatalogSourceCustodyKernel =>
    typeof value === 'object' && value !== null && productionKernels.has(value);

/**
 * Loads one integrity-pinned scalar kernel and binds every source operation to
 * one exact canonical preparation context.
 */
export const openProductionSeedCatalogSourceCustodyKernel = async (
    transcriptCoreKernelUrl: URL,
    preparationContextBytes: Uint8Array,
): Promise<ProductionSeedCatalogSourceCustodyKernel> => {
    if (packagedKernelSha256Hex === undefined) {
        throw new Error(
            'The seed-catalog source kernel requires the package build integrity identity.',
        );
    }
    if (
        !isUint8Array(preparationContextBytes) ||
        preparationContextBytes.byteLength === 0 ||
        preparationContextBytes.byteLength > maximumPreparationContextByteLength
    ) {
        throw new TypeError(
            'The seed-catalog source kernel requires bounded canonical preparation-context bytes.',
        );
    }
    const retainedPreparationContextBytes = preparationContextBytes.slice();
    const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
        transcriptCoreKernelUrl,
        { expectedKernelSha256Hex: packagedKernelSha256Hex },
    );
    const kernel = Object.freeze({
        [seedCatalogSourceCustodyKernelBrand]: true as const,
        preparationContextByteLength:
            retainedPreparationContextBytes.byteLength,
        produceCatalog: (
            input: SeedCatalogProductionInput,
        ): RetainedLocalSeedCatalog =>
            runOperation({
                operation: produceCatalogOperation,
                parseResponse: (responseBytes) =>
                    parseCatalogResponse(responseBytes, input),
                preparationContextBytes: retainedPreparationContextBytes,
                productionInput: input,
                runtime,
            }),
        produceDeliverySource: (
            input: SeedCatalogDeliverySourceProductionInput,
        ): Readonly<{
            recipientPosition: number;
            sourcePayloadBytes: Uint8Array;
        }> =>
            runOperation({
                operation: produceDeliveryOperation,
                parseResponse: (responseBytes) =>
                    parseDeliveryResponse(responseBytes, input),
                preparationContextBytes: retainedPreparationContextBytes,
                productionInput: input,
                runtime,
            }),
        validateCatalog: (input: SeedCatalogValidationInput): void =>
            runOperation({
                operation: validateCatalogOperation,
                parseResponse: parseValidationResponse,
                preparationContextBytes: retainedPreparationContextBytes,
                productionInput: input,
                runtime,
            }),
        validateDeliverySource: (
            input: SeedCatalogDeliverySourceValidationInput,
        ): void =>
            runOperation({
                operation: validateDeliveryOperation,
                parseResponse: parseValidationResponse,
                preparationContextBytes: retainedPreparationContextBytes,
                productionInput: input,
                runtime,
            }),
    });
    productionKernels.add(kernel);
    return kernel;
};
