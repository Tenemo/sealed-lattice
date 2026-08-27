import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';

const responseMagic = Uint8Array.of(0x53, 0x4c, 0x4a, 0x52);
const responseVersion = 1;
const failureStatus = 0;
const joinStatus = 1;
const validationStatus = 2;
const responseHeaderByteLength = responseMagic.byteLength + 2 + 1;
const failureResponseByteLength = responseHeaderByteLength + 2;
const joinResponseHeaderByteLength = responseHeaderByteLength + 4;
const joinedSeedMasterCustodyKernelBrand: unique symbol = Symbol(
    'joined-seed-master-custody-kernel',
);

// The package build replaces this identifier with the normalized hash of the
// exact copied WASM artifact. An unreplaced source build remains fail-closed.
declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

export type JoinedSeedMasterKernelErrorCode =
    | 'ContextMismatch'
    | 'JoinedPayload'
    | 'MalformedKernelResponse'
    | 'MalformedRequest'
    | 'PublicVerification'
    | 'ReceiptCustody'
    | 'ResourceLimit'
    | 'SourceCustody';

export class JoinedSeedMasterKernelError extends Error {
    public readonly code: JoinedSeedMasterKernelErrorCode;

    public constructor(code: JoinedSeedMasterKernelErrorCode, message: string) {
        super(message);
        this.name = 'JoinedSeedMasterKernelError';
        this.code = code;
    }
}

/**
 * Integrity-pinned scalar Rust/WebAssembly boundary for exact joined-custody
 * bytes. The brand is private to this module and is also checked at runtime.
 */
export type ProductionJoinedSeedMasterCustodyKernel = Readonly<{
    readonly [joinedSeedMasterCustodyKernelBrand]: true;
    joinAndEncode(requestBytes: Uint8Array): Uint8Array;
    validateRetained(recordBytes: Uint8Array): void;
}>;

const productionKernels = new WeakSet<object>();

const responseCodeByNumber = new Map<
    number,
    Exclude<JoinedSeedMasterKernelErrorCode, 'MalformedKernelResponse'>
>([
    [1, 'MalformedRequest'],
    [2, 'ResourceLimit'],
    [3, 'ContextMismatch'],
    [4, 'PublicVerification'],
    [5, 'SourceCustody'],
    [6, 'ReceiptCustody'],
    [7, 'JoinedPayload'],
]);

const malformedResponse = (detail: string): JoinedSeedMasterKernelError =>
    new JoinedSeedMasterKernelError(
        'MalformedKernelResponse',
        `The joined seed-master kernel returned ${detail}.`,
    );

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

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
        responseView.getUint16(responseMagic.byteLength, true) !==
        responseVersion
    ) {
        throw malformedResponse('an unsupported response version');
    }
    return responseBytes[responseHeaderByteLength - 1];
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
    throw new JoinedSeedMasterKernelError(
        code,
        `The joined seed-master kernel refused the request with ${code}.`,
    );
};

const parseJoinResponse = (responseBytes: Uint8Array): Uint8Array => {
    const status = requireResponseHeader(responseBytes);
    if (status === failureStatus) {
        throwKernelFailure(responseBytes);
    }
    if (
        status !== joinStatus ||
        responseBytes.byteLength < joinResponseHeaderByteLength
    ) {
        throw malformedResponse('an invalid join response status or length');
    }
    const payloadByteLength = new DataView(
        responseBytes.buffer,
        responseBytes.byteOffset,
        responseBytes.byteLength,
    ).getUint32(responseHeaderByteLength, true);
    if (
        payloadByteLength !==
        responseBytes.byteLength - joinResponseHeaderByteLength
    ) {
        throw malformedResponse('a mismatched join payload length');
    }
    return responseBytes.slice(joinResponseHeaderByteLength);
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

const runJoin = (
    runtime: TranscriptCoreKernelCommandRuntime,
    requestBytes: Uint8Array,
): Uint8Array => {
    if (!isUint8Array(requestBytes)) {
        throw new TypeError(
            'Joined seed-master production requires an exact byte request.',
        );
    }
    const responseBytes = runtime.executeJoinedSeedMasterJoin(requestBytes);
    try {
        return parseJoinResponse(responseBytes);
    } finally {
        responseBytes.fill(0);
    }
};

const runValidation = (
    runtime: TranscriptCoreKernelCommandRuntime,
    recordBytes: Uint8Array,
): void => {
    if (!isUint8Array(recordBytes)) {
        throw new TypeError(
            'Joined seed-master validation requires exact record bytes.',
        );
    }
    const responseBytes =
        runtime.executeJoinedSeedMasterValidation(recordBytes);
    try {
        parseValidationResponse(responseBytes);
    } finally {
        responseBytes.fill(0);
    }
};

export const isProductionJoinedSeedMasterCustodyKernel = (
    value: unknown,
): value is ProductionJoinedSeedMasterCustodyKernel =>
    typeof value === 'object' && value !== null && productionKernels.has(value);

/**
 * Loads one exact integrity-pinned scalar kernel. There is intentionally no
 * unpinned or JavaScript-object construction route for this custody boundary.
 */
export const openProductionJoinedSeedMasterCustodyKernel = async (
    transcriptCoreKernelUrl: URL,
): Promise<ProductionJoinedSeedMasterCustodyKernel> => {
    if (packagedKernelSha256Hex === undefined) {
        throw new Error(
            'The joined seed-master kernel requires the package build integrity identity.',
        );
    }
    const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
        transcriptCoreKernelUrl,
        { expectedKernelSha256Hex: packagedKernelSha256Hex },
    );
    const kernel = Object.freeze({
        [joinedSeedMasterCustodyKernelBrand]: true as const,
        joinAndEncode: (requestBytes: Uint8Array): Uint8Array =>
            runJoin(runtime, requestBytes),
        validateRetained: (recordBytes: Uint8Array): void =>
            runValidation(runtime, recordBytes),
    });
    productionKernels.add(kernel);
    return kernel;
};
