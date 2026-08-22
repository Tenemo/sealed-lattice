import {
    foundationProfile,
    type CanonicalError,
    type CanonicalErrorCode,
} from '@sealed-lattice/types';

import type {
    KernelFailureResponse,
    KernelSuccessResponse,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from './kernel-contracts.js';
import {
    bytesToHex,
    concatenateByteChunks,
    hasWasmHeader,
    normalizeRustSourcePathsForHash,
    readWasmVarUint32,
    sha256HexPattern,
    textDecoder,
    textEncoder,
    wasm32UsizeByteLength,
    wasmCustomSectionId,
    wasmHeaderByteLength,
} from './kernel-contracts.js';
import { canonicalErrorCodes } from './kernel-errors.js';

export class TranscriptCoreKernelCommandError extends Error {
    readonly code: CanonicalErrorCode;

    constructor(error: CanonicalError) {
        super(`${error.code}: ${error.message}`);
        this.name = 'TranscriptCoreKernelCommandError';
        this.code = error.code;
    }
}

const wasmPageByteLength = 65_536;
const maximumTranscriptCoreCommandByteLength = 64 * 1024 * 1024;
const maximumTranscriptCoreCommandResponseByteLength = 256 * 1024 * 1024;
const maximumTranscriptCoreCommandJsonContainerDepth = 64;
const maximumTranscriptCoreKernelMemoryByteLength =
    foundationProfile.maximumWasmMemoryByteLength;

const commandBoundaryError = (
    code: CanonicalErrorCode,
    message: string,
): TranscriptCoreKernelCommandError =>
    new TranscriptCoreKernelCommandError({ code, message });

const jsonStringByteLength = (value: string): number => {
    let byteLength = 2;
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit === 0x22 || codeUnit === 0x5c) {
            byteLength += 2;
        } else if (codeUnit <= 0x1f) {
            byteLength += [0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(codeUnit)
                ? 2
                : 6;
        } else if (codeUnit <= 0x7f) {
            byteLength += 1;
        } else if (codeUnit <= 0x7ff) {
            byteLength += 2;
        } else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const followingCodeUnit = value.charCodeAt(index + 1);
            if (followingCodeUnit >= 0xdc00 && followingCodeUnit <= 0xdfff) {
                byteLength += 4;
                index += 1;
            } else {
                byteLength += 6;
            }
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            byteLength += 6;
        } else {
            byteLength += 3;
        }
    }

    return byteLength;
};

const serializeBoundedKernelCommandRequest = (
    request: unknown,
    maximumByteLength = maximumTranscriptCoreCommandByteLength,
): Uint8Array => {
    if (!Number.isSafeInteger(maximumByteLength) || maximumByteLength < 0) {
        throw new RangeError(
            'The transcript-core command byte limit must be a non-negative safe integer.',
        );
    }
    if (
        typeof request !== 'object' ||
        request === null ||
        Array.isArray(request)
    ) {
        throw commandBoundaryError(
            'InvalidProtocolObject',
            'The transcript-core command must be a JSON object.',
        );
    }

    let measuredByteLength = 0;
    const activeContainers = new WeakSet<object>();
    const charge = (additionalByteLength: number): void => {
        if (additionalByteLength > maximumByteLength - measuredByteLength) {
            throw commandBoundaryError(
                'MalformedLength',
                'The transcript-core command exceeds the accepted byte length.',
            );
        }
        measuredByteLength += additionalByteLength;
    };
    const omittedObjectValue = Symbol('omitted-object-value');
    const serializeValue = (
        value: unknown,
        arrayElement: boolean,
        containerDepth: number,
    ): string | typeof omittedObjectValue => {
        if (value === null) {
            charge(4);
            return 'null';
        }

        switch (typeof value) {
            case 'string': {
                charge(jsonStringByteLength(value));
                return JSON.stringify(value);
            }
            case 'boolean':
                charge(value ? 4 : 5);
                return value ? 'true' : 'false';
            case 'number': {
                if (!Number.isFinite(value)) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command contains a non-finite number.',
                    );
                }
                if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command contains an integer outside the interoperable safe range.',
                    );
                }
                const serializedNumber = String(
                    Object.is(value, -0) ? 0 : value,
                );
                charge(serializedNumber.length);
                return serializedNumber;
            }
            case 'undefined':
            case 'function':
            case 'symbol':
                if (arrayElement) {
                    charge(4);
                    return 'null';
                }
                return omittedObjectValue;
            case 'bigint':
                throw commandBoundaryError(
                    'InvalidProtocolObject',
                    'The transcript-core command cannot contain a bigint.',
                );
            case 'object':
                break;
            default:
                return omittedObjectValue;
        }

        const container = value;
        if (containerDepth >= maximumTranscriptCoreCommandJsonContainerDepth) {
            throw commandBoundaryError(
                'MalformedLength',
                'The transcript-core command exceeds the accepted JSON nesting depth.',
            );
        }
        if (activeContainers.has(container)) {
            throw commandBoundaryError(
                'InvalidProtocolObject',
                'The transcript-core command contains a cyclic value.',
            );
        }
        activeContainers.add(container);
        try {
            const toJsonDescriptor = Object.getOwnPropertyDescriptor(
                container,
                'toJSON',
            );
            if (
                toJsonDescriptor !== undefined &&
                ('get' in toJsonDescriptor ||
                    'set' in toJsonDescriptor ||
                    ('value' in toJsonDescriptor &&
                        typeof toJsonDescriptor.value === 'function'))
            ) {
                throw commandBoundaryError(
                    'InvalidProtocolObject',
                    'The transcript-core command cannot contain custom JSON serialization.',
                );
            }

            if (Array.isArray(container)) {
                const prototype = Reflect.getPrototypeOf(container);
                if (prototype !== Array.prototype && prototype !== null) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command must contain only plain objects and arrays.',
                    );
                }
                const lengthDescriptor = Object.getOwnPropertyDescriptor(
                    container,
                    'length',
                );
                if (
                    lengthDescriptor === undefined ||
                    !('value' in lengthDescriptor) ||
                    !Number.isSafeInteger(lengthDescriptor.value) ||
                    lengthDescriptor.value < 0
                ) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command contains an invalid array length.',
                    );
                }
                const arrayLength = lengthDescriptor.value as number;
                charge(2 + Math.max(0, arrayLength - 1));
                const serializedItems: string[] = [];
                for (let index = 0; index < arrayLength; index += 1) {
                    const descriptor = Object.getOwnPropertyDescriptor(
                        container,
                        String(index),
                    );
                    if (descriptor === undefined) {
                        charge(4);
                        serializedItems.push('null');
                    } else if ('get' in descriptor || 'set' in descriptor) {
                        throw commandBoundaryError(
                            'InvalidProtocolObject',
                            'The transcript-core command cannot contain accessor properties.',
                        );
                    } else {
                        const serializedItem = serializeValue(
                            descriptor.value,
                            true,
                            containerDepth + 1,
                        );
                        if (serializedItem === omittedObjectValue) {
                            throw new Error(
                                'Array-element JSON serialization unexpectedly omitted a value.',
                            );
                        }
                        serializedItems.push(serializedItem);
                    }
                }
                return `[${serializedItems.join(',')}]`;
            }

            const prototype = Reflect.getPrototypeOf(container);
            if (prototype !== Object.prototype && prototype !== null) {
                throw commandBoundaryError(
                    'InvalidProtocolObject',
                    'The transcript-core command must contain only plain objects and arrays.',
                );
            }

            const descriptors = Object.getOwnPropertyDescriptors(container);
            const serializedEntries: string[] = [];
            for (const [fieldName, descriptor] of Object.entries(descriptors)) {
                if (descriptor.enumerable !== true) {
                    continue;
                }
                if ('get' in descriptor || 'set' in descriptor) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command cannot contain accessor properties.',
                    );
                }
                const serializedValue = serializeValue(
                    descriptor.value,
                    false,
                    containerDepth + 1,
                );
                if (serializedValue === omittedObjectValue) {
                    continue;
                }
                charge(jsonStringByteLength(fieldName) + 1);
                serializedEntries.push(
                    `${JSON.stringify(fieldName)}:${serializedValue}`,
                );
            }
            charge(2 + Math.max(0, serializedEntries.length - 1));
            return `{${serializedEntries.join(',')}}`;
        } finally {
            activeContainers.delete(container);
        }
    };

    const serializedRequest = serializeValue(request, false, 0);
    if (serializedRequest === omittedObjectValue) {
        throw commandBoundaryError(
            'InvalidProtocolObject',
            'The transcript-core command is not a JSON object.',
        );
    }
    const requestBytes = textEncoder.encode(serializedRequest);
    if (requestBytes.byteLength > maximumByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The transcript-core command exceeds the accepted byte length.',
        );
    }
    return requestBytes;
};

// Excludes WASM custom sections (debug / producers / name) from the integrity hash:
// they vary by toolchain but do not affect execution, so dropping them keeps the
// hash reproducible across build environments.
const stripWasmCustomSectionsForHash = (bytes: Uint8Array): Uint8Array => {
    if (!hasWasmHeader(bytes)) {
        return bytes;
    }

    const chunks: Uint8Array[] = [bytes.subarray(0, wasmHeaderByteLength)];
    let totalByteLength = wasmHeaderByteLength;
    let sectionOffset = wasmHeaderByteLength;

    while (sectionOffset < bytes.length) {
        const sectionId = bytes[sectionOffset];
        const sectionSize = readWasmVarUint32(bytes, sectionOffset + 1);
        const sectionPayloadOffset = sectionSize.nextOffset;
        const nextSectionOffset = sectionPayloadOffset + sectionSize.value;
        if (nextSectionOffset > bytes.length) {
            throw new Error(
                'The transcript-core kernel contains a truncated WASM section.',
            );
        }

        if (sectionId !== wasmCustomSectionId) {
            const sectionBytes = bytes.subarray(
                sectionOffset,
                nextSectionOffset,
            );
            chunks.push(sectionBytes);
            totalByteLength += sectionBytes.length;
        }

        sectionOffset = nextSectionOffset;
    }

    return concatenateByteChunks(chunks, totalByteLength);
};

export const normalizeTranscriptCoreKernelBytesForHash = (
    bytes: Uint8Array,
): Uint8Array =>
    stripWasmCustomSectionsForHash(normalizeRustSourcePathsForHash(bytes));

const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
    const subtleCrypto = globalThis.crypto?.subtle;
    /* v8 ignore next 5 */
    if (subtleCrypto === undefined) {
        throw new Error(
            'The transcript-core kernel loader requires Web Crypto SHA-256 support.',
        );
    }

    const hashInput = Uint8Array.from(bytes);

    return bytesToHex(
        new Uint8Array(await subtleCrypto.digest('SHA-256', hashInput.buffer)),
    );
};

const verifyKernelIntegrity = async (
    bytes: ArrayBuffer,
    expectedSha256Hex: string,
): Promise<void> => {
    if (!sha256HexPattern.test(expectedSha256Hex)) {
        throw new Error(
            `The transcript-core kernel expected integrity hash is invalid: ${expectedSha256Hex}.`,
        );
    }

    const actualSha256Hex = await sha256Hex(
        normalizeTranscriptCoreKernelBytesForHash(new Uint8Array(bytes)),
    );
    if (actualSha256Hex !== expectedSha256Hex) {
        throw new Error(
            `The transcript-core kernel failed integrity verification: expected ${expectedSha256Hex}, received ${actualSha256Hex}.`,
        );
    }
};

export type TranscriptCoreKernelLoaderOptions = {
    readonly allowUnpinnedKernel?: boolean;
    readonly expectedKernelSha256Hex?: string;
};

export type TranscriptCoreKernelCommandRuntime = Readonly<{
    readonly allocate: (length: number) => number;
    readonly deallocate: (pointer: number, length: number) => void;
    readonly executeCommand: <Result>(
        request: TranscriptCoreKernelCommand,
    ) => Result;
    readonly memory: WebAssembly.Memory;
    readonly runExclusive: <Result>(
        operationName: string,
        operation: () => Result,
    ) => Result;
    readonly wasmExports: TranscriptCoreKernelExports;
}>;

const requireKernelIntegrityExpectation = (
    options: TranscriptCoreKernelLoaderOptions,
): string | undefined => {
    const { expectedKernelSha256Hex } = options;
    if (expectedKernelSha256Hex !== undefined) {
        if (!sha256HexPattern.test(expectedKernelSha256Hex)) {
            throw new Error(
                `The transcript-core kernel expected integrity hash is invalid: ${expectedKernelSha256Hex}.`,
            );
        }

        return expectedKernelSha256Hex;
    }
    if (options.allowUnpinnedKernel === true) {
        return undefined;
    }

    throw new Error(
        'The transcript-core kernel loader requires expectedKernelSha256Hex unless allowUnpinnedKernel is explicitly enabled.',
    );
};

const readWasmFile = async (fileUrl: URL): Promise<ArrayBuffer> => {
    const { readNodeFileAsArrayBuffer } =
        await import('./kernel-node-file-loader.js');

    return readNodeFileAsArrayBuffer(fileUrl);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const isCanonicalErrorCode = (value: unknown): value is CanonicalErrorCode =>
    typeof value === 'string' &&
    canonicalErrorCodes.has(value as CanonicalErrorCode);

const isCanonicalError = (value: unknown): value is CanonicalError =>
    isRecord(value) &&
    isCanonicalErrorCode(value.code) &&
    typeof value.message === 'string';

const isKernelFailureResponse = (
    value: unknown,
): value is KernelFailureResponse =>
    isRecord(value) && value.success === false && isCanonicalError(value.error);

const isKernelSuccessResponse = <T>(
    value: unknown,
): value is KernelSuccessResponse<T> =>
    isRecord(value) && value.success === true && 'value' in value;

const resolveKernelBytes = async (
    transcriptCoreKernelUrl: URL,
): Promise<ArrayBuffer> => {
    /* v8 ignore next */
    if (transcriptCoreKernelUrl.protocol === 'file:') {
        return readWasmFile(transcriptCoreKernelUrl);
    }

    /* v8 ignore start */
    const response = await fetch(transcriptCoreKernelUrl);
    if (!response.ok) {
        throw new Error(
            `Failed to fetch the transcript-core kernel from ${transcriptCoreKernelUrl.toString()}.`,
        );
    }

    return response.arrayBuffer();
    /* v8 ignore stop */
};

const assertKernelMemoryWithinProfile = (
    memory: WebAssembly.Memory,
    maximumByteLength: number = maximumTranscriptCoreKernelMemoryByteLength,
): void => {
    if (
        !Number.isSafeInteger(maximumByteLength) ||
        maximumByteLength < wasmPageByteLength ||
        maximumByteLength % wasmPageByteLength !== 0
    ) {
        throw new RangeError(
            'The transcript-core kernel memory limit must be a positive whole number of WASM pages.',
        );
    }
    if (memory.buffer.byteLength > maximumByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The transcript-core kernel exceeded the absolute linear-memory safety bound.',
        );
    }
};

const resolveMemory = (
    exports: TranscriptCoreKernelExports,
): WebAssembly.Memory => {
    const { memory } = exports;
    /* v8 ignore next 3 */
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error(
            'The transcript-core kernel did not expose linear memory.',
        );
    }

    assertKernelMemoryWithinProfile(memory);

    return memory;
};

const requireKernelMemoryRange = (
    memory: WebAssembly.Memory,
    pointer: number,
    length: number,
    operationName: string,
): number => {
    assertKernelMemoryWithinProfile(memory);
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error(
            `The transcript-core kernel returned an invalid ${operationName} byte length.`,
        );
    }
    const unsignedPointer = pointer >>> 0;
    const endOffset = unsignedPointer + length;
    if (
        (length > 0 && unsignedPointer === 0) ||
        endOffset > memory.buffer.byteLength ||
        endOffset > maximumTranscriptCoreKernelMemoryByteLength
    ) {
        throw new Error(
            `The transcript-core kernel returned an out-of-bounds ${operationName} memory range.`,
        );
    }

    return unsignedPointer;
};

type NumberExportName =
    | 'sealed_lattice_allocate'
    | 'sealed_lattice_action_randomness_command'
    | 'sealed_lattice_aggregate_threshold_share_absorb_authenticated_recipient_payload'
    | 'sealed_lattice_aggregate_threshold_share_begin_recipient_authority'
    | 'sealed_lattice_aggregate_threshold_share_cancel_private_share_acceptance_carrier'
    | 'sealed_lattice_aggregate_threshold_share_discard_recipient_authority'
    | 'sealed_lattice_aggregate_threshold_share_finish_private_share_acceptance_carrier'
    | 'sealed_lattice_aggregate_threshold_share_prepare_private_share_acceptance_carrier'
    | 'sealed_lattice_accepted_setup_authority_release'
    | 'sealed_lattice_accepted_setup_package_builder_add_proof_source'
    | 'sealed_lattice_accepted_setup_package_builder_begin'
    | 'sealed_lattice_accepted_setup_package_builder_cancel'
    | 'sealed_lattice_accepted_setup_package_builder_copy_bytes'
    | 'sealed_lattice_accepted_setup_package_builder_finish'
    | 'sealed_lattice_accepted_setup_public_key_share_finish_generated_verification'
    | 'sealed_lattice_accepted_setup_public_key_share_prepare_compact_verification'
    | 'sealed_lattice_accepted_setup_compact_public_key_begin_verification'
    | 'sealed_lattice_accepted_setup_compact_public_key_cancel_verification'
    | 'sealed_lattice_accepted_setup_compact_public_key_copy_checkpoint_source_digests'
    | 'sealed_lattice_accepted_setup_compact_public_key_copy_verification_checkpoint'
    | 'sealed_lattice_accepted_setup_compact_public_key_discard_capability'
    | 'sealed_lattice_accepted_setup_compact_public_key_discard_prepared_verification'
    | 'sealed_lattice_accepted_setup_compact_public_key_finish_verification'
    | 'sealed_lattice_accepted_setup_compact_public_key_resume_verification'
    | 'sealed_lattice_accepted_setup_compact_public_key_verification_checkpoint_byte_length'
    | 'sealed_lattice_accepted_setup_compact_public_key_verification_safe_boundary_count'
    | 'sealed_lattice_accepted_setup_compact_public_key_verification_poll'
    | 'sealed_lattice_accepted_setup_same_secret_finish_generated_verification'
    | 'sealed_lattice_accepted_setup_verification_begin_from_package_builder'
    | 'sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources'
    | 'sealed_lattice_prepackage_evaluator_source_catalog_begin'
    | 'sealed_lattice_prepackage_evaluator_source_catalog_cancel'
    | 'sealed_lattice_prepackage_evaluator_source_catalog_complete'
    | 'sealed_lattice_prepackage_evaluator_generated_proofs_bind_package'
    | 'sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk'
    | 'sealed_lattice_evaluator_aggregate_absorb_store_material_chunk'
    | 'sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk'
    | 'sealed_lattice_evaluator_aggregate_application_statement_byte_length'
    | 'sealed_lattice_evaluator_aggregate_begin_runtime_component_tree'
    | 'sealed_lattice_evaluator_aggregate_begin_store_construction'
    | 'sealed_lattice_evaluator_aggregate_commit_generated_proof'
    | 'sealed_lattice_evaluator_aggregate_commit_verified_store'
    | 'sealed_lattice_evaluator_aggregate_contribute_package'
    | 'sealed_lattice_evaluator_aggregate_copy_application_statement'
    | 'sealed_lattice_evaluator_aggregate_copy_store_output_chunk'
    | 'sealed_lattice_evaluator_aggregate_copy_store_source_request'
    | 'sealed_lattice_evaluator_aggregate_describe_store'
    | 'sealed_lattice_evaluator_aggregate_discard_session'
    | 'sealed_lattice_evaluator_aggregate_finalize_statement'
    | 'sealed_lattice_evaluator_aggregate_finish_runtime_component_tree'
    | 'sealed_lattice_evaluator_aggregate_finish_store_construction'
    | 'sealed_lattice_evaluator_aggregate_finish_store_material'
    | 'sealed_lattice_evaluator_aggregate_finish_verification'
    | 'sealed_lattice_evaluator_aggregate_prepare_generation'
    | 'sealed_lattice_evaluator_aggregate_prepare_resumed_generation'
    | 'sealed_lattice_evaluator_aggregate_prepare_verification'
    | 'sealed_lattice_evaluator_aggregate_store_construction_poll'
    | 'sealed_lattice_evaluator_aggregate_store_source_request_byte_length'
    | 'sealed_lattice_evaluator_aggregate_supply_store_source_range'
    | 'sealed_lattice_evaluator_aggregate_take_package_statement_source'
    | 'sealed_lattice_collective_public_key_aggregate_absorb_participant_chunk'
    | 'sealed_lattice_collective_public_key_aggregate_begin'
    | 'sealed_lattice_collective_public_key_aggregate_begin_participant'
    | 'sealed_lattice_collective_public_key_aggregate_commit_generated_proof'
    | 'sealed_lattice_collective_public_key_aggregate_copy_participant_source_description'
    | 'sealed_lattice_collective_public_key_aggregate_contribute_package'
    | 'sealed_lattice_collective_public_key_aggregate_copy_statement'
    | 'sealed_lattice_collective_public_key_aggregate_copy_stream_range'
    | 'sealed_lattice_collective_public_key_aggregate_describe_stream'
    | 'sealed_lattice_collective_public_key_aggregate_discard_session'
    | 'sealed_lattice_collective_public_key_aggregate_discard_verification_terminal_source'
    | 'sealed_lattice_collective_public_key_aggregate_finish_participant'
    | 'sealed_lattice_collective_public_key_aggregate_finish_roster'
    | 'sealed_lattice_collective_public_key_aggregate_finish_verification'
    | 'sealed_lattice_collective_public_key_aggregate_participant_body_byte_length'
    | 'sealed_lattice_collective_public_key_aggregate_prepare_generation'
    | 'sealed_lattice_collective_public_key_aggregate_prepare_resumed_generation'
    | 'sealed_lattice_collective_public_key_aggregate_prepare_verification'
    | 'sealed_lattice_collective_public_key_aggregate_statement_byte_length'
    | 'sealed_lattice_ballot_aggregation_absorb'
    | 'sealed_lattice_ballot_aggregation_absorb_store_chunk'
    | 'sealed_lattice_ballot_aggregation_aggregate_carrier_byte_length'
    | 'sealed_lattice_ballot_aggregation_begin'
    | 'sealed_lattice_ballot_aggregation_bind_aggregate_object'
    | 'sealed_lattice_ballot_aggregation_cancel'
    | 'sealed_lattice_ballot_aggregation_copy_aggregate_carrier'
    | 'sealed_lattice_ballot_aggregation_discard_verified_aggregate'
    | 'sealed_lattice_ballot_aggregation_poll'
    | 'sealed_lattice_ballot_aggregation_prepare'
    | 'sealed_lattice_evaluator_execution_absorb_store_chunk'
    | 'sealed_lattice_evaluator_execution_begin'
    | 'sealed_lattice_evaluator_execution_bind_replay_object'
    | 'sealed_lattice_evaluator_execution_cancel'
    | 'sealed_lattice_evaluator_execution_copy_replay_carrier'
    | 'sealed_lattice_evaluator_execution_finish'
    | 'sealed_lattice_evaluator_execution_poll'
    | 'sealed_lattice_evaluator_execution_replay_carrier_byte_length'
    | 'sealed_lattice_evaluator_replay_release'
    | 'sealed_lattice_ballot_validity_absorb_ciphertext_chunk'
    | 'sealed_lattice_ballot_validity_begin_verification'
    | 'sealed_lattice_ballot_validity_bind_generated_proof_to_board'
    | 'sealed_lattice_ballot_validity_ciphertext_descriptor_byte_length'
    | 'sealed_lattice_ballot_validity_copy_ciphertext_descriptor'
    | 'sealed_lattice_ballot_validity_discard_ciphertext_readback'
    | 'sealed_lattice_ballot_validity_discard_verification_preparation'
    | 'sealed_lattice_ballot_validity_discard_verification_terminal_source'
    | 'sealed_lattice_ballot_validity_discard_verified_output'
    | 'sealed_lattice_ballot_validity_finish_ciphertext_readback'
    | 'sealed_lattice_ballot_validity_finish_verification'
    | 'sealed_lattice_ballot_validity_finish_verification_preparation'
    | 'sealed_lattice_ballot_validity_prepare_generation'
    | 'sealed_lattice_ballot_validity_prepare_resumed_generation'
    | 'sealed_lattice_ballot_validity_read_ciphertext_chunk'
    | 'sealed_lattice_board_verifier_begin'
    | 'sealed_lattice_board_verifier_cached_carrier_length'
    | 'sealed_lattice_board_verifier_cancel_ballot_candidate_list'
    | 'sealed_lattice_board_verifier_cancel'
    | 'sealed_lattice_board_verifier_copy_cached_carrier'
    | 'sealed_lattice_board_verifier_describe'
    | 'sealed_lattice_board_verifier_finish_ballot_candidate_list'
    | 'sealed_lattice_board_verifier_prepare_ballot_candidate_list'
    | 'sealed_lattice_board_verifier_release'
    | 'sealed_lattice_board_verifier_verify_unordered'
    | 'sealed_lattice_finality_verifier_begin'
    | 'sealed_lattice_finality_verifier_cancel'
    | 'sealed_lattice_finality_verifier_describe'
    | 'sealed_lattice_finality_verifier_release'
    | 'sealed_lattice_finality_verifier_verify'
    | 'sealed_lattice_galois_key_share_commit_generated_source'
    | 'sealed_lattice_galois_key_share_component_absorb_chunk'
    | 'sealed_lattice_galois_key_share_component_begin'
    | 'sealed_lattice_galois_key_share_component_finish'
    | 'sealed_lattice_galois_key_share_component_readback_cancel'
    | 'sealed_lattice_galois_key_share_component_readback_component_count'
    | 'sealed_lattice_galois_key_share_component_readback_copy_descriptor'
    | 'sealed_lattice_galois_key_share_component_readback_copy_material_root'
    | 'sealed_lattice_galois_key_share_component_readback_descriptor_byte_length'
    | 'sealed_lattice_galois_key_share_component_readback_finish'
    | 'sealed_lattice_galois_key_share_component_readback_open'
    | 'sealed_lattice_galois_key_share_component_readback_read_chunk'
    | 'sealed_lattice_galois_key_share_component_readback_total_byte_length'
    | 'sealed_lattice_galois_key_share_discard_generation_source'
    | 'sealed_lattice_galois_key_share_discard_verification_ingress'
    | 'sealed_lattice_galois_key_share_discard_verification_terminal_source'
    | 'sealed_lattice_galois_key_share_finish_verification'
    | 'sealed_lattice_galois_key_share_prepare_generation'
    | 'sealed_lattice_galois_key_share_prepare_resumed_generation'
    | 'sealed_lattice_galois_key_share_prepare_verification'
    | 'sealed_lattice_galois_key_share_verification_ingress_begin'
    | 'sealed_lattice_relinearization_round_two_activation_begin'
    | 'sealed_lattice_relinearization_round_two_activation_next_source_read'
    | 'sealed_lattice_relinearization_round_two_activation_absorb_source'
    | 'sealed_lattice_relinearization_round_two_activation_finish'
    | 'sealed_lattice_relinearization_round_two_activation_discard'
    | 'sealed_lattice_relinearization_round_one_prepare_generation'
    | 'sealed_lattice_relinearization_round_one_prepare_resumed_generation'
    | 'sealed_lattice_relinearization_round_two_prepare_generation'
    | 'sealed_lattice_relinearization_round_two_prepare_resumed_generation'
    | 'sealed_lattice_relinearization_generation_component_count'
    | 'sealed_lattice_relinearization_generation_component_descriptor_byte_length'
    | 'sealed_lattice_relinearization_generation_component_copy_descriptor'
    | 'sealed_lattice_relinearization_generation_component_copy_material_root'
    | 'sealed_lattice_relinearization_generation_component_total_byte_length'
    | 'sealed_lattice_relinearization_generation_component_read_chunk'
    | 'sealed_lattice_relinearization_generation_source_commit'
    | 'sealed_lattice_relinearization_generation_source_discard'
    | 'sealed_lattice_relinearization_round_one_aggregate_construction_begin'
    | 'sealed_lattice_relinearization_round_one_aggregate_construction_next_read'
    | 'sealed_lattice_relinearization_round_one_aggregate_construction_absorb'
    | 'sealed_lattice_relinearization_round_one_aggregate_construction_finish'
    | 'sealed_lattice_relinearization_round_one_aggregate_component_count'
    | 'sealed_lattice_relinearization_round_one_aggregate_component_descriptor_byte_length'
    | 'sealed_lattice_relinearization_round_one_aggregate_component_copy_descriptor'
    | 'sealed_lattice_relinearization_round_one_aggregate_component_copy_material_root'
    | 'sealed_lattice_relinearization_round_one_aggregate_component_total_byte_length'
    | 'sealed_lattice_relinearization_round_one_aggregate_component_read_chunk'
    | 'sealed_lattice_relinearization_round_one_aggregate_prepare_generation'
    | 'sealed_lattice_relinearization_round_one_aggregate_prepare_resumed_generation'
    | 'sealed_lattice_relinearization_round_one_aggregate_commit_generated_source'
    | 'sealed_lattice_relinearization_round_one_aggregate_discard'
    | 'sealed_lattice_relinearization_round_one_verification_ingress_begin'
    | 'sealed_lattice_relinearization_round_one_aggregate_verification_ingress_begin'
    | 'sealed_lattice_relinearization_round_two_verification_ingress_begin'
    | 'sealed_lattice_relinearization_verification_component_begin'
    | 'sealed_lattice_relinearization_verification_component_absorb_chunk'
    | 'sealed_lattice_relinearization_verification_component_finish'
    | 'sealed_lattice_relinearization_prepare_verification'
    | 'sealed_lattice_relinearization_discard_verification_ingress'
    | 'sealed_lattice_relinearization_round_one_finish_verification'
    | 'sealed_lattice_relinearization_round_one_discard_verification_terminal_source'
    | 'sealed_lattice_relinearization_round_one_aggregate_finish_verification'
    | 'sealed_lattice_relinearization_round_one_aggregate_discard_verification_terminal_source'
    | 'sealed_lattice_relinearization_round_two_finish_verification'
    | 'sealed_lattice_relinearization_round_two_discard_verification_terminal_source'
    | 'sealed_lattice_canonical_stream_absorb_chunk'
    | 'sealed_lattice_canonical_stream_begin_verifier'
    | 'sealed_lattice_canonical_stream_begin_writer'
    | 'sealed_lattice_canonical_stream_cancel'
    | 'sealed_lattice_canonical_stream_finish_verifier'
    | 'sealed_lattice_canonical_stream_finish_writer'
    | 'sealed_lattice_common_proof_begin_generation'
    | 'sealed_lattice_common_proof_begin_verification'
    | 'sealed_lattice_compact_public_key_algebraic_verification_poll'
    | 'sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length'
    | 'sealed_lattice_compact_public_key_algebraic_verification_safe_boundary_count'
    | 'sealed_lattice_compact_public_key_begin_algebraic_verification'
    | 'sealed_lattice_compact_public_key_cancel_algebraic_verification'
    | 'sealed_lattice_compact_public_key_copy_algebraic_verification_checkpoint'
    | 'sealed_lattice_compact_public_key_resume_algebraic_verification'
    | 'sealed_lattice_compact_public_key_transport_bindings_byte_length'
    | 'sealed_lattice_compact_public_key_validate_transport'
    | 'sealed_lattice_compact_public_key_generation_cancel'
    | 'sealed_lattice_compact_public_key_generation_copy_external_memory_usage'
    | 'sealed_lattice_compact_public_key_generation_copy_proof'
    | 'sealed_lattice_compact_public_key_generation_copy_public_input'
    | 'sealed_lattice_compact_public_key_generation_copy_storage_request'
    | 'sealed_lattice_compact_public_key_generation_copy_transport_bindings'
    | 'sealed_lattice_compact_public_key_generation_external_memory_usage_word_count'
    | 'sealed_lattice_compact_public_key_generation_pending_storage_request_byte_length'
    | 'sealed_lattice_compact_public_key_generation_poll'
    | 'sealed_lattice_compact_public_key_generation_proof_byte_length'
    | 'sealed_lattice_compact_public_key_generation_public_input_byte_length'
    | 'sealed_lattice_compact_public_key_generation_release_completed'
    | 'sealed_lattice_compact_public_key_generation_supply_storage_response'
    | 'sealed_lattice_common_proof_abort_application'
    | 'sealed_lattice_common_proof_application_frame_byte_length'
    | 'sealed_lattice_common_proof_confirm_application'
    | 'sealed_lattice_common_proof_describe_generation_family_adapter'
    | 'sealed_lattice_common_proof_describe_verification_family_adapter'
    | 'sealed_lattice_common_proof_discard_generation_family_adapter'
    | 'sealed_lattice_common_proof_discard_prepared_generation'
    | 'sealed_lattice_common_proof_discard_prepared_verification'
    | 'sealed_lattice_common_proof_discard_verification_family_adapter'
    | 'sealed_lattice_common_proof_discard_verified_proof'
    | 'sealed_lattice_common_proof_generation_acknowledge_checkpoint'
    | 'sealed_lattice_common_proof_generation_acknowledge_output_chunk'
    | 'sealed_lattice_common_proof_generation_authenticated_source_request_byte_length'
    | 'sealed_lattice_common_proof_generation_checkpoint_state_byte_length'
    | 'sealed_lattice_common_proof_generation_confirm_output_readback'
    | 'sealed_lattice_common_proof_generation_copy_external_memory_accounting'
    | 'sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest'
    | 'sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash'
    | 'sealed_lattice_common_proof_generation_copy_checkpoint_state'
    | 'sealed_lattice_common_proof_generation_copy_authenticated_source_request'
    | 'sealed_lattice_common_proof_generation_copy_output_chunk'
    | 'sealed_lattice_common_proof_generation_copy_storage_request'
    | 'sealed_lattice_common_proof_generation_describe_checkpoint'
    | 'sealed_lattice_common_proof_generation_discard_checkpoint'
    | 'sealed_lattice_common_proof_generation_external_memory_accounting_byte_length'
    | 'sealed_lattice_common_proof_generation_finish'
    | 'sealed_lattice_common_proof_generation_poll'
    | 'sealed_lattice_common_proof_generation_release_cancelled'
    | 'sealed_lattice_common_proof_generation_retire_failed'
    | 'sealed_lattice_common_proof_generation_request_cancellation'
    | 'sealed_lattice_common_proof_generation_supply_storage_response'
    | 'sealed_lattice_common_proof_generation_supply_authenticated_source_range'
    | 'sealed_lattice_common_proof_prepare_application'
    | 'sealed_lattice_common_proof_prepare_generation_family_adapter'
    | 'sealed_lattice_common_proof_prepare_verification_family_adapter'
    | 'sealed_lattice_common_proof_release_generated_proof'
    | 'sealed_lattice_common_proof_copy_selected_suite_record'
    | 'sealed_lattice_common_proof_release_suite'
    | 'sealed_lattice_common_proof_selected_suite_record_byte_length'
    | 'sealed_lattice_common_proof_select_suite'
    | 'sealed_lattice_common_proof_resume_generation'
    | 'sealed_lattice_common_proof_verification_absorb_input_chunk'
    | 'sealed_lattice_common_proof_verification_cancel'
    | 'sealed_lattice_common_proof_verification_copy_readback_accounting'
    | 'sealed_lattice_common_proof_verification_finish'
    | 'sealed_lattice_common_proof_verification_finish_input'
    | 'sealed_lattice_common_proof_verification_poll'
    | 'sealed_lattice_common_proof_verification_readback_accounting_byte_length'
    | 'sealed_lattice_common_proof_verification_supply_readback_chunk'
    | 'sealed_lattice_mailbox_gcm_authenticate_chunk'
    | 'sealed_lattice_mailbox_gcm_begin_encryptor'
    | 'sealed_lattice_mailbox_gcm_begin_verifier'
    | 'sealed_lattice_mailbox_gcm_cancel'
    | 'sealed_lattice_mailbox_gcm_decrypt_chunk'
    | 'sealed_lattice_mailbox_gcm_encrypt_chunk'
    | 'sealed_lattice_mailbox_gcm_finish_authentication'
    | 'sealed_lattice_mailbox_gcm_finish_decryptor'
    | 'sealed_lattice_mailbox_gcm_finish_encryptor'
    | 'sealed_lattice_foundation_roster_encode'
    | 'sealed_lattice_foundation_roster_encoded_byte_length'
    | 'sealed_lattice_deallocate'
    | 'sealed_lattice_local_storage_root_command'
    | 'sealed_lattice_state_producer_command'
    | 'sealed_lattice_state_verifier_begin'
    | 'sealed_lattice_state_verifier_cancel'
    | 'sealed_lattice_state_verifier_certify_intent'
    | 'sealed_lattice_state_verifier_certify_unordered_votes'
    | 'sealed_lattice_state_verifier_describe'
    | 'sealed_lattice_state_verifier_release'
    | 'sealed_lattice_state_verifier_finish_output'
    | 'sealed_lattice_state_verifier_prepare_output'
    | 'sealed_lattice_state_verifier_prepare_reservation'
    | 'sealed_lattice_state_verifier_verify_reservation'
    | 'sealed_lattice_setup_generation_authority_begin'
    | 'sealed_lattice_setup_generation_authority_release'
    | 'sealed_lattice_setup_generation_public_key_share_body_byte_length'
    | 'sealed_lattice_setup_generation_public_key_share_body_cancel'
    | 'sealed_lattice_setup_generation_public_key_share_body_open'
    | 'sealed_lattice_setup_generation_public_key_share_body_read'
    | 'sealed_lattice_setup_generation_public_key_share_source_byte_length'
    | 'sealed_lattice_setup_generation_recipient_vss_payload_byte_length'
    | 'sealed_lattice_setup_generation_recipient_vss_payload_cancel'
    | 'sealed_lattice_setup_generation_recipient_vss_payload_open'
    | 'sealed_lattice_setup_generation_recipient_vss_payload_read'
    | 'sealed_lattice_setup_generation_recipient_vss_payload_source_byte_length'
    | 'sealed_lattice_setup_generation_recipient_vss_payload_source_recipient_roster_position'
    | 'sealed_lattice_same_secret_prepare_generation'
    | 'sealed_lattice_same_secret_prepare_resumed_generation'
    | 'sealed_lattice_same_secret_generation_cancel'
    | 'sealed_lattice_same_secret_generation_contribute_package'
    | 'sealed_lattice_same_secret_generation_supply_authenticated_transcript_prefix'
    | 'sealed_lattice_public_key_share_prepare_generation'
    | 'sealed_lattice_compact_public_key_reference_prepare_generation'
    | 'sealed_lattice_compact_public_key_share_prepare_generation'
    | 'sealed_lattice_public_key_share_prepare_resumed_generation'
    | 'sealed_lattice_public_key_share_generation_cancel'
    | 'sealed_lattice_public_key_share_generation_contribute_package'
    | 'sealed_lattice_accepted_setup_same_secret_prepare_generated_verification'
    | 'sealed_lattice_accepted_setup_public_key_share_prepare_generated_verification'
    | 'sealed_lattice_setup_key_relation_generation_statement_discard'
    | 'sealed_lattice_vss_share_linkage_board_object_handle_catalog_byte_length'
    | 'sealed_lattice_vss_share_linkage_bind_generated_proof_to_board'
    | 'sealed_lattice_vss_share_linkage_discard_generation_board_binding_source'
    | 'sealed_lattice_vss_share_linkage_discard_verification_terminal_source'
    | 'sealed_lattice_vss_share_linkage_discard_verified_terminal'
    | 'sealed_lattice_vss_share_linkage_discard_low_degree_evidence'
    | 'sealed_lattice_vss_share_linkage_finish_verification'
    | 'sealed_lattice_vss_share_linkage_finish_low_degree_evidence'
    | 'sealed_lattice_vss_share_linkage_prepare_generation'
    | 'sealed_lattice_vss_share_linkage_prepare_resumed_generation'
    | 'sealed_lattice_vss_share_linkage_prepare_verification'
    | 'sealed_lattice_target_release_prepare_generation'
    | 'sealed_lattice_target_release_prepare_resumed_generation'
    | 'sealed_lattice_target_release_partial_descriptor_byte_length'
    | 'sealed_lattice_target_release_copy_partial_descriptor'
    | 'sealed_lattice_target_release_partial_total_byte_length'
    | 'sealed_lattice_target_release_read_partial_chunk'
    | 'sealed_lattice_target_release_prepare_output_carrier'
    | 'sealed_lattice_target_release_finish_output_carrier'
    | 'sealed_lattice_target_release_cancel_output_carrier'
    | 'sealed_lattice_target_release_bind_generated_proof'
    | 'sealed_lattice_target_release_discard_generation_source'
    | 'sealed_lattice_target_release_prepare_verification'
    | 'sealed_lattice_target_release_finish_verification'
    | 'sealed_lattice_target_release_discard_verification_terminal_source'
    | 'sealed_lattice_target_release_discard_verified_share'
    | 'sealed_lattice_target_release_reconstruct_verified_shares'
    | 'sealed_lattice_target_release_reconstructed_selected_option_count'
    | 'sealed_lattice_target_release_copy_reconstructed_option_identifiers'
    | 'sealed_lattice_target_release_finish_reconstruction'
    | 'sealed_lattice_target_release_discard_reconstruction'
    | 'sealed_lattice_transcript_core_command_with_length';

const resolveNumberExport = <ExportName extends NumberExportName>(
    exports: TranscriptCoreKernelExports,
    exportName: ExportName,
): NonNullable<TranscriptCoreKernelExports[ExportName]> => {
    const exportValue = exports[exportName];
    /* v8 ignore next 3 */
    if (typeof exportValue !== 'function') {
        throw new Error(
            `The transcript-core kernel did not expose ${exportName}.`,
        );
    }

    return exportValue;
};

const resolveOptionalNumberExport = <ExportName extends NumberExportName>(
    exports: TranscriptCoreKernelExports,
    exportName: ExportName,
): NonNullable<TranscriptCoreKernelExports[ExportName]> | undefined =>
    typeof exports[exportName] === 'function'
        ? resolveNumberExport(exports, exportName)
        : undefined;

const copyIntoKernelMemory = (
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    input: Uint8Array,
): number => {
    assertKernelMemoryWithinProfile(memory);
    if (input.length === 0) {
        return 0;
    }

    const pointer = allocate(input.length) >>> 0;
    assertKernelMemoryWithinProfile(memory);
    if (pointer === 0) {
        throw new Error(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    }

    const requiredByteLength = pointer + input.length;
    if (requiredByteLength > maximumTranscriptCoreKernelMemoryByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The transcript-core command allocation exceeds the absolute linear-memory safety bound.',
        );
    }
    if (requiredByteLength > memory.buffer.byteLength) {
        const missingByteLength = requiredByteLength - memory.buffer.byteLength;
        const missingPageCount = Math.ceil(
            missingByteLength / wasmPageByteLength,
        );
        memory.grow(missingPageCount);
        assertKernelMemoryWithinProfile(memory);
    }
    new Uint8Array(memory.buffer).set(input, pointer);

    return pointer;
};

const copyFromKernelMemory = (
    memory: WebAssembly.Memory,
    pointer: number,
    length: number,
    operationName: string,
): Uint8Array => {
    assertKernelMemoryWithinProfile(memory);
    if (length === 0) {
        return new Uint8Array();
    }
    const unsignedPointer = requireKernelMemoryRange(
        memory,
        pointer,
        length,
        operationName,
    );

    return Uint8Array.from(
        new Uint8Array(memory.buffer, unsignedPointer, length),
    );
};

// The kernel writes the response byte length as a little-endian u32 into this
// caller-allocated 4-byte cell (separate from the returned data pointer); read it back.
const readKernelOutputLength = (
    memory: WebAssembly.Memory,
    pointer: number,
): number =>
    new DataView(
        memory.buffer,
        requireKernelMemoryRange(
            memory,
            pointer,
            wasm32UsizeByteLength,
            'output-length',
        ),
        wasm32UsizeByteLength,
    ).getUint32(0, true);

const parseKernelResponse = <T>(bytes: Uint8Array): T => {
    const decodedResponse = JSON.parse(textDecoder.decode(bytes)) as unknown;

    if (isKernelFailureResponse(decodedResponse)) {
        throw new TranscriptCoreKernelCommandError(decodedResponse.error);
    }
    if (isKernelSuccessResponse<T>(decodedResponse)) {
        return decodedResponse.value;
    }

    throw new Error(
        'The transcript-core kernel returned an invalid command response.',
    );
};

const runKernelCommand = <T>(
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    deallocate: (pointer: number, length: number) => void,
    commandWithLength: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number,
    request: TranscriptCoreKernelCommand,
): T => {
    const requestBytes = serializeBoundedKernelCommandRequest(request);
    let inputPointer = 0;
    let outputPointer = 0;
    let outputLengthPointer = 0;
    let outputLength = 0;

    try {
        inputPointer = copyIntoKernelMemory(memory, allocate, requestBytes);
        outputLengthPointer = allocate(wasm32UsizeByteLength) >>> 0;
        assertKernelMemoryWithinProfile(memory);
        if (outputLengthPointer === 0) {
            throw new Error(
                'The transcript-core kernel returned a null pointer for the output-length allocation.',
            );
        }
        outputPointer =
            commandWithLength(
                inputPointer,
                requestBytes.length,
                outputLengthPointer,
            ) >>> 0;
        assertKernelMemoryWithinProfile(memory);
        outputLength = readKernelOutputLength(memory, outputLengthPointer);
        if (outputLength > maximumTranscriptCoreCommandResponseByteLength) {
            throw commandBoundaryError(
                'MalformedLength',
                'The transcript-core command response exceeds the accepted byte length.',
            );
        }
        const outputBytes = copyFromKernelMemory(
            memory,
            outputPointer,
            outputLength,
            'transcript-core command',
        );

        return parseKernelResponse<T>(outputBytes);
    } finally {
        // The kernel may alias the input buffer as the output or otherwise reuse
        // pointers, so each distinct region is freed exactly once: the equality
        // guards below skip a dealloc whose pointer coincides with an already-freed
        // region, preventing a double free.
        if (outputPointer !== 0) {
            deallocate(outputPointer, outputLength);
        }
        if (inputPointer !== 0 && inputPointer !== outputPointer) {
            deallocate(inputPointer, requestBytes.length);
        }
        if (
            outputLengthPointer !== 0 &&
            outputLengthPointer !== inputPointer &&
            outputLengthPointer !== outputPointer
        ) {
            deallocate(outputLengthPointer, wasm32UsizeByteLength);
        }
    }
};

export const instantiateTranscriptCoreKernelCommandRuntime = async (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): Promise<TranscriptCoreKernelCommandRuntime> => {
    const expectedKernelSha256Hex = requireKernelIntegrityExpectation(options);
    const bytes = await resolveKernelBytes(transcriptCoreKernelUrl);
    if (expectedKernelSha256Hex !== undefined) {
        await verifyKernelIntegrity(bytes, expectedKernelSha256Hex);
    }
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const wasmExports = instantiatedSource.instance
        .exports as TranscriptCoreKernelExports;
    const memory = resolveMemory(wasmExports);
    const allocate = resolveNumberExport(
        wasmExports,
        'sealed_lattice_allocate',
    );
    const deallocate = resolveNumberExport(
        wasmExports,
        'sealed_lattice_deallocate',
    );
    const commandWithLength = resolveNumberExport(
        wasmExports,
        'sealed_lattice_transcript_core_command_with_length',
    );
    let kernelOperationInProgress = false;
    const runExclusive = <Result>(
        operationName: string,
        operation: () => Result,
    ): Result => {
        if (kernelOperationInProgress) {
            throw new Error(
                `The transcript-core kernel cannot run overlapping ${operationName} operations on one instance.`,
            );
        }
        kernelOperationInProgress = true;
        try {
            return operation();
        } finally {
            kernelOperationInProgress = false;
        }
    };
    const executeCommand = <Result>(
        request: TranscriptCoreKernelCommand,
    ): Result =>
        runExclusive('command', () =>
            runKernelCommand<Result>(
                memory,
                allocate,
                deallocate,
                commandWithLength,
                request,
            ),
        );

    return {
        allocate,
        deallocate,
        executeCommand,
        memory,
        runExclusive,
        wasmExports,
    };
};

export {
    resolveNumberExport,
    resolveOptionalNumberExport,
    copyIntoKernelMemory,
    copyFromKernelMemory,
    assertKernelMemoryWithinProfile,
    serializeBoundedKernelCommandRequest,
};
