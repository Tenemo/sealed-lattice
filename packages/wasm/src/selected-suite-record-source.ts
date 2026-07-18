import { foundationProfile } from '@sealed-lattice/types';

import { isUint8Array } from './byte-array.js';
import {
    FoundationBootstrapInternalError,
    FoundationBootstrapRefusalError,
    FoundationBootstrapResourceError,
} from './foundation-bootstrap-errors.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const maximumWasm32UnsignedInteger = 0xffff_ffff;
const wasm32WordByteLength = 4;

type SelectedSuiteRecordExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_common_proof_copy_selected_suite_record'
        | 'sealed_lattice_common_proof_release_suite'
        | 'sealed_lattice_common_proof_select_suite'
        | 'sealed_lattice_common_proof_selected_suite_record_byte_length'
    >
>;

type SelectedSuiteRecordContext = TranscriptCoreKernelCommandRuntime & {
    readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
        SelectedSuiteRecordExports;
};

declare const selectedSuiteRecordSourceBrand: unique symbol;

/** Opaque same-kernel custody of one exact positively selected suite record. */
export type SelectedSuiteRecordSource = Readonly<{
    readonly [selectedSuiteRecordSourceBrand]: true;
}>;

type SelectedSuiteRecordSourceRecord = Readonly<{
    context: SelectedSuiteRecordContext;
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

type OwnedSelectedSuiteRecordSource = Readonly<{
    record: SelectedSuiteRecordSourceRecord;
    source: SelectedSuiteRecordSource;
}>;

export type SelectedSuiteRecordSourceKernelOwner = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const sourceRecords = new WeakMap<
    SelectedSuiteRecordSource,
    SelectedSuiteRecordSourceRecord
>();

const statusBoundary = new WasmStatusBoundary({
    createInternalError: (message) =>
        new FoundationBootstrapInternalError(message),
    createRefusalError: (refusalReason) =>
        new FoundationBootstrapRefusalError(refusalReason),
    createResourceError: () =>
        new FoundationBootstrapResourceError(
            'The selected suite record is outside the browser/WASM resource profile.',
        ),
    internalFailureMessage:
        'The selected-suite record source failed inside the Rust/WASM kernel.',
    unknownStatusMessage:
        'The selected-suite record source returned an unknown refusal code.',
});

const snapshotDataProperty = (
    container: unknown,
    propertyName: string,
    containerName: string,
): unknown => {
    if (
        container === null ||
        (typeof container !== 'object' && typeof container !== 'function')
    ) {
        throw new TypeError(`${containerName} must be an object.`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(container, propertyName);
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new TypeError(
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const requireContext = (
    kernel: TranscriptCoreKernel,
): SelectedSuiteRecordContext => {
    if (
        (typeof kernel !== 'object' && typeof kernel !== 'function') ||
        kernel === null
    ) {
        throw new TypeError(
            'kernel must be a transcript-core kernel owned by this WASM package.',
        );
    }
    const context = resolveCommonProofKernelContext(kernel);
    const exports = context?.wasmExports as
        | Partial<SelectedSuiteRecordExports>
        | undefined;
    if (
        context === undefined ||
        exports === undefined ||
        typeof exports.sealed_lattice_common_proof_copy_selected_suite_record !==
            'function' ||
        typeof exports.sealed_lattice_common_proof_release_suite !==
            'function' ||
        typeof exports.sealed_lattice_common_proof_select_suite !==
            'function' ||
        typeof exports.sealed_lattice_common_proof_selected_suite_record_byte_length !==
            'function'
    ) {
        throw new FoundationBootstrapInternalError(
            'The transcript-core kernel lacks the selected-suite record source boundary.',
        );
    }
    return context as SelectedSuiteRecordContext;
};

const memoryBoundary = (
    context: SelectedSuiteRecordContext,
): WasmMemoryBoundary =>
    new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new FoundationBootstrapInternalError(message),
        createResourceError: (message) =>
            new FoundationBootstrapResourceError(message),
        label: 'selected-suite record source',
    });

const copyCanonicalSuiteRecordBytes = (
    value: unknown,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new TypeError(
            'canonicalSuiteRecordBytes must be a nonempty Uint8Array within the copied-buffer bound.',
        );
    }
    try {
        return Uint8Array.from(value);
    } catch {
        throw new TypeError(
            'canonicalSuiteRecordBytes must reference an attached byte array.',
        );
    }
};

const requireHandle = (handle: number): number => {
    if (
        !Number.isSafeInteger(handle) ||
        handle <= 0 ||
        handle > maximumWasm32UnsignedInteger
    ) {
        throw new FoundationBootstrapInternalError(
            'The Rust/WASM kernel returned an invalid selected-suite handle.',
        );
    }
    return handle;
};

const requireOwnedSource = (input: {
    kernel: TranscriptCoreKernel;
    source: SelectedSuiteRecordSource;
}): OwnedSelectedSuiteRecordSource => {
    const source = snapshotDataProperty(input, 'source', 'input') as
        | SelectedSuiteRecordSource
        | undefined;
    const kernelValue = snapshotDataProperty(input, 'kernel', 'input') as
        | TranscriptCoreKernel
        | undefined;
    if (
        (typeof source !== 'object' && typeof source !== 'function') ||
        source === null
    ) {
        throw new TypeError(
            'source must be a live selected-suite record source.',
        );
    }
    const record = sourceRecords.get(source);
    if (record === undefined) {
        throw new TypeError(
            'The selected-suite record source is unavailable or already released.',
        );
    }
    if (record.kernel !== kernelValue) {
        throw new TypeError(
            'The selected-suite record source belongs to another Rust/WASM kernel.',
        );
    }
    return Object.freeze({ record, source });
};

/** Internal same-worker borrow of the positively selected Rust suite. */
export const requireSelectedSuiteRecordSourceKernelOwner = (input: {
    kernel: TranscriptCoreKernel;
    source: SelectedSuiteRecordSource;
}): SelectedSuiteRecordSourceKernelOwner => {
    const { record } = requireOwnedSource(input);
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};

/** Positively selects and retains one exact canonical suite record in Rust. */
export const activateSelectedSuiteRecordSource = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    kernel: TranscriptCoreKernel;
}): SelectedSuiteRecordSource => {
    const kernelValue = snapshotDataProperty(input, 'kernel', 'input') as
        | TranscriptCoreKernel
        | undefined;
    const kernel = kernelValue as TranscriptCoreKernel;
    const context = requireContext(kernel);
    const boundary = memoryBoundary(context);
    const canonicalSuiteRecordBytes = copyCanonicalSuiteRecordBytes(
        snapshotDataProperty(input, 'canonicalSuiteRecordBytes', 'input'),
    );
    let handle = 0;
    try {
        handle = context.runExclusive('selected-suite record activation', () => {
            let inputPointer = 0;
            let statusPointer = 0;
            let selectedHandle = 0;
            try {
                inputPointer = boundary.copy(canonicalSuiteRecordBytes);
                statusPointer = boundary.allocateZeroedWords(1);
                selectedHandle =
                    context.wasmExports.sealed_lattice_common_proof_select_suite(
                        inputPointer,
                        canonicalSuiteRecordBytes.byteLength,
                        statusPointer,
                    );
                const [status] = boundary.readWords(statusPointer, 1);
                statusBoundary.throwIfError(status);
                return requireHandle(selectedHandle);
            } catch (error) {
                if (selectedHandle !== 0) {
                    try {
                        statusBoundary.throwIfError(
                            context.wasmExports.sealed_lattice_common_proof_release_suite(
                                selectedHandle,
                            ),
                        );
                    } catch (cleanupFailure) {
                        throw new FoundationBootstrapInternalError(
                            'Selected-suite activation and cleanup both failed.',
                            Object.freeze({ cleanupFailure, error }),
                        );
                    }
                }
                throw error;
            } finally {
                if (statusPointer !== 0) {
                    boundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
                if (inputPointer !== 0) {
                    boundary.zeroAndDeallocate(
                        inputPointer,
                        canonicalSuiteRecordBytes.byteLength,
                    );
                }
            }
        });
        const source = Object.freeze(
            Object.create(null) as object,
        ) as SelectedSuiteRecordSource;
        sourceRecords.set(source, Object.freeze({ context, handle, kernel }));
        return source;
    } catch (error) {
        if (handle !== 0) {
            try {
                statusBoundary.throwIfError(
                    context.runExclusive(
                        'selected-suite failed activation release',
                        () =>
                            context.wasmExports.sealed_lattice_common_proof_release_suite(
                                handle,
                            ),
                    ),
                );
            } catch (cleanupFailure) {
                throw new FoundationBootstrapInternalError(
                    'Selected-suite source creation and cleanup both failed.',
                    Object.freeze({ cleanupFailure, error }),
                );
            }
        }
        throw error;
    } finally {
        canonicalSuiteRecordBytes.fill(0);
    }
};

/** Copies the exact bytes retained by the matching live Rust suite handle. */
export const copySelectedSuiteRecordSourceBytes = (input: {
    kernel: TranscriptCoreKernel;
    source: SelectedSuiteRecordSource;
}): Uint8Array<ArrayBuffer> => {
    const { record } = requireOwnedSource(input);
    const boundary = memoryBoundary(record.context);
    return record.context.runExclusive(
        'selected-suite record copy',
        () => {
            let statusPointer = 0;
            let outputPointer = 0;
            let outputByteLength = 0;
            try {
                statusPointer = boundary.allocateZeroedWords(1);
                outputByteLength =
                    record.context.wasmExports.sealed_lattice_common_proof_selected_suite_record_byte_length(
                        record.handle,
                        statusPointer,
                    );
                const [status] = boundary.readWords(statusPointer, 1);
                statusBoundary.throwIfError(status);
                boundary.validateAllocationByteLength(outputByteLength);
                outputPointer = boundary.allocate(outputByteLength);
                statusBoundary.throwIfError(
                    record.context.wasmExports.sealed_lattice_common_proof_copy_selected_suite_record(
                        record.handle,
                        outputPointer,
                        outputByteLength,
                    ),
                );
                return Uint8Array.from(
                    new Uint8Array(
                        record.context.memory.buffer,
                        outputPointer,
                        outputByteLength,
                    ),
                );
            } finally {
                if (outputPointer !== 0) {
                    boundary.zeroAndDeallocate(
                        outputPointer,
                        outputByteLength,
                    );
                }
                if (statusPointer !== 0) {
                    boundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            }
        },
    );
};

/** Releases the Rust suite capability and its retained exact bytes. */
export const releaseSelectedSuiteRecordSource = (input: {
    kernel: TranscriptCoreKernel;
    source: SelectedSuiteRecordSource;
}): void => {
    const { record, source } = requireOwnedSource(input);
    statusBoundary.throwIfError(
        record.context.runExclusive('selected-suite record release', () =>
            record.context.wasmExports.sealed_lattice_common_proof_release_suite(
                record.handle,
            ),
        ),
    );
    sourceRecords.delete(source);
};
