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

const rosterPositionByteLength = 2;
const mlDsa65VerificationKeyByteLength = 1_952;
const mlKem768EncapsulationKeyByteLength = 1_184;
const rosterEntryInputByteLength =
    rosterPositionByteLength +
    mlDsa65VerificationKeyByteLength +
    mlKem768EncapsulationKeyByteLength;
const wasm32WordByteLength = 4;

type FoundationRosterExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_foundation_roster_encode'
        | 'sealed_lattice_foundation_roster_encoded_byte_length'
    >
>;

type FoundationRosterContext = TranscriptCoreKernelCommandRuntime & {
    readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
        FoundationRosterExports;
};

export type FoundationRosterEntryInput = Readonly<{
    mailboxEncapsulationKey: Uint8Array;
    rosterPosition: number;
    signingVerificationKey: Uint8Array;
}>;

const statusBoundary = new WasmStatusBoundary({
    createInternalError: (message) =>
        new FoundationBootstrapInternalError(message),
    createRefusalError: (refusalReason) =>
        new FoundationBootstrapRefusalError(refusalReason),
    createResourceError: () =>
        new FoundationBootstrapResourceError(
            'The foundation roster is outside the selected browser/WASM resource profile.',
        ),
    internalFailureMessage:
        'The foundation roster encoder failed inside the Rust/WASM kernel.',
    unknownStatusMessage:
        'The foundation roster encoder returned an unknown refusal code.',
});

const requireContext = (
    kernel: TranscriptCoreKernel,
): FoundationRosterContext => {
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
        | Partial<FoundationRosterExports>
        | undefined;
    if (
        context === undefined ||
        exports === undefined ||
        typeof exports.sealed_lattice_foundation_roster_encode !==
            'function' ||
        typeof exports.sealed_lattice_foundation_roster_encoded_byte_length !==
            'function'
    ) {
        throw new FoundationBootstrapInternalError(
            'The transcript-core kernel lacks the canonical foundation-roster boundary.',
        );
    }
    return context as FoundationRosterContext;
};

const memoryBoundary = (
    context: FoundationRosterContext,
): WasmMemoryBoundary =>
    new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new FoundationBootstrapInternalError(message),
        createResourceError: (message) =>
            new FoundationBootstrapResourceError(message),
        label: 'foundation roster',
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

const copyExactBytes = (
    value: unknown,
    byteLength: number,
    fieldName: string,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength !== byteLength) {
        throw new TypeError(
            `${fieldName} must contain exactly ${String(byteLength)} bytes.`,
        );
    }
    try {
        return Uint8Array.from(value);
    } catch {
        throw new TypeError(`${fieldName} must reference an attached byte array.`);
    }
};

const encodeRosterInput = (
    orderedEntries: readonly FoundationRosterEntryInput[],
): Uint8Array<ArrayBuffer> => {
    if (!Array.isArray(orderedEntries)) {
        throw new TypeError('orderedEntries must be an array.');
    }
    if (orderedEntries.length !== foundationProfile.participantCount) {
        throw new RangeError(
            `orderedEntries must contain exactly ${String(foundationProfile.participantCount)} entries.`,
        );
    }

    const encodedInput = new Uint8Array(
        orderedEntries.length * rosterEntryInputByteLength,
    );
    const encodedView = new DataView(encodedInput.buffer);
    const copiedKeys: Uint8Array<ArrayBuffer>[] = [];
    try {
        for (
            let entryIndex = 0;
            entryIndex < orderedEntries.length;
            entryIndex += 1
        ) {
            const entryName = `orderedEntries[${String(entryIndex)}]`;
            const entry = snapshotDataProperty(
                orderedEntries,
                String(entryIndex),
                'orderedEntries',
            );
            const rosterPosition = snapshotDataProperty(
                entry,
                'rosterPosition',
                entryName,
            );
            if (
                typeof rosterPosition !== 'number' ||
                !Number.isSafeInteger(rosterPosition) ||
                rosterPosition !== entryIndex
            ) {
                throw new TypeError(
                    `${entryName}.rosterPosition must match its canonical ordered position.`,
                );
            }
            const signingVerificationKey = copyExactBytes(
                snapshotDataProperty(
                    entry,
                    'signingVerificationKey',
                    entryName,
                ),
                mlDsa65VerificationKeyByteLength,
                `${entryName}.signingVerificationKey`,
            );
            copiedKeys.push(signingVerificationKey);
            const mailboxEncapsulationKey = copyExactBytes(
                snapshotDataProperty(
                    entry,
                    'mailboxEncapsulationKey',
                    entryName,
                ),
                mlKem768EncapsulationKeyByteLength,
                `${entryName}.mailboxEncapsulationKey`,
            );
            copiedKeys.push(mailboxEncapsulationKey);

            let byteOffset = entryIndex * rosterEntryInputByteLength;
            encodedView.setUint16(byteOffset, rosterPosition, true);
            byteOffset += rosterPositionByteLength;
            encodedInput.set(signingVerificationKey, byteOffset);
            byteOffset += mlDsa65VerificationKeyByteLength;
            encodedInput.set(mailboxEncapsulationKey, byteOffset);
        }
        return encodedInput;
    } catch (error) {
        encodedInput.fill(0);
        throw error;
    } finally {
        for (const key of copiedKeys) {
            key.fill(0);
        }
    }
};

/** Encodes one exact ten-participant roster exclusively through the Rust schema. */
export const encodeCanonicalFoundationRoster = (input: {
    kernel: TranscriptCoreKernel;
    orderedEntries: readonly FoundationRosterEntryInput[];
}): Uint8Array<ArrayBuffer> => {
    const kernel = snapshotDataProperty(input, 'kernel', 'input') as
        | TranscriptCoreKernel
        | undefined;
    const orderedEntries = snapshotDataProperty(
        input,
        'orderedEntries',
        'input',
    ) as readonly FoundationRosterEntryInput[];
    const context = requireContext(kernel as TranscriptCoreKernel);
    const boundary = memoryBoundary(context);
    const encodedInput = encodeRosterInput(orderedEntries);

    try {
        return context.runExclusive(
            'canonical foundation roster encoding',
            () => {
                let inputPointer = 0;
                let statusPointer = 0;
                let outputPointer = 0;
                let outputByteLength = 0;
                try {
                    inputPointer = boundary.copy(encodedInput);
                    statusPointer = boundary.allocateZeroedWords(1);
                    outputByteLength =
                        context.wasmExports.sealed_lattice_foundation_roster_encoded_byte_length(
                            inputPointer,
                            encodedInput.byteLength,
                            statusPointer,
                        );
                    const [lengthStatus] = boundary.readWords(
                        statusPointer,
                        1,
                    );
                    statusBoundary.throwIfError(lengthStatus);
                    boundary.validateAllocationByteLength(outputByteLength);
                    outputPointer = boundary.allocate(outputByteLength);
                    statusBoundary.throwIfError(
                        context.wasmExports.sealed_lattice_foundation_roster_encode(
                            inputPointer,
                            encodedInput.byteLength,
                            outputPointer,
                            outputByteLength,
                        ),
                    );
                    return Uint8Array.from(
                        new Uint8Array(
                            context.memory.buffer,
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
                    if (inputPointer !== 0) {
                        boundary.zeroAndDeallocate(
                            inputPointer,
                            encodedInput.byteLength,
                        );
                    }
                }
            },
        );
    } finally {
        encodedInput.fill(0);
    }
};
