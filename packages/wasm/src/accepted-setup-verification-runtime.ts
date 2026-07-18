import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

/**
 * Browser-worker ownership of one positively verified accepted setup.
 *
 * The Rust handle is deliberately absent from this public shape. Exact proof
 * and evaluator adapters resolve it only through the same-kernel handoff
 * below, so copied numbers cannot stand in for accepted setup verification.
 */
export type VerifiedAcceptedSetupAuthority = Readonly<{
    release(): void;
}>;

type VerifiedAcceptedSetupAuthorityRecord = {
    readonly handle: number;
    readonly kernel: TranscriptCoreKernel;
    readonly releaseKernelAuthority: (handle: number) => void;
    released: boolean;
};

const authorityRecords = new WeakMap<
    VerifiedAcceptedSetupAuthority,
    VerifiedAcceptedSetupAuthorityRecord
>();

export type VerifiedAcceptedSetupAuthorityKernelOwner = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const requireLiveAuthorityRecord = (
    authority: VerifiedAcceptedSetupAuthority,
): VerifiedAcceptedSetupAuthorityRecord => {
    if (
        (typeof authority !== 'object' && typeof authority !== 'function') ||
        authority === null
    ) {
        throw new TypeError(
            'The accepted-setup authority was not issued by this WASM runtime.',
        );
    }
    const record = authorityRecords.get(authority);
    if (record === undefined || record.released) {
        throw new TypeError(
            'The accepted-setup authority is unavailable or already released.',
        );
    }
    return record;
};

/**
 * Internal mint used only after the Rust finalizer returns a nonzero verified
 * authority handle. It is intentionally not re-exported by the package entry
 * point.
 */
export const createVerifiedAcceptedSetupAuthorityKernelOwner = (input: {
    handle: number;
    kernel: TranscriptCoreKernel;
    readonly releaseKernelAuthority: (handle: number) => void;
}): VerifiedAcceptedSetupAuthority => {
    if (!Number.isSafeInteger(input.handle) || input.handle <= 0) {
        throw new TypeError(
            'The WASM kernel returned an invalid accepted-setup authority handle.',
        );
    }
    const authority: VerifiedAcceptedSetupAuthority = Object.freeze({
        release: (): void => {
            const record = requireLiveAuthorityRecord(authority);
            record.releaseKernelAuthority(record.handle);
            record.released = true;
        },
    });
    authorityRecords.set(authority, {
        handle: input.handle,
        kernel: input.kernel,
        releaseKernelAuthority: input.releaseKernelAuthority,
        released: false,
    });
    return authority;
};

/**
 * Mints browser custody from the nonzero handle returned by the Rust
 * accepted-setup finalizer. Release remains in the same worker and kernel;
 * the Rust registry decides whether the authority is still live.
 */
export const createVerifiedAcceptedSetupAuthorityFromKernelHandle = (input: {
    handle: number;
    kernel: TranscriptCoreKernel;
}): VerifiedAcceptedSetupAuthority => {
    const context = resolveCommonProofKernelContext(input.kernel);
    const releaseKernelAuthority =
        context?.wasmExports.sealed_lattice_accepted_setup_authority_release;
    if (context === undefined || typeof releaseKernelAuthority !== 'function') {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks accepted-setup authority release.',
        );
    }
    const statusBoundary = new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The accepted-setup authority release failed internally.',
        unknownStatusMessage:
            'The accepted-setup authority release returned an unknown status code.',
    });
    return createVerifiedAcceptedSetupAuthorityKernelOwner({
        handle: input.handle,
        kernel: input.kernel,
        releaseKernelAuthority: (handle): void => {
            const status = context.runExclusive(
                'accepted-setup authority release',
                () => releaseKernelAuthority(handle),
            );
            statusBoundary.throwIfError(status);
        },
    });
};

/**
 * Internal same-worker handoff for exact browser/WASM consumers. This merely
 * borrows the live Rust owner; evaluator execution remains atomically owned
 * and consumed by Rust after its complete binding preflight.
 */
export const requireVerifiedAcceptedSetupAuthorityKernelOwner = (
    authority: VerifiedAcceptedSetupAuthority,
    kernel: TranscriptCoreKernel,
): VerifiedAcceptedSetupAuthorityKernelOwner => {
    const record = requireLiveAuthorityRecord(authority);
    if (record.kernel !== kernel) {
        throw new TypeError(
            'The accepted-setup authority belongs to another WASM kernel.',
        );
    }
    return Object.freeze({
        handle: record.handle,
        kernel: record.kernel,
    });
};
