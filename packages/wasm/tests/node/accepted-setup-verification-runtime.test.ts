import { describe, expect, it, vi } from 'vitest';

import {
    createVerifiedAcceptedSetupAuthorityKernelOwner,
    requireVerifiedAcceptedSetupAuthorityKernelOwner,
    type VerifiedAcceptedSetupAuthority,
} from '#packages/wasm/src/accepted-setup-verification-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const kernelOwner = (): TranscriptCoreKernel =>
    Object.freeze({}) as TranscriptCoreKernel;

describe('Accepted-setup verification runtime authority', () => {
    it('resolves only the live authority in its exact WASM kernel', () => {
        const kernel = kernelOwner();
        const releaseKernelAuthority = vi.fn();
        const authority = createVerifiedAcceptedSetupAuthorityKernelOwner({
            handle: 37,
            kernel,
            releaseKernelAuthority,
        });

        expect(
            requireVerifiedAcceptedSetupAuthorityKernelOwner(authority, kernel),
        ).toEqual({ handle: 37, kernel });
        expect(() =>
            requireVerifiedAcceptedSetupAuthorityKernelOwner(
                authority,
                kernelOwner(),
            ),
        ).toThrow('belongs to another WASM kernel');
        expect(releaseKernelAuthority).not.toHaveBeenCalled();
    });

    it('releases the Rust owner once and permanently invalidates the brand', () => {
        const kernel = kernelOwner();
        const releaseKernelAuthority = vi.fn();
        const authority = createVerifiedAcceptedSetupAuthorityKernelOwner({
            handle: 91,
            kernel,
            releaseKernelAuthority,
        });

        authority.release();

        expect(releaseKernelAuthority).toHaveBeenCalledExactlyOnceWith(91);
        expect(() => authority.release()).toThrow('already released');
        expect(() =>
            requireVerifiedAcceptedSetupAuthorityKernelOwner(authority, kernel),
        ).toThrow('already released');
    });

    it('rejects forged authorities and invalid Rust handles', () => {
        const kernel = kernelOwner();
        const forgedAuthority = Object.freeze({
            release: vi.fn(),
        }) as VerifiedAcceptedSetupAuthority;

        expect(() =>
            requireVerifiedAcceptedSetupAuthorityKernelOwner(
                forgedAuthority,
                kernel,
            ),
        ).toThrow('unavailable');
        for (const invalidHandle of [0, -1, 1.5, Number.MAX_VALUE]) {
            expect(() =>
                createVerifiedAcceptedSetupAuthorityKernelOwner({
                    handle: invalidHandle,
                    kernel,
                    releaseKernelAuthority: vi.fn(),
                }),
            ).toThrow('invalid accepted-setup authority handle');
        }
    });

    it('keeps the authority retryable when release refuses before Rust consumes it', () => {
        const kernel = kernelOwner();
        let releaseAttemptCount = 0;
        const authority = createVerifiedAcceptedSetupAuthorityKernelOwner({
            handle: 12,
            kernel,
            releaseKernelAuthority: () => {
                releaseAttemptCount += 1;
                if (releaseAttemptCount === 1) {
                    throw new Error(
                        'kernel release refused before consumption',
                    );
                }
            },
        });

        expect(() => authority.release()).toThrow(
            'kernel release refused before consumption',
        );
        expect(
            requireVerifiedAcceptedSetupAuthorityKernelOwner(authority, kernel),
        ).toEqual({ handle: 12, kernel });

        authority.release();

        expect(releaseAttemptCount).toBe(2);
        expect(() => authority.release()).toThrow('already released');
    });
});
