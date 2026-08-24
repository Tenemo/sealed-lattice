import { describe, expect, it, vi } from 'vitest';

import {
    createVerifiedBallotOutputKernelAuthority,
    markVerifiedBallotOutputConsumedAfterKernelSuccess,
    requireVerifiedBallotOutputKernelAuthority,
    type VerifiedBallotOutput,
} from '#packages/wasm/src/ballot-validity-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const kernelOwner = (): TranscriptCoreKernel =>
    Object.freeze({}) as TranscriptCoreKernel;

describe('Ballot-validity output custody', () => {
    it('borrows only a live output from the exact kernel', () => {
        const kernel = kernelOwner();
        const output = createVerifiedBallotOutputKernelAuthority({
            handle: 37,
            kernel,
            releaseKernelOutput: vi.fn(),
        });

        expect(
            requireVerifiedBallotOutputKernelAuthority(output, kernel),
        ).toEqual({ handle: 37, kernel });
        expect(() =>
            requireVerifiedBallotOutputKernelAuthority(output, kernelOwner()),
        ).toThrow('wrongContext');
        output.release();
    });

    it('marks custody consumed only after the kernel succeeds', () => {
        const kernel = kernelOwner();
        const releaseKernelOutput = vi.fn();
        const output = createVerifiedBallotOutputKernelAuthority({
            handle: 49,
            kernel,
            releaseKernelOutput,
        });

        markVerifiedBallotOutputConsumedAfterKernelSuccess(output, kernel);

        expect(releaseKernelOutput).not.toHaveBeenCalled();
        expect(() =>
            requireVerifiedBallotOutputKernelAuthority(output, kernel),
        ).toThrow('consumedState');
        expect(() => output.release()).toThrow('consumedState');
    });

    it('releases an unconsumed Rust output once and fails closed on release error', () => {
        const kernel = kernelOwner();
        const releaseKernelOutput = vi.fn(() => {
            throw new Error('release failed');
        });
        const output = createVerifiedBallotOutputKernelAuthority({
            handle: 61,
            kernel,
            releaseKernelOutput,
        });

        expect(() => output.release()).toThrow('release failed');
        expect(releaseKernelOutput).toHaveBeenCalledExactlyOnceWith(61);
        expect(() => output.release()).toThrow('consumedState');
    });

    it('admits only one live output in the browser worker', () => {
        const kernel = kernelOwner();
        const firstOutput = createVerifiedBallotOutputKernelAuthority({
            handle: 71,
            kernel,
            releaseKernelOutput: vi.fn(),
        });

        expect(() =>
            createVerifiedBallotOutputKernelAuthority({
                handle: 72,
                kernel,
                releaseKernelOutput: vi.fn(),
            }),
        ).toThrow('already owns a ballot verification output');

        firstOutput.release();
        const replacementOutput = createVerifiedBallotOutputKernelAuthority({
            handle: 73,
            kernel,
            releaseKernelOutput: vi.fn(),
        });
        expect(
            requireVerifiedBallotOutputKernelAuthority(
                replacementOutput,
                kernel,
            ).handle,
        ).toBe(73);
        replacementOutput.release();
    });

    it('rejects forged outputs and every invalid WASM handle shape', () => {
        const kernel = kernelOwner();
        const forged = Object.freeze({
            release: vi.fn(),
        }) as unknown as VerifiedBallotOutput;

        expect(() =>
            requireVerifiedBallotOutputKernelAuthority(forged, kernel),
        ).toThrow('consumedState');
        for (const handle of [0, -1, 1.5, 0x1_0000_0000]) {
            expect(() =>
                createVerifiedBallotOutputKernelAuthority({
                    handle,
                    kernel,
                    releaseKernelOutput: vi.fn(),
                }),
            ).toThrow('invalid verified ballot-output handle');
        }
    });
});
