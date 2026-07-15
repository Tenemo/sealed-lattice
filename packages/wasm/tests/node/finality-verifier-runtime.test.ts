import { describe, expect, it } from 'vitest';

import {
    issueVerifiedEvaluatorReplayCapability,
    openFinalityVerifierSession,
    registerFinalityVerifierKernelContext,
    revokeVerifiedEvaluatorReplayCapability,
    type FinalityVerifierConfiguration,
    type FinalityVerifierKernelContext,
    type VerifiedEvaluatorReplay,
} from '#packages/wasm/src/finality-verifier-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const configuration = (): FinalityVerifierConfiguration => ({
    actionContextHash: new Uint8Array(64).fill(0x33),
    canonicalRosterBytes: Uint8Array.of(0xaa, 0xbb),
    ceremonyContextHash: new Uint8Array(64).fill(0x22),
    suiteIdentifier: new Uint8Array(64).fill(0x11),
});

const createFakeKernel = (): Readonly<{
    allocations: ReadonlyMap<number, number>;
    kernel: TranscriptCoreKernel;
}> => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    let nextPointer = 8;
    const context: FinalityVerifierKernelContext = {
        allocate: (byteLength) => {
            const pointer = nextPointer;
            nextPointer += byteLength;
            allocations.set(pointer, byteLength);
            return pointer;
        },
        begin: (
            _configurationPointer,
            _configurationLength,
            _capabilityPointer,
            _capabilityLength,
            statusPointer,
        ) => {
            new DataView(memory.buffer).setUint32(statusPointer, 0, true);
            return 1;
        },
        cancel: () => 0,
        deallocate: (pointer, byteLength) => {
            if (allocations.get(pointer) !== byteLength) {
                throw new Error('test deallocation does not match allocation');
            }
            allocations.delete(pointer);
        },
        describe: () => {
            throw new Error('describe must not run in this test');
        },
        memory,
        release: () => {
            throw new Error('release must not run in this test');
        },
        runExclusive: (_operationName, operation) => operation(),
        verify: () => {
            throw new Error(
                'WASM verification must not run without a live evaluator capability',
            );
        },
    };
    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    registerFinalityVerifierKernelContext(kernel, context);
    return { allocations, kernel };
};

describe('Finality verifier capability boundary', () => {
    it('does not promote raw or forged replay data into evaluator evidence', () => {
        const fake = createFakeKernel();
        const opened = openFinalityVerifierSession({
            configuration: configuration(),
            kernel: fake.kernel,
        });
        expect(opened.isValid).toBe(true);
        if (!opened.isValid) {
            throw new Error(opened.refusalReason);
        }
        try {
            const forgedReplay = Object.freeze(
                Object.create(null),
            ) as VerifiedEvaluatorReplay;
            expect(
                opened.value.verify({
                    canonicalCertificate: Uint8Array.of(1),
                    canonicalStatement: Uint8Array.of(2),
                    verifiedEvaluatorReplay: forgedReplay,
                    verifiedFinalityObjects: [
                        Object.freeze(Object.create(null)),
                    ],
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'missingPrerequisite',
            });
        } finally {
            opened.value.cancel();
        }
        expect(fake.allocations.size).toBe(0);
    });

    it('invalidates an evaluator capability at its owning runtime boundary', () => {
        const fake = createFakeKernel();
        const replay = issueVerifiedEvaluatorReplayCapability({
            handle: 7,
            kernel: fake.kernel,
        });
        revokeVerifiedEvaluatorReplayCapability(replay);
        expect(() => revokeVerifiedEvaluatorReplayCapability(replay)).toThrow(
            'unavailable',
        );
    });

    it('refuses malformed configuration before opening a WASM session', () => {
        const fake = createFakeKernel();
        expect(
            openFinalityVerifierSession({
                configuration: {
                    ...configuration(),
                    suiteIdentifier: new Uint8Array(63),
                },
                kernel: fake.kernel,
            }),
        ).toEqual({ isValid: false, refusalReason: 'wrongTypeOrLength' });
        expect(fake.allocations.size).toBe(0);
    });
});
