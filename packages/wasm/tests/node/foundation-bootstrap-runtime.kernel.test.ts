import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '#packages/crypto/src/index';
import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    activateSelectedSuiteRecordSource,
    copySelectedSuiteRecordSourceBytes,
    encodeCanonicalFoundationRoster,
    FoundationBootstrapRefusalError,
    loadFreshTranscriptCoreKernel,
    releaseSelectedSuiteRecordSource,
    type FoundationRosterEntryInput,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import { createCanonicalTestRosterBytes } from '#packages/wasm/tests/canonical-tuple-test-helpers';

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const selectedRosterEntries = (): readonly FoundationRosterEntryInput[] => {
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
        foundationProfile.participantCount,
    );
    try {
        return Object.freeze(
            signingKeyPairs.map((signingKeyPair, rosterPosition) => {
                const mailboxKeyPair = mailboxKeyPairs[rosterPosition];
                if (mailboxKeyPair === undefined) {
                    throw new Error(
                        'The deterministic mailbox-key set is incomplete.',
                    );
                }
                return Object.freeze({
                    mailboxEncapsulationKey: mailboxKeyPair.publicKey.slice(),
                    rosterPosition,
                    signingVerificationKey: signingKeyPair.publicKey.slice(),
                });
            }),
        );
    } finally {
        for (const keyPair of signingKeyPairs) {
            keyPair.secretKey.fill(0);
        }
        for (const keyPair of mailboxKeyPairs) {
            keyPair.secretKey.fill(0);
        }
    }
};

const expectRefusal = (
    operation: () => unknown,
    expectedRefusalReason: string,
): void => {
    try {
        operation();
    } catch (error) {
        expect(error).toBeInstanceOf(FoundationBootstrapRefusalError);
        expect((error as FoundationBootstrapRefusalError).refusalReason).toBe(
            expectedRefusalReason,
        );
        return;
    }
    throw new Error('The expected foundation bootstrap refusal was absent.');
};

type FakeSelectedSuiteKernel = Readonly<{
    kernel: TranscriptCoreKernel;
    retainedHandleCount(): number;
}>;

const createFakeSelectedSuiteKernel = (
    acceptedSuiteRecordBytes: Uint8Array,
    options: Readonly<{ failFirstRelease?: boolean }> = {},
): FakeSelectedSuiteKernel => {
    const exactAcceptedBytes = Uint8Array.from(acceptedSuiteRecordBytes);
    const memory = new WebAssembly.Memory({ initial: 2 });
    const retainedBytes = new Map<number, Uint8Array>();
    let nextAllocationPointer = 8;
    let nextHandle = 1;
    let releaseFailurePending = options.failFirstRelease === true;
    const allocate = (byteLength: number): number => {
        const pointer = nextAllocationPointer;
        nextAllocationPointer += byteLength;
        if (nextAllocationPointer > memory.buffer.byteLength) {
            throw new Error('The fake WASM memory was exhausted.');
        }
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        new Uint8Array(memory.buffer, pointer, byteLength).fill(0);
    };
    const writeStatus = (pointer: number, status: number): void => {
        new DataView(memory.buffer).setUint32(pointer, status, true);
    };
    const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
        left.byteLength === right.byteLength &&
        left.every((byte, byteIndex) => byte === right[byteIndex]);

    const context = {
        allocate,
        deallocate,
        executeCommand: (): never => {
            throw new Error('The fake suite source has no command boundary.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports: {
            memory,
            sealed_lattice_common_proof_copy_selected_suite_record: (
                handle: number,
                outputPointer: number,
                outputByteLength: number,
            ): number => {
                const bytes = retainedBytes.get(handle);
                if (bytes === undefined) {
                    return 13;
                }
                if (outputByteLength !== bytes.byteLength) {
                    return 5;
                }
                new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).set(bytes);
                return 0;
            },
            sealed_lattice_common_proof_release_suite: (
                handle: number,
            ): number => {
                if (!retainedBytes.has(handle)) {
                    return 13;
                }
                if (releaseFailurePending) {
                    releaseFailurePending = false;
                    return 3;
                }
                retainedBytes.delete(handle);
                return 0;
            },
            sealed_lattice_common_proof_select_suite: (
                inputPointer: number,
                inputByteLength: number,
                statusPointer: number,
            ): number => {
                const candidate = new Uint8Array(
                    memory.buffer,
                    inputPointer,
                    inputByteLength,
                );
                if (!bytesEqual(candidate, exactAcceptedBytes)) {
                    writeStatus(statusPointer, 2);
                    return 0;
                }
                const handle = nextHandle;
                nextHandle += 1;
                retainedBytes.set(handle, Uint8Array.from(candidate));
                writeStatus(statusPointer, 0);
                return handle;
            },
            sealed_lattice_common_proof_selected_suite_record_byte_length: (
                handle: number,
                statusPointer: number,
            ): number => {
                const bytes = retainedBytes.get(handle);
                if (bytes === undefined) {
                    writeStatus(statusPointer, 13);
                    return 0;
                }
                writeStatus(statusPointer, 0);
                return bytes.byteLength;
            },
        },
    } as unknown as TranscriptCoreKernelCommandRuntime;
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    registerCommonProofKernelContext(kernel, context);
    return Object.freeze({
        kernel,
        retainedHandleCount: () => retainedBytes.size,
    });
};

describe('foundation browser bootstrap Rust/WASM boundaries', () => {
    it('canonically encodes the exact generated roster and derives distinct identities', async () => {
        const kernel = await loadFreshTranscriptCoreKernel();
        const entries = selectedRosterEntries();
        const firstEncoding = encodeCanonicalFoundationRoster({
            kernel,
            orderedEntries: entries,
        });
        const secondEncoding = encodeCanonicalFoundationRoster({
            kernel,
            orderedEntries: entries,
        });

        expect(secondEncoding).toEqual(firstEncoding);
        expect(secondEncoding).not.toBe(firstEncoding);
        expect(firstEncoding).toEqual(
            createCanonicalTestRosterBytes(
                entries.map((entry) => ({
                    mailboxEncapsulationKey: entry.mailboxEncapsulationKey,
                    signingVerificationKey: entry.signingVerificationKey,
                })),
            ),
        );
        const participantIdentities =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(firstEncoding),
            );
        expect(participantIdentities).toHaveLength(
            foundationProfile.participantCount,
        );
        expect(new Set(participantIdentities.map(bytesToHex)).size).toBe(
            foundationProfile.participantCount,
        );
    });

    it('refuses malformed keys, duplicate derived identities, and noncanonical order', async () => {
        const kernel = await loadFreshTranscriptCoreKernel();
        const entries = selectedRosterEntries();
        const malformedMailboxEntries = entries.map((entry, entryIndex) =>
            entryIndex === 0
                ? Object.freeze({
                      ...entry,
                      mailboxEncapsulationKey: new Uint8Array(
                          entry.mailboxEncapsulationKey.byteLength,
                      ).fill(0xff),
                  })
                : entry,
        );
        expectRefusal(
            () =>
                encodeCanonicalFoundationRoster({
                    kernel,
                    orderedEntries: malformedMailboxEntries,
                }),
            'malformedEncoding',
        );

        const duplicateIdentityEntries = entries.map((entry, entryIndex) =>
            entryIndex === 1
                ? Object.freeze({
                      ...entry,
                      signingVerificationKey:
                          entries[0].signingVerificationKey.slice(),
                  })
                : entry,
        );
        expectRefusal(
            () =>
                encodeCanonicalFoundationRoster({
                    kernel,
                    orderedEntries: duplicateIdentityEntries,
                }),
            'duplicateIdentity',
        );

        const reorderedEntries = [...entries];
        [reorderedEntries[0], reorderedEntries[1]] = [
            reorderedEntries[1],
            reorderedEntries[0],
        ];
        expect(() =>
            encodeCanonicalFoundationRoster({
                kernel,
                orderedEntries: reorderedEntries,
            }),
        ).toThrow(TypeError);
        expect(() =>
            encodeCanonicalFoundationRoster({
                kernel,
                orderedEntries: entries.map((entry, entryIndex) =>
                    entryIndex === 0
                        ? Object.freeze({
                              ...entry,
                              signingVerificationKey:
                                  entry.signingVerificationKey.subarray(1),
                          })
                        : entry,
                ),
            }),
        ).toThrow(TypeError);
    });

    it('retains immutable suite bytes in one kernel until explicit release', () => {
        const acceptedSuiteRecordBytes = Uint8Array.of(
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
        );
        const exactBytes = acceptedSuiteRecordBytes.slice();
        const owner = createFakeSelectedSuiteKernel(exactBytes);
        const otherOwner = createFakeSelectedSuiteKernel(exactBytes);
        const source = activateSelectedSuiteRecordSource({
            canonicalSuiteRecordBytes: acceptedSuiteRecordBytes,
            kernel: owner.kernel,
        });
        acceptedSuiteRecordBytes.fill(0xff);

        expect(owner.retainedHandleCount()).toBe(1);
        expect(
            copySelectedSuiteRecordSourceBytes({
                kernel: owner.kernel,
                source,
            }),
        ).toEqual(exactBytes);
        expect(() =>
            copySelectedSuiteRecordSourceBytes({
                kernel: otherOwner.kernel,
                source,
            }),
        ).toThrow(TypeError);
        expect(owner.retainedHandleCount()).toBe(1);

        releaseSelectedSuiteRecordSource({ kernel: owner.kernel, source });
        expect(owner.retainedHandleCount()).toBe(0);
        expect(() =>
            copySelectedSuiteRecordSourceBytes({
                kernel: owner.kernel,
                source,
            }),
        ).toThrow(TypeError);
        expect(() =>
            releaseSelectedSuiteRecordSource({
                kernel: owner.kernel,
                source,
            }),
        ).toThrow(TypeError);
    });

    it('refuses altered suite bytes without retaining a handle', () => {
        const exactBytes = Uint8Array.of(0x61, 0x72, 0x83, 0x94);
        const owner = createFakeSelectedSuiteKernel(exactBytes);
        const alteredBytes = exactBytes.slice();
        alteredBytes[2] ^= 0x80;

        expectRefusal(
            () =>
                activateSelectedSuiteRecordSource({
                    canonicalSuiteRecordBytes: alteredBytes,
                    kernel: owner.kernel,
                }),
            'unsupportedVersionOrSuite',
        );
        expect(owner.retainedHandleCount()).toBe(0);
    });

    it('keeps the suite source live when release fails and permits a clean retry', () => {
        const exactBytes = Uint8Array.of(0xa1, 0xb2, 0xc3);
        const owner = createFakeSelectedSuiteKernel(exactBytes, {
            failFirstRelease: true,
        });
        const source = activateSelectedSuiteRecordSource({
            canonicalSuiteRecordBytes: exactBytes,
            kernel: owner.kernel,
        });

        expect(() =>
            releaseSelectedSuiteRecordSource({
                kernel: owner.kernel,
                source,
            }),
        ).toThrow();
        expect(owner.retainedHandleCount()).toBe(1);
        expect(
            copySelectedSuiteRecordSourceBytes({
                kernel: owner.kernel,
                source,
            }),
        ).toEqual(exactBytes);

        releaseSelectedSuiteRecordSource({ kernel: owner.kernel, source });
        expect(owner.retainedHandleCount()).toBe(0);
    });
});
