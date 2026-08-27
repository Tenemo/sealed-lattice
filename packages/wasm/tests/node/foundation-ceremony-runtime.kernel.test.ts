import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { shake256 } from '@noble/hashes/sha3.js';
import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it, vi } from 'vitest';

import { openFoundationCeremonyRuntime } from '../../src/foundation-ceremony-runtime.js';
import { normalizeTranscriptCoreKernelBytesForHash } from '../../src/transcript-core-bridge/kernel-runtime.js';
import { createPublishedSdkKernelLoader } from '../../src/transcript-core-bridge/published-sdk-kernel-loader.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const loadRuntime = async () =>
    openFoundationCeremonyRuntime(
        await createPublishedSdkKernelLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })(),
    );

const currentKernelSha256Hex = async (): Promise<string> =>
    createHash('sha256')
        .update(
            normalizeTranscriptCoreKernelBytesForHash(
                new Uint8Array(await readFile(kernelUrl)),
            ),
        )
        .digest('hex');

const encodeVariableUnsignedInteger = (value: number): Uint8Array => {
    const bytes: number[] = [];
    let remaining = value;
    do {
        let byte = remaining & 0x7f;
        remaining = Math.floor(remaining / 128);
        if (remaining !== 0) {
            byte |= 0x80;
        }
        bytes.push(byte);
    } while (remaining !== 0);
    return Uint8Array.from(bytes);
};

const concatenateBytes = (parts: readonly Uint8Array[]): Uint8Array => {
    const byteLength = parts.reduce(
        (total, part) => total + part.byteLength,
        0,
    );
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const frameBytes = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes([encodeVariableUnsignedInteger(bytes.byteLength), bytes]);

const hashFramedParts = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => {
    const textEncoder = new TextEncoder();
    const preimage = concatenateBytes([
        textEncoder.encode('sealed.vote/hash512'),
        frameBytes(textEncoder.encode(domain)),
        encodeVariableUnsignedInteger(parts.length),
        ...parts.map(frameBytes),
    ]);
    try {
        const hash = shake256.create({ dkLen: 64 });
        hash.update(preimage);
        return hash.digest();
    } finally {
        preimage.fill(0);
    }
};

const completionPreparationContextBytes = (): Uint8Array => {
    const textEncoder = new TextEncoder();
    return concatenateBytes([
        frameBytes(
            textEncoder.encode('sealed-lattice/tally-preparation-context'),
        ),
        encodeVariableUnsignedInteger(1),
        frameBytes(new Uint8Array(64).fill(0x91)),
        frameBytes(new Uint8Array(64).fill(0x93)),
        frameBytes(new Uint8Array(64).fill(0x95)),
        frameBytes(new Uint8Array(64).fill(0x97)),
        frameBytes(new Uint8Array(32).fill(0x51)),
        encodeVariableUnsignedInteger(foundationProfile.participantCount),
        encodeVariableUnsignedInteger(foundationProfile.optionCount),
        encodeVariableUnsignedInteger(foundationProfile.optionCount),
    ]);
};

const manifestInput = (optionCount: number) => ({
    displayTitle: 'Choose priorities',
    optionDefinitions: Array.from(
        { length: optionCount },
        (_unused, optionIndex) => ({
            displayLabel: `Option ${String(optionIndex)}`,
            optionIdentifier: `option-${String(optionIndex)}`,
            optionIndex,
        }),
    ),
});

describe('foundation ceremony runtime with the scalar WASM kernel', () => {
    it('exports only the active command and source-custody ABI with standard WASM globals', async () => {
        const module = await WebAssembly.compile(await readFile(kernelUrl));
        expect(WebAssembly.Module.exports(module)).toEqual([
            { kind: 'memory', name: 'memory' },
            { kind: 'function', name: 'sealed_lattice_allocate' },
            { kind: 'function', name: 'sealed_lattice_deallocate' },
            { kind: 'function', name: 'sealed_lattice_deallocate_secret' },
            {
                kind: 'function',
                name: 'sealed_lattice_transcript_core_command_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_join_seed_masters_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_validate_joined_seed_masters_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_validate_joined_seed_master_restoration_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_seed_catalog_source_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_seed_mailbox_sender_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_seed_recipient_receipt_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_seed_receipt_terminal_endorsement_320_with_length',
            },
            { kind: 'global', name: '__data_end' },
            { kind: 'global', name: '__heap_base' },
        ]);
    });

    it('loads only an integrity-pinned source-custody kernel and preserves typed Rust refusals', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const sourceKernelModule =
                await import('../../src/seed-catalog-source-custody-kernel.js');
            const malformedPreparationContext = Uint8Array.of(0x01);
            const kernel =
                await sourceKernelModule.openProductionSeedCatalogSourceCustodyKernel(
                    kernelUrl,
                    malformedPreparationContext,
                );
            expect(
                sourceKernelModule.isProductionSeedCatalogSourceCustodyKernel(
                    kernel,
                ),
            ).toBe(true);
            expect(
                sourceKernelModule.isProductionSeedCatalogSourceCustodyKernel({
                    produceCatalog: () => undefined,
                    produceDeliverySource: () => undefined,
                    validateCatalog: () => undefined,
                    validateDeliverySource: () => undefined,
                }),
            ).toBe(false);

            const hash = new Uint8Array(64).fill(0x41);
            const sourceInput = Object.freeze({
                context: Object.freeze({
                    actionContextIdentity: hash,
                    catalogCompilerIdentity: hash,
                    parameterIdentity: hash,
                    participantCount: 2,
                    participantPosition: 0,
                    preparationAttemptOrdinal: 0,
                    preparationContextIdentity: hash,
                    rosterIdentity: hash,
                    statePredecessorIdentity: hash,
                }),
                geometry: Object.freeze({
                    commitmentSaltByteLength: 1,
                    deliverySourcePayloadByteLengths: Object.freeze([1]),
                    inclusionProofByteLength: 1,
                    leafOpeningByteLengths: Object.freeze([1]),
                    rootBodyByteLength: 1,
                    sourceContributionByteLength: 1,
                }),
                sourceInventory: Object.freeze([
                    Object.freeze({
                        commitmentSalt: Uint8Array.of(0x43),
                        sourceContribution: Uint8Array.of(0x42),
                    }),
                ]),
            });
            expect(() => kernel.produceCatalog(sourceInput)).toThrowError(
                expect.objectContaining({ code: 'ContextMismatch' }),
            );
            expect(malformedPreparationContext).toEqual(Uint8Array.of(0x01));
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it('generates and revalidates the exact completion catalog and delivery through scalar WASM', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const sourceKernelModule =
                await import('../../src/seed-catalog-source-custody-kernel.js');
            const preparationContextBytes = completionPreparationContextBytes();
            const sourcePath = new URL(
                '../../../../crates/sealed-lattice-kernel/src/tally_preparation/pseudorandom_zero_sharing_seed_catalog_320.rs',
                import.meta.url,
            );
            const catalogCompilerIdentity = hashFramedParts(
                'sealed-lattice/v1/preparation/seed-catalog-compiler-identity',
                [
                    new Uint8Array(await readFile(sourcePath)),
                    Uint8Array.of(1, 0),
                ],
            );
            const preparationContextIdentity = hashFramedParts(
                'sealed-lattice/tally-preparation-context-identity/v1',
                [preparationContextBytes],
            );
            const kernel =
                await sourceKernelModule.openProductionSeedCatalogSourceCustodyKernel(
                    kernelUrl,
                    preparationContextBytes,
                );
            const sourceInput = Object.freeze({
                context: Object.freeze({
                    actionContextIdentity: new Uint8Array(64).fill(0x91),
                    catalogCompilerIdentity,
                    parameterIdentity: new Uint8Array(64).fill(0x61),
                    participantCount: foundationProfile.participantCount,
                    participantPosition: 3,
                    preparationAttemptOrdinal: 0,
                    preparationContextIdentity,
                    rosterIdentity: new Uint8Array(64).fill(0x93),
                    statePredecessorIdentity: new Uint8Array(64).fill(0xa5),
                }),
                geometry: Object.freeze({
                    commitmentSaltByteLength: 64,
                    deliverySourcePayloadByteLengths: Object.freeze(
                        Array.from({ length: 9 }, () => 62_590),
                    ),
                    inclusionProofByteLength: 658,
                    leafOpeningByteLengths: Object.freeze([
                        ...Array.from({ length: 84 }, () => 440),
                        ...Array.from({ length: 9 }, () => 444),
                        428,
                    ]),
                    rootBodyByteLength: 522,
                    sourceContributionByteLength: 40,
                }),
                sourceInventory: Object.freeze(
                    Array.from({ length: 94 }, (_unused, leafOrdinal) =>
                        Object.freeze({
                            commitmentSalt: Uint8Array.from(
                                { length: 64 },
                                (_unusedByte, bytePosition) =>
                                    (leafOrdinal * 29 + bytePosition + 1) &
                                    0xff,
                            ),
                            sourceContribution: Uint8Array.from(
                                { length: 40 },
                                (_unusedByte, bytePosition) =>
                                    (leafOrdinal * 17 + bytePosition) & 0xff,
                            ),
                        }),
                    ),
                ),
            });
            const catalog = kernel.produceCatalog(sourceInput);
            expect(catalog.catalogIdentity).toHaveLength(64);
            expect(catalog.rootBodyBytes).toHaveLength(522);
            expect(catalog.entries).toHaveLength(94);
            kernel.validateCatalog({ ...sourceInput, catalog });

            const deliveryInput = {
                ...sourceInput,
                catalog,
                recipientPosition: 7,
            } as const;
            const delivery = kernel.produceDeliverySource(deliveryInput);
            expect(delivery.recipientPosition).toBe(7);
            expect(delivery.sourcePayloadBytes).toBeInstanceOf(Uint8Array);
            expect(delivery.sourcePayloadBytes).toHaveLength(62_590);
            kernel.validateDeliverySource({
                ...deliveryInput,
                sourcePayloadBytes: delivery.sourcePayloadBytes,
            });
            const mutatedPayload = delivery.sourcePayloadBytes.slice();
            mutatedPayload[mutatedPayload.length - 1] ^= 0x01;
            expect(() =>
                kernel.validateDeliverySource({
                    ...deliveryInput,
                    sourcePayloadBytes: mutatedPayload,
                }),
            ).toThrowError(
                expect.objectContaining({ code: 'DeliveryMismatch' }),
            );
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it('loads the sender-mailbox ABI only through an integrity-pinned adapter and preserves public-context refusal', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const senderKernelModule =
                await import('../../src/seed-mailbox-sender-stream-kernel.js');
            expect(
                senderKernelModule.isProductionSeedMailboxSenderStreamKernel({
                    close: () => undefined,
                    produce: () => undefined,
                    validate: () => undefined,
                }),
            ).toBe(false);
            const oneByte = Uint8Array.of(1);
            await expect(
                senderKernelModule.openProductionSeedMailboxSenderStreamKernel(
                    kernelUrl,
                    {
                        parameterIdentity: new Uint8Array(64).fill(0x41),
                        preparationContextBytes: oneByte,
                        rootAuthorizationPackages: [
                            {
                                contributorSignatureEnvelopeBytes: oneByte,
                                exactOutputCertificateBytes: oneByte,
                                reservationCertificateBytes: oneByte,
                                rootBodyBytes: oneByte,
                            },
                        ],
                        rootTerminalCertificateBytes: oneByte,
                        rosterBytes: oneByte,
                        senderPosition: 0,
                        signingOperations: {
                            assertMatchesSenderVerificationKey: () => undefined,
                            signManifestBody: () => new Uint8Array(3_309),
                        },
                        sourceCustodyContext: {
                            actionContextIdentity: new Uint8Array(64).fill(
                                0x42,
                            ),
                            catalogCompilerIdentity: new Uint8Array(64).fill(
                                0x43,
                            ),
                            parameterIdentity: new Uint8Array(64).fill(0x41),
                            participantCount: 10,
                            participantPosition: 0,
                            preparationAttemptOrdinal: 0,
                            preparationContextIdentity: new Uint8Array(64).fill(
                                0x44,
                            ),
                            rosterIdentity: new Uint8Array(64).fill(0x45),
                            statePredecessorIdentity: new Uint8Array(64).fill(
                                0x46,
                            ),
                        },
                        sourceCustodyRecordBytes: oneByte,
                    },
                ),
            ).rejects.toMatchObject({ code: 'PublicVerification' });
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it('loads the recipient-receipt ABI only through an integrity-pinned adapter and preserves public-context refusal', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const receiptKernelModule =
                await import('../../src/seed-recipient-receipt-kernel.js');
            expect(
                receiptKernelModule.isProductionSeedRecipientReceiptKernel({
                    authenticatedInventoryAuthorization: () => ({}),
                    close: () => undefined,
                    prepare: () => undefined,
                    produce: () => undefined,
                    validate: () => undefined,
                }),
            ).toBe(false);
            expect(
                receiptKernelModule.isAuthenticatedSeedRecipientReceiptInconsistency(
                    new receiptKernelModule.SeedRecipientReceiptKernelError(
                        'AuthenticatedInconsistency',
                        'Caller-created imitation.',
                    ),
                ),
            ).toBe(false);
            const oneByte = Uint8Array.of(1);
            const retainAuthenticatedInconsistency = vi.fn(() =>
                Promise.resolve(),
            );
            const retainVerifiedPublicSelection = vi.fn(() =>
                Promise.resolve(),
            );
            await expect(
                receiptKernelModule.openProductionSeedRecipientReceiptKernel(
                    kernelUrl,
                    {
                        carriers: [
                            {
                                encryptedChunks: [oneByte],
                                headerBytes: oneByte,
                                manifestBytes: oneByte,
                                senderPosition: 0,
                                signatureEnvelopeBytes: oneByte,
                            },
                        ],
                        keyOperations: {
                            assertMatchesRecipientKeys: () => undefined,
                            decapsulateMailboxCiphertext: () =>
                                new Uint8Array(32),
                            signReceiptBody: () => new Uint8Array(3_309),
                        },
                        parameterIdentity: new Uint8Array(64).fill(0x41),
                        preparationContextBytes: oneByte,
                        recipientPosition: 1,
                        rootAuthorizationPackages: [
                            {
                                contributorSignatureEnvelopeBytes: oneByte,
                                exactOutputCertificateBytes: oneByte,
                                reservationCertificateBytes: oneByte,
                                rootBodyBytes: oneByte,
                            },
                        ],
                        rootTerminalCertificateBytes: oneByte,
                        rosterBytes: oneByte,
                        stateOperations: {
                            retainAuthenticatedInconsistency,
                            retainVerifiedPublicSelection,
                        },
                    },
                ),
            ).rejects.toMatchObject({ code: 'PublicVerification' });
            expect(retainAuthenticatedInconsistency).not.toHaveBeenCalled();
            expect(retainVerifiedPublicSelection).not.toHaveBeenCalled();
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it('loads the receipt-terminal endorsement ABI only through an integrity-pinned adapter and preserves public-context refusal', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const endorsementKernelModule =
                await import('../../src/seed-receipt-terminal-endorsement-kernel.js');
            expect(
                endorsementKernelModule.isProductionSeedReceiptTerminalEndorsementKernel(
                    {
                        close: () => undefined,
                        prepare: () => undefined,
                        produce: () => undefined,
                        validate: () => undefined,
                    },
                ),
            ).toBe(false);
            const oneByte = Uint8Array.of(1);
            await expect(
                endorsementKernelModule.openProductionSeedReceiptTerminalEndorsementKernel(
                    kernelUrl,
                    {
                        endorserPosition: 0,
                        parameterIdentity: new Uint8Array(64).fill(0x41),
                        preparationContextBytes: oneByte,
                        receiptCustodyContext: {
                            parameterIdentity: new Uint8Array(64).fill(0x41),
                            participantCount: 10,
                            preparationAttemptOrdinal: 0,
                            preparationContextIdentity: new Uint8Array(64).fill(
                                0x42,
                            ),
                            recipientPosition: 0,
                            rootTerminalIdentity: new Uint8Array(64).fill(0x43),
                        },
                        receiptCustodyRecordBytes: oneByte,
                        receiptEnvelopeBytes: [oneByte],
                        rootAuthorizationPackages: [
                            {
                                contributorSignatureEnvelopeBytes: oneByte,
                                exactOutputCertificateBytes: oneByte,
                                reservationCertificateBytes: oneByte,
                                rootBodyBytes: oneByte,
                            },
                        ],
                        rootTerminalCertificateBytes: oneByte,
                        rosterBytes: oneByte,
                        signingOperations: {
                            assertMatchesEndorserVerificationKey: () =>
                                undefined,
                            signEndorsementBody: () => new Uint8Array(3_309),
                        },
                    },
                ),
            ).rejects.toMatchObject({ code: 'PublicVerification' });
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it('loads only an integrity-pinned joined-custody kernel and preserves typed Rust refusals', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: '00'.repeat(32),
            });
            vi.resetModules();
            const wrongIdentityModule =
                await import('../../src/joined-seed-master-custody-kernel.js');
            await expect(
                wrongIdentityModule.openProductionJoinedSeedMasterCustodyKernel(
                    kernelUrl,
                ),
            ).rejects.toThrow('failed integrity verification');

            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const joinedKernelModule =
                await import('../../src/joined-seed-master-custody-kernel.js');
            const kernel =
                await joinedKernelModule.openProductionJoinedSeedMasterCustodyKernel(
                    kernelUrl,
                );
            expect(
                joinedKernelModule.isProductionJoinedSeedMasterCustodyKernel(
                    kernel,
                ),
            ).toBe(true);
            expect(
                joinedKernelModule.isProductionJoinedSeedMasterCustodyKernel({
                    joinAndEncode: () => new Uint8Array(),
                    validateRestoration: () => undefined,
                    validateRetained: () => undefined,
                }),
            ).toBe(false);

            const malformedRequest = Uint8Array.of(0x53, 0x4c, 0x4a);
            expect(() => kernel.joinAndEncode(malformedRequest)).toThrowError(
                expect.objectContaining({ code: 'MalformedRequest' }),
            );
            expect(() =>
                kernel.validateRetained(malformedRequest),
            ).toThrowError(
                expect.objectContaining({ code: 'MalformedRequest' }),
            );
            expect(() =>
                kernel.validateRestoration(malformedRequest),
            ).toThrowError(
                expect.objectContaining({ code: 'MalformedRequest' }),
            );
            expect(malformedRequest).toEqual(Uint8Array.of(0x53, 0x4c, 0x4a));
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it.each([2, 10, 20])(
        'roundtrips a canonical %i-option manifest through the exact kernel bytes',
        async (optionCount) => {
            const runtime = await loadRuntime();
            const encoded = runtime.encodeManifest(manifestInput(optionCount));

            expect(encoded.canonicalBytes.byteLength).toBeGreaterThan(0);
            expect(runtime.verifyManifest(encoded.canonicalBytes)).toEqual({
                isValid: true,
                value: { manifestHash: encoded.manifestHash },
            });
            expect(
                runtime.verifyManifest(encoded.canonicalBytes.slice(0, -1)),
            ).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
        },
    );

    it('refuses duplicate option indexes and trailing canonical bytes', async () => {
        const runtime = await loadRuntime();
        const duplicateIndexInput = manifestInput(2);
        duplicateIndexInput.optionDefinitions[1] = {
            ...duplicateIndexInput.optionDefinitions[1],
            optionIndex: 0,
        };
        expect(() => runtime.encodeManifest(duplicateIndexInput)).toThrow();

        const encoded = runtime.encodeManifest(manifestInput(2));
        const trailing = new Uint8Array(encoded.canonicalBytes.length + 1);
        trailing.set(encoded.canonicalBytes);
        expect(runtime.verifyManifest(trailing)).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
    });
});
