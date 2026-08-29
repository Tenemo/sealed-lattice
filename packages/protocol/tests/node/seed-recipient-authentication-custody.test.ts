import type {
    BrowserLocalMailboxCapability,
    BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import type {
    OpenProductionSeedRecipientReceiptKernelInput,
    ProductionSeedRecipientReceiptKernel,
} from '@sealed-lattice/wasm';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
    openKernel: vi.fn(),
}));

vi.mock('@sealed-lattice/crypto', () => ({
    assertSeedRecipientReceiptCapabilitiesMatchRosterKeys: vi.fn(),
    decapsulateSeedRecipientMailboxCiphertext: vi.fn(),
    signSeedRecipientReceiptBody: vi.fn(),
}));

vi.mock('@sealed-lattice/wasm', () => ({
    openProductionSeedRecipientReceiptKernel: mocks.openKernel,
}));

import {
    createRuntimeRecordProtection,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    assertSeedRecipientActionSelected,
    consumePreprocessingSourceStateAuthorization,
    createSeedRecipientActionStateGuard,
    deriveSeedRecipientAuthenticationCustodyByteLengths,
    openBrowserLocalSeedRecipientReceiptKernel,
    retainConflictingSeedReceiptTerminalEndorsementBurn,
    retainConflictingSeedRecipientReceiptBurn,
    SeedRecipientAuthenticationCustody,
    type SeedRecipientAuthenticationCustodyLimits,
    type SeedRecipientReceiptCustodyContext,
} from '#packages/protocol/src/runtime/seed-recipient-authentication-custody';
import {
    generateRuntimeStorageRootKey,
    hashFilledWith,
    InMemoryAuthenticatedStorageRecencyAnchor,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const limits: SeedRecipientAuthenticationCustodyLimits = Object.freeze({
    maximumCanonicalOpenRequestByteLength: 2_000_000,
    transactionLifetimeMilliseconds: 1_000,
});

const defaultContext = (): SeedRecipientReceiptCustodyContext =>
    Object.freeze({
        parameterIdentity: hashFilledWith(0x11),
        participantCount: 4,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: hashFilledWith(0x22),
        recipientPosition: 2,
        rootTerminalIdentity: hashFilledWith(0x33),
    });

const deterministicCryptoProvider = (): Crypto => {
    let invocationCount = 0;
    return {
        getRandomValues: <Value extends ArrayBufferView>(
            value: Value,
        ): Value => {
            invocationCount += 1;
            const bytes = new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
            );
            for (
                let byteIndex = 0;
                byteIndex < bytes.byteLength;
                byteIndex += 1
            ) {
                bytes[byteIndex] =
                    ((invocationCount * 37 + byteIndex * 19) % 255) + 1;
            }
            return value;
        },
        subtle: globalThis.crypto.subtle,
    } as Crypto;
};

const createIdentifierFactory = (): ((
    kind: 'lease' | 'transaction',
) => string) => {
    const counts = { lease: 0, transaction: 0 };
    return (kind) => {
        counts[kind] += 1;
        const kindByte = kind === 'transaction' ? '01' : '02';
        return `${kindByte}${counts[kind].toString(16).padStart(62, '0')}`;
    };
};

type CustodyFixture = Readonly<{
    adapter: InMemoryRuntimeStorageAdapter;
    anchor: InMemoryAuthenticatedStorageRecencyAnchor;
    context: SeedRecipientReceiptCustodyContext;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: SeedRecipientAuthenticationCustody;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const createFixture = async (
    context = defaultContext(),
): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `seed-recipient-authentication-custody-${fixtureOrdinal}`;
    const createIdentifier = createIdentifierFactory();
    const opened = await openRuntimeTestStore({
        createIdentifier,
        namespace,
    });
    const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
    const coordinator = new AuthenticatedStorageRecencyCoordinator({
        anchor,
        store: opened.store,
    });
    const rootKey = await generateRuntimeStorageRootKey();
    const cryptoProvider = deterministicCryptoProvider();
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider,
        maximumRecordSealingCount: 32,
        rootKey,
    });
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        context,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody: new SeedRecipientAuthenticationCustody({
            context,
            limits,
            protection,
            recencyCoordinator: coordinator,
        }),
        namespace,
        protection,
        rootKey,
    });
};

const reopenCustody = async (
    fixture: CustodyFixture,
    context = fixture.context,
): Promise<SeedRecipientAuthenticationCustody> => {
    const opened = await openRuntimeTestStore({
        adapter: fixture.adapter,
        createIdentifier: fixture.createIdentifier,
        namespace: fixture.namespace,
    });
    const coordinator = new AuthenticatedStorageRecencyCoordinator({
        anchor: fixture.anchor,
        store: opened.store,
    });
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider: fixture.cryptoProvider,
        maximumRecordSealingCount: 32,
        rootKey: fixture.rootKey,
    });
    return new SeedRecipientAuthenticationCustody({
        context,
        limits,
        protection,
        recencyCoordinator: coordinator,
    });
};

const productionKernel = Object.freeze({
    authenticatedInventoryAuthorization: () => Object.freeze({}),
    close: (): void => undefined,
    prepare: (): never => {
        throw new Error('The authentication-custody test does not prepare.');
    },
    produce: (): never => {
        throw new Error('The authentication-custody test does not produce.');
    },
    validate: (): void => undefined,
}) as unknown as ProductionSeedRecipientReceiptKernel;

const openInput = (
    authenticationCustody: SeedRecipientAuthenticationCustody,
    marker: number,
) =>
    Object.freeze({
        authenticationCustody,
        carriers: Object.freeze([
            Object.freeze({
                encryptedChunks: Object.freeze([Uint8Array.of(marker + 1)]),
                headerBytes: Uint8Array.of(marker),
                manifestBytes: Uint8Array.of(marker + 2),
                senderPosition: 0,
                signatureEnvelopeBytes: Uint8Array.of(marker + 3),
            }),
        ]),
        mailboxCapability: Object.freeze({}) as BrowserLocalMailboxCapability,
        parameterIdentity: hashFilledWith(0x11),
        preparationContextBytes: Uint8Array.of(0x41),
        recipientPosition: 2,
        rootAuthorizationPackages: Object.freeze([
            Object.freeze({
                contributorSignatureEnvelopeBytes: Uint8Array.of(0x42),
                exactOutputCertificateBytes: Uint8Array.of(0x43),
                reservationCertificateBytes: Uint8Array.of(0x44),
                rootBodyBytes: Uint8Array.of(0x45),
            }),
        ]),
        rootTerminalCertificateBytes: Uint8Array.of(0x46),
        rosterBytes: Uint8Array.of(0x47),
        signingCapability: Object.freeze({}) as BrowserLocalSigningCapability,
    });

const installSelectedOpen = (input?: {
    beforeBurn?: () => void;
    burn?: boolean;
    verifiedContext?: SeedRecipientReceiptCustodyContext;
}): void => {
    mocks.openKernel.mockImplementation(
        async (
            _kernelUrl: URL,
            kernelInput: OpenProductionSeedRecipientReceiptKernelInput,
        ) => {
            const marker = kernelInput.carriers[0]?.headerBytes[0] ?? 0;
            const canonicalOpenRequestBytes = new Uint8Array(23).fill(marker);
            const verifiedContext = input?.verifiedContext ?? defaultContext();
            await kernelInput.stateOperations.retainVerifiedPublicSelection({
                canonicalOpenRequestBytes,
                verifiedContext,
            });
            if (input?.burn === true) {
                input.beforeBurn?.();
                await kernelInput.stateOperations.retainAuthenticatedInconsistency(
                    {
                        canonicalOpenRequestBytes,
                        disclosedAuthenticatedEncryptionKey: new Uint8Array(
                            32,
                        ).fill(marker + 4),
                        evidenceIdentity: new Uint8Array(64).fill(marker + 5),
                        recipientPosition: verifiedContext.recipientPosition,
                        senderPosition:
                            verifiedContext.recipientPosition === 0 ? 1 : 0,
                        verifiedContext,
                    },
                );
                throw new Error('Authenticated seed-delivery inconsistency.');
            }
            return productionKernel;
        },
    );
};

beforeEach(() => {
    mocks.openKernel.mockReset();
});

describe('seed-recipient authentication custody', () => {
    it('independently accounts for the exact selection and terminal-burn records', () => {
        const derived = deriveSeedRecipientAuthenticationCustodyByteLengths({
            canonicalOpenRequestByteLength: 1_235_408,
        });
        const independentlyDerivedPrefixByteLength =
            4 + 2 + 1 + 64 * 3 + 2 * 3 + 4;
        const independentlyDerivedSelectedPlaintextByteLength =
            independentlyDerivedPrefixByteLength + 1_235_408;
        const independentlyDerivedConflictingIntentBurnedPlaintextByteLength =
            independentlyDerivedSelectedPlaintextByteLength + 1;
        const independentlyDerivedAuthenticatedInconsistencyBurnedPlaintextByteLength =
            independentlyDerivedConflictingIntentBurnedPlaintextByteLength +
            2 +
            2 +
            32 +
            64;
        const independentlyDerivedJoinedPlaintextByteLength =
            4 + 2 + 1 + 64 * 3 + 2 * 3 + 64;
        expect(derived).toEqual({
            authenticatedInconsistencyBurnedCiphertextByteLength:
                independentlyDerivedAuthenticatedInconsistencyBurnedPlaintextByteLength +
                54,
            authenticatedInconsistencyBurnedPlaintextByteLength:
                independentlyDerivedAuthenticatedInconsistencyBurnedPlaintextByteLength,
            authenticatedInconsistencyBurnTransitionCiphertextOverlapByteLength:
                independentlyDerivedSelectedPlaintextByteLength +
                independentlyDerivedAuthenticatedInconsistencyBurnedPlaintextByteLength +
                54 * 2,
            conflictingIntentBurnedCiphertextByteLength:
                independentlyDerivedConflictingIntentBurnedPlaintextByteLength +
                54,
            conflictingIntentBurnedPlaintextByteLength:
                independentlyDerivedConflictingIntentBurnedPlaintextByteLength,
            conflictingIntentBurnTransitionCiphertextOverlapByteLength:
                independentlyDerivedSelectedPlaintextByteLength +
                independentlyDerivedConflictingIntentBurnedPlaintextByteLength +
                54 * 2,
            joinedCiphertextByteLength:
                independentlyDerivedJoinedPlaintextByteLength + 54,
            joinedPlaintextByteLength:
                independentlyDerivedJoinedPlaintextByteLength,
            selectedCiphertextByteLength:
                independentlyDerivedSelectedPlaintextByteLength + 54,
            selectedPlaintextByteLength:
                independentlyDerivedSelectedPlaintextByteLength,
        });
        expect(derived).toEqual({
            authenticatedInconsistencyBurnedCiphertextByteLength: 1_235_772,
            authenticatedInconsistencyBurnedPlaintextByteLength: 1_235_718,
            authenticatedInconsistencyBurnTransitionCiphertextOverlapByteLength: 2_471_443,
            conflictingIntentBurnedCiphertextByteLength: 1_235_672,
            conflictingIntentBurnedPlaintextByteLength: 1_235_618,
            conflictingIntentBurnTransitionCiphertextOverlapByteLength: 2_471_343,
            joinedCiphertextByteLength: 323,
            joinedPlaintextByteLength: 269,
            selectedCiphertextByteLength: 1_235_671,
            selectedPlaintextByteLength: 1_235_617,
        });
    });

    it('retains one exact Rust-verified public selection across cold resume', async () => {
        const fixture = await createFixture();
        installSelectedOpen();

        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x51),
            ),
        ).resolves.toBe(productionKernel);
        await expect(fixture.custody.readStatus()).resolves.toBe('selected');

        const reopened = await reopenCustody(fixture);
        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(reopened, 0x51),
            ),
        ).resolves.toBe(productionKernel);
        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(reopened, 0x52),
            ),
        ).rejects.toMatchObject({ code: 'Conflict' });

        const authorization = reopened.authorizePreprocessingSourceState();
        const consumed =
            await consumePreprocessingSourceStateAuthorization(authorization);
        expect(consumed.context).toEqual(fixture.context);
        expect(consumed.recordBytes.byteLength).toBe(
            deriveSeedRecipientAuthenticationCustodyByteLengths({
                canonicalOpenRequestByteLength: 23,
            }).selectedPlaintextByteLength,
        );
        expect(
            new DataView(consumed.recordBytes.buffer).getUint16(4, true),
        ).toBe(2);
        await expect(
            consumePreprocessingSourceStateAuthorization(authorization),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        consumed.recordBytes.fill(0);
    });

    it('durably burns an authenticated inconsistency and blocks same-action replay', async () => {
        const fixture = await createFixture();
        installSelectedOpen({ burn: true });

        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x61),
            ),
        ).rejects.toThrow('Authenticated seed-delivery inconsistency.');
        await expect(fixture.custody.readStatus()).resolves.toBe('burned');

        const reopened = await reopenCustody(fixture);
        installSelectedOpen();
        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(reopened, 0x61),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        await expect(reopened.readStatus()).resolves.toBe('burned');

        const consumed = await consumePreprocessingSourceStateAuthorization(
            reopened.authorizePreprocessingSourceState(),
        );
        const byteLengths = deriveSeedRecipientAuthenticationCustodyByteLengths(
            {
                canonicalOpenRequestByteLength: 23,
            },
        );
        expect(consumed.recordBytes.byteLength).toBe(
            byteLengths.authenticatedInconsistencyBurnedPlaintextByteLength,
        );
        const evidenceOffset =
            byteLengths.conflictingIntentBurnedPlaintextByteLength;
        const evidenceView = new DataView(
            consumed.recordBytes.buffer,
            consumed.recordBytes.byteOffset + evidenceOffset,
        );
        expect(evidenceView.getUint16(0, true)).toBe(0);
        expect(evidenceView.getUint16(2, true)).toBe(2);
        expect(
            consumed.recordBytes.slice(evidenceOffset + 4, evidenceOffset + 36),
        ).toEqual(new Uint8Array(32).fill(0x65));
        expect(consumed.recordBytes.slice(evidenceOffset + 36)).toEqual(
            new Uint8Array(64).fill(0x66),
        );
        consumed.recordBytes.fill(0);
    });

    it('retains canonical downstream receipt and terminal-endorsement burns', async () => {
        const burnOperations = [
            retainConflictingSeedRecipientReceiptBurn,
            retainConflictingSeedReceiptTerminalEndorsementBurn,
        ] as const;
        for (const [operationIndex, retainBurn] of burnOperations.entries()) {
            const fixture = await createFixture();
            installSelectedOpen();
            await openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0xa1 + operationIndex),
            );
            const guard = createSeedRecipientActionStateGuard({
                authenticationCustody: fixture.custody,
                context: fixture.context,
                recencyCoordinator: fixture.coordinator,
            });

            await expect(
                assertSeedRecipientActionSelected(guard),
            ).resolves.toBeUndefined();
            await expect(retainBurn(guard)).resolves.toBeUndefined();
            await expect(
                assertSeedRecipientActionSelected(guard),
            ).rejects.toMatchObject({ code: 'InvalidState' });

            const reopened = await reopenCustody(fixture);
            await expect(reopened.readStatus()).resolves.toBe('burned');
            await expect(
                consumePreprocessingSourceStateAuthorization(
                    reopened.authorizePreprocessingSourceState(),
                ),
            ).rejects.toMatchObject({ code: 'InvalidState' });
        }
    });

    it('rejects forged or cross-coordinator action-state guards', async () => {
        const fixture = await createFixture();
        const otherFixture = await createFixture();

        expect(() =>
            createSeedRecipientActionStateGuard({
                authenticationCustody: fixture.custody,
                context: fixture.context,
                recencyCoordinator: otherFixture.coordinator,
            }),
        ).toThrowError(
            expect.objectContaining({ code: 'InvalidConfiguration' }),
        );
        expect(() =>
            createSeedRecipientActionStateGuard({
                authenticationCustody: fixture.custody,
                context: Object.freeze({
                    ...fixture.context,
                    rootTerminalIdentity: hashFilledWith(0x34),
                }),
                recencyCoordinator: fixture.coordinator,
            }),
        ).toThrowError(
            expect.objectContaining({ code: 'InvalidConfiguration' }),
        );
        expect(() =>
            assertSeedRecipientActionSelected(Object.freeze({}) as never),
        ).toThrowError(
            expect.objectContaining({ code: 'InvalidConfiguration' }),
        );
    });

    it('repairs an interrupted downstream receipt burn before continuation', async () => {
        const fixture = await createFixture();
        installSelectedOpen();
        await openBrowserLocalSeedRecipientReceiptKernel(
            new URL('https://example.invalid/kernel.wasm'),
            openInput(fixture.custody, 0xb1),
        );
        const guard = createSeedRecipientActionStateGuard({
            authenticationCustody: fixture.custody,
            context: fixture.context,
            recencyCoordinator: fixture.coordinator,
        });
        fixture.anchor.failNextCompareAndSetCount = 1;

        await expect(
            retainConflictingSeedRecipientReceiptBurn(guard),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });

        const reopened = await reopenCustody(fixture);
        await expect(reopened.readStatus()).resolves.toBe('burned');
    });

    it('repairs an interrupted burn anchor before exposing the terminal state', async () => {
        const fixture = await createFixture();
        installSelectedOpen({
            beforeBurn: () => {
                fixture.anchor.failNextCompareAndSetCount = 1;
            },
            burn: true,
        });

        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x69),
            ),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });

        const reopened = await reopenCustody(fixture);
        await expect(reopened.readStatus()).resolves.toBe('burned');
        installSelectedOpen();
        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(reopened, 0x69),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('leaves unsigned or malformed public refusal pending', async () => {
        const fixture = await createFixture();
        mocks.openKernel.mockRejectedValue(
            new Error('Public carrier verification failed.'),
        );

        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x71),
            ),
        ).rejects.toThrow('Public carrier verification failed.');
        await expect(fixture.custody.readStatus()).resolves.toBe('pending');
        expect(fixture.adapter.atomicMutationCount).toBe(0);
    });

    it('refuses a JavaScript object that only imitates the durable owner', async () => {
        const input = openInput(
            Object.freeze({}) as SeedRecipientAuthenticationCustody,
            0x79,
        );
        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                input,
            ),
        ).rejects.toMatchObject({ code: 'InvalidConfiguration' });
        expect(mocks.openKernel).not.toHaveBeenCalled();
    });

    it('refuses a mismatched Rust-verified scope before retaining state', async () => {
        const fixture = await createFixture();
        installSelectedOpen({
            verifiedContext: Object.freeze({
                ...defaultContext(),
                rootTerminalIdentity: hashFilledWith(0x34),
            }),
        });

        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x81),
            ),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(fixture.custody.readStatus()).resolves.toBe('pending');
    });

    it('repairs an interrupted selection anchor before private work can resume', async () => {
        const fixture = await createFixture();
        await fixture.coordinator.reconcile();
        fixture.anchor.failNextCompareAndSetCount = 1;
        installSelectedOpen();

        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x91),
            ),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        await expect(
            openBrowserLocalSeedRecipientReceiptKernel(
                new URL('https://example.invalid/kernel.wasm'),
                openInput(fixture.custody, 0x91),
            ),
        ).resolves.toBe(productionKernel);
        await expect(fixture.custody.readStatus()).resolves.toBe('selected');
    });
});
