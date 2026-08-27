import type { BrowserLocalSigningCapability } from '@sealed-lattice/crypto';
import type {
    OpenProductionSeedMailboxSenderStreamKernelInput,
    ProductionSeedMailboxSenderStreamKernel,
} from '@sealed-lattice/wasm';
import { beforeEach, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
    assertSigningKey: vi.fn(),
    consumeSourceAuthorization: vi.fn(),
    openKernel: vi.fn(),
    signManifest: vi.fn(),
}));

vi.mock('@sealed-lattice/crypto', () => ({
    assertSeedMailboxSenderSigningCapabilityMatchesRosterKey:
        mocks.assertSigningKey,
    signSeedMailboxManifestBody: mocks.signManifest,
}));

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedMailboxSenderStreamKernel: () => true,
    openProductionSeedMailboxSenderStreamKernel: mocks.openKernel,
}));

vi.mock('../../src/runtime/seed-catalog-source-custody.js', () => ({
    consumeSeedCatalogSourceSenderAuthorization:
        mocks.consumeSourceAuthorization,
}));

import { openBrowserLocalSeedMailboxSenderStreamKernel } from '#packages/protocol/src/runtime/seed-mailbox-sender-stream-custody';

beforeEach(() => {
    mocks.assertSigningKey.mockReset();
    mocks.consumeSourceAuthorization.mockReset();
    mocks.openKernel.mockReset();
    mocks.signManifest.mockReset();
});

it('binds the fixed sender-manifest operations to one opaque browser-local capability', async () => {
    const productionKernel = Object.freeze({
        close: (): void => undefined,
        produce: (): never => {
            throw new Error('The binding test does not produce a carrier.');
        },
        validate: (): void => undefined,
    }) as unknown as ProductionSeedMailboxSenderStreamKernel;
    const sourceContext = Object.freeze({
        actionContextIdentity: new Uint8Array(64).fill(0xa1),
        catalogCompilerIdentity: new Uint8Array(64).fill(0xa2),
        parameterIdentity: new Uint8Array(64).fill(0x21),
        participantCount: 10,
        participantPosition: 3,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: new Uint8Array(64).fill(0xa3),
        rosterIdentity: new Uint8Array(64).fill(0xa4),
        statePredecessorIdentity: new Uint8Array(64).fill(0xa5),
    });
    const sourceRecordBytes = new Uint8Array(73).fill(0xb1);
    const sourceCustodyAuthorization = Object.freeze({});
    mocks.consumeSourceAuthorization.mockResolvedValue({
        context: sourceContext,
        recordBytes: sourceRecordBytes,
    });
    let openedInput:
        | OpenProductionSeedMailboxSenderStreamKernelInput
        | undefined;
    mocks.openKernel.mockImplementation(
        (
            _kernelUrl: URL,
            input: OpenProductionSeedMailboxSenderStreamKernelInput,
        ) => {
            expect(input.parameterIdentity).toEqual(parameterIdentity);
            expect(input.preparationContextBytes).toEqual(
                preparationContextBytes,
            );
            expect(input.rootAuthorizationPackages).toEqual([
                {
                    contributorSignatureEnvelopeBytes,
                    exactOutputCertificateBytes,
                    reservationCertificateBytes,
                    rootBodyBytes,
                },
            ]);
            expect(input.rootTerminalCertificateBytes).toEqual(
                rootTerminalCertificateBytes,
            );
            expect(input.rosterBytes).toEqual(rosterBytes);
            expect(input.sourceCustodyContext).toEqual(sourceContext);
            expect(input.sourceCustodyRecordBytes).toEqual(sourceRecordBytes);
            openedInput = input;
            return Promise.resolve(productionKernel);
        },
    );
    const signingCapability = Object.freeze(
        {},
    ) as BrowserLocalSigningCapability;
    const kernelUrl = new URL('https://example.invalid/kernel.wasm');
    const parameterIdentity = new Uint8Array(64).fill(0x21);
    const preparationContextBytes = Uint8Array.of(0x31);
    const rootBodyBytes = Uint8Array.of(0x41);
    const reservationCertificateBytes = Uint8Array.of(0x51);
    const exactOutputCertificateBytes = Uint8Array.of(0x61);
    const contributorSignatureEnvelopeBytes = Uint8Array.of(0x71);
    const rootTerminalCertificateBytes = Uint8Array.of(0x81);
    const rosterBytes = Uint8Array.of(0x91);

    await expect(
        openBrowserLocalSeedMailboxSenderStreamKernel(kernelUrl, {
            parameterIdentity,
            preparationContextBytes,
            rootAuthorizationPackages: [
                {
                    contributorSignatureEnvelopeBytes,
                    exactOutputCertificateBytes,
                    reservationCertificateBytes,
                    rootBodyBytes,
                },
            ],
            rootTerminalCertificateBytes,
            rosterBytes,
            senderPosition: 3,
            signingCapability,
            sourceCustodyAuthorization: sourceCustodyAuthorization as never,
        }),
    ).resolves.toBe(productionKernel);
    expect(mocks.consumeSourceAuthorization).toHaveBeenCalledExactlyOnceWith(
        sourceCustodyAuthorization,
    );
    expect(mocks.openKernel).toHaveBeenCalledTimes(1);

    const senderSigningVerificationKey = new Uint8Array(1_952).fill(0xa1);
    openedInput?.signingOperations.assertMatchesSenderVerificationKey({
        senderSigningVerificationKey,
    });
    expect(mocks.assertSigningKey).toHaveBeenCalledWith({
        senderSigningVerificationKey,
        signingCapability,
    });

    const signatureBodyBytes = new Uint8Array(309).fill(0xb1);
    const signatureRandomness = new Uint8Array(32).fill(0xc1);
    const signature = new Uint8Array(3_309).fill(0xd1);
    mocks.signManifest.mockReturnValue(signature);
    expect(
        openedInput?.signingOperations.signManifestBody({
            senderSigningVerificationKey,
            signatureBodyBytes,
            signatureRandomness,
        }),
    ).toBe(signature);
    expect(mocks.signManifest).toHaveBeenCalledWith({
        senderSigningVerificationKey,
        signatureBodyBytes,
        signatureRandomness,
        signingCapability,
    });
});
