import { afterEach, expect, it, vi } from 'vitest';

const runtimeMocks = vi.hoisted(() => ({
    execute: vi.fn(),
    instantiate: vi.fn(),
}));

vi.mock('../../src/transcript-core-bridge/kernel-runtime.js', () => ({
    instantiateTranscriptCoreKernelCommandRuntime: runtimeMocks.instantiate,
}));

const responseHeader = (status: number): Uint8Array =>
    Uint8Array.of(0x53, 0x4c, 0x52, 0x52, 1, 0, status);

const concatenateBytes = (parts: readonly Uint8Array[]): Uint8Array => {
    const output = new Uint8Array(
        parts.reduce((total, part) => total + part.byteLength, 0),
    );
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const verifiedContext = Object.freeze({
    parameterIdentity: new Uint8Array(64).fill(0x11),
    participantCount: 2,
    preparationAttemptOrdinal: 0,
    preparationContextIdentity: new Uint8Array(64).fill(0x22),
    recipientPosition: 1,
    rootTerminalIdentity: new Uint8Array(64).fill(0x33),
});

const openResponse = (): Uint8Array =>
    concatenateBytes([
        responseHeader(1),
        unsigned32LittleEndian(7),
        verifiedContext.parameterIdentity,
        verifiedContext.preparationContextIdentity,
        verifiedContext.rootTerminalIdentity,
        unsigned16LittleEndian(verifiedContext.preparationAttemptOrdinal),
        unsigned16LittleEndian(verifiedContext.participantCount),
        unsigned16LittleEndian(verifiedContext.recipientPosition),
        new Uint8Array(1_952).fill(0x41),
        new Uint8Array(1_184).fill(0x42),
        unsigned16LittleEndian(1),
        new Uint8Array(1_088).fill(0x43),
    ]);

const failureResponse = (code: number): Uint8Array =>
    concatenateBytes([responseHeader(0), unsigned16LittleEndian(code)]);

const closeResponse = (): Uint8Array => responseHeader(5);

const input = (stateOperations: {
    retainAuthenticatedInconsistency(input: {
        canonicalOpenRequestBytes: Uint8Array;
        verifiedContext: typeof verifiedContext;
    }): Promise<void>;
    retainVerifiedPublicSelection(input: {
        canonicalOpenRequestBytes: Uint8Array;
        verifiedContext: typeof verifiedContext;
    }): Promise<void>;
}) => ({
    carriers: [
        {
            encryptedChunks: [Uint8Array.of(0x51)],
            headerBytes: Uint8Array.of(0x52),
            manifestBytes: Uint8Array.of(0x53),
            senderPosition: 0,
            signatureEnvelopeBytes: Uint8Array.of(0x54),
        },
    ],
    keyOperations: {
        assertMatchesRecipientKeys: () => undefined,
        decapsulateMailboxCiphertext: () => new Uint8Array(32).fill(0x61),
        signReceiptBody: () => new Uint8Array(3_309).fill(0x62),
    },
    parameterIdentity: verifiedContext.parameterIdentity.slice(),
    preparationContextBytes: Uint8Array.of(0x63),
    recipientPosition: 1,
    rootAuthorizationPackages: [
        {
            contributorSignatureEnvelopeBytes: Uint8Array.of(0x64),
            exactOutputCertificateBytes: Uint8Array.of(0x65),
            reservationCertificateBytes: Uint8Array.of(0x66),
            rootBodyBytes: Uint8Array.of(0x67),
        },
    ],
    rootTerminalCertificateBytes: Uint8Array.of(0x68),
    rosterBytes: Uint8Array.of(0x69),
    stateOperations,
});

afterEach(() => {
    runtimeMocks.execute.mockReset();
    runtimeMocks.instantiate.mockReset();
    vi.resetModules();
    Reflect.deleteProperty(
        globalThis,
        '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__',
    );
});

it('retains the verified public selection and genuine authenticated refusal in order', async () => {
    Object.defineProperty(
        globalThis,
        '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__',
        { configurable: true, value: 'a'.repeat(64) },
    );
    runtimeMocks.instantiate.mockResolvedValue({
        executeSeedRecipientReceipt: runtimeMocks.execute,
    });
    runtimeMocks.execute.mockImplementation((requestBytes: Uint8Array) => {
        const operation = requestBytes[6];
        if (operation === 1) {
            return openResponse();
        }
        if (operation === 2) {
            return failureResponse(5);
        }
        if (operation === 5) {
            return closeResponse();
        }
        throw new Error(`Unexpected receipt-kernel operation ${operation}.`);
    });
    const retainedEvents: Array<{
        context: typeof verifiedContext;
        kind: 'burned' | 'selected';
        requestBytes: Uint8Array;
    }> = [];
    const stateOperations = {
        retainAuthenticatedInconsistency: (event: {
            canonicalOpenRequestBytes: Uint8Array;
            verifiedContext: typeof verifiedContext;
        }): Promise<void> => {
            retainedEvents.push({
                context: Object.freeze({
                    ...event.verifiedContext,
                    parameterIdentity:
                        event.verifiedContext.parameterIdentity.slice(),
                    preparationContextIdentity:
                        event.verifiedContext.preparationContextIdentity.slice(),
                    rootTerminalIdentity:
                        event.verifiedContext.rootTerminalIdentity.slice(),
                }),
                kind: 'burned',
                requestBytes: event.canonicalOpenRequestBytes.slice(),
            });
            return Promise.resolve();
        },
        retainVerifiedPublicSelection: (event: {
            canonicalOpenRequestBytes: Uint8Array;
            verifiedContext: typeof verifiedContext;
        }): Promise<void> => {
            retainedEvents.push({
                context: Object.freeze({
                    ...event.verifiedContext,
                    parameterIdentity:
                        event.verifiedContext.parameterIdentity.slice(),
                    preparationContextIdentity:
                        event.verifiedContext.preparationContextIdentity.slice(),
                    rootTerminalIdentity:
                        event.verifiedContext.rootTerminalIdentity.slice(),
                }),
                kind: 'selected',
                requestBytes: event.canonicalOpenRequestBytes.slice(),
            });
            return Promise.resolve();
        },
    };
    const module = await import('../../src/seed-recipient-receipt-kernel.js');

    let refusal: unknown;
    try {
        await module.openProductionSeedRecipientReceiptKernel(
            new URL('https://example.invalid/kernel.wasm'),
            input(stateOperations),
        );
    } catch (error) {
        refusal = error;
    }

    expect(refusal).toMatchObject({ code: 'AuthenticatedInconsistency' });
    expect(
        module.isAuthenticatedSeedRecipientReceiptInconsistency(refusal),
    ).toBe(true);
    expect(retainedEvents.map((event) => event.kind)).toEqual([
        'selected',
        'burned',
    ]);
    expect(retainedEvents[0]?.context).toEqual(verifiedContext);
    expect(retainedEvents[1]?.context).toEqual(verifiedContext);
    expect(retainedEvents[0]?.requestBytes).toEqual(
        retainedEvents[1]?.requestBytes,
    );
    expect(retainedEvents[0]?.requestBytes.byteLength).toBeGreaterThan(0);
    expect(runtimeMocks.execute).toHaveBeenCalledTimes(3);
});

it('fails closed when a genuine authenticated refusal cannot be retained', async () => {
    Object.defineProperty(
        globalThis,
        '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__',
        { configurable: true, value: 'b'.repeat(64) },
    );
    runtimeMocks.instantiate.mockResolvedValue({
        executeSeedRecipientReceipt: runtimeMocks.execute,
    });
    runtimeMocks.execute.mockImplementation((requestBytes: Uint8Array) => {
        const operation = requestBytes[6];
        if (operation === 1) {
            return openResponse();
        }
        if (operation === 2) {
            return failureResponse(5);
        }
        if (operation === 5) {
            return closeResponse();
        }
        throw new Error(`Unexpected receipt-kernel operation ${operation}.`);
    });
    const retentionFailure = new Error('External recency anchor unavailable.');
    const stateOperations = {
        retainAuthenticatedInconsistency: (): Promise<void> =>
            Promise.reject(retentionFailure),
        retainVerifiedPublicSelection: (): Promise<void> => Promise.resolve(),
    };
    const module = await import('../../src/seed-recipient-receipt-kernel.js');

    let refusal: unknown;
    try {
        await module.openProductionSeedRecipientReceiptKernel(
            new URL('https://example.invalid/kernel.wasm'),
            input(stateOperations),
        );
    } catch (error) {
        refusal = error;
    }

    expect(refusal).toMatchObject({ code: 'ContextUnavailable' });
    expect(refusal).toBeInstanceOf(module.SeedRecipientReceiptKernelError);
    if (!(refusal instanceof module.SeedRecipientReceiptKernelError)) {
        throw new Error('Expected a typed receipt-kernel refusal.');
    }
    const failureCause = refusal.failureCause;
    if (!Array.isArray(failureCause)) {
        throw new Error('Expected the burn-retention failure pair.');
    }
    expect(failureCause[1]).toBe(retentionFailure);
    expect(
        module.isAuthenticatedSeedRecipientReceiptInconsistency(refusal),
    ).toBe(false);
    expect(runtimeMocks.execute).toHaveBeenCalledTimes(3);
});
