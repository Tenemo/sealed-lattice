import type {
    ProductionJoinedSeedMasterCustodyKernel,
    ProductionSeedCatalogSourceCustodyKernel,
    ProductionSeedRecipientReceiptKernel,
} from '@sealed-lattice/wasm';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionJoinedSeedMasterCustodyKernel: () => true,
    isProductionSeedCatalogSourceCustodyKernel: () => true,
    isProductionSeedRecipientReceiptKernel: () => true,
}));

import {
    createRuntimeRecordProtection,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    JoinedSeedMasterCustody,
    deriveJoinedSeedMasterCustodyRecordByteLengths,
    type JoinedSeedMasterCustodyContext,
    type JoinedSeedMasterCustodyLimits,
} from '#packages/protocol/src/runtime/joined-seed-master-custody';
import {
    SeedCatalogSourceCustody,
    readCompletedSeedCatalogSourceCustodyForMasterJoin,
    type RetainedLocalSeedCatalog,
    type SeedCatalogDeliverySourceProductionInput,
    type SeedCatalogDeliverySourceValidationInput,
    type SeedCatalogProductionInput,
    type SeedCatalogSourceCustodyContext,
    type SeedCatalogSourceCustodyGeometry,
    type SeedCatalogSourceCustodyKernel,
    type SeedCatalogSourceCustodyLimits,
    type SeedCatalogValidationInput,
} from '#packages/protocol/src/runtime/seed-catalog-source-custody';
import {
    SeedRecipientReceiptCustody,
    readCompletedSeedRecipientReceiptCustodyForMasterJoin,
    type PreparedSeedRecipientReceiptInventory,
    type SeedRecipientReceiptCustodyContext,
    type SeedRecipientReceiptCustodyKernel,
    type SeedRecipientReceiptCustodyLimits,
    type SeedRecipientReceiptProductionInput,
    type SeedRecipientReceiptValidationInput,
} from '#packages/protocol/src/runtime/seed-recipient-receipt-custody';
import {
    generateRuntimeStorageRootKey,
    hashFilledWith,
    InMemoryAuthenticatedStorageRecencyAnchor,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const sourceLimits: SeedCatalogSourceCustodyLimits = Object.freeze({
    maximumCatalogLeafCount: 8,
    maximumCommitmentSaltByteLength: 64,
    maximumDeliverySourcePayloadByteLength: 128,
    maximumInclusionProofByteLength: 128,
    maximumLeafOpeningByteLength: 128,
    maximumRootBodyByteLength: 128,
    maximumSourceContributionByteLength: 64,
    transactionLifetimeMilliseconds: 1_000,
});

const receiptLimits: SeedRecipientReceiptCustodyLimits = Object.freeze({
    maximumAuthenticatedInventoryBodyByteLength: 256,
    maximumLocalSeedCustodySegmentByteLength: 256,
    maximumReceiptEnvelopeByteLength: 256,
    maximumReceiptIntentByteLength: 256,
    transactionLifetimeMilliseconds: 1_000,
});

const joinedLimits: JoinedSeedMasterCustodyLimits = Object.freeze({
    maximumJoinedMasterPayloadByteLength: 2_048,
    maximumReceiptTerminalCertificateByteLength: 2_048,
    maximumRootTerminalCertificateByteLength: 2_048,
    maximumVerificationContextByteLength: 2_048,
    transactionLifetimeMilliseconds: 1_000,
});

const sourceGeometry: SeedCatalogSourceCustodyGeometry = Object.freeze({
    commitmentSaltByteLength: 9,
    deliverySourcePayloadByteLengths: Object.freeze([17, 19, 23]),
    inclusionProofByteLength: 13,
    leafOpeningByteLengths: Object.freeze([11, 15]),
    rootBodyByteLength: 29,
    sourceContributionByteLength: 7,
});

const context = (): JoinedSeedMasterCustodyContext =>
    Object.freeze({
        actionContextIdentity: hashFilledWith(0x11),
        authenticatedRecipientInventoryIdentity: hashFilledWith(0x12),
        catalogCompilerIdentity: hashFilledWith(0x13),
        parameterIdentity: hashFilledWith(0x14),
        participantCount: 4,
        participantPosition: 0,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: hashFilledWith(0x15),
        receiptBodyIdentity: hashFilledWith(0x16),
        receiptEnvelopeIdentity: hashFilledWith(0x17),
        receiptTerminalCertificateIdentity: hashFilledWith(0x18),
        receiptTerminalIdentity: hashFilledWith(0x19),
        rootTerminalCertificateIdentity: hashFilledWith(0x1a),
        rootTerminalIdentity: hashFilledWith(0x1b),
        rosterIdentity: hashFilledWith(0x1c),
        statePredecessorIdentity: hashFilledWith(0x1d),
    });

const sourceContext = (
    joinedContext: JoinedSeedMasterCustodyContext,
): SeedCatalogSourceCustodyContext =>
    Object.freeze({
        actionContextIdentity: joinedContext.actionContextIdentity.slice(),
        catalogCompilerIdentity: joinedContext.catalogCompilerIdentity.slice(),
        parameterIdentity: joinedContext.parameterIdentity.slice(),
        participantCount: joinedContext.participantCount,
        participantPosition: joinedContext.participantPosition,
        preparationAttemptOrdinal: joinedContext.preparationAttemptOrdinal,
        preparationContextIdentity:
            joinedContext.preparationContextIdentity.slice(),
        rosterIdentity: joinedContext.rosterIdentity.slice(),
        statePredecessorIdentity:
            joinedContext.statePredecessorIdentity.slice(),
    });

const receiptContext = (
    joinedContext: JoinedSeedMasterCustodyContext,
): SeedRecipientReceiptCustodyContext =>
    Object.freeze({
        parameterIdentity: joinedContext.parameterIdentity.slice(),
        participantCount: joinedContext.participantCount,
        preparationAttemptOrdinal: joinedContext.preparationAttemptOrdinal,
        preparationContextIdentity:
            joinedContext.preparationContextIdentity.slice(),
        recipientPosition: joinedContext.participantPosition,
        rootTerminalIdentity: joinedContext.rootTerminalIdentity.slice(),
    });

const concatenate = (parts: readonly Uint8Array[]): Uint8Array => {
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

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((byte, byteIndex) => byte === right[byteIndex]);

const containsBytes = (
    container: Uint8Array,
    expected: Uint8Array,
): boolean => {
    if (expected.byteLength > container.byteLength) {
        return false;
    }
    for (
        let offset = 0;
        offset <= container.byteLength - expected.byteLength;
        offset += 1
    ) {
        if (
            expected.every(
                (byte, byteIndex) => container[offset + byteIndex] === byte,
            )
        ) {
            return true;
        }
    }
    return false;
};

const rootTerminalBytes = (
    joinedContext: JoinedSeedMasterCustodyContext,
): Uint8Array =>
    concatenate([
        Uint8Array.of(0xa1, 0x01),
        joinedContext.parameterIdentity,
        joinedContext.preparationContextIdentity,
        joinedContext.rootTerminalIdentity,
        joinedContext.rootTerminalCertificateIdentity,
        joinedContext.rosterIdentity,
    ]);

const receiptTerminalBytes = (
    joinedContext: JoinedSeedMasterCustodyContext,
): Uint8Array =>
    concatenate([
        Uint8Array.of(0xa2, 0x01),
        joinedContext.rootTerminalIdentity,
        joinedContext.receiptTerminalIdentity,
        joinedContext.receiptTerminalCertificateIdentity,
        joinedContext.authenticatedRecipientInventoryIdentity,
        joinedContext.receiptBodyIdentity,
        joinedContext.receiptEnvelopeIdentity,
    ]);

const verificationContextBytes = (
    joinedContext: JoinedSeedMasterCustodyContext,
): Uint8Array =>
    concatenate([
        Uint8Array.of(0xa3, 0x01),
        joinedContext.actionContextIdentity,
        joinedContext.catalogCompilerIdentity,
        joinedContext.parameterIdentity,
        joinedContext.preparationContextIdentity,
        joinedContext.rosterIdentity,
        joinedContext.statePredecessorIdentity,
    ]);

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
                    ((invocationCount * 43 + byteIndex * 29) % 255) + 1;
            }
            return value;
        },
        subtle: globalThis.crypto.subtle,
    } as Crypto;
};

const catalogForInput = (
    input: SeedCatalogProductionInput,
): RetainedLocalSeedCatalog => {
    const inventoryMarker = input.sourceInventory.reduce(
        (marker, leaf) =>
            marker ^
            (leaf.sourceContribution[0] ?? 0) ^
            (leaf.commitmentSalt[0] ?? 0),
        0x61,
    );
    return Object.freeze({
        catalogIdentity: hashFilledWith(inventoryMarker || 1),
        entries: Object.freeze(
            input.geometry.leafOpeningByteLengths.map(
                (openingByteLength, leafOrdinal) =>
                    Object.freeze({
                        inclusionProofBytes: new Uint8Array(
                            input.geometry.inclusionProofByteLength,
                        ).fill((inventoryMarker + leafOrdinal * 5) & 0xff),
                        openingBytes: new Uint8Array(openingByteLength).fill(
                            (inventoryMarker + leafOrdinal * 7 + 1) & 0xff,
                        ),
                    }),
            ),
        ),
        rootBodyBytes: new Uint8Array(input.geometry.rootBodyByteLength).fill(
            inventoryMarker,
        ),
    });
};

const catalogsEqual = (
    left: RetainedLocalSeedCatalog,
    right: RetainedLocalSeedCatalog,
): boolean =>
    bytesEqual(left.catalogIdentity, right.catalogIdentity) &&
    bytesEqual(left.rootBodyBytes, right.rootBodyBytes) &&
    left.entries.length === right.entries.length &&
    left.entries.every(
        (entry, entryIndex) =>
            bytesEqual(
                entry.openingBytes,
                right.entries[entryIndex]?.openingBytes ?? new Uint8Array(),
            ) &&
            bytesEqual(
                entry.inclusionProofBytes,
                right.entries[entryIndex]?.inclusionProofBytes ??
                    new Uint8Array(),
            ),
    );

const deliveryBytes = (
    input: SeedCatalogDeliverySourceProductionInput,
): Uint8Array => {
    const canonicalRecipients = [1, 2, 3];
    const deliveryIndex = canonicalRecipients.indexOf(input.recipientPosition);
    const byteLength =
        input.geometry.deliverySourcePayloadByteLengths[deliveryIndex];
    if (deliveryIndex < 0 || byteLength === undefined) {
        throw new Error('The test source kernel received a wrong recipient.');
    }
    const marker =
        (input.catalog.rootBodyBytes[0] ?? 0) ^ input.recipientPosition ^ 0x73;
    return new Uint8Array(byteLength).fill(marker);
};

class DeterministicSourceKernel implements SeedCatalogSourceCustodyKernel {
    public readonly preparationContextByteLength = 338;
    public produceCatalog(
        input: SeedCatalogProductionInput,
    ): RetainedLocalSeedCatalog {
        return catalogForInput(input);
    }

    public produceDeliverySource(
        input: SeedCatalogDeliverySourceProductionInput,
    ): Readonly<{
        recipientPosition: number;
        sourcePayloadBytes: Uint8Array;
    }> {
        return Object.freeze({
            recipientPosition: input.recipientPosition,
            sourcePayloadBytes: deliveryBytes(input),
        });
    }

    public validateCatalog(input: SeedCatalogValidationInput): void {
        const expected = catalogForInput(input);
        if (!catalogsEqual(expected, input.catalog)) {
            throw new Error('The test catalog failed independent validation.');
        }
    }

    public validateDeliverySource(
        input: SeedCatalogDeliverySourceValidationInput,
    ): void {
        if (!bytesEqual(deliveryBytes(input), input.sourcePayloadBytes)) {
            throw new Error('The test delivery failed independent validation.');
        }
    }
}

class AuthenticatedInventoryCapability {}

const preparedReceiptInventory = (): PreparedSeedRecipientReceiptInventory =>
    Object.freeze({
        authenticatedInventoryBodyBytes: new Uint8Array(31).fill(0x81),
        authenticatedInventoryIdentity: hashFilledWith(0x12),
        localSeedCustodySegments: Object.freeze([
            new Uint8Array(17).fill(0x82),
            new Uint8Array(19).fill(0x83),
            new Uint8Array(23).fill(0x84),
        ]),
        receiptIntentBytes: new Uint8Array(29).fill(0x85),
        receiptIntentIdentity: hashFilledWith(0x86),
    });

const receiptEnvelope = (
    input: SeedRecipientReceiptProductionInput,
): Uint8Array => {
    const bytes = new Uint8Array(37).fill(0x91);
    bytes[0] = input.preparedInventory.authenticatedInventoryIdentity[0] ?? 0;
    bytes[1] = input.preparedInventory.receiptIntentIdentity[0] ?? 0;
    bytes[2] = input.signatureRandomness[0] ?? 0;
    return bytes;
};

class DeterministicReceiptKernel implements SeedRecipientReceiptCustodyKernel<AuthenticatedInventoryCapability> {
    public prepare(
        _authenticatedInventory: AuthenticatedInventoryCapability,
    ): PreparedSeedRecipientReceiptInventory {
        return preparedReceiptInventory();
    }

    public produce(input: SeedRecipientReceiptProductionInput): Uint8Array {
        return receiptEnvelope(input);
    }

    public validate(input: SeedRecipientReceiptValidationInput): void {
        const expected = preparedReceiptInventory();
        if (
            !bytesEqual(
                input.preparedInventory.authenticatedInventoryBodyBytes,
                expected.authenticatedInventoryBodyBytes,
            ) ||
            !bytesEqual(
                input.preparedInventory.authenticatedInventoryIdentity,
                expected.authenticatedInventoryIdentity,
            ) ||
            input.preparedInventory.localSeedCustodySegments.length !== 3
        ) {
            throw new Error(
                'The test receipt inventory failed independent validation.',
            );
        }
        if (
            input.receiptEnvelopeBytes !== undefined &&
            (input.receiptEnvelopeBytes.byteLength !== 37 ||
                input.receiptEnvelopeBytes[0] !==
                    expected.authenticatedInventoryIdentity[0] ||
                input.receiptEnvelopeBytes[1] !==
                    expected.receiptIntentIdentity[0])
        ) {
            throw new Error(
                'The test receipt envelope failed independent validation.',
            );
        }
    }
}

const expectedJoinedPayload = (
    joinedContext: JoinedSeedMasterCustodyContext,
): Uint8Array =>
    concatenate([
        Uint8Array.of(0xb1, 0x01),
        joinedContext.parameterIdentity,
        joinedContext.preparationContextIdentity,
        joinedContext.rootTerminalIdentity,
        joinedContext.rootTerminalCertificateIdentity,
        joinedContext.receiptTerminalIdentity,
        joinedContext.receiptTerminalCertificateIdentity,
        joinedContext.authenticatedRecipientInventoryIdentity,
        joinedContext.receiptBodyIdentity,
        joinedContext.receiptEnvelopeIdentity,
        Uint8Array.of(
            joinedContext.participantCount,
            joinedContext.participantPosition,
        ),
    ]);

class DeterministicJoinedKernel {
    readonly #context: JoinedSeedMasterCustodyContext;
    public failNextValidationCount = 0;
    public joinCallCount = 0;
    public validationCallCount = 0;

    public constructor(joinedContext: JoinedSeedMasterCustodyContext) {
        this.#context = joinedContext;
    }

    public joinAndEncode(requestBytes: Uint8Array): Uint8Array {
        this.joinCallCount += 1;
        if (
            !bytesEqual(
                requestBytes.subarray(0, 4),
                Uint8Array.of(0x53, 0x4c, 0x4a, 0x51),
            ) ||
            !containsBytes(
                requestBytes,
                Uint8Array.of(0x53, 0x4c, 0x43, 0x53),
            ) ||
            !containsBytes(
                requestBytes,
                Uint8Array.of(0x53, 0x4c, 0x52, 0x43),
            ) ||
            !containsBytes(
                requestBytes,
                this.#context.catalogCompilerIdentity,
            ) ||
            !containsBytes(
                requestBytes,
                this.#context.authenticatedRecipientInventoryIdentity,
            )
        ) {
            throw new Error('The test join received a wrong predecessor.');
        }
        this.requirePublicInputs(requestBytes);
        return expectedJoinedPayload(this.#context);
    }

    public validateRetained(recordBytes: Uint8Array): void {
        this.validationCallCount += 1;
        if (this.failNextValidationCount > 0) {
            this.failNextValidationCount -= 1;
            throw new Error('Injected retained-state validation failure.');
        }
        if (
            !bytesEqual(
                recordBytes.subarray(0, 4),
                Uint8Array.of(0x53, 0x4c, 0x4a, 0x4d),
            ) ||
            !containsBytes(recordBytes, expectedJoinedPayload(this.#context))
        ) {
            throw new Error('The test joined payload is noncanonical.');
        }
        this.requirePublicInputs(recordBytes);
    }

    private requirePublicInputs(recordBytes: Uint8Array): void {
        if (
            !containsBytes(recordBytes, rootTerminalBytes(this.#context)) ||
            !containsBytes(recordBytes, receiptTerminalBytes(this.#context)) ||
            !containsBytes(recordBytes, verificationContextBytes(this.#context))
        ) {
            throw new Error('The test join received a mixed terminal view.');
        }
    }
}

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
    context: JoinedSeedMasterCustodyContext;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: JoinedSeedMasterCustody;
    kernel: DeterministicJoinedKernel;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const createFixture = async (input?: {
    retainPredecessors?: boolean;
}): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `joined-seed-master-custody-${fixtureOrdinal}`;
    const createIdentifier = createIdentifierFactory();
    const opened = await openRuntimeTestStore({ createIdentifier, namespace });
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
        maximumRecordSealingCount: 128,
        rootKey,
    });
    const joinedContext = context();
    if (input?.retainPredecessors !== false) {
        const sourceCustody = new SeedCatalogSourceCustody({
            context: sourceContext(joinedContext),
            geometry: sourceGeometry,
            kernel: new DeterministicSourceKernel() as unknown as ProductionSeedCatalogSourceCustodyKernel,
            limits: sourceLimits,
            protection,
            recencyCoordinator: coordinator,
        });
        const catalog =
            await sourceCustody.retainCatalogBeforeRootPublication();
        catalog.catalogIdentity.fill(0);
        catalog.rootBodyBytes.fill(0);
        catalog.entries.forEach((entry) => {
            entry.inclusionProofBytes.fill(0);
            entry.openingBytes.fill(0);
        });

        const receiptCustody =
            new SeedRecipientReceiptCustody<AuthenticatedInventoryCapability>({
                context: receiptContext(joinedContext),
                kernel: new DeterministicReceiptKernel() as unknown as ProductionSeedRecipientReceiptKernel,
                limits: receiptLimits,
                protection,
                recencyCoordinator: coordinator,
            });
        const publication = await receiptCustody.retainForPublication({
            authenticatedInventory: new AuthenticatedInventoryCapability(),
        });
        publication.receiptEnvelopeBytes.fill(0);
    }
    const kernel = new DeterministicJoinedKernel(joinedContext);
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        context: joinedContext,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody: new JoinedSeedMasterCustody({
            context: joinedContext,
            kernel: kernel as unknown as ProductionJoinedSeedMasterCustodyKernel,
            limits: joinedLimits,
            protection,
            receiptCustodyLimits: receiptLimits,
            recencyCoordinator: coordinator,
            sourceCustodyLimits: sourceLimits,
        }),
        kernel,
        namespace,
        protection,
        rootKey,
    });
};

const reopen = async (
    fixture: CustodyFixture,
): Promise<JoinedSeedMasterCustody> => {
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
        maximumRecordSealingCount: 128,
        rootKey: fixture.rootKey,
    });
    return new JoinedSeedMasterCustody({
        context: fixture.context,
        kernel: fixture.kernel as unknown as ProductionJoinedSeedMasterCustodyKernel,
        limits: joinedLimits,
        protection,
        receiptCustodyLimits: receiptLimits,
        recencyCoordinator: coordinator,
        sourceCustodyLimits: sourceLimits,
    });
};

const transitionInput = (
    joinedContext: JoinedSeedMasterCustodyContext,
): Readonly<{
    receiptTerminalCertificateBytes: Uint8Array;
    rootTerminalCertificateBytes: Uint8Array;
    verificationContextBytes: Uint8Array;
}> =>
    Object.freeze({
        receiptTerminalCertificateBytes: receiptTerminalBytes(joinedContext),
        rootTerminalCertificateBytes: rootTerminalBytes(joinedContext),
        verificationContextBytes: verificationContextBytes(joinedContext),
    });

const assertRawPredecessorsAbsent = async (
    fixture: CustodyFixture,
): Promise<void> => {
    await fixture.coordinator.runRead(async (store) => {
        expect(
            await readCompletedSeedCatalogSourceCustodyForMasterJoin({
                context: sourceContext(fixture.context),
                limits: sourceLimits,
                protection: fixture.protection,
                store,
            }),
        ).toBeUndefined();
        expect(
            await readCompletedSeedRecipientReceiptCustodyForMasterJoin({
                context: receiptContext(fixture.context),
                limits: receiptLimits,
                protection: fixture.protection,
                store,
            }),
        ).toBeUndefined();
    });
};

describe('joined seed-master custody', () => {
    it('independently derives the exact joined record and atomic predecessor overlap', () => {
        const derived = deriveJoinedSeedMasterCustodyRecordByteLengths({
            joinedMasterPayloadByteLength: 4_894,
            receiptPredecessorCiphertextByteLength: 569_465,
            receiptTerminalCertificateByteLength: 36_340,
            rootTerminalCertificateByteLength: 36_230,
            sourcePredecessorCiphertextByteLength: 677_795,
            verificationContextByteLength: 623_110,
        });
        const independentFixedRecordByteLength =
            4 + 2 + 13 * 64 + 3 * 2 + 4 * 4;
        const independentJoinedPlaintextByteLength =
            independentFixedRecordByteLength +
            4_894 +
            36_340 +
            36_230 +
            623_110;
        const independentJoinedCiphertextByteLength =
            independentJoinedPlaintextByteLength + 54;
        const independentPredecessorCiphertextByteLength = 677_795 + 569_465;
        const independentJoinRequestByteLength =
            4 +
            2 +
            13 * 64 +
            3 * 2 +
            5 * 4 +
            (677_795 - 54) +
            (569_465 - 54) +
            623_110 +
            36_230 +
            36_340;
        const independentJoinResponseByteLength = 4 + 2 + 1 + 4 + 4_894;

        expect(derived).toEqual({
            atomicTransitionCiphertextOverlapByteLength:
                independentPredecessorCiphertextByteLength +
                independentJoinedCiphertextByteLength,
            joinRequestByteLength: independentJoinRequestByteLength,
            joinResponseByteLength: independentJoinResponseByteLength,
            joinedCiphertextByteLength: independentJoinedCiphertextByteLength,
            joinedPlaintextByteLength: independentJoinedPlaintextByteLength,
            joinedValidationRequestByteLength:
                independentJoinedPlaintextByteLength,
            joinedValidationResponseByteLength: 7,
            logicallyReclaimedPredecessorCiphertextByteLength:
                independentPredecessorCiphertextByteLength,
            maximumKernelInputByteLength: independentJoinRequestByteLength,
            maximumColdRestartReadByteLength:
                independentJoinedCiphertextByteLength,
        });
        expect(derived.joinedPlaintextByteLength).toBe(701_434);
        expect(derived.joinedCiphertextByteLength).toBe(701_488);
        expect(derived.joinRequestByteLength).toBe(1_943_696);
        expect(derived.joinResponseByteLength).toBe(4_905);
        expect(derived.atomicTransitionCiphertextOverlapByteLength).toBe(
            1_948_748,
        );
    });

    it('refuses an empty predecessor plaintext and an oversized exact kernel request', () => {
        const commonInput = {
            joinedMasterPayloadByteLength: 4_894,
            receiptPredecessorCiphertextByteLength: 569_465,
            receiptTerminalCertificateByteLength: 36_340,
            rootTerminalCertificateByteLength: 36_230,
            sourcePredecessorCiphertextByteLength: 677_795,
            verificationContextByteLength: 623_110,
        };
        expect(() =>
            deriveJoinedSeedMasterCustodyRecordByteLengths({
                ...commonInput,
                sourcePredecessorCiphertextByteLength: 54,
            }),
        ).toThrow('cannot contain an empty authenticated plaintext');
        expect(() =>
            deriveJoinedSeedMasterCustodyRecordByteLengths({
                ...commonInput,
                verificationContextByteLength: 8 * 1024 * 1024,
            }),
        ).toThrow('absolute copied-buffer bound');
    });

    it('atomically replaces actual completed predecessor records and resumes without exposing masters', async () => {
        const fixture = await createFixture();
        const mutationCountBeforeJoin = fixture.adapter.atomicMutationCount;
        const retained = await fixture.custody.retainJoinedMasters(
            transitionInput(fixture.context),
        );

        expect(fixture.adapter.atomicMutationCount).toBe(
            mutationCountBeforeJoin + 1,
        );
        expect(retained.joinedCiphertextByteLength).toBeGreaterThan(0);
        expect(retained.participantPosition).toBe(0);
        expect(retained.receiptTerminalIdentity).toEqual(hashFilledWith(0x19));
        expect(retained.rootTerminalIdentity).toEqual(hashFilledWith(0x1b));
        expect('joinedMasterPayloadBytes' in retained).toBe(false);
        expect(fixture.kernel.joinCallCount).toBe(1);
        expect(fixture.kernel.validationCallCount).toBe(2);
        await assertRawPredecessorsAbsent(fixture);

        const resumed = await fixture.custody.resumeRetained();
        expect(resumed).toEqual(retained);
        expect(fixture.kernel.joinCallCount).toBe(1);
        expect(fixture.kernel.validationCallCount).toBe(3);
    });

    it('keeps missing predecessor data pending without invoking the join', async () => {
        const fixture = await createFixture({ retainPredecessors: false });
        await expect(
            fixture.custody.retainJoinedMasters(
                transitionInput(fixture.context),
            ),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
        expect(fixture.kernel.joinCallCount).toBe(0);
        expect(await fixture.custody.resumeRetained()).toBeUndefined();
    });

    it('preserves both predecessors when retained-state validation fails', async () => {
        const fixture = await createFixture();
        fixture.kernel.failNextValidationCount = 1;
        await expect(
            fixture.custody.retainJoinedMasters(
                transitionInput(fixture.context),
            ),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(fixture.kernel.joinCallCount).toBe(1);
        expect(await fixture.custody.resumeRetained()).toBeUndefined();

        await fixture.coordinator.runRead(async (store) => {
            const source =
                await readCompletedSeedCatalogSourceCustodyForMasterJoin({
                    context: sourceContext(fixture.context),
                    limits: sourceLimits,
                    protection: fixture.protection,
                    store,
                });
            const receipt =
                await readCompletedSeedRecipientReceiptCustodyForMasterJoin({
                    context: receiptContext(fixture.context),
                    limits: receiptLimits,
                    protection: fixture.protection,
                    store,
                });
            expect(source).toBeTypeOf('object');
            expect(receipt).toBeTypeOf('object');
            if (typeof source === 'object') {
                source.recordBytes.fill(0);
                source.sealedBytes.fill(0);
            }
            if (typeof receipt === 'object') {
                receipt.recordBytes.fill(0);
                receipt.sealedBytes.fill(0);
            }
        });
    });

    it('refuses an alternate terminal carrier after the atomic selection', async () => {
        const fixture = await createFixture();
        const selectedInput = transitionInput(fixture.context);
        await fixture.custody.retainJoinedMasters(selectedInput);
        const alternateRootTerminal =
            selectedInput.rootTerminalCertificateBytes.slice();
        alternateRootTerminal[alternateRootTerminal.byteLength - 1] ^= 0x01;

        await expect(
            fixture.custody.retainJoinedMasters({
                ...selectedInput,
                rootTerminalCertificateBytes: alternateRootTerminal,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(fixture.kernel.joinCallCount).toBe(1);
        await assertRawPredecessorsAbsent(fixture);
    });

    it('cold-resumes an atomically committed transition after external-anchor interruption', async () => {
        const fixture = await createFixture();
        fixture.anchor.failNextCompareAndSetCount = 1;
        await expect(
            fixture.custody.retainJoinedMasters(
                transitionInput(fixture.context),
            ),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(fixture.kernel.joinCallCount).toBe(1);

        const reopened = await reopen(fixture);
        const resumed = await reopened.retainJoinedMasters(
            transitionInput(fixture.context),
        );
        expect(resumed.participantPosition).toBe(0);
        expect(fixture.kernel.joinCallCount).toBe(1);
        expect(fixture.anchor.compareAndSetCallCount).toBeGreaterThan(1);
    });
});
