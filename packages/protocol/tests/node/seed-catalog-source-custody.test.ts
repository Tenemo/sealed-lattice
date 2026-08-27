import type { ProductionSeedCatalogSourceCustodyKernel } from '@sealed-lattice/wasm';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedCatalogSourceCustodyKernel: () => true,
}));

import {
    bytesEqual,
    createRuntimeRecordProtection,
    readRuntimeRecord,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    SeedCatalogSourceCustody,
    deriveSeedCatalogSourceCustodyKernelByteLengths,
    deriveSeedCatalogSourceCustodyRecordByteLengths,
    type RetainedLocalSeedCatalog,
    type RetainedSeedCatalogDeliverySource,
    type SeedCatalogDeliverySourceProductionInput,
    type SeedCatalogDeliverySourceValidationInput,
    type SeedCatalogProductionInput,
    type SeedCatalogSourceCustodyContext,
    type SeedCatalogSourceCustodyGeometry,
    type SeedCatalogSourceCustodyKernel,
    type SeedCatalogSourceCustodyLimits,
    type SeedCatalogSourceInventory,
    type SeedCatalogValidationInput,
} from '#packages/protocol/src/runtime/seed-catalog-source-custody';
import {
    InMemoryAuthenticatedStorageRecencyAnchor,
    generateRuntimeStorageRootKey,
    hashFilledWith,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const smallGeometry: SeedCatalogSourceCustodyGeometry = Object.freeze({
    commitmentSaltByteLength: 6,
    deliverySourcePayloadByteLengths: Object.freeze([
        13, 14, 15, 16, 17, 18, 19, 20, 21,
    ]),
    inclusionProofByteLength: 7,
    leafOpeningByteLengths: Object.freeze([8, 9, 10, 11, 12]),
    rootBodyByteLength: 11,
    sourceContributionByteLength: 4,
});

const sourceCustodyOperationDomain =
    'sealed-lattice/runtime/seed-catalog-source-custody-record/v1';
const sourceCustodyRecordKey = 'seed-catalog/source-custody/00000/00003';
const sourceCustodyLeafCountOffset = 4 + 2 + 1 + 6 * 64 + 3 * 2;

const testLimits: SeedCatalogSourceCustodyLimits = Object.freeze({
    maximumCatalogLeafCount: 128,
    maximumCommitmentSaltByteLength: 128,
    maximumDeliverySourcePayloadByteLength: 128 * 1_024,
    maximumInclusionProofByteLength: 4_096,
    maximumLeafOpeningByteLength: 4_096,
    maximumRootBodyByteLength: 4_096,
    maximumSourceContributionByteLength: 128,
    transactionLifetimeMilliseconds: 1_000,
});

const defaultContext = (): SeedCatalogSourceCustodyContext =>
    Object.freeze({
        actionContextIdentity: hashFilledWith(0x13),
        catalogCompilerIdentity: hashFilledWith(0x14),
        parameterIdentity: hashFilledWith(0x11),
        participantCount: 10,
        participantPosition: 3,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: hashFilledWith(0x15),
        rosterIdentity: hashFilledWith(0x12),
        statePredecessorIdentity: hashFilledWith(0x16),
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
                    ((invocationCount * 41 + byteIndex * 17) % 255) + 1;
            }
            return value;
        },
        subtle: globalThis.crypto.subtle,
    } as Crypto;
};

const uniformEdgeCaseCryptoProvider = (): Crypto => {
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
            if (bytes.byteLength === 4) {
                bytes.fill(0);
            } else if (bytes.byteLength === 6) {
                bytes.fill(0x6a);
            } else {
                bytes.fill((invocationCount % 254) + 1);
            }
            return value;
        },
        subtle: globalThis.crypto.subtle,
    } as Crypto;
};

const copyInventory = (
    inventory: SeedCatalogSourceInventory,
): SeedCatalogSourceInventory =>
    Object.freeze(
        inventory.map((leaf) =>
            Object.freeze({
                commitmentSalt: leaf.commitmentSalt.slice(),
                sourceContribution: leaf.sourceContribution.slice(),
            }),
        ),
    );

const expectedCatalog = (
    input: SeedCatalogProductionInput,
): RetainedLocalSeedCatalog => {
    const inventoryMarker = input.sourceInventory.reduce(
        (marker, leaf, leafOrdinal) =>
            marker ^
            (leaf.sourceContribution[0] ?? 0) ^
            (leaf.commitmentSalt[0] ?? 0) ^
            leafOrdinal,
        0x5d,
    );
    return Object.freeze({
        catalogIdentity: new Uint8Array(64).fill(inventoryMarker || 1),
        entries: Object.freeze(
            input.sourceInventory.map((leaf, leafOrdinal) => {
                const entryMarker =
                    (leaf.sourceContribution[0] ?? 0) ^
                    (leaf.commitmentSalt[0] ?? 0) ^
                    leafOrdinal ^
                    0x91;
                return Object.freeze({
                    inclusionProofBytes: new Uint8Array(
                        input.geometry.inclusionProofByteLength,
                    ).fill((entryMarker + 1) & 0xff),
                    openingBytes: new Uint8Array(
                        input.geometry.leafOpeningByteLengths[leafOrdinal],
                    ).fill(entryMarker),
                });
            }),
        ),
        rootBodyBytes: new Uint8Array(input.geometry.rootBodyByteLength).fill(
            (inventoryMarker + 2) & 0xff,
        ),
    });
};

const catalogEquals = (
    left: RetainedLocalSeedCatalog,
    right: RetainedLocalSeedCatalog,
): boolean =>
    bytesEqual(left.catalogIdentity, right.catalogIdentity) &&
    bytesEqual(left.rootBodyBytes, right.rootBodyBytes) &&
    left.entries.length === right.entries.length &&
    left.entries.every(
        (entry, leafOrdinal) =>
            bytesEqual(
                entry.openingBytes,
                right.entries[leafOrdinal]?.openingBytes ?? new Uint8Array(),
            ) &&
            bytesEqual(
                entry.inclusionProofBytes,
                right.entries[leafOrdinal]?.inclusionProofBytes ??
                    new Uint8Array(),
            ),
    );

const expectedDeliverySource = (
    input: SeedCatalogDeliverySourceProductionInput,
): RetainedSeedCatalogDeliverySource => {
    const canonicalRecipients = Array.from(
        { length: input.context.participantCount },
        (_unused, participantPosition) => participantPosition,
    ).filter(
        (participantPosition) =>
            participantPosition !== input.context.participantPosition,
    );
    const deliveryIndex = canonicalRecipients.indexOf(input.recipientPosition);
    const byteLength =
        input.geometry.deliverySourcePayloadByteLengths[deliveryIndex];
    if (deliveryIndex < 0 || byteLength === undefined) {
        throw new Error('Noncanonical test delivery position.');
    }
    const marker =
        (input.catalog.catalogIdentity[0] ?? 0) ^
        input.recipientPosition ^
        (input.sourceInventory[deliveryIndex]?.sourceContribution[0] ?? 0) ^
        0xc3;
    return Object.freeze({
        recipientPosition: input.recipientPosition,
        sourcePayloadBytes: new Uint8Array(byteLength).fill(marker),
    });
};

class DeterministicSeedCatalogKernel implements SeedCatalogSourceCustodyKernel {
    public readonly preparationContextByteLength = 338;
    public afterCatalogProduction: (() => void) | undefined;
    public afterDeliveryProduction:
        | ((recipientPosition: number) => void)
        | undefined;
    public readonly catalogProductionInventories: SeedCatalogSourceInventory[] =
        [];
    public deliveryProductionFailureRecipient: number | undefined;
    public readonly deliveryProductionObservations: Readonly<{
        recipientPosition: number;
        sourceInventory: SeedCatalogSourceInventory;
    }>[] = [];
    public failNextCatalogProductionCount = 0;
    public failNextCatalogValidationCount = 0;
    public failNextDeliveryValidationCount = 0;
    public malformedNextCatalog = false;
    public malformedNextDelivery = false;
    public catalogValidationCallCount = 0;
    public deliveryValidationCallCount = 0;

    public produceCatalog(
        input: SeedCatalogProductionInput,
    ): RetainedLocalSeedCatalog {
        this.catalogProductionInventories.push(
            copyInventory(input.sourceInventory),
        );
        if (this.failNextCatalogProductionCount > 0) {
            this.failNextCatalogProductionCount -= 1;
            throw new Error('Injected catalog production failure.');
        }
        const catalog = expectedCatalog(input);
        this.afterCatalogProduction?.();
        if (this.malformedNextCatalog) {
            this.malformedNextCatalog = false;
            return Object.freeze({
                ...catalog,
                rootBodyBytes: catalog.rootBodyBytes.subarray(1),
            });
        }
        return catalog;
    }

    public validateCatalog(input: SeedCatalogValidationInput): void {
        this.catalogValidationCallCount += 1;
        if (this.failNextCatalogValidationCount > 0) {
            this.failNextCatalogValidationCount -= 1;
            throw new Error('Injected catalog validation failure.');
        }
        if (
            input.context.preparationAttemptOrdinal !== 0 ||
            input.context.participantPosition !== 3 ||
            !catalogEquals(input.catalog, expectedCatalog(input))
        ) {
            throw new Error('Catalog failed the deterministic validator.');
        }
    }

    public produceDeliverySource(
        input: SeedCatalogDeliverySourceProductionInput,
    ): RetainedSeedCatalogDeliverySource {
        this.deliveryProductionObservations.push(
            Object.freeze({
                recipientPosition: input.recipientPosition,
                sourceInventory: copyInventory(input.sourceInventory),
            }),
        );
        if (
            this.deliveryProductionFailureRecipient === input.recipientPosition
        ) {
            this.deliveryProductionFailureRecipient = undefined;
            throw new Error('Injected delivery-source production failure.');
        }
        const deliverySource = expectedDeliverySource(input);
        this.afterDeliveryProduction?.(input.recipientPosition);
        if (this.malformedNextDelivery) {
            this.malformedNextDelivery = false;
            return Object.freeze({
                ...deliverySource,
                sourcePayloadBytes:
                    deliverySource.sourcePayloadBytes.subarray(1),
            });
        }
        return deliverySource;
    }

    public validateDeliverySource(
        input: SeedCatalogDeliverySourceValidationInput,
    ): void {
        this.deliveryValidationCallCount += 1;
        if (this.failNextDeliveryValidationCount > 0) {
            this.failNextDeliveryValidationCount -= 1;
            throw new Error('Injected delivery-source validation failure.');
        }
        const expected = expectedDeliverySource(input);
        if (
            !bytesEqual(input.sourcePayloadBytes, expected.sourcePayloadBytes)
        ) {
            throw new Error(
                'Delivery source failed the deterministic validator.',
            );
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
    context: SeedCatalogSourceCustodyContext;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: SeedCatalogSourceCustody;
    geometry: SeedCatalogSourceCustodyGeometry;
    kernel: DeterministicSeedCatalogKernel;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const createFixture = async (input?: {
    cryptoProvider?: Crypto;
    kernel?: DeterministicSeedCatalogKernel;
}): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `seed-catalog-source-custody-${fixtureOrdinal}`;
    const createIdentifier = createIdentifierFactory();
    const opened = await openRuntimeTestStore({ createIdentifier, namespace });
    const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
    const coordinator = new AuthenticatedStorageRecencyCoordinator({
        anchor,
        store: opened.store,
    });
    const rootKey = await generateRuntimeStorageRootKey();
    const cryptoProvider =
        input?.cryptoProvider ?? deterministicCryptoProvider();
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider,
        maximumRecordSealingCount: 128,
        rootKey,
    });
    const context = defaultContext();
    const kernel = input?.kernel ?? new DeterministicSeedCatalogKernel();
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        context,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody: new SeedCatalogSourceCustody({
            context,
            geometry: smallGeometry,
            kernel: kernel as unknown as ProductionSeedCatalogSourceCustodyKernel,
            limits: testLimits,
            protection,
            recencyCoordinator: coordinator,
        }),
        geometry: smallGeometry,
        kernel,
        namespace,
        protection,
        rootKey,
    });
};

const reopenCustody = async (
    fixture: CustodyFixture,
    kernel: DeterministicSeedCatalogKernel,
    context = fixture.context,
    geometry = fixture.geometry,
): Promise<SeedCatalogSourceCustody> => {
    const reopened = await openRuntimeTestStore({
        adapter: fixture.adapter,
        createIdentifier: fixture.createIdentifier,
        namespace: fixture.namespace,
    });
    const coordinator = new AuthenticatedStorageRecencyCoordinator({
        anchor: fixture.anchor,
        store: reopened.store,
    });
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider: fixture.cryptoProvider,
        maximumRecordSealingCount: 128,
        rootKey: fixture.rootKey,
    });
    return new SeedCatalogSourceCustody({
        context,
        geometry,
        kernel: kernel as unknown as ProductionSeedCatalogSourceCustodyKernel,
        limits: testLimits,
        protection,
        recencyCoordinator: coordinator,
    });
};

describe('seed-catalog source custody', () => {
    it('independently accounts for the completion catalog checkpoints', () => {
        const completionGeometry: SeedCatalogSourceCustodyGeometry = {
            commitmentSaltByteLength: 64,
            deliverySourcePayloadByteLengths: Array.from(
                { length: 9 },
                () => 62_590,
            ),
            inclusionProofByteLength: 658,
            leafOpeningByteLengths: [
                ...Array.from({ length: 84 }, () => 440),
                ...Array.from({ length: 9 }, () => 444),
                428,
            ],
            rootBodyByteLength: 522,
            sourceContributionByteLength: 40,
        };
        const derived = deriveSeedCatalogSourceCustodyRecordByteLengths({
            geometry: completionGeometry,
        });
        const kernelDerived = deriveSeedCatalogSourceCustodyKernelByteLengths({
            geometry: completionGeometry,
            preparationContextByteLength: 338,
        });

        const independentlyDerivedHeaderByteLength =
            4 + 2 + 1 + 6 * 64 + 3 * 2 + 5 * 4 + 2 + (94 + 9) * 4;
        const independentlyDerivedRawInventoryByteLength = 94 * (40 + 64);
        const independentlyDerivedEntryInventoryByteLength =
            84 * (440 + 658) + 9 * (444 + 658) + (428 + 658);
        const independentlyDerivedReservationPlaintextByteLength =
            independentlyDerivedHeaderByteLength +
            independentlyDerivedRawInventoryByteLength;
        const independentlyDerivedRootProductionOutputByteLength =
            64 + 522 + independentlyDerivedEntryInventoryByteLength;
        const independentlyDerivedRootCheckpointPlaintextByteLength =
            independentlyDerivedReservationPlaintextByteLength +
            independentlyDerivedRootProductionOutputByteLength +
            2;
        const independentlyDerivedDeliveryPlaintextByteLengths = Array.from(
            { length: 9 },
            (_unused, deliveryIndex) =>
                independentlyDerivedRootCheckpointPlaintextByteLength +
                (deliveryIndex + 1) * 62_590,
        );
        const independentlyDerivedCheckpointCiphertextByteLengths = [
            independentlyDerivedReservationPlaintextByteLength + 54,
            independentlyDerivedRootCheckpointPlaintextByteLength + 54,
            ...independentlyDerivedDeliveryPlaintextByteLengths.map(
                (byteLength) => byteLength + 54,
            ),
        ];
        const independentlyDerivedCopyOnWriteOverlap = Math.max(
            ...independentlyDerivedCheckpointCiphertextByteLengths
                .slice(1)
                .map(
                    (byteLength, checkpointIndex) =>
                        byteLength +
                        independentlyDerivedCheckpointCiphertextByteLengths[
                            checkpointIndex
                        ],
                ),
        );

        expect(derived).toEqual({
            completedCiphertextByteLength: 677_795,
            completedPlaintextByteLength: 677_741,
            cumulativeCheckpointCiphertextWriteByteLength: 3_972_061,
            deliveryCheckpointCiphertextByteLengths: [
                177_075, 239_665, 302_255, 364_845, 427_435, 490_025, 552_615,
                615_205, 677_795,
            ],
            deliveryCheckpointPlaintextByteLengths: [
                177_021, 239_611, 302_201, 364_791, 427_381, 489_971, 552_561,
                615_151, 677_741,
            ],
            maximumColdRestartReadByteLength: 677_795,
            maximumCopyOnWriteCiphertextOverlapByteLength: 1_293_000,
            maximumUncommittedDeliverySourceByteLength: 62_590,
            maximumUncommittedProductionByteLength: 103_822,
            reservationCiphertextByteLength: 10_661,
            reservationPlaintextByteLength: 10_607,
            rootCheckpointCiphertextByteLength: 114_485,
            rootCheckpointPlaintextByteLength: 114_431,
            rootProductionOutputByteLength: 103_822,
        });
        expect(derived.reservationPlaintextByteLength).toBe(
            independentlyDerivedReservationPlaintextByteLength,
        );
        expect(derived.rootProductionOutputByteLength).toBe(
            independentlyDerivedRootProductionOutputByteLength,
        );
        expect(derived.rootCheckpointPlaintextByteLength).toBe(
            independentlyDerivedRootCheckpointPlaintextByteLength,
        );
        expect(derived.deliveryCheckpointPlaintextByteLengths).toEqual(
            independentlyDerivedDeliveryPlaintextByteLengths,
        );
        expect(derived.maximumCopyOnWriteCiphertextOverlapByteLength).toBe(
            independentlyDerivedCopyOnWriteOverlap,
        );
        expect(derived.cumulativeCheckpointCiphertextWriteByteLength).toBe(
            independentlyDerivedCheckpointCiphertextByteLengths.reduce(
                (total, byteLength) => total + byteLength,
                0,
            ),
        );
        const independentlyDerivedCatalogProductionRequestByteLength =
            independentlyDerivedReservationPlaintextByteLength + 4 + 338;
        const independentlyDerivedCatalogValidationRequestByteLength =
            independentlyDerivedCatalogProductionRequestByteLength +
            independentlyDerivedRootProductionOutputByteLength;
        const independentlyDerivedDeliveryProductionRequestByteLength =
            independentlyDerivedCatalogValidationRequestByteLength + 2;
        const independentlyDerivedDeliveryValidationRequestByteLength =
            independentlyDerivedDeliveryProductionRequestByteLength + 62_590;
        const independentlyDerivedDeliveryValidationInvocationCounts =
            Array.from(
                { length: 9 },
                (_unused, deliveryIndex) => 10 - deliveryIndex,
            );
        expect(kernelDerived).toEqual({
            catalogProductionRequestByteLength: 10_949,
            catalogProductionResponseByteLength: 103_829,
            catalogValidationRequestByteLength: 114_771,
            coldValidationCumulativeRequestByteLength: 1_711_038,
            coldValidationInvocationCount: 10,
            deliveryProductionRequestByteLengths: Array.from(
                { length: 9 },
                () => 114_773,
            ),
            deliveryProductionResponseByteLengths: Array.from(
                { length: 9 },
                () => 62_599,
            ),
            deliveryValidationRequestByteLengths: Array.from(
                { length: 9 },
                () => 177_363,
            ),
            maximumKernelInputByteLength: 177_363,
            maximumKernelResponseByteLength: 103_829,
            successPathCumulativeRequestByteLength: 11_883_989,
            successPathCumulativeResponseByteLength: 667_675,
            successPathInvocationCount: 75,
            validationResponseByteLength: 7,
        });
        expect(kernelDerived.catalogProductionRequestByteLength).toBe(
            independentlyDerivedCatalogProductionRequestByteLength,
        );
        expect(kernelDerived.catalogValidationRequestByteLength).toBe(
            independentlyDerivedCatalogValidationRequestByteLength,
        );
        expect(kernelDerived.deliveryProductionRequestByteLengths).toEqual(
            Array.from(
                { length: 9 },
                () => independentlyDerivedDeliveryProductionRequestByteLength,
            ),
        );
        expect(kernelDerived.deliveryValidationRequestByteLengths).toEqual(
            Array.from(
                { length: 9 },
                () => independentlyDerivedDeliveryValidationRequestByteLength,
            ),
        );
        expect(kernelDerived.successPathInvocationCount).toBe(
            1 +
                11 +
                9 +
                independentlyDerivedDeliveryValidationInvocationCounts.reduce(
                    (total, count) => total + count,
                    0,
                ),
        );
        expect(kernelDerived.successPathCumulativeRequestByteLength).toBe(
            independentlyDerivedCatalogProductionRequestByteLength +
                11 * independentlyDerivedCatalogValidationRequestByteLength +
                9 * independentlyDerivedDeliveryProductionRequestByteLength +
                independentlyDerivedDeliveryValidationInvocationCounts.reduce(
                    (total, invocationCount) =>
                        total +
                        invocationCount *
                            independentlyDerivedDeliveryValidationRequestByteLength,
                    0,
                ),
        );

        for (const impossibleSecretGeometry of [
            {
                ...completionGeometry,
                commitmentSaltByteLength: 0x1_0000,
            },
            {
                ...completionGeometry,
                sourceContributionByteLength: 0x1_0000,
            },
        ]) {
            expect(() =>
                deriveSeedCatalogSourceCustodyRecordByteLengths({
                    geometry: impossibleSecretGeometry,
                }),
            ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        }
    });

    it('samples every leaf internally before retaining the exact root and delivery prefix', async () => {
        const fixture = await createFixture();

        const firstCatalog =
            await fixture.custody.retainCatalogBeforeRootPublication();
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(1);
        const sampledInventory = fixture.kernel.catalogProductionInventories[0];
        expect(sampledInventory).toHaveLength(5);
        for (const leaf of sampledInventory ?? []) {
            expect(leaf.sourceContribution).toHaveLength(4);
            expect(leaf.commitmentSalt).toHaveLength(6);
        }
        expect(
            fixture.kernel.deliveryProductionObservations.map(
                (observation) => observation.recipientPosition,
            ),
        ).toEqual([0, 1, 2, 4, 5, 6, 7, 8, 9]);
        expect(fixture.anchor.compareAndSetCallCount).toBe(12);

        const expectedRetainedCatalog = structuredClone(firstCatalog);
        firstCatalog.rootBodyBytes.fill(0);
        firstCatalog.entries[0]?.openingBytes.fill(0);
        const replayedCatalog =
            await fixture.custody.retainCatalogBeforeRootPublication();
        expect(replayedCatalog).toEqual(expectedRetainedCatalog);
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(1);
        expect(fixture.kernel.deliveryProductionObservations).toHaveLength(9);
        expect(fixture.anchor.compareAndSetCallCount).toBe(12);

        const delivery = await fixture.custody.loadRetainedDeliverySource({
            recipientPosition: 7,
        });
        const expectedDelivery = delivery.sourcePayloadBytes.slice();
        delivery.sourcePayloadBytes.fill(0);
        await expect(
            fixture.custody.loadRetainedDeliverySource({
                recipientPosition: 7,
            }),
        ).resolves.toEqual({
            recipientPosition: 7,
            sourcePayloadBytes: expectedDelivery,
        });
        expect(fixture.kernel.deliveryProductionObservations).toHaveLength(9);
    });

    it('cold-resumes a canonical delivery prefix from the same retained sources', async () => {
        const kernel = new DeterministicSeedCatalogKernel();
        kernel.deliveryProductionFailureRecipient = 6;
        const fixture = await createFixture({ kernel });

        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        expect(kernel.catalogProductionInventories).toHaveLength(1);
        expect(
            kernel.deliveryProductionObservations.map(
                (observation) => observation.recipientPosition,
            ),
        ).toEqual([0, 1, 2, 4, 5, 6]);
        const initiallySampledInventory =
            kernel.catalogProductionInventories[0];

        const resumedKernel = new DeterministicSeedCatalogKernel();
        const resumedCustody = await reopenCustody(fixture, resumedKernel);
        const completed =
            await resumedCustody.retainCatalogBeforeRootPublication();
        expect(completed.rootBodyBytes).toHaveLength(
            smallGeometry.rootBodyByteLength,
        );
        expect(resumedKernel.catalogProductionInventories).toHaveLength(0);
        expect(
            resumedKernel.deliveryProductionObservations.map(
                (observation) => observation.recipientPosition,
            ),
        ).toEqual([6, 7, 8, 9]);
        expect(
            resumedKernel.deliveryProductionObservations[0]?.sourceInventory,
        ).toEqual(initiallySampledInventory);

        const replayKernel = new DeterministicSeedCatalogKernel();
        replayKernel.failNextCatalogProductionCount = 1;
        replayKernel.deliveryProductionFailureRecipient = 0;
        const replayCustody = await reopenCustody(fixture, replayKernel);
        await expect(
            replayCustody.retainCatalogBeforeRootPublication(),
        ).resolves.toEqual(completed);
        expect(replayKernel.catalogProductionInventories).toHaveLength(0);
        expect(replayKernel.deliveryProductionObservations).toHaveLength(0);
    });

    it('withholds root bytes until the last delivery checkpoint is anchored', async () => {
        const kernel = new DeterministicSeedCatalogKernel();
        const fixture = await createFixture({ kernel });
        kernel.afterDeliveryProduction = (recipientPosition) => {
            if (recipientPosition === 9) {
                fixture.anchor.failNextCompareAndSetCount = 1;
                kernel.afterDeliveryProduction = undefined;
            }
        };

        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(kernel.catalogProductionInventories).toHaveLength(1);
        expect(kernel.deliveryProductionObservations).toHaveLength(9);

        const recovered =
            await fixture.custody.retainCatalogBeforeRootPublication();
        expect(recovered.rootBodyBytes).toHaveLength(
            smallGeometry.rootBodyByteLength,
        );
        expect(kernel.catalogProductionInventories).toHaveLength(1);
        expect(kernel.deliveryProductionObservations).toHaveLength(9);
    });

    it('does not produce a catalog until an interrupted reservation anchor is repaired', async () => {
        const fixture = await createFixture();
        await fixture.coordinator.reconcile();
        fixture.anchor.failNextCompareAndSetCount = 1;

        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(0);

        const recoveredCatalog =
            await fixture.custody.retainCatalogBeforeRootPublication();
        expect(recoveredCatalog.rootBodyBytes).toBeInstanceOf(Uint8Array);
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(1);
    });

    it('keeps one action slot across context and geometry alternatives', async () => {
        const fixture = await createFixture();
        await fixture.custody.retainCatalogBeforeRootPublication();

        const alternateContext: SeedCatalogSourceCustodyContext = {
            ...fixture.context,
            statePredecessorIdentity: hashFilledWith(0x17),
        };
        const alternateContextCustody = await reopenCustody(
            fixture,
            new DeterministicSeedCatalogKernel(),
            alternateContext,
        );
        await expect(
            alternateContextCustody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'Conflict' });

        const alternateGeometry: SeedCatalogSourceCustodyGeometry = {
            ...fixture.geometry,
            deliverySourcePayloadByteLengths: [
                13, 14, 15, 16, 17, 18, 19, 20, 22,
            ],
        };
        const alternateGeometryCustody = await reopenCustody(
            fixture,
            new DeterministicSeedCatalogKernel(),
            fixture.context,
            alternateGeometry,
        );
        await expect(
            alternateGeometryCustody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('rejects an authenticated stored inventory count before kernel validation', async () => {
        const fixture = await createFixture();
        await fixture.custody.retainCatalogBeforeRootPublication();
        const catalogValidationCallCount =
            fixture.kernel.catalogValidationCallCount;
        const deliveryValidationCallCount =
            fixture.kernel.deliveryValidationCallCount;

        await fixture.coordinator.runMutation(async (store) => {
            const opened = await readRuntimeRecord({
                logicalRecordKey: sourceCustodyRecordKey,
                operationDomain: sourceCustodyOperationDomain,
                protection: fixture.protection,
                store,
            });
            if (opened === undefined) {
                throw new Error(
                    'Expected retained source custody in test storage.',
                );
            }
            const malformedPlaintext = opened.plaintext.slice();
            let malformedSealedBytes: Uint8Array | undefined;
            try {
                new DataView(
                    malformedPlaintext.buffer,
                    malformedPlaintext.byteOffset,
                    malformedPlaintext.byteLength,
                ).setUint32(
                    sourceCustodyLeafCountOffset,
                    testLimits.maximumCatalogLeafCount + 1,
                    true,
                );
                const transaction = await store.beginTransaction({
                    lifetimeMilliseconds:
                        testLimits.transactionLifetimeMilliseconds,
                });
                malformedSealedBytes = await stageRuntimeRecordWrite({
                    expectedCurrentSealedBytes: opened.sealedBytes,
                    logicalRecordKey: sourceCustodyRecordKey,
                    operationDomain: sourceCustodyOperationDomain,
                    plaintext: malformedPlaintext,
                    protection: fixture.protection,
                    transaction,
                });
                await transaction.commit();
            } finally {
                malformedPlaintext.fill(0);
                malformedSealedBytes?.fill(0);
                opened.plaintext.fill(0);
                opened.sealedBytes.fill(0);
            }
        });

        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(fixture.kernel.catalogValidationCallCount).toBe(
            catalogValidationCallCount,
        );
        expect(fixture.kernel.deliveryValidationCallCount).toBe(
            deliveryValidationCallCount,
        );
    });

    it('retains one sampled reservation across malformed output and validation failure', async () => {
        const kernel = new DeterministicSeedCatalogKernel();
        kernel.malformedNextCatalog = true;
        const fixture = await createFixture({ kernel });

        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        const firstInventory = kernel.catalogProductionInventories[0];

        kernel.failNextCatalogValidationCount = 1;
        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(kernel.catalogProductionInventories[1]).toEqual(firstInventory);

        kernel.malformedNextDelivery = true;
        await expect(
            fixture.custody.retainCatalogBeforeRootPublication(),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(kernel.catalogProductionInventories[2]).toEqual(firstInventory);

        const completed =
            await fixture.custody.retainCatalogBeforeRootPublication();
        expect(completed.entries).toHaveLength(5);
        expect(kernel.catalogProductionInventories).toHaveLength(3);
        expect(
            kernel.deliveryProductionObservations[0]?.sourceInventory,
        ).toEqual(firstInventory);
        expect(
            kernel.deliveryProductionObservations[1]?.sourceInventory,
        ).toEqual(firstInventory);
    });

    it('serializes duplicate root requests without sampling or producing twice', async () => {
        const fixture = await createFixture();

        const [first, second] = await Promise.all([
            fixture.custody.retainCatalogBeforeRootPublication(),
            fixture.custody.retainCatalogBeforeRootPublication(),
        ]);
        expect(first).toEqual(second);
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(1);
        expect(fixture.kernel.deliveryProductionObservations).toHaveLength(9);
    });

    it('preserves valid zero and collision outcomes without conditioning the sampled distribution', async () => {
        const fixture = await createFixture({
            cryptoProvider: uniformEdgeCaseCryptoProvider(),
        });

        const retainedCatalog =
            await fixture.custody.retainCatalogBeforeRootPublication();
        expect(retainedCatalog.entries).toHaveLength(5);
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(1);
        const sampledInventory = fixture.kernel.catalogProductionInventories[0];
        expect(
            sampledInventory?.every((leaf) =>
                leaf.sourceContribution.every((byte) => byte === 0),
            ),
        ).toBe(true);
        expect(
            sampledInventory?.every((leaf) =>
                leaf.commitmentSalt.every((byte) => byte === 0x6a),
            ),
        ).toBe(true);
    });

    it('refuses owner delivery and hostile accessor input before state changes', async () => {
        const fixture = await createFixture();

        expect(() =>
            fixture.custody.loadRetainedDeliverySource({
                recipientPosition: fixture.context.participantPosition,
            }),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        const accessorInput = Object.create(null) as Record<string, unknown>;
        Object.defineProperty(accessorInput, 'recipientPosition', {
            get: () => 7,
        });
        expect(() =>
            fixture.custody.loadRetainedDeliverySource(
                accessorInput as { recipientPosition: number },
            ),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        expect(fixture.anchor.compareAndSetCallCount).toBe(0);
        expect(fixture.kernel.catalogProductionInventories).toHaveLength(0);
    });
});
