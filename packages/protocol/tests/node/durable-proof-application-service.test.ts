import { describe, expect, it } from 'vitest';

import {
    DurableProofApplicationServiceError,
    openDurableProofApplicationService,
    type DurableProofApplicationReservationInput,
    type DurableProofApplicationResourceCeilings,
    type DurableProofApplicationService,
    type DurableProofApplicationServiceLimits,
} from '#packages/protocol/src/index';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const textDecoder = new TextDecoder();

const defaultResourceCeilings: DurableProofApplicationResourceCeilings = {
    proofByteCount: 1_000n,
    proofObjectCount: 100n,
    queryCount: 1_000n,
    signatureCount: 1_000n,
    verificationCount: 1_000n,
};

const defaultServiceLimits: DurableProofApplicationServiceLimits = {
    maximumApplicationSlotByteLength: 128,
    maximumOperationIdentifierByteLength: 128,
    maximumRecordSealingCount: 10_000,
    resourceCeilings: defaultResourceCeilings,
    transactionLifetimeMilliseconds: 5_000,
};

const applicationSlotBytes = (slotNumber: number): Uint8Array =>
    new Uint8Array([
        0x01,
        0x00,
        slotNumber & 0xff,
        (slotNumber >>> 8) & 0xff,
        0xa5,
    ]);

const operationIdentifierBytes = (operationNumber: number): Uint8Array =>
    new Uint8Array([
        0x02,
        0x00,
        operationNumber & 0xff,
        (operationNumber >>> 8) & 0xff,
        0x5a,
    ]);

const reservationInput = (
    slotNumber: number,
    completeProofByteLength = 10n,
): DurableProofApplicationReservationInput => ({
    canonicalApplicationSlotBytes: applicationSlotBytes(slotNumber),
    completeProofByteLength,
    fullProofObjectDigest: hashFilledWith(0x80 + slotNumber),
    proofHeaderHash: hashFilledWith(0x40 + slotNumber),
});

const createHarness = async (input?: {
    adapter?: InMemoryRuntimeStorageAdapter;
    encryptionKey?: CryptoKey;
    maximumApplicationSlotByteLength?: number;
    maximumOperationIdentifierByteLength?: number;
    maximumRecordSealingCount?: number;
    resourceCeilings?: Partial<DurableProofApplicationResourceCeilings>;
    runtimeBuildManifestByte?: number;
    storeHarness?: Awaited<ReturnType<typeof openRuntimeTestStore>>;
    transactionLifetimeMilliseconds?: number;
}): Promise<{
    adapter: InMemoryRuntimeStorageAdapter;
    encryptionKey: CryptoKey;
    service: DurableProofApplicationService;
    storeHarness: Awaited<ReturnType<typeof openRuntimeTestStore>>;
}> => {
    const storeHarness =
        input?.storeHarness ??
        (await openRuntimeTestStore({
            adapter: input?.adapter,
            namespace: 'proof-application-test',
        }));
    const encryptionKey =
        input?.encryptionKey ?? (await generateRuntimeStorageEncryptionKey());
    const service = openDurableProofApplicationService({
        authorityContext: runtimeAuthorityContext({
            runtimeBuildManifestHash: hashFilledWith(
                input?.runtimeBuildManifestByte ?? 0x55,
            ),
        }),
        encryptionKey,
        limits: {
            ...defaultServiceLimits,
            maximumApplicationSlotByteLength:
                input?.maximumApplicationSlotByteLength ??
                defaultServiceLimits.maximumApplicationSlotByteLength,
            maximumOperationIdentifierByteLength:
                input?.maximumOperationIdentifierByteLength ??
                defaultServiceLimits.maximumOperationIdentifierByteLength,
            maximumRecordSealingCount:
                input?.maximumRecordSealingCount ??
                defaultServiceLimits.maximumRecordSealingCount,
            resourceCeilings: {
                ...defaultResourceCeilings,
                ...input?.resourceCeilings,
            },
            transactionLifetimeMilliseconds:
                input?.transactionLifetimeMilliseconds ??
                defaultServiceLimits.transactionLifetimeMilliseconds,
        },
        store: storeHarness.store,
    });

    return {
        adapter: storeHarness.adapter,
        encryptionKey,
        service,
        storeHarness,
    };
};

const decodeLogicalRecordKey = (indexKey: string): string | undefined => {
    const marker = '/indices/';
    const markerOffset = indexKey.indexOf(marker);
    if (markerOffset < 0) {
        return undefined;
    }
    const encoded = indexKey.slice(markerOffset + marker.length);
    if (encoded.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(encoded)) {
        return undefined;
    }
    const bytes = new Uint8Array(encoded.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            encoded.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return textDecoder.decode(bytes);
};

const tamperProofApplicationLedger = (
    adapter: InMemoryRuntimeStorageAdapter,
): Uint8Array => {
    const indexKey = adapter
        .keys()
        .find((key) =>
            decodeLogicalRecordKey(key)?.startsWith(
                'proof-application-ledger/',
            ),
        );
    if (indexKey === undefined) {
        throw new Error(
            'Expected proof-application ledger index was not found.',
        );
    }
    const indexValue = adapter.rawRead(indexKey);
    if (indexValue === undefined) {
        throw new Error(
            'Expected proof-application index value was not found.',
        );
    }
    const objectKey = textDecoder.decode(indexValue);
    const objectValue = adapter.rawRead(objectKey);
    if (objectValue === undefined) {
        throw new Error('Expected proof-application object was not found.');
    }
    objectValue[Math.floor(objectValue.byteLength / 2)] ^= 0x80;
    adapter.rawWrite(objectKey, objectValue);
    return objectValue;
};

describe('Durable proof-application service', () => {
    it('charges a fresh exact binding once and refuses every conflicting replacement', async () => {
        const { service } = await createHarness();
        const exactInput = reservationInput(1, 17n);
        const fresh = await service.reserve(exactInput);

        expect(fresh.disposition).toBe('fresh');
        await expect(service.readResourceCounters()).resolves.toEqual({
            proofByteCount: 17n,
            proofObjectCount: 1n,
            queryCount: 0n,
            signatureCount: 0n,
            verificationCount: 0n,
        });

        const exactReopen = await service.reserve({
            ...exactInput,
            canonicalApplicationSlotBytes:
                exactInput.canonicalApplicationSlotBytes.slice(),
            fullProofObjectDigest: exactInput.fullProofObjectDigest.slice(),
            proofHeaderHash: exactInput.proofHeaderHash.slice(),
        });
        expect(exactReopen.disposition).toBe('exactReopen');
        await expect(service.readResourceCounters()).resolves.toMatchObject({
            proofByteCount: 17n,
            proofObjectCount: 1n,
        });

        await expect(
            service.reserve({
                ...exactInput,
                proofHeaderHash: hashFilledWith(0xf1),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(
            service.reserve({
                ...exactInput,
                completeProofByteLength: 18n,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(
            service.reserve({
                ...exactInput,
                fullProofObjectDigest: hashFilledWith(0xf2),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(service.readResourceCounters()).resolves.toMatchObject({
            proofByteCount: 17n,
            proofObjectCount: 1n,
        });
    });

    it('makes an exact operation replay free and refuses reuse with another charge', async () => {
        const { service } = await createHarness();
        const reservation = await service.reserve(reservationInput(2));
        const charge = {
            canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
            queryCount: 3n,
            signatureCount: 2n,
            verificationCount: 1n,
        };

        const fresh = await reservation.chargeOperation(charge);
        expect(fresh).toEqual({
            disposition: 'fresh',
            resourceCounters: {
                proofByteCount: 10n,
                proofObjectCount: 1n,
                queryCount: 3n,
                signatureCount: 2n,
                verificationCount: 1n,
            },
        });
        await expect(
            reservation.chargeOperation({
                ...charge,
                canonicalOperationIdentifierBytes:
                    charge.canonicalOperationIdentifierBytes.slice(),
            }),
        ).resolves.toMatchObject({
            disposition: 'exactReplay',
            resourceCounters: {
                queryCount: 3n,
                signatureCount: 2n,
                verificationCount: 1n,
            },
        });
        await expect(
            reservation.chargeOperation({
                ...charge,
                verificationCount: 2n,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('accepts each configured resource edge and refuses the first value beyond it', async () => {
        const proofObjectHarness = await createHarness({
            resourceCeilings: { proofObjectCount: 1n },
        });
        await proofObjectHarness.service.reserve(reservationInput(1));
        await expect(
            proofObjectHarness.service.reserve(reservationInput(2)),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });

        const proofByteHarness = await createHarness({
            resourceCeilings: { proofByteCount: 9n },
        });
        await proofByteHarness.service.reserve(reservationInput(1, 9n));
        await expect(
            proofByteHarness.service.reserve(reservationInput(2, 1n)),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });

        for (const counterName of [
            'verificationCount',
            'queryCount',
            'signatureCount',
        ] as const) {
            const harness = await createHarness({
                resourceCeilings: { [counterName]: 2n },
            });
            const reservation = await harness.service.reserve(
                reservationInput(1),
            );
            await reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
                queryCount: counterName === 'queryCount' ? 2n : 0n,
                signatureCount: counterName === 'signatureCount' ? 2n : 0n,
                verificationCount:
                    counterName === 'verificationCount' ? 2n : 0n,
            });
            await expect(
                reservation.chargeOperation({
                    canonicalOperationIdentifierBytes:
                        operationIdentifierBytes(2),
                    queryCount: counterName === 'queryCount' ? 1n : 0n,
                    signatureCount: counterName === 'signatureCount' ? 1n : 0n,
                    verificationCount:
                        counterName === 'verificationCount' ? 1n : 0n,
                }),
            ).rejects.toMatchObject({ code: 'ResourceLimit' });
        }
    });

    it('enforces canonical input byte limits and the record-sealing ceiling at their edges', async () => {
        const harness = await createHarness({
            maximumApplicationSlotByteLength: 5,
            maximumOperationIdentifierByteLength: 5,
            maximumRecordSealingCount: 2,
        });
        const reservation = await harness.service.reserve(reservationInput(1));
        await expect(
            harness.service.reserve({
                ...reservationInput(2),
                canonicalApplicationSlotBytes: new Uint8Array(6).fill(0x22),
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await reservation.chargeOperation({
            canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
            queryCount: 1n,
            signatureCount: 0n,
            verificationCount: 0n,
        });
        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: new Uint8Array(6).fill(0x33),
                queryCount: 1n,
                signatureCount: 0n,
                verificationCount: 0n,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(2),
                queryCount: 1n,
                signatureCount: 0n,
                verificationCount: 0n,
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        await expect(
            harness.service.readResourceCounters(),
        ).resolves.toMatchObject({ queryCount: 1n });

        expect(() =>
            openDurableProofApplicationService({
                authorityContext: runtimeAuthorityContext(),
                encryptionKey: harness.encryptionKey,
                limits: {
                    ...defaultServiceLimits,
                    maximumApplicationSlotByteLength: 0,
                },
                store: harness.storeHarness.store,
            }),
        ).toThrow(DurableProofApplicationServiceError);
        expect(() =>
            openDurableProofApplicationService({
                authorityContext: runtimeAuthorityContext(),
                encryptionKey: harness.encryptionKey,
                limits: {
                    ...defaultServiceLimits,
                    maximumRecordSealingCount: 0x1_0000_0001,
                },
                store: harness.storeHarness.store,
            }),
        ).toThrow(DurableProofApplicationServiceError);
        expect(() =>
            openDurableProofApplicationService({
                authorityContext: runtimeAuthorityContext(),
                encryptionKey: harness.encryptionKey,
                limits: {
                    ...defaultServiceLimits,
                    transactionLifetimeMilliseconds: 0,
                },
                store: harness.storeHarness.store,
            }),
        ).toThrow(DurableProofApplicationServiceError);
    });

    it('checks unsigned-64 overflow, invalid values, and an empty operation charge', async () => {
        const byteHarness = await createHarness({
            resourceCeilings: {
                proofByteCount: maximumUnsigned64,
                proofObjectCount: 2n,
            },
        });
        await byteHarness.service.reserve(
            reservationInput(1, maximumUnsigned64),
        );
        await expect(
            byteHarness.service.reserve(reservationInput(2, 1n)),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        await expect(
            byteHarness.service.reserve(
                reservationInput(3, maximumUnsigned64 + 1n),
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const operationHarness = await createHarness({
            resourceCeilings: { verificationCount: maximumUnsigned64 },
        });
        const reservation = await operationHarness.service.reserve(
            reservationInput(1),
        );
        await reservation.chargeOperation({
            canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
            queryCount: 0n,
            signatureCount: 0n,
            verificationCount: maximumUnsigned64,
        });
        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(2),
                queryCount: 0n,
                signatureCount: 0n,
                verificationCount: 1n,
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(3),
                queryCount: 0n,
                signatureCount: 0n,
                verificationCount: maximumUnsigned64 + 1n,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(4),
                queryCount: 0n,
                signatureCount: 0n,
                verificationCount: 0n,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        expect(() =>
            openDurableProofApplicationService({
                authorityContext: runtimeAuthorityContext(),
                encryptionKey: operationHarness.encryptionKey,
                limits: {
                    ...defaultServiceLimits,
                    resourceCeilings: {
                        ...defaultResourceCeilings,
                        queryCount: maximumUnsigned64 + 1n,
                    },
                },
                store: operationHarness.storeHarness.store,
            }),
        ).toThrow(DurableProofApplicationServiceError);
    });

    it('does not expose a charge when the atomic commit fails before publication', async () => {
        const { adapter, service } = await createHarness();
        const reservation = await service.reserve(reservationInput(1));
        adapter.failAtomicMutationAfter(1);

        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
                queryCount: 1n,
                signatureCount: 1n,
                verificationCount: 1n,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await expect(service.readResourceCounters()).resolves.toEqual({
            proofByteCount: 10n,
            proofObjectCount: 1n,
            queryCount: 0n,
            signatureCount: 0n,
            verificationCount: 0n,
        });
        await expect(
            reservation.chargeOperation({
                canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
                queryCount: 1n,
                signatureCount: 1n,
                verificationCount: 1n,
            }),
        ).resolves.toMatchObject({
            disposition: 'fresh',
            resourceCounters: {
                queryCount: 1n,
                signatureCount: 1n,
                verificationCount: 1n,
            },
        });
    });

    it('charges proof-object and proof-byte reservations exactly once across publication failures', async () => {
        const beforePublication = await createHarness();
        beforePublication.adapter.failAtomicMutationAfter(1);
        await expect(
            beforePublication.service.reserve(reservationInput(1, 13n)),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await expect(
            beforePublication.service.readResourceCounters(),
        ).resolves.toEqual({
            proofByteCount: 0n,
            proofObjectCount: 0n,
            queryCount: 0n,
            signatureCount: 0n,
            verificationCount: 0n,
        });
        await expect(
            beforePublication.service.reserve(reservationInput(1, 13n)),
        ).resolves.toMatchObject({ disposition: 'fresh' });

        const afterPublication = await createHarness();
        await afterPublication.service.reserve(reservationInput(1, 7n));
        afterPublication.adapter.failNextDeleteCount = 1;
        await expect(
            afterPublication.service.reserve(reservationInput(2, 11n)),
        ).rejects.toMatchObject({ code: 'CleanupFailed' });
        await expect(
            afterPublication.service.reserve(reservationInput(2, 11n)),
        ).resolves.toMatchObject({ disposition: 'exactReopen' });
        await expect(
            afterPublication.service.readResourceCounters(),
        ).resolves.toMatchObject({
            proofByteCount: 18n,
            proofObjectCount: 2n,
        });
    });

    it('replays a committed charge after cleanup failure and recovers its unreferenced predecessor', async () => {
        const firstHarness = await createHarness();
        const reservation = await firstHarness.service.reserve(
            reservationInput(1),
        );
        firstHarness.adapter.failNextDeleteCount = 1;
        const charge = {
            canonicalOperationIdentifierBytes: operationIdentifierBytes(1),
            queryCount: 2n,
            signatureCount: 3n,
            verificationCount: 4n,
        };

        await expect(reservation.chargeOperation(charge)).rejects.toMatchObject(
            { code: 'CleanupFailed' },
        );
        await expect(
            reservation.chargeOperation(charge),
        ).resolves.toMatchObject({
            disposition: 'exactReplay',
            resourceCounters: {
                queryCount: 2n,
                signatureCount: 3n,
                verificationCount: 4n,
            },
        });

        const reopenedStore = await openRuntimeTestStore({
            adapter: firstHarness.adapter,
            namespace: 'proof-application-test',
        });
        expect(
            reopenedStore.recoveryReport.removedUnreferencedObjectCount,
        ).toBe(1);
        const reopenedHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: reopenedStore,
        });
        const reopenedReservation = await reopenedHarness.service.reserve(
            reservationInput(1),
        );
        expect(reopenedReservation.disposition).toBe('exactReopen');
        await expect(
            reopenedReservation.chargeOperation(charge),
        ).resolves.toMatchObject({ disposition: 'exactReplay' });
        await expect(
            reopenedHarness.service.readResourceCounters(),
        ).resolves.toEqual({
            proofByteCount: 10n,
            proofObjectCount: 1n,
            queryCount: 2n,
            signatureCount: 3n,
            verificationCount: 4n,
        });
    });

    it('serializes concurrent service instances without dropping or double-charging work', async () => {
        const firstHarness = await createHarness();
        const secondHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const reservations = await Promise.all([
            firstHarness.service.reserve(reservationInput(1)),
            secondHarness.service.reserve(reservationInput(1)),
            firstHarness.service.reserve(reservationInput(2)),
            secondHarness.service.reserve(reservationInput(3)),
        ]);

        expect(
            reservations.filter(({ disposition }) => disposition === 'fresh'),
        ).toHaveLength(3);
        expect(
            reservations.filter(
                ({ disposition }) => disposition === 'exactReopen',
            ),
        ).toHaveLength(1);
        await Promise.all(
            Array.from({ length: 24 }, (_, operationIndex) =>
                reservations[0].chargeOperation({
                    canonicalOperationIdentifierBytes: operationIdentifierBytes(
                        operationIndex + 1,
                    ),
                    queryCount: 1n,
                    signatureCount: operationIndex % 2 === 0 ? 1n : 0n,
                    verificationCount: 1n,
                }),
            ),
        );
        await expect(
            secondHarness.service.readResourceCounters(),
        ).resolves.toEqual({
            proofByteCount: 30n,
            proofObjectCount: 3n,
            queryCount: 24n,
            signatureCount: 12n,
            verificationCount: 24n,
        });
    });

    it('rejects authenticated-object tamper without replacing the evidence', async () => {
        const { adapter, service } = await createHarness();
        await service.reserve(reservationInput(1));
        const tamperedBytes = tamperProofApplicationLedger(adapter);

        await expect(service.readResourceCounters()).rejects.toMatchObject({
            code: 'AuthenticationFailed',
        });
        expect(
            adapter
                .keys()
                .map((key) => adapter.rawRead(key))
                .some(
                    (value) =>
                        value !== undefined &&
                        value.byteLength === tamperedBytes.byteLength &&
                        value.every(
                            (byte, index) => byte === tamperedBytes[index],
                        ),
                ),
        ).toBe(true);
    });

    it('isolates authority contexts and rejects the wrong record key or resource policy', async () => {
        const firstHarness = await createHarness();
        await firstHarness.service.reserve(reservationInput(1));

        const isolatedAuthority = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            runtimeBuildManifestByte: 0x99,
            storeHarness: firstHarness.storeHarness,
        });
        await expect(
            isolatedAuthority.service.readResourceCounters(),
        ).resolves.toEqual({
            proofByteCount: 0n,
            proofObjectCount: 0n,
            queryCount: 0n,
            signatureCount: 0n,
            verificationCount: 0n,
        });

        const wrongKeyHarness = await createHarness({
            storeHarness: firstHarness.storeHarness,
        });
        await expect(
            wrongKeyHarness.service.readResourceCounters(),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

        const changedPolicyHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            resourceCeilings: { queryCount: 999n },
            storeHarness: firstHarness.storeHarness,
        });
        await expect(
            changedPolicyHarness.service.readResourceCounters(),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });
});
