import { foundationProfile, stateCapabilityKinds } from '@sealed-lattice/types';
import {
    afterAll,
    afterEach,
    beforeAll,
    beforeEach,
    describe,
    expect,
    expectTypeOf,
    it,
} from 'vitest';

import { openBrowserLocalExternalKeyProvider } from '#packages/crypto/src/index';
import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    createBrowserLocalStateWitnessVoteIssuer,
    openDurableStateWitnessService,
    type BrowserLocalStateWitnessVoteIssuer,
    type DurableStateWitnessService,
    type DurableStateWitnessServiceLimits,
} from '#packages/protocol/src/index';
import {
    generateRuntimeStorageEncryptionKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    openStateVerifierSession,
    type StateVerifierSession,
    type VerifiedStateIntent,
} from '#packages/wasm/src/state-verifier-runtime';
import {
    createStateVerifierTestVector,
    type StateVerifierTestVector,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const serviceLimits = {
    maximumCachedVoteCount: 12,
    maximumExactOutputByteLength:
        foundationProfile.streamChunkByteLength + 1_024,
    maximumRecordSealingCount: 256,
    maximumSignedCarrierByteLength: 4_096,
    transactionLifetimeMilliseconds: 5_000,
} as const;

const requireValid = <Value>(result: {
    isValid: boolean;
    refusalReason?: string;
    value?: Value;
}): Value => {
    if (!result.isValid) {
        throw new Error(result.refusalReason ?? 'verification failed');
    }
    return result.value as Value;
};

const chunkBuffers = (bytes: Uint8Array): readonly ArrayBuffer[] => {
    const chunks: ArrayBuffer[] = [];
    for (
        let offset = 0;
        offset < bytes.byteLength;
        offset += foundationProfile.streamChunkByteLength
    ) {
        chunks.push(
            bytes.slice(
                offset,
                offset + foundationProfile.streamChunkByteLength,
            ).buffer,
        );
    }
    return chunks;
};

const descriptorFor = (
    kernel: TranscriptCoreKernel,
    streamDomain: CanonicalStreamDomain,
    bytes: Uint8Array,
): Uint8Array => {
    const writer = openCanonicalStreamWorkerRuntime({ kernel }).openWriter({
        streamDomain,
        totalByteLength: bytes.byteLength,
    });
    for (const [chunkIndex, chunk] of chunkBuffers(bytes).entries()) {
        writer.absorbChunk(chunkIndex, chunk);
    }
    return writer.finish();
};

const openSession = (
    kernel: TranscriptCoreKernel,
    vector: StateVerifierTestVector,
): StateVerifierSession =>
    requireValid(
        openStateVerifierSession({
            configuration: {
                actionContextHash: vector.actionContextHash,
                canonicalRosterBytes: vector.canonicalRosterBytes,
                ceremonyContextHash: vector.ceremonyContextHash,
                maximumRecoveryTransitionsPerStateKey: 2,
                suiteIdentifier: vector.suiteIdentifier,
            },
            kernel,
        }),
    );

type VoteIntentKind =
    | 'conflicting-reservation'
    | 'output'
    | 'recovery'
    | 'reservation';

const verifyVoteIntent = (input: {
    kind: VoteIntentKind;
    kernel: TranscriptCoreKernel;
    session: StateVerifierSession;
    vector: StateVerifierTestVector;
}): VerifiedStateIntent => {
    if (
        input.kind === 'reservation' ||
        input.kind === 'conflicting-reservation'
    ) {
        const expectedAuthorizationHash =
            input.vector.authorizationHash.slice();
        if (input.kind === 'conflicting-reservation') {
            expectedAuthorizationHash[0] ^= 0xff;
        }
        return requireValid(
            input.session.verifyReservationIntent({
                canonicalReservationIntentCarrier:
                    input.kind === 'reservation'
                        ? input.vector.reservation.canonicalIntentCarrier
                        : input.vector.conflictingReservation
                              .canonicalIntentCarrier,
                capabilityKind: stateCapabilityKinds.targetRelease,
                expectedAuthorizationHash,
                subjectParticipantIdentity:
                    input.vector.subjectParticipantIdentity,
            }),
        );
    }

    const reservation = requireValid(
        input.session.verifyReservation({
            canonicalReservationIntentCarrier:
                input.vector.reservation.canonicalIntentCarrier,
            canonicalStateCertificate:
                input.vector.reservation.canonicalStateCertificate,
            capabilityKind: stateCapabilityKinds.targetRelease,
            expectedAuthorizationHash: input.vector.authorizationHash,
            subjectParticipantIdentity: input.vector.subjectParticipantIdentity,
        }),
    );

    if (input.kind === 'output') {
        const output = requireValid(
            input.session.openOutputIntentVerification({
                canonicalOutputIntentCarrier:
                    input.vector.output.canonicalIntentCarrier,
                exactOutputDescriptorBytes: descriptorFor(
                    input.kernel,
                    canonicalStreamDomains.stateTargetReleaseExactOutput,
                    input.vector.exactOutputBytes,
                ),
                verifiedReservation: reservation,
            }),
        );
        for (const [chunkIndex, chunk] of chunkBuffers(
            input.vector.exactOutputBytes,
        ).entries()) {
            requireValid(output.absorbChunk(chunkIndex, chunk));
        }
        return requireValid(output.finish());
    }

    const output = requireValid(
        input.session.openOutputVerification({
            canonicalOutputIntentCarrier:
                input.vector.output.canonicalIntentCarrier,
            canonicalStateCertificate:
                input.vector.output.canonicalStateCertificate,
            exactOutputDescriptorBytes: descriptorFor(
                input.kernel,
                canonicalStreamDomains.stateTargetReleaseExactOutput,
                input.vector.exactOutputBytes,
            ),
            verifiedReservation: reservation,
        }),
    );
    for (const [chunkIndex, chunk] of chunkBuffers(
        input.vector.exactOutputBytes,
    ).entries()) {
        requireValid(output.absorbChunk(chunkIndex, chunk));
    }
    const certifiedOutput = requireValid(output.finish());
    return requireValid(
        input.session.verifyRecoveryIntent({
            canonicalRecoveryTransitionCarrier:
                input.vector.recoveryPreservingOutput.canonicalIntentCarrier,
            capabilityKind: stateCapabilityKinds.targetRelease,
            preservedStateIntent: certifiedOutput,
            subjectParticipantIdentity: input.vector.subjectParticipantIdentity,
        }),
    );
};

describe('durable state witness service', () => {
    let kernel: TranscriptCoreKernel;
    let vector: StateVerifierTestVector;
    let encryptionKey: CryptoKey;
    let signingKeyPairs: ReturnType<
        typeof createCanonicalCarrierSigningKeyPairFixtures
    >;
    let mailboxKeyPairs: ReturnType<
        typeof createCanonicalCarrierMailboxKeyPairFixtures
    >;
    let activeStateSession: StateVerifierSession | undefined;
    const activeIssuerHarnesses = new Set<{
        close(): void;
    }>();

    beforeAll(async () => {
        vector = createStateVerifierTestVector();
        kernel = await loadFreshTranscriptCoreKernel();
        signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
            foundationProfile.participantCount,
        );
        mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
            foundationProfile.participantCount,
        );
    });

    afterAll(() => {
        for (const { secretKey } of signingKeyPairs) {
            secretKey.fill(0);
        }
        for (const { secretKey } of mailboxKeyPairs) {
            secretKey.fill(0);
        }
    });

    beforeEach(async () => {
        encryptionKey = await generateRuntimeStorageEncryptionKey();
    });

    afterEach(() => {
        for (const harness of activeIssuerHarnesses) {
            harness.close();
        }
        activeIssuerHarnesses.clear();
        activeStateSession?.cancel();
        activeStateSession = undefined;
    });

    const openService = async (input?: {
        limits?: DurableStateWitnessServiceLimits;
    }): Promise<{
        adapter: Awaited<ReturnType<typeof openRuntimeTestStore>>['adapter'];
        service: DurableStateWitnessService;
        store: Awaited<ReturnType<typeof openRuntimeTestStore>>['store'];
    }> => {
        const { adapter, store } = await openRuntimeTestStore();
        return {
            adapter,
            service: openDurableStateWitnessService({
                authorityContext: runtimeAuthorityContext({
                    actionContextHash: vector.actionContextHash,
                    ceremonyContextHash: vector.ceremonyContextHash,
                    suiteIdentifier: vector.suiteIdentifier,
                }),
                encryptionKey,
                limits: input?.limits ?? serviceLimits,
                store,
            }),
            store,
        };
    };

    const openVoteIssuer = (input?: {
        entropyByte?: number;
        kind?: VoteIntentKind;
    }) => {
        let entropyAvailable = true;
        let entropyCallCount = 0;
        const provider = openBrowserLocalExternalKeyProvider({
            entropy: (byteLength) => {
                entropyCallCount += 1;
                if (!entropyAvailable) {
                    throw new Error('injected browser entropy failure');
                }
                return new Uint8Array(byteLength).fill(
                    (input?.entropyByte ?? 0x40) + entropyCallCount,
                );
            },
            mailbox: {
                decapsulationKey: mailboxKeyPairs[1].secretKey,
                expectedEncapsulationKey: mailboxKeyPairs[1].publicKey,
            },
            signing: {
                expectedVerificationKey: signingKeyPairs[1].publicKey,
                secretKey: signingKeyPairs[1].secretKey,
            },
        });
        const initialEntropyCallCount = entropyCallCount;
        activeStateSession ??= openSession(kernel, vector);
        const session = activeStateSession;
        const verifiedIntent = verifyVoteIntent({
            kernel,
            kind: input?.kind ?? 'reservation',
            session,
            vector,
        });
        const verifiedIntentBinding = requireValid(
            session.durableBindingFor(verifiedIntent),
        );
        const voteIssuer = createBrowserLocalStateWitnessVoteIssuer({
            session,
            signingCapability: provider.signingCapability,
            verifiedIntent,
            witnessParticipantIdentity: vector.witnessParticipantIdentity,
        });
        let closed = false;
        const harness = {
            close: (): void => {
                if (closed) {
                    return;
                }
                closed = true;
                provider.close();
            },
            disableEntropy: (): void => {
                entropyAvailable = false;
            },
            provider,
            session,
            signatureEntropyCallCount: (): number =>
                entropyCallCount - initialEntropyCallCount,
            verifiedIntent,
            verifiedIntentBinding,
            voteIssuer,
        };
        activeIssuerHarnesses.add(harness);
        return harness;
    };

    it('exposes only closed service operations and replays one carrier byte-for-byte across restarts', async () => {
        expectTypeOf<keyof DurableStateWitnessService>().toEqualTypeOf<
            | 'cacheExactOutput'
            | 'readExactOutput'
            | 'signOrReplayBrowserLocalVote'
        >();
        const issuer = openVoteIssuer();
        const unusedIssuer = openVoteIssuer({ entropyByte: 0x70 });
        const { service, store } = await openService();
        expect(Object.keys(service).sort()).toEqual([
            'cacheExactOutput',
            'readExactOutput',
            'signOrReplayBrowserLocalVote',
        ]);

        const firstCarrier = await service.signOrReplayBrowserLocalVote({
            voteIssuer: issuer.voteIssuer,
        });
        const replayedCarrier = await service.signOrReplayBrowserLocalVote({
            voteIssuer: unusedIssuer.voteIssuer,
        });
        const reopened = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: vector.actionContextHash,
                ceremonyContextHash: vector.ceremonyContextHash,
                suiteIdentifier: vector.suiteIdentifier,
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });
        const restartedReplay = await reopened.signOrReplayBrowserLocalVote({
            voteIssuer: unusedIssuer.voteIssuer,
        });

        expect(issuer.signatureEntropyCallCount()).toBe(1);
        expect(unusedIssuer.signatureEntropyCallCount()).toBe(0);
        expect(firstCarrier).toHaveLength(3_801);
        expect(replayedCarrier).toEqual(firstCarrier);
        expect(restartedReplay).toEqual(firstCarrier);
    });

    it('certifies the browser-local carrier from unordered adversarial transport input', async () => {
        const issuer = openVoteIssuer();
        const { service } = await openService();
        const cachedCarrier = await service.signOrReplayBrowserLocalVote({
            voteIssuer: issuer.voteIssuer,
        });
        const otherWitnesses = vector.reservationVoteCarriers.slice(1);
        const carrierWithUntrustedTransportMetadata = {
            canonicalCarrier: otherWitnesses[5],
            ignoredTransportSequence: 99,
        };
        const certification =
            issuer.session.certifyIntentFromUntrustedVoteCarriers({
                untrustedVoteCarriers: [
                    carrierWithUntrustedTransportMetadata,
                    { canonicalCarrier: cachedCarrier },
                    { canonicalCarrier: otherWitnesses[2] },
                    { canonicalCarrier: otherWitnesses[0] },
                    { canonicalCarrier: cachedCarrier.slice() },
                    { canonicalCarrier: otherWitnesses[4] },
                    { canonicalCarrier: otherWitnesses[1] },
                    { canonicalCarrier: otherWitnesses[3] },
                ],
                verifiedIntent: issuer.verifiedIntent,
            });
        expect(certification).toMatchObject({ isValid: true });
    });

    it('rejects a competing intent before its issuer can consume signing entropy', async () => {
        const firstIssuer = openVoteIssuer();
        const conflictingIssuer = openVoteIssuer({
            entropyByte: 0x73,
            kind: 'conflicting-reservation',
        });
        const { service } = await openService();
        await service.signOrReplayBrowserLocalVote({
            voteIssuer: firstIssuer.voteIssuer,
        });
        await expect(
            service.signOrReplayBrowserLocalVote({
                voteIssuer: conflictingIssuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(conflictingIssuer.signatureEntropyCallCount()).toBe(0);
    });

    it('preserves the lock across entropy failure, capability revocation, and provider key loss', async () => {
        const failureCases = [
            {
                code: 'EntropyUnavailable',
                fail: (issuer: ReturnType<typeof openVoteIssuer>) =>
                    issuer.disableEntropy(),
            },
            {
                code: 'CapabilityUnavailable',
                fail: (issuer: ReturnType<typeof openVoteIssuer>) =>
                    issuer.provider.revokeSigningCapability(),
            },
            {
                code: 'CapabilityUnavailable',
                fail: (issuer: ReturnType<typeof openVoteIssuer>) =>
                    issuer.provider.close(),
            },
        ] as const;

        for (const [caseIndex, failureCase] of failureCases.entries()) {
            const failingIssuer = openVoteIssuer({
                entropyByte: 0x20 + caseIndex * 0x10,
            });
            const replacementIssuer = openVoteIssuer({
                entropyByte: 0x70 + caseIndex * 0x10,
            });
            const { service } = await openService();
            failureCase.fail(failingIssuer);
            await expect(
                service.signOrReplayBrowserLocalVote({
                    voteIssuer: failingIssuer.voteIssuer,
                }),
            ).rejects.toMatchObject({ code: failureCase.code });
            await expect(
                service.signOrReplayBrowserLocalVote({
                    voteIssuer: replacementIssuer.voteIssuer,
                }),
            ).resolves.toHaveLength(3_801);
            expect(replacementIssuer.signatureEntropyCallCount()).toBe(1);
        }
    });

    it('selects exactly one carrier across concurrent service instances', async () => {
        const leftIssuer = openVoteIssuer({ entropyByte: 0x21 });
        const rightIssuer = openVoteIssuer({ entropyByte: 0x73 });
        const { service, store } = await openService();
        const concurrentService = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: vector.actionContextHash,
                ceremonyContextHash: vector.ceremonyContextHash,
                suiteIdentifier: vector.suiteIdentifier,
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });
        const [left, right] = await Promise.all([
            service.signOrReplayBrowserLocalVote({
                voteIssuer: leftIssuer.voteIssuer,
            }),
            concurrentService.signOrReplayBrowserLocalVote({
                voteIssuer: rightIssuer.voteIssuer,
            }),
        ]);
        expect(left).toEqual(right);
        expect(
            leftIssuer.signatureEntropyCallCount() +
                rightIssuer.signatureEntropyCallCount(),
        ).toBe(1);
    });

    it('never issues before the lock commits and reuses the issuer carrier after cache failure', async () => {
        const lockFailureIssuer = openVoteIssuer();
        const lockFailureRuntime = await openService();
        lockFailureRuntime.adapter.failAtomicMutationAfter(1);
        await expect(
            lockFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: lockFailureIssuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(lockFailureIssuer.signatureEntropyCallCount()).toBe(0);
        await expect(
            lockFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: lockFailureIssuer.voteIssuer,
            }),
        ).resolves.toHaveLength(3_801);
        expect(lockFailureIssuer.signatureEntropyCallCount()).toBe(1);

        const cacheFailureIssuer = openVoteIssuer({ entropyByte: 0x65 });
        const cacheFailureRuntime = await openService();
        cacheFailureRuntime.adapter.failAtomicMutationAfter(2);
        await expect(
            cacheFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: cacheFailureIssuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        const selectedCarrier =
            await cacheFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: cacheFailureIssuer.voteIssuer,
            });
        await expect(
            cacheFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: cacheFailureIssuer.voteIssuer,
            }),
        ).resolves.toEqual(selectedCarrier);
        expect(cacheFailureIssuer.signatureEntropyCallCount()).toBe(1);
    });

    it('releases transaction ownership after authentication and cleanup failures', async () => {
        const authenticationFailureIssuer = openVoteIssuer();
        const authenticationFailureRuntime = await openService();
        authenticationFailureRuntime.adapter.afterNextAtomicMutation = (
            mutation,
        ) => {
            const indexWrite = mutation.writes[0];
            if (indexWrite === undefined) {
                throw new Error('expected an index publication');
            }
            const objectKey = new TextDecoder().decode(indexWrite.value);
            const sealedBytes =
                authenticationFailureRuntime.adapter.rawRead(objectKey);
            if (sealedBytes === undefined) {
                throw new Error('published object is missing');
            }
            sealedBytes[sealedBytes.byteLength - 1] ^= 1;
            authenticationFailureRuntime.adapter.rawWrite(
                objectKey,
                sealedBytes,
            );
        };
        await expect(
            authenticationFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: authenticationFailureIssuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(authenticationFailureIssuer.signatureEntropyCallCount()).toBe(0);
        await expect(
            authenticationFailureRuntime.store.recover(),
        ).resolves.toMatchObject({ retainedObjectCount: 1 });

        const cleanupFailureIssuer = openVoteIssuer({ entropyByte: 0x68 });
        const cleanupFailureRuntime = await openService();
        cleanupFailureRuntime.adapter.failNextDeleteCount = 1;
        await expect(
            cleanupFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: cleanupFailureIssuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'CleanupFailed' });
        const replayedCarrier =
            await cleanupFailureRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: cleanupFailureIssuer.voteIssuer,
            });
        expect(replayedCarrier).toHaveLength(3_801);
        expect(cleanupFailureIssuer.signatureEntropyCallCount()).toBe(1);
        await expect(
            cleanupFailureRuntime.store.recover(),
        ).resolves.toBeDefined();
    });

    it('fails closed at the action-scoped runtime-record sealing ceiling', async () => {
        const issuer = openVoteIssuer();
        const boundedRuntime = await openService({
            limits: { ...serviceLimits, maximumRecordSealingCount: 1 },
        });
        await expect(
            boundedRuntime.service.signOrReplayBrowserLocalVote({
                voteIssuer: issuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        expect(issuer.signatureEntropyCallCount()).toBe(1);
        await expect(boundedRuntime.store.recover()).resolves.toBeDefined();
    });

    it('seals exact output independently and permits bound output and recovery votes', async () => {
        const reservationIssuer = openVoteIssuer();
        const outputIssuer = openVoteIssuer({ kind: 'output' });
        const recoveryIssuer = openVoteIssuer({ kind: 'recovery' });
        const { adapter, service } = await openService();

        await expect(
            service.signOrReplayBrowserLocalVote({
                voteIssuer: outputIssuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await service.signOrReplayBrowserLocalVote({
            voteIssuer: reservationIssuer.voteIssuer,
        });
        const changedOutput = vector.exactOutputBytes.slice();
        changedOutput[changedOutput.byteLength - 1] ^= 1;
        await expect(
            service.cacheExactOutput({
                exactOutputBytes: changedOutput,
                verifiedOutputBinding: outputIssuer.verifiedIntentBinding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        adapter.failAtomicMutationAfter(1);
        await expect(
            service.cacheExactOutput({
                exactOutputBytes: vector.exactOutputBytes,
                verifiedOutputBinding: outputIssuer.verifiedIntentBinding,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await service.cacheExactOutput({
            exactOutputBytes: vector.exactOutputBytes,
            verifiedOutputBinding: outputIssuer.verifiedIntentBinding,
        });
        await service.cacheExactOutput({
            exactOutputBytes: vector.exactOutputBytes,
            verifiedOutputBinding: outputIssuer.verifiedIntentBinding,
        });
        await expect(
            service.readExactOutput({
                verifiedOutputBinding: outputIssuer.verifiedIntentBinding,
            }),
        ).resolves.toEqual(vector.exactOutputBytes);
        await expect(
            service.signOrReplayBrowserLocalVote({
                voteIssuer: outputIssuer.voteIssuer,
            }),
        ).resolves.toHaveLength(3_801);
        await expect(
            service.signOrReplayBrowserLocalVote({
                voteIssuer: recoveryIssuer.voteIssuer,
            }),
        ).resolves.toHaveLength(3_801);

        const emptyRecoveryIssuer = openVoteIssuer({
            entropyByte: 0x76,
            kind: 'recovery',
        });
        const { service: emptyService } = await openService();
        await expect(
            emptyService.signOrReplayBrowserLocalVote({
                voteIssuer: emptyRecoveryIssuer.voteIssuer,
            }),
        ).resolves.toHaveLength(3_801);

        const reservationUpgradeIssuer = openVoteIssuer({ entropyByte: 0x28 });
        const recoveryUpgradeIssuer = openVoteIssuer({
            entropyByte: 0x58,
            kind: 'recovery',
        });
        const { service: reservationUpgradeService } = await openService();
        await reservationUpgradeService.signOrReplayBrowserLocalVote({
            voteIssuer: reservationUpgradeIssuer.voteIssuer,
        });
        await expect(
            reservationUpgradeService.signOrReplayBrowserLocalVote({
                voteIssuer: recoveryUpgradeIssuer.voteIssuer,
            }),
        ).resolves.toHaveLength(3_801);

        const exactOutputObjectKey = adapter
            .keys()
            .filter((key) => key.includes('/objects/'))
            .map((key) => ({
                byteLength: adapter.rawRead(key)?.byteLength ?? 0,
                key,
            }))
            .sort((left, right) => right.byteLength - left.byteLength)[0]?.key;
        if (exactOutputObjectKey === undefined) {
            throw new Error('exact-output cache object is missing');
        }
        adapter.rawDelete(exactOutputObjectKey);
        await expect(
            service.readExactOutput({
                verifiedOutputBinding: outputIssuer.verifiedIntentBinding,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('refuses forged issuers and issuers from another authority context', async () => {
        const issuer = openVoteIssuer();
        const { store } = await openRuntimeTestStore();
        const wrongContextService = openDurableStateWitnessService({
            authorityContext: runtimeAuthorityContext({
                actionContextHash: new Uint8Array(64).fill(0x99),
            }),
            encryptionKey,
            limits: serviceLimits,
            store,
        });
        await expect(
            wrongContextService.signOrReplayBrowserLocalVote({
                voteIssuer: issuer.voteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(issuer.signatureEntropyCallCount()).toBe(0);
        await expect(
            wrongContextService.signOrReplayBrowserLocalVote({
                voteIssuer: Object.freeze(
                    Object.create(null),
                ) as BrowserLocalStateWitnessVoteIssuer,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });
});
