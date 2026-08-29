import type {
    DirectMpcPreprocessingSourceStateKernelOpening,
    OpenDirectMpcPreprocessingSourceStateKernelInput,
    ProductionDirectMpcPreprocessingSourceStateKernel,
} from '@sealed-lattice/wasm';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const stateBoundaryMocks = vi.hoisted(() => ({
    actionStateGuard: Object.freeze({}),
    assertSigningKey: vi.fn(),
    assertUsesRecencyCoordinator: vi.fn(),
    consumeAuthentication: vi.fn(),
    consumeJoined: vi.fn(),
    openKernel: vi.fn(),
    signSubject: vi.fn(
        (input: {
            signatureRandomness: Uint8Array;
            subjectAuthorizationBodyBytes: Uint8Array;
        }) =>
            new Uint8Array(3_309).fill(
                (input.signatureRandomness[0] ?? 0) ^
                    (input.subjectAuthorizationBodyBytes[0] ?? 0) ^
                    0x52,
            ),
    ),
    signWitness: vi.fn(
        (input: {
            signatureRandomness: Uint8Array;
            witnessAuthorizationBodyBytes: Uint8Array;
        }) =>
            new Uint8Array(3_309).fill(
                (input.signatureRandomness[0] ?? 0) ^
                    (input.witnessAuthorizationBodyBytes[0] ?? 0) ^
                    0x31,
            ),
    ),
}));

vi.mock('@sealed-lattice/crypto', () => ({
    assertDirectMpcPreprocessingSourceStateSigningCapabilityMatchesRosterKey:
        stateBoundaryMocks.assertSigningKey,
    signDirectMpcPreprocessingSourceStateSubjectBody:
        stateBoundaryMocks.signSubject,
    signDirectMpcPreprocessingSourceStateWitnessBody:
        stateBoundaryMocks.signWitness,
}));

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionDirectMpcPreprocessingSourceStateKernel: () => true,
    openProductionDirectMpcPreprocessingSourceStateKernel:
        stateBoundaryMocks.openKernel,
}));

vi.mock(
    '#packages/protocol/src/runtime/seed-recipient-authentication-custody',
    () => ({
        assertSeedRecipientActionStateGuardUsesRecencyCoordinator:
            stateBoundaryMocks.assertUsesRecencyCoordinator,
        consumePreprocessingSourceStateAuthorization:
            stateBoundaryMocks.consumeAuthentication,
    }),
);

vi.mock('#packages/protocol/src/runtime/joined-seed-master-custody', () => ({
    consumeJoinedSeedMasterRestorationAuthorization:
        stateBoundaryMocks.consumeJoined,
}));

import {
    createRuntimeRecordProtection,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    DirectMpcPreprocessingSourceStateCustody,
    openBrowserLocalDirectMpcPreprocessingSourceStateKernel,
    type DirectMpcPreprocessingSourceStateCustodyKernel,
    type DirectMpcPreprocessingSourceStateCustodyLimits,
} from '#packages/protocol/src/runtime/direct-mpc-preprocessing-source-state-custody';
import {
    generateRuntimeStorageRootKey,
    hashFilledWith,
    InMemoryAuthenticatedStorageRecencyAnchor,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const testLimits: DirectMpcPreprocessingSourceStateCustodyLimits =
    Object.freeze({
        maximumEndorsementCarrierByteLength: 512,
        maximumIntentByteLength: 512,
        maximumTerminalByteLength: 512,
        maximumWitnessEnvelopeByteLength: 512,
        transactionLifetimeMilliseconds: 1_000,
    });

const foundationEvidence = Object.freeze({
    actionIdentifier: 'state-custody-action',
    canonicalActionDefinitionBytes: Uint8Array.of(0x41, 0x42),
    canonicalBoardPolicyBytes: Uint8Array.of(0x51, 0x52),
    canonicalManifestBytes: Uint8Array.of(0x61, 0x62),
    canonicalRosterBytes: Uint8Array.of(0x71, 0x72),
    ceremonyIdentifier: 'state-custody-ceremony',
    suiteIdentity: hashFilledWith(0x81),
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
            for (let index = 0; index < bytes.byteLength; index += 1) {
                bytes[index] = ((invocationCount * 29 + index * 13) % 255) + 1;
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
        const prefix = kind === 'transaction' ? '01' : '02';
        return `${prefix}${counts[kind].toString(16).padStart(62, '0')}`;
    };
};

const expectFailureCode = async (
    operation: Promise<unknown>,
    expectedCode: string,
): Promise<void> => {
    try {
        await operation;
        throw new Error('Expected operation to reject.');
    } catch (error) {
        expect(error).toMatchObject({ code: expectedCode });
    }
};

const stateKeyForSubject = (subjectPosition: number): Uint8Array =>
    hashFilledWith(0x90 + subjectPosition);

class DeterministicStateKernel implements DirectMpcPreprocessingSourceStateCustodyKernel {
    public readonly localParticipantPosition = 0;
    public readonly outcome: 'burn' | 'success';
    public readonly publicInconsistencyCarrierBytes: Uint8Array;
    public readonly sourceOutcomeBodyBytes: Uint8Array;
    public readonly stateNamespaceIdentity = hashFilledWith(0x33);
    public failNextWitnessCompletionCount = 0;
    readonly #outcomeMarker: number;

    public constructor(outcome: 'burn' | 'success' = 'success') {
        this.outcome = outcome;
        this.#outcomeMarker = outcome === 'success' ? 0x41 : 0x62;
        this.publicInconsistencyCarrierBytes =
            outcome === 'burn' ? Uint8Array.of(0xb1, 0xb2) : new Uint8Array();
        this.sourceOutcomeBodyBytes = new Uint8Array(23).fill(
            this.#outcomeMarker,
        );
    }

    public close(): void {}

    public prepareWitness(input: { subjectPosition: number }) {
        return Object.freeze({
            authorizationBodyBytes: new Uint8Array(170).fill(
                this.#outcomeMarker + input.subjectPosition,
            ),
            intentBytes: Uint8Array.of(
                0x11,
                this.#outcomeMarker,
                input.subjectPosition,
            ),
            signingVerificationKey: new Uint8Array(1_952).fill(0x73),
            stateKeyIdentity: stateKeyForSubject(input.subjectPosition),
        });
    }

    public completeWitness(input: {
        authorizationBodyBytes: Uint8Array;
        signature: Uint8Array;
        subjectPosition: number;
    }) {
        if (this.failNextWitnessCompletionCount > 0) {
            this.failNextWitnessCompletionCount -= 1;
            throw new Error('Injected witness completion interruption.');
        }
        if (
            input.authorizationBodyBytes.byteLength !== 170 ||
            input.signature.byteLength !== 3_309
        ) {
            throw new Error('Malformed witness completion input.');
        }
        const witnessEnvelopeBytes = new Uint8Array(47).fill(
            (input.authorizationBodyBytes[0] ?? 0) ^
                (input.signature[0] ?? 0) ^
                input.subjectPosition,
        );
        witnessEnvelopeBytes[0] = 0xa1;
        witnessEnvelopeBytes[1] = input.authorizationBodyBytes[0] ?? 0;
        witnessEnvelopeBytes[2] = input.signature[0] ?? 0;
        return Object.freeze({
            stateKeyIdentity: stateKeyForSubject(input.subjectPosition),
            witnessEnvelopeBytes,
        });
    }

    public prepareSubject(input: {
        witnessEnvelopeBytes: readonly Uint8Array[];
    }) {
        if (input.witnessEnvelopeBytes.length !== 7) {
            throw new Error('Subject preparation requires seven witnesses.');
        }
        return Object.freeze({
            authorizationBodyBytes: new Uint8Array(240).fill(
                this.#outcomeMarker,
            ),
            intentBytes: Uint8Array.of(
                0x22,
                this.#outcomeMarker,
                input.witnessEnvelopeBytes[0]?.[0] ?? 0,
            ),
            signingVerificationKey: new Uint8Array(1_952).fill(0x73),
            stateKeyIdentity: stateKeyForSubject(this.localParticipantPosition),
        });
    }

    public completeSubject(input: {
        authorizationBodyBytes: Uint8Array;
        signature: Uint8Array;
        witnessEnvelopeBytes: readonly Uint8Array[];
    }) {
        if (
            input.authorizationBodyBytes.byteLength !== 240 ||
            input.signature.byteLength !== 3_309 ||
            input.witnessEnvelopeBytes.length !== 7
        ) {
            throw new Error('Malformed subject completion input.');
        }
        const endorsementCarrierBytes = new Uint8Array(59).fill(
            (input.authorizationBodyBytes[0] ?? 0) ^ (input.signature[0] ?? 0),
        );
        endorsementCarrierBytes[0] = 0xc1;
        endorsementCarrierBytes[1] = input.authorizationBodyBytes[0] ?? 0;
        endorsementCarrierBytes[2] = input.signature[0] ?? 0;
        return Object.freeze({
            endorsementCarrierBytes,
            stateKeyIdentity: stateKeyForSubject(this.localParticipantPosition),
        });
    }

    public createTerminal(input: {
        endorsementCarrierBytes: readonly Uint8Array[];
    }) {
        if (input.endorsementCarrierBytes.length !== 7) {
            throw new Error('Terminal creation requires seven subjects.');
        }
        const terminalBytes = Uint8Array.of(
            0xd1,
            this.#outcomeMarker,
            ...input.endorsementCarrierBytes.map((bytes) => bytes[0] ?? 0),
        );
        return Object.freeze({
            outcome: this.outcome,
            stateNamespaceIdentity: this.stateNamespaceIdentity.slice(),
            terminalBytes,
            terminalIdentity: hashFilledWith(
                this.#outcomeMarker ^ (terminalBytes[2] ?? 0),
            ),
        });
    }

    public validateTerminal(input: { terminalBytes: Uint8Array }) {
        if (input.terminalBytes.byteLength > 9) {
            throw Object.assign(
                new Error('Terminal has an appended semantic event.'),
                { code: 'ConsumedState' },
            );
        }
        if (
            input.terminalBytes.byteLength !== 9 ||
            input.terminalBytes[0] !== 0xd1 ||
            input.terminalBytes[1] !== this.#outcomeMarker
        ) {
            throw new Error('Terminal does not match this source outcome.');
        }
        return Object.freeze({
            outcome: this.outcome,
            stateNamespaceIdentity: this.stateNamespaceIdentity.slice(),
            terminalBytes: input.terminalBytes.slice(),
            terminalIdentity: hashFilledWith(
                this.#outcomeMarker ^ (input.terminalBytes[2] ?? 0),
            ),
        });
    }
}

type CustodyFixture = Readonly<{
    adapter: InMemoryRuntimeStorageAdapter;
    anchor: InMemoryAuthenticatedStorageRecencyAnchor;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: DirectMpcPreprocessingSourceStateCustody;
    kernel: DeterministicStateKernel;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const authorizeKernelForTest = async (
    kernel: DeterministicStateKernel,
    coordinator: AuthenticatedStorageRecencyCoordinator,
): Promise<ProductionDirectMpcPreprocessingSourceStateKernel> => {
    stateBoundaryMocks.assertUsesRecencyCoordinator.mockImplementationOnce(
        (_guard, suppliedCoordinator) => {
            if (suppliedCoordinator !== coordinator) {
                throw Object.assign(new Error('Wrong recency coordinator.'), {
                    code: 'InvalidConfiguration',
                });
            }
        },
    );
    stateBoundaryMocks.consumeAuthentication.mockResolvedValueOnce(
        Object.freeze({
            actionStateGuard: stateBoundaryMocks.actionStateGuard,
            context: Object.freeze({
                parameterIdentity: hashFilledWith(0x11),
                participantCount: 10,
                preparationAttemptOrdinal: 0,
                preparationContextIdentity: hashFilledWith(0x12),
                recipientPosition: 0,
                rootTerminalIdentity: hashFilledWith(0x13),
            }),
            recordBytes: Uint8Array.of(0x81, 0x82),
        }),
    );
    stateBoundaryMocks.openKernel.mockResolvedValueOnce(
        Object.freeze({
            kernel: kernel as unknown as ProductionDirectMpcPreprocessingSourceStateKernel,
            status: 'verified' as const,
        }) satisfies DirectMpcPreprocessingSourceStateKernelOpening,
    );
    const opening =
        await openBrowserLocalDirectMpcPreprocessingSourceStateKernel({
            foundationEvidence,
            preprocessingSourceStateAuthorization: Object.freeze({}) as never,
            signingCapability: Object.freeze({}) as never,
        });
    if (opening.status !== 'verified') {
        throw new Error('Test kernel unexpectedly remained pending.');
    }
    return opening.kernel;
};

const createFixture = async (
    kernel = new DeterministicStateKernel(),
): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `direct-mpc-source-state-${fixtureOrdinal}`;
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
        maximumRecordSealingCount: 64,
        rootKey,
    });
    const productionKernel = await authorizeKernelForTest(kernel, coordinator);
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody: new DirectMpcPreprocessingSourceStateCustody({
            kernel: productionKernel,
            limits: testLimits,
            protection,
            recencyCoordinator: coordinator,
        }),
        kernel,
        namespace,
        protection,
        rootKey,
    });
};

const reopenCustody = async (
    fixture: CustodyFixture,
    kernel = new DeterministicStateKernel(),
): Promise<DirectMpcPreprocessingSourceStateCustody> => {
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
        maximumRecordSealingCount: 64,
        rootKey: fixture.rootKey,
    });
    const productionKernel = await authorizeKernelForTest(kernel, coordinator);
    return new DirectMpcPreprocessingSourceStateCustody({
        kernel: productionKernel,
        limits: testLimits,
        protection,
        recencyCoordinator: coordinator,
    });
};

describe('direct-MPC preprocessing-source state custody', () => {
    beforeEach(() => {
        stateBoundaryMocks.assertSigningKey.mockReset();
        stateBoundaryMocks.assertUsesRecencyCoordinator.mockReset();
        stateBoundaryMocks.consumeAuthentication.mockReset();
        stateBoundaryMocks.consumeJoined.mockReset();
        stateBoundaryMocks.openKernel.mockReset();
        stateBoundaryMocks.signSubject.mockClear();
        stateBoundaryMocks.signWitness.mockClear();
    });

    it('consumes exact local predecessor bytes and associates only the resulting verified kernel', async () => {
        const kernel = new DeterministicStateKernel();
        const opened = await openRuntimeTestStore({
            namespace: 'direct-mpc-source-state-open-boundary',
        });
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor: new InMemoryAuthenticatedStorageRecencyAnchor(),
            store: opened.store,
        });
        const authenticationRecordBytes = Uint8Array.of(0xa1, 0xa2, 0xa3);
        const joinedRecordBytes = Uint8Array.of(0xb1, 0xb2, 0xb3);
        stateBoundaryMocks.consumeAuthentication.mockResolvedValueOnce(
            Object.freeze({
                actionStateGuard: stateBoundaryMocks.actionStateGuard,
                context: Object.freeze({
                    parameterIdentity: hashFilledWith(0x11),
                    participantCount: 10,
                    preparationAttemptOrdinal: 0,
                    preparationContextIdentity: hashFilledWith(0x12),
                    recipientPosition: 0,
                    rootTerminalIdentity: hashFilledWith(0x13),
                }),
                recordBytes: authenticationRecordBytes,
            }),
        );
        stateBoundaryMocks.consumeJoined.mockResolvedValueOnce(
            Object.freeze({
                context: Object.freeze({
                    actionContextIdentity: hashFilledWith(0x21),
                    participantPosition: 0,
                }),
                recordBytes: joinedRecordBytes,
            }),
        );
        stateBoundaryMocks.openKernel.mockImplementationOnce(
            (input: OpenDirectMpcPreprocessingSourceStateKernelInput) => {
                expect(input.authenticationRecordBytes).toEqual(
                    Uint8Array.of(0xa1, 0xa2, 0xa3),
                );
                expect(input.joinedCustodyRecordBytes).toEqual(
                    Uint8Array.of(0xb1, 0xb2, 0xb3),
                );
                return Promise.resolve(
                    Object.freeze({
                        kernel,
                        status: 'verified' as const,
                    }),
                );
            },
        );
        const opening =
            await openBrowserLocalDirectMpcPreprocessingSourceStateKernel({
                foundationEvidence,
                joinedSeedMasterRestorationAuthorization: Object.freeze(
                    {},
                ) as never,
                preprocessingSourceStateAuthorization: Object.freeze(
                    {},
                ) as never,
                signingCapability: Object.freeze({}) as never,
            });

        expect(opening.status).toBe('verified');
        expect(authenticationRecordBytes).toEqual(new Uint8Array(3));
        expect(joinedRecordBytes).toEqual(new Uint8Array(3));

        const rootKey = await generateRuntimeStorageRootKey();
        const protection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            cryptoProvider: deterministicCryptoProvider(),
            maximumRecordSealingCount: 8,
            rootKey,
        });
        expect(
            () =>
                new DirectMpcPreprocessingSourceStateCustody({
                    kernel: new DeterministicStateKernel() as never,
                    limits: testLimits,
                    protection,
                    recencyCoordinator: coordinator,
                }),
        ).toThrow(/authenticated local predecessor custody/u);
    });

    it('retains the signing hedge before use and replays one carrier without a second signature', async () => {
        const interruptedKernel = new DeterministicStateKernel();
        interruptedKernel.failNextWitnessCompletionCount = 1;
        const fixture = await createFixture(interruptedKernel);

        await expectFailureCode(
            fixture.custody.retainWitness(4),
            'AuthenticationFailed',
        );
        expect(stateBoundaryMocks.signWitness).toHaveBeenCalledTimes(1);
        const firstRandomness = (
            stateBoundaryMocks.signWitness.mock.calls[0]?.[0] as {
                signatureRandomness: Uint8Array;
            }
        ).signatureRandomness.slice();

        const resumed = await reopenCustody(fixture);
        const firstPublication = await resumed.retainWitness(4);
        expect(stateBoundaryMocks.signWitness).toHaveBeenCalledTimes(2);
        expect(
            (
                stateBoundaryMocks.signWitness.mock.calls[1]?.[0] as {
                    signatureRandomness: Uint8Array;
                }
            ).signatureRandomness,
        ).toEqual(firstRandomness);
        stateBoundaryMocks.assertSigningKey.mockImplementation(() => {
            throw new Error('Signing capability was revoked after retention.');
        });

        const exactReplay = await resumed.retainWitness(4);
        expect(exactReplay).toEqual(firstPublication);
        expect(stateBoundaryMocks.signWitness).toHaveBeenCalledTimes(2);

        const coldReplay = await reopenCustody(fixture);
        expect(await coldReplay.retainWitness(4)).toEqual(firstPublication);
        expect(stateBoundaryMocks.signWitness).toHaveBeenCalledTimes(2);

        const conflictingOutcome = await reopenCustody(
            fixture,
            new DeterministicStateKernel('burn'),
        );
        await expectFailureCode(
            conflictingOutcome.retainWitness(4),
            'Conflict',
        );
        expect(stateBoundaryMocks.signWitness).toHaveBeenCalledTimes(2);
        firstRandomness.fill(0);
    });

    it('retains one terminal, refuses alternatives and appended events, and retires after lost state', async () => {
        const fixture = await createFixture();
        const witnesses = await Promise.all(
            Array.from({ length: 7 }, (_unused, subjectOffset) =>
                fixture.custody.retainWitness(subjectOffset + 1),
            ),
        );
        const subject = await fixture.custody.retainSubject(
            witnesses.map((witness) => witness.witnessEnvelopeBytes),
        );
        fixture.kernel.failNextWitnessCompletionCount = 1;
        await expectFailureCode(
            fixture.custody.retainWitness(8),
            'AuthenticationFailed',
        );
        const signatureCountBeforeTerminal =
            stateBoundaryMocks.signWitness.mock.calls.length;
        const terminalCarriers = Array.from({ length: 7 }, () =>
            subject.endorsementCarrierBytes.slice(),
        );
        const terminal =
            await fixture.custody.createAndRetainTerminal(terminalCarriers);
        expect(
            await fixture.custody.validateAndRetainTerminal(
                terminal.terminalBytes,
            ),
        ).toEqual(terminal);
        expect(await fixture.custody.resumeTerminal()).toEqual(terminal);

        const appendedTerminal = new Uint8Array(
            terminal.terminalBytes.byteLength + 1,
        );
        appendedTerminal.set(terminal.terminalBytes);
        appendedTerminal[appendedTerminal.byteLength - 1] = 0xff;
        await expectFailureCode(
            fixture.custody.validateAndRetainTerminal(appendedTerminal),
            'InvalidState',
        );
        await expectFailureCode(
            fixture.custody.retainWitness(8),
            'InvalidState',
        );
        expect(stateBoundaryMocks.signWitness).toHaveBeenCalledTimes(
            signatureCountBeforeTerminal,
        );

        const conflictingCarriers = terminalCarriers.map((carrier) =>
            carrier.slice(),
        );
        conflictingCarriers[0][0] ^= 0x01;
        await expectFailureCode(
            fixture.custody.createAndRetainTerminal(conflictingCarriers),
            'Conflict',
        );

        const authenticatedHeadKey = fixture.adapter
            .keys()
            .find((key) => key.endsWith('/repair/current-head'));
        expect(authenticatedHeadKey).toBeDefined();
        fixture.adapter.rawDelete(authenticatedHeadKey!);
        await expectFailureCode(fixture.custody.resumeTerminal(), 'Conflict');
        await expectFailureCode(fixture.custody.resumeTerminal(), 'Conflict');
    });
});
