import { describe, expect, it } from 'vitest';

import {
    NamespaceFreshnessError,
    openNamespaceFreshnessSubjectRuntime,
    openNamespaceFreshnessWitnessService,
    type NamespaceFreshnessCheckpointDescription,
    type NamespaceFreshnessContext,
    type NamespaceFreshnessLocalHead,
    type NamespaceFreshnessPreparedCheckpoint,
    type NamespaceFreshnessVerifier,
    type NamespaceFreshnessWitnessCoordinate,
    type NamespaceFreshnessWitnessStoreSnapshot,
    type UntrustedNamespaceFreshnessCertificate,
    type VerifiedNamespaceFreshnessCertificate,
    type VerifiedNamespaceFreshnessCheckpoint,
} from '#packages/protocol/src/runtime/namespace-freshness-runtime';

const bytes = (value: number): Uint8Array => new Uint8Array(64).fill(value);
const key = (value: Uint8Array): string =>
    Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

const context = (): NamespaceFreshnessContext => ({
    actionContextHash: bytes(0x33),
    ceremonyContextHash: bytes(0x22),
    storageInstanceIdentity: bytes(0x44),
    subjectParticipantIdentity: bytes(0x55),
    suiteIdentifier: bytes(0x11),
});

const rosterParticipantWitnessIdentities = (): readonly Uint8Array[] =>
    Array.from({ length: 9 }, (_unused, index) => bytes(0x60 + index));

type FakeVerifier = Readonly<{
    prepare(input: {
        authenticatedHeadDigest: Uint8Array;
        namespaceSequence: bigint;
        previousCheckpointHash?: Uint8Array;
    }): NamespaceFreshnessPreparedCheckpoint;
    verifier: NamespaceFreshnessVerifier;
}>;

const createFakeVerifier = (): FakeVerifier => {
    const checkpoints = new Map<string, NamespaceFreshnessPreparedCheckpoint>();
    const prepare = (input: {
        authenticatedHeadDigest: Uint8Array;
        namespaceSequence: bigint;
        previousCheckpointHash?: Uint8Array;
    }): NamespaceFreshnessPreparedCheckpoint => {
        const sequenceNumber = Number(input.namespaceSequence);
        const checkpointHash = bytes(
            (0x80 + sequenceNumber + (input.authenticatedHeadDigest[0] ?? 0)) &
                0xff,
        );
        const canonicalCheckpoint = Uint8Array.of(
            sequenceNumber,
            input.authenticatedHeadDigest[0] ?? 0,
            input.previousCheckpointHash?.[0] ?? 0,
        );
        const description: NamespaceFreshnessCheckpointDescription = {
            ...context(),
            authenticatedHeadDigest: input.authenticatedHeadDigest.slice(),
            checkpointHash,
            namespaceSequence: input.namespaceSequence,
            ...(input.previousCheckpointHash === undefined
                ? {}
                : {
                      previousCheckpointHash:
                          input.previousCheckpointHash.slice(),
                  }),
            version: 1,
        };
        const prepared: NamespaceFreshnessPreparedCheckpoint = {
            canonicalCheckpoint,
            description,
            verifiedCheckpoint: Object.freeze(
                Object.create(null),
            ) as VerifiedNamespaceFreshnessCheckpoint,
        };
        checkpoints.set(key(canonicalCheckpoint), prepared);
        return prepared;
    };
    const verifier: NamespaceFreshnessVerifier = {
        prepareCheckpoint: (input) => ({
            isValid: true,
            value: prepare(input),
        }),
        verifyCheckpoint: (input) => {
            const prepared = checkpoints.get(key(input.canonicalCheckpoint));
            return prepared === undefined
                ? { isValid: false, refusalReason: 'malformedEncoding' }
                : { isValid: true, value: prepared };
        },
        verifyVoteCarrier: (input) =>
            input.untrustedVoteCarrier.byteLength === 0
                ? { isValid: false, refusalReason: 'wrongTypeOrLength' }
                : { isValid: true, value: undefined },
        verifyCertificate: (input) => {
            const prepared = checkpoints.get(key(input.canonicalCheckpoint));
            if (prepared === undefined) {
                return { isValid: false, refusalReason: 'malformedEncoding' };
            }
            if (input.untrustedVoteCarriers.length < input.freshnessQuorum) {
                return {
                    isValid: false,
                    refusalReason: 'missingPrerequisite',
                };
            }
            if (
                input.untrustedVoteCarriers.some(
                    (carrier) => carrier[0] === 0xff,
                )
            ) {
                return { isValid: false, refusalReason: 'malformedEncoding' };
            }
            const witnessIndexes = input.untrustedVoteCarriers.map(
                (carrier) => carrier[0] ?? 0,
            );
            if (new Set(witnessIndexes).size !== witnessIndexes.length) {
                return { isValid: false, refusalReason: 'equivocation' };
            }
            return {
                isValid: true,
                value: {
                    description: prepared.description,
                    verifiedCertificate: Object.freeze(
                        Object.create(null),
                    ) as VerifiedNamespaceFreshnessCertificate,
                    verifiedWitnessIdentities: witnessIndexes.map(
                        (index) =>
                            input.rosterParticipantWitnessIdentities[index],
                    ),
                },
            };
        },
    };
    return { prepare, verifier };
};

const certificateFor = (
    prepared: NamespaceFreshnessPreparedCheckpoint,
    carrierCount = 7,
): UntrustedNamespaceFreshnessCertificate => ({
    canonicalCheckpoint: prepared.canonicalCheckpoint,
    untrustedVoteCarriers: Array.from(
        { length: carrierCount },
        (_unused, index) => Uint8Array.of(index),
    ),
});

const createSubjectHarness = (input: {
    available: readonly UntrustedNamespaceFreshnessCertificate[];
    head: NamespaceFreshnessLocalHead;
    publish?: UntrustedNamespaceFreshnessCertificate;
    verifier: NamespaceFreshnessVerifier;
}) => {
    let head = input.head;
    let retired = 0;
    let journalWrites = 0;
    const runtime = openNamespaceFreshnessSubjectRuntime({
        acceptedCheckpointJournal: {
            storeAcceptedCertificate: () => {
                journalWrites += 1;
                return Promise.resolve();
            },
        },
        certificateTransport: {
            publishCheckpoint: () => {
                if (input.publish === undefined) {
                    return Promise.reject(
                        new Error('witness quorum unavailable'),
                    );
                }
                return Promise.resolve(input.publish);
            },
            readAvailableCertificates: () => Promise.resolve(input.available),
        },
        context: context(),
        rosterParticipantWitnessIdentities:
            rosterParticipantWitnessIdentities(),
        freshnessQuorum: 7,
        localAuthority: {
            authenticateCurrentHead: () =>
                Promise.resolve({
                    authenticatedHeadDigest:
                        head.authenticatedHeadDigest.slice(),
                    namespaceSequence: head.namespaceSequence,
                    storageInstanceIdentity:
                        head.storageInstanceIdentity.slice(),
                }),
            retireActionSecrets: () => {
                retired += 1;
                return Promise.resolve();
            },
        },
        verifier: input.verifier,
    });
    return {
        counts: () => ({ journalWrites, retired }),
        runtime,
        setHead: (next: NamespaceFreshnessLocalHead) => {
            head = next;
        },
    };
};

describe('Namespace freshness subject runtime', () => {
    it('activates only when a roster-participant quorum certifies the exact local head', async () => {
        const fake = createFakeVerifier();
        const genesis = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        const harness = createSubjectHarness({
            available: [certificateFor(genesis)],
            head: {
                authenticatedHeadDigest: bytes(0x10),
                namespaceSequence: 0n,
                storageInstanceIdentity: bytes(0x44),
            },
            verifier: fake.verifier,
        });
        await expect(harness.runtime.startup()).resolves.toBe('active');
        expect(harness.runtime.activeCapability()).toBeTypeOf('object');
        expect(harness.counts()).toEqual({
            journalWrites: 1,
            retired: 0,
        });
    });

    it('irreversibly retires when the freshest certificate differs from local state', async () => {
        const fake = createFakeVerifier();
        const genesis = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        const next = fake.prepare({
            authenticatedHeadDigest: bytes(0x20),
            namespaceSequence: 1n,
            previousCheckpointHash: genesis.description.checkpointHash,
        });
        const harness = createSubjectHarness({
            available: [certificateFor(genesis), certificateFor(next)],
            head: {
                authenticatedHeadDigest: bytes(0x10),
                namespaceSequence: 0n,
                storageInstanceIdentity: bytes(0x44),
            },
            verifier: fake.verifier,
        });
        await expect(harness.runtime.startup()).resolves.toBe('retired');
        expect(harness.runtime.retirementReason()).toBe('localStateMismatch');
        await expect(harness.runtime.startup()).resolves.toBe('retired');
        expect(() => harness.runtime.activeCapability()).toThrow(
            NamespaceFreshnessError,
        );
        expect(harness.counts().retired).toBe(1);
    });

    it('never rolls a locally newer authenticated head back to an older certificate', async () => {
        const fake = createFakeVerifier();
        const genesis = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        const harness = createSubjectHarness({
            available: [certificateFor(genesis)],
            head: {
                authenticatedHeadDigest: bytes(0x30),
                namespaceSequence: 1n,
                storageInstanceIdentity: bytes(0x44),
            },
            verifier: fake.verifier,
        });
        await expect(harness.runtime.startup()).resolves.toBe('unavailable');
        expect(harness.counts()).toEqual({
            journalWrites: 0,
            retired: 0,
        });
    });

    it('retires on competing certificates or any invalid extra carrier', async () => {
        const fake = createFakeVerifier();
        const first = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        const competing = fake.prepare({
            authenticatedHeadDigest: bytes(0x11),
            namespaceSequence: 0n,
        });
        const competingHarness = createSubjectHarness({
            available: [certificateFor(first), certificateFor(competing)],
            head: {
                authenticatedHeadDigest: bytes(0x10),
                namespaceSequence: 0n,
                storageInstanceIdentity: bytes(0x44),
            },
            verifier: fake.verifier,
        });
        await expect(competingHarness.runtime.startup()).resolves.toBe(
            'retired',
        );
        expect(competingHarness.runtime.retirementReason()).toBe(
            'competingCertificates',
        );

        const invalid = certificateFor(first, 8);
        invalid.untrustedVoteCarriers[7][0] = 0xff;
        const invalidHarness = createSubjectHarness({
            available: [invalid],
            head: {
                authenticatedHeadDigest: bytes(0x10),
                namespaceSequence: 0n,
                storageInstanceIdentity: bytes(0x44),
            },
            verifier: fake.verifier,
        });
        await expect(invalidHarness.runtime.startup()).resolves.toBe('retired');
        expect(invalidHarness.runtime.retirementReason()).toBe(
            'invalidCertificate',
        );
    });

    it('leaves a post-commit namespace unavailable until publication reaches quorum', async () => {
        const fake = createFakeVerifier();
        const genesis = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        const harness = createSubjectHarness({
            available: [certificateFor(genesis)],
            head: {
                authenticatedHeadDigest: bytes(0x10),
                namespaceSequence: 0n,
                storageInstanceIdentity: bytes(0x44),
            },
            verifier: fake.verifier,
        });
        await harness.runtime.startup();
        await expect(
            harness.runtime.certifyMutation(() => {
                harness.setHead({
                    authenticatedHeadDigest: bytes(0x20),
                    namespaceSequence: 1n,
                    storageInstanceIdentity: bytes(0x44),
                });
                return Promise.resolve();
            }),
        ).resolves.toBe('unavailable');
        expect(() => harness.runtime.activeCapability()).toThrow(
            'no roster-certified freshness capability',
        );
        await expect(
            harness.runtime.certifyMutation(() => Promise.resolve()),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });
});

describe('Namespace freshness participant witness service', () => {
    it('atomically locks one successor and replays only byte-identical votes', async () => {
        const fake = createFakeVerifier();
        const genesis = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        const next = fake.prepare({
            authenticatedHeadDigest: bytes(0x20),
            namespaceSequence: 1n,
            previousCheckpointHash: genesis.description.checkpointHash,
        });
        const competingNext = fake.prepare({
            authenticatedHeadDigest: bytes(0x21),
            namespaceSequence: 1n,
            previousCheckpointHash: genesis.description.checkpointHash,
        });
        let coordinate: NamespaceFreshnessWitnessCoordinate | undefined;
        let signCount = 0;
        let retired = 0;
        const service = openNamespaceFreshnessWitnessService({
            context: context(),
            signer: {
                signVerifiedCheckpoint: () =>
                    Promise.resolve(Uint8Array.of(++signCount, 0x90)),
            },
            store: {
                compareAndLock: ({
                    expectedCheckpointHash,
                    nextCoordinate,
                }) => {
                    if (
                        coordinate === undefined
                            ? expectedCheckpointHash !== undefined
                            : expectedCheckpointHash === undefined ||
                              key(expectedCheckpointHash) !==
                                  key(coordinate.description.checkpointHash)
                    ) {
                        return Promise.resolve({ kind: 'changed' });
                    }
                    coordinate = nextCoordinate;
                    return Promise.resolve({ kind: 'committed' });
                },
                load: (): Promise<NamespaceFreshnessWitnessStoreSnapshot> =>
                    Promise.resolve(
                        coordinate === undefined
                            ? { kind: 'authorized-empty' }
                            : { kind: 'current', coordinate },
                    ),
                retire: () => {
                    retired += 1;
                    return Promise.resolve();
                },
            },
            verifier: fake.verifier,
            witnessParticipantIdentity: bytes(0x60),
        });

        const firstVote = await service.vote(genesis.canonicalCheckpoint);
        expect(firstVote.isValid).toBe(true);
        const replayedVote = await service.vote(genesis.canonicalCheckpoint);
        expect(replayedVote).toEqual(firstVote);
        expect(signCount).toBe(1);
        expect((await service.vote(next.canonicalCheckpoint)).isValid).toBe(
            true,
        );
        expect(await service.vote(competingNext.canonicalCheckpoint)).toEqual({
            isValid: false,
            refusalReason: 'equivocation',
        });
        expect(service.state()).toBe('active');
        expect(retired).toBe(0);
    });

    it('retires rather than reinitializing after witness-store authentication loss', async () => {
        const fake = createFakeVerifier();
        const genesis = fake.prepare({
            authenticatedHeadDigest: bytes(0x10),
            namespaceSequence: 0n,
        });
        let retired = 0;
        const service = openNamespaceFreshnessWitnessService({
            context: context(),
            signer: {
                signVerifiedCheckpoint: () => Promise.resolve(Uint8Array.of(1)),
            },
            store: {
                compareAndLock: () =>
                    Promise.resolve({
                        kind: 'authentication-failed',
                    }),
                load: () => Promise.resolve({ kind: 'authentication-failed' }),
                retire: () => {
                    retired += 1;
                    return Promise.resolve();
                },
            },
            verifier: fake.verifier,
            witnessParticipantIdentity: bytes(0x60),
        });
        expect(await service.vote(genesis.canonicalCheckpoint)).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
        expect(service.state()).toBe('retired');
        expect(retired).toBe(1);
        expect(await service.vote(genesis.canonicalCheckpoint)).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
    });
});
