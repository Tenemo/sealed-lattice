import { describe, expect, it } from 'vitest';

import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import {
    compileContributionProofStorage,
    compileGcmKeyHistory,
    compileParticipantCustodyCensus,
    compileParticipantVaultKeyClasses,
    projectContributionProofPadding,
} from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import {
    completionProfile,
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

// The exhaustive assertions inspect the same immutable owner-derived cases.
// Reuse their construction, not one assertion's expected result.
const custodyCases = new Map<
    string,
    {
        body: ReturnType<typeof compileContributionBodyCensus>;
        storage: ReturnType<typeof compileContributionProofStorage>;
        custody: ReturnType<typeof compileParticipantCustodyCensus>;
    }
>();
const custodyCase = (profile: SupportedProfile) => {
    const key = `${profile.participantCount}/${profile.optionCount}`;
    let value = custodyCases.get(key);
    if (value === undefined) {
        value = {
            body: compileContributionBodyCensus(profile),
            storage: compileContributionProofStorage(profile),
            custody: compileParticipantCustodyCensus(profile),
        };
        custodyCases.set(key, value);
    }
    return value;
};

describe('shared participant custody', () => {
    it('retains every contribution polynomial once without storing the expanded statement header as a body record', () => {
        const value = compileParticipantCustodyCensus(completionProfile());
        const body = compileContributionBodyCensus(completionProfile());
        // The setup reference and its confirmation inventory each add one
        // authenticated root record.
        expect(value.maximumRootRecords).toBe(
            compileRegistrationEnrollmentCensus().maximumRecords + 2n,
        );
        // The marker, inventory identity, and public-polynomial identities of
        // the 45 aggregate polynomials, followed by a 64-byte protocol tag.
        expect(body.polynomials).toHaveLength(45);
        expect(value.setupReferenceBytes).toBe(4n + 64n + 45n * 64n + 64n);
        expect(value.publicRecords.some((record) => record.object === 0)).toBe(
            false,
        );
        for (const polynomial of body.polynomials) {
            const records = value.publicRecords.filter(
                (record) => record.object === polynomial.expandedIndex + 1,
            );
            expect(
                records.reduce((total, record) => total + record.length, 0n),
            ).toBe(polynomial.bytes);
            expect(
                records.every(
                    (record, index) =>
                        record.offset === BigInt(index) * (1n << 20n),
                ),
            ).toBe(true);
        }
    });

    it.each(Array.from({ length: 18 }, (_unused, index) => index + 3))(
        'fixes proof slots and the body header for every option count at roster %i',
        (participantCount) => {
            const chunk = 1n << 20n;
            const referenceBytes = BigInt(
                Buffer.concat([
                    Buffer.alloc(2),
                    Buffer.alloc(4),
                    Buffer.alloc(4),
                    Buffer.alloc(32),
                    Buffer.alloc(64),
                ]).length,
            );
            for (const profile of listSupportedProfiles().filter(
                (value) => value.participantCount === participantCount,
            )) {
                const { body, storage, custody } = custodyCase(profile);
                const records = (body.maximumProofBytes + chunk - 1n) / chunk;
                expect(BigInt(storage.records.length)).toBe(records);
                expect(
                    storage.records.reduce(
                        (total, record) => total + record.length,
                        0n,
                    ),
                ).toBe(body.maximumProofBytes);
                for (const [index, record] of storage.records.entries()) {
                    expect(record.offset).toBe(BigInt(index) * chunk);
                    expect(record.length).toBe(
                        index + 1 === storage.records.length
                            ? body.maximumProofBytes - BigInt(index) * chunk
                            : chunk,
                    );
                }
                expect(storage.ciphertextBytes).toBe(
                    body.maximumProofBytes + 16n * records,
                );
                expect(storage.dataKeyBytes).toBe(32n * records);
                expect(storage.recordIdentityBytes).toBe(64n * records);
                expect(storage.recordReferenceBytes).toBe(
                    referenceBytes * records,
                );
                expect(storage.completedBodyHeaderBytes).toBe(4n + 8n + 64n);
                const prefix = 4n + 2n + body.saltBytes + 4n * 4n;
                const bodyRecords = body.polynomials.reduce(
                    (count, polynomial) =>
                        count + (polynomial.bytes + chunk - 1n) / chunk,
                    0n,
                );
                const signingReferences = 5n * (2n + 4n + 32n + 64n);
                expect(custody.maximumCompletedMetadataBytes).toBe(
                    prefix +
                        storage.completedBodyHeaderBytes +
                        referenceBytes * (bodyRecords + records) +
                        signingReferences,
                );
                expect(custody.maximumPublicBodyCiphertextBytes).toBe(
                    body.polynomialPayloadBytes +
                        body.maximumProofBytes +
                        16n * (bodyRecords + records),
                );
            }
        },
    );

    it.each(Array.from({ length: 18 }, (_unused, index) => index + 3))(
        'recomputes checkpoint and later-root maxima at roster %i',
        (participantCount) => {
            const enrollment = compileRegistrationEnrollmentCensus();
            const target = compileTargetSigningStateCensus();
            for (const profile of listSupportedProfiles().filter(
                (value) => value.participantCount === participantCount,
            )) {
                const { body, custody: current } = custodyCase(profile);
                const checkpoint = compileFirstOracleCheckpointCensus(profile);
                const ballot = compileParticipantBallotCustody(profile);
                const close = compileParticipantCloseCustody(profile);
                const release = compileParticipantReleaseCustody(profile);
                const chunk = 1n << 20n;
                const bodyRecords = body.polynomials.reduce(
                    (total, polynomial) =>
                        total + (polynomial.bytes + chunk - 1n) / chunk,
                    0n,
                );
                const proofRecords =
                    (body.maximumProofBytes + chunk - 1n) / chunk;
                const prefix = 4n + 2n + body.saltBytes + 16n;
                const checkpointBytes =
                    prefix +
                    checkpoint.maximumHeaderBytes +
                    106n * bodyRecords +
                    96n * checkpoint.recordCount +
                    64n;
                const completedBefore =
                    prefix + 106n * (bodyRecords + proofRecords) + 5n * 102n;
                const maximum = (...values: bigint[]) =>
                    values.reduce((largest, value) =>
                        value > largest ? value : largest,
                    );
                const completedBallot = ballot.phaseBytes.find(
                    (phase) => phase.phase === 17,
                )!.bytes;
                const root = (completed: bigint) =>
                    enrollment.manifestPrefixBytes +
                    73n * (enrollment.maximumRecords + 2n) +
                    4n +
                    16n +
                    maximum(
                        checkpointBytes,
                        completed,
                        completed +
                            8n +
                            ballot.maximumStateBytes +
                            close.collectingBytes,
                        completed +
                            16n +
                            completedBallot +
                            close.maximumStateBytes +
                            target.maximumStateBytes +
                            release.maximumStateBytes,
                    );
                expect(current.maximumCheckpointMetadataBytes).toBe(
                    checkpointBytes,
                );
                expect(current.maximumMetadataBytes).toBe(
                    maximum(
                        checkpointBytes,
                        completedBefore + body.headerBytes,
                    ),
                );
                expect(current.completedHeaderStateDeltaBytes).toBe(
                    maximum(
                        checkpointBytes,
                        completedBefore + body.headerBytes,
                    ) - maximum(checkpointBytes, completedBefore),
                );
                expect(current.maximumRootBytes).toBe(
                    root(completedBefore + body.headerBytes),
                );
                const rootDelta =
                    current.maximumRootBytes - root(completedBefore);
                expect(current.completedHeaderRootDeltaBytes).toBe(rootDelta);
                expect(rootDelta).toBeGreaterThanOrEqual(0n);
                expect(rootDelta).toBeLessThanOrEqual(body.headerBytes);
            }
        },
    );

    it('projects padding, new record keys and complete read passes from a supplied proof length', () => {
        const profile = completionProfile();
        const body = compileContributionBodyCensus(profile);
        const chunk = 1n << 20n;
        const slots = (body.maximumProofBytes + chunk - 1n) / chunk;
        const lastOffset = (slots - 1n) * chunk;
        // Hypothetical coordinates test byte accounting at slot boundaries;
        // they are not measured lengths or claims that those proofs exist.
        for (const length of [
            body.maximumProofBytes,
            body.maximumProofBytes - 1n,
            lastOffset - 1n,
            lastOffset,
            lastOffset + 1n,
        ]) {
            const oldSlots = (length + chunk - 1n) / chunk;
            const added = slots - oldSlots;
            const expectedCiphertextDelta =
                body.maximumProofBytes - length + 16n * added;
            for (const passes of [0n, 1n, 2n, 5n]) {
                const projection = projectContributionProofPadding(
                    profile,
                    length,
                    passes,
                );
                expect(projection.paddingBytes).toBe(
                    body.maximumProofBytes - length,
                );
                expect(projection.additionalProofRecords).toBe(added);
                expect(projection.additionalProofRecordKeyBytes).toBe(
                    32n * added,
                );
                expect(projection.additionalProofRecordIdentityBytes).toBe(
                    64n * added,
                );
                expect(projection.additionalProofRecordTagBytes).toBe(
                    16n * added,
                );
                expect(projection.additionalProofCiphertextBytes).toBe(
                    expectedCiphertextDelta,
                );
                expect(projection.additionalCompletedRootBytes).toBe(
                    body.headerBytes + 106n * added,
                );
                expect(projection.additionalProofWriteBytes).toBe(
                    expectedCiphertextDelta,
                );
                expect(projection.additionalProofReadBytes).toBe(
                    passes * expectedCiphertextDelta,
                );
                expect(projection.additionalProofVerificationCalls).toBe(
                    passes * added,
                );
                expect(projection.publishedProofBytes).toBe(length);
            }
        }
        expect(() =>
            projectContributionProofPadding(
                profile,
                body.minimumProofBytes - 1n,
                1n,
            ),
        ).toThrow('bounds');
        expect(() =>
            projectContributionProofPadding(
                profile,
                body.maximumProofBytes + 1n,
                1n,
            ),
        ).toThrow('bounds');
        expect(() =>
            projectContributionProofPadding(
                profile,
                body.maximumProofBytes,
                -1n,
            ),
        ).toThrow('bounds');
    });

    it('carries the complete existing private checkpoint without exceeding the root or storage bounds', () => {
        const value = compileParticipantCustodyCensus(completionProfile());
        const checkpoint =
            compileFirstOracleCheckpointCensus(completionProfile());
        expect(BigInt(value.checkpointLengths.length)).toBe(
            checkpoint.recordCount,
        );
        expect(
            value.checkpointLengths.reduce(
                (total, length) => total + length,
                0n,
            ),
        ).toBe(checkpoint.ciphertextBytes);
        expect(value.maximumRootBytes).toBeLessThan(1_572_864n);
        expect(value.maximumRetainedPayloadBytes).toBeLessThan(2_147_483_648n);
    });

    it('bounds the continuation intent with its checkpoint and its randomness seed', () => {
        const value = compileParticipantCustodyCensus(completionProfile());
        const checkpoint =
            compileFirstOracleCheckpointCensus(completionProfile());
        const body = compileContributionBodyCensus(completionProfile());
        // The marker, position, salt and four counts, the checkpoint header,
        // each body record's object, offset, length, key and hash, each
        // checkpoint record's key and hash, and the 512-bit seed.
        const expected =
            4n +
            2n +
            body.saltBytes +
            16n +
            checkpoint.maximumHeaderBytes +
            (2n + 4n + 4n + 32n + 64n) * BigInt(value.publicRecords.length) +
            (32n + 64n) * checkpoint.recordCount +
            512n / 8n;
        expect(value.maximumCheckpointMetadataBytes).toBe(expected);
        expect(value.maximumMetadataBytes).toBeGreaterThanOrEqual(expected);
    });

    it('counts repeated reads as work without inventing new AES inputs', () => {
        const first = { nonce: 0n, plaintextBytes: 17n, associatedBytes: 1n };
        const second = { nonce: 1n, plaintextBytes: 1n, associatedBytes: 0n };
        const value = compileGcmKeyHistory([first, second], [first, first]);
        // Independently enumerate full AES input blocks, including H and J0.
        const inputs = new Set(['0:0']);
        for (const [nonce, payload] of [
            [0, 2],
            [1, 1],
        ])
            for (let counter = 1; counter <= payload + 1; counter++)
                inputs.add(`${nonce}:${counter}`);
        expect(value.distinctAesInputUpperBound).toBe(BigInt(inputs.size));
        expect(value.algorithmicAesCallUpperBound).toBe(4n + 3n + 4n + 4n);
        expect(value.permutationSwitchNumerator).toBe(15n);
        expect(value.authenticationNumerator).toBe(8n);
        expect(value.statisticalDenominator).toBe(2n ** 128n);
    });

    it('rejects encryption nonce reuse while allowing verification-only and empty histories', () => {
        const empty = {
            nonce: (1n << 96n) - 1n,
            plaintextBytes: 0n,
            associatedBytes: 0n,
        };
        expect(() => compileGcmKeyHistory([empty, empty], [])).toThrow(
            'reused',
        );
        expect(
            compileGcmKeyHistory([], [empty]).distinctAesInputUpperBound,
        ).toBe(2n);
        expect(compileGcmKeyHistory([], []).algorithmicAesCallUpperBound).toBe(
            0n,
        );
        expect(compileGcmKeyHistory([], []).permutationSwitchNumerator).toBe(
            0n,
        );
        for (const changed of [
            { ...empty, nonce: 1n << 96n },
            { ...empty, plaintextBytes: (1n << 36n) - 31n },
            { ...empty, associatedBytes: 1n << 61n },
            { ...empty, plaintextBytes: -1n },
        ])
            expect(() => compileGcmKeyHistory([changed], [])).toThrow('bounds');
        expect(
            compileGcmKeyHistory(
                [{ ...empty, plaintextBytes: (1n << 36n) - 32n }],
                [],
            ).distinctAesInputUpperBound,
        ).toBe(1n << 32n);
    });

    it('leaves lifetime key and read populations unknown across the complete emitted custody graph', () => {
        const classes = compileParticipantVaultKeyClasses(completionProfile());
        expect(classes.map((value) => value.name)).toEqual([
            'Initial root',
            'Later root',
            'Recipient capsule',
            'Signing capsule',
            'FHE source capsule',
            'Contribution body record',
            'Contribution checkpoint record',
            'Contribution signing record',
            'Ballot body record',
            'Release body record',
        ]);
        expect(
            classes.every(
                (value) =>
                    value.lifetimeKeys === null &&
                    value.lifetimeVerifications === null,
            ),
        ).toBe(true);
        expect(
            classes.find((value) => value.name === 'Later root')!
                .maximumPerCompletedCorpus,
        ).toBeNull();
        expect(classes[0].encryptionWork.invocations).toBe(2n);
        expect(
            classes
                .slice(1)
                .every((value) => value.encryptionWork.invocations === 1n),
        ).toBe(true);
        expect(classes[3].encryptionWork.distinctAesInputUpperBound).toBe(5n);
    });

    it('includes target-bound release records without turning corpus maxima into lifetime limits', () => {
        const classes = compileParticipantVaultKeyClasses(completionProfile());
        const release = compileParticipantReleaseCustody(completionProfile());
        // The poll, runtime and setup inventory, the position, the certified
        // target digest, and the record's index and length.
        const associatedBytes = Buffer.concat([
            Buffer.from('sealed-lattice/participant-release-record/v2'),
            Buffer.alloc(64),
            Buffer.alloc(64),
            Buffer.alloc(64),
            Buffer.alloc(2),
            Buffer.alloc(64),
            Buffer.alloc(2),
            Buffer.alloc(4),
        ]);
        for (const [name, maximumRecords] of [
            ['Release body record', release.maximumBodyRecords],
        ] as const) {
            const value = classes.find((entry) => entry.name === name);
            expect(value, name).toBeDefined();
            expect(value!.maximumPerCompletedCorpus).toBe(maximumRecords);
            expect(value!.encryptions).toEqual([
                {
                    nonce: 0n,
                    plaintextBytes: 1_048_576n,
                    associatedBytes: BigInt(associatedBytes.length),
                },
            ]);
            expect(value!.encryptionWork.maximumHashDegree).toBe(
                65_536n + BigInt(Math.ceil(associatedBytes.length / 16)) + 1n,
            );
            expect(value!.lifetimeKeys).toBeNull();
            expect(value!.lifetimeVerifications).toBeNull();
        }
    });
});
