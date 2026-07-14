import { describe, expect, it } from 'vitest';

import {
    decodeAggregateThresholdShareRecord,
    encodeAggregateThresholdShareRecord,
} from '#packages/protocol/src/setup/local-trustee-aggregate-threshold-share-record';
import type { LocalTrusteeVssPublicAggregateOpeningCredentialHandoff } from '#packages/protocol/src/setup/vss-commitments';
import { makeSetupFixtureHash } from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash(
    'local-trustee-aggregate-threshold-share-record',
);
const trusteeIdentity = 'North trustee π';

const credential = (rnsLimbIndex: number) =>
    ({
        objectType: 'LocalTrusteeVssPublicAggregateOpeningCredential',
        recipientIdentity: trusteeIdentity,
        recipientRosterPosition: 3,
        rnsLimbIndex,
        rnsPrime: 65_537 + rnsLimbIndex * 2,
        aggregateCommitmentRoot: fixtureHash(
            `aggregate-commitment-${String(rnsLimbIndex)}`,
        ),
        aggregateOpeningRoot: fixtureHash(
            `aggregate-opening-${String(rnsLimbIndex)}`,
        ),
        aggregateCommitmentMessageValuesLeHex:
            rnsLimbIndex === 0
                ? '0100000000000000ffffffffffff1f00'
                : '02000000000000000300000000000000',
        aggregateMaterialSeedHex: fixtureHash(
            `aggregate-material-${String(rnsLimbIndex)}`,
        ),
    }) as const;

const handoff = (): LocalTrusteeVssPublicAggregateOpeningCredentialHandoff => ({
    objectType: 'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff',
    trusteeIdentity,
    trusteeRosterPosition: 3,
    aggregateOpeningCredentials: [credential(0), credential(1)],
});

describe('aggregate threshold-share local-record codec', () => {
    it('round-trips ordered credentials with canonical UTF-8 and binary material', () => {
        const encoded = encodeAggregateThresholdShareRecord(handoff());
        const decoded = decodeAggregateThresholdShareRecord(encoded);

        expect(decoded).toEqual(handoff());
        expect(encodeAggregateThresholdShareRecord(decoded)).toEqual(encoded);
    });

    it('rejects non-canonical lengths, trailing bytes, wrong magic, and reordered limbs', () => {
        const encoded = encodeAggregateThresholdShareRecord(handoff());
        const nonCanonicalIdentityLength = new Uint8Array(
            encoded.byteLength + 1,
        );
        nonCanonicalIdentityLength.set(encoded.subarray(0, 8));
        nonCanonicalIdentityLength.set([encoded[8] | 0x80, 0], 8);
        nonCanonicalIdentityLength.set(encoded.subarray(9), 10);

        expect(() =>
            decodeAggregateThresholdShareRecord(nonCanonicalIdentityLength),
        ).toThrow(/non-canonical varuint/u);
        expect(() =>
            decodeAggregateThresholdShareRecord(
                new Uint8Array([...encoded, 0]),
            ),
        ).toThrow(/trailing bytes/u);
        const wrongMagic = encoded.slice();
        wrongMagic[0] ^= 1;
        expect(() => decodeAggregateThresholdShareRecord(wrongMagic)).toThrow(
            /wrong magic/u,
        );
        expect(() =>
            encodeAggregateThresholdShareRecord({
                ...handoff(),
                aggregateOpeningCredentials: [credential(1), credential(0)],
            }),
        ).toThrow(/increasing RNS limb index/u);
    });

    it('rejects credentials rebound to another trustee or without complete share bytes', () => {
        expect(() =>
            encodeAggregateThresholdShareRecord({
                ...handoff(),
                aggregateOpeningCredentials: [
                    { ...credential(0), recipientIdentity: 'South trustee' },
                ],
            }),
        ).toThrow(/belong to the local trustee/u);
        expect(() =>
            encodeAggregateThresholdShareRecord({
                ...handoff(),
                aggregateOpeningCredentials: [
                    {
                        ...credential(0),
                        aggregateCommitmentMessageValuesLeHex: '',
                    },
                ],
            }),
        ).toThrow(/non-empty vector/u);
    });
});
