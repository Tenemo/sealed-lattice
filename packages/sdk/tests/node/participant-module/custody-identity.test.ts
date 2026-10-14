import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    custodyIdentity,
    custodyPurpose,
} from '#packages/sdk/src/participant/worker/module/custody-identity.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import { instantiateParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import {
    participantModule,
    payload as fixturePayload,
} from '#packages/sdk/tests/node/participant-module/packaged-participant-fixture.js';

// A custody identity as the foundation framing defines it, encoded here: the
// tuple header (schema 1, two items), the domain as an ASCII item
// (type 2) and the payload as a raw-bytes item (type 1), each item's length
// before its inner length, hashed with SHAKE256 to 64 bytes.
const independentIdentity = (domain: string, payload: Uint8Array) => {
    const label = Buffer.from(domain, 'ascii');
    const framing = Buffer.alloc(26 + label.length);
    let offset = framing.writeUInt16LE(1, 0);
    offset = framing.writeUInt32LE(2, offset);
    offset = framing.writeUInt16LE(2, offset);
    offset = framing.writeUInt32LE(4 + label.length, offset);
    offset = framing.writeUInt32LE(label.length, offset);
    offset += label.copy(framing, offset);
    offset = framing.writeUInt16LE(1, offset);
    offset = framing.writeUInt32LE(4 + payload.length, offset);
    framing.writeUInt32LE(payload.length, offset);
    return new Uint8Array(
        createHash('shake256', { outputLength: 64 })
            .update(framing)
            .update(payload)
            .digest(),
    );
};

const rootDomain = 'sealed-lattice/participant-root/v1';

// Lengths below, at and above the module's input buffer, and several whole
// buffers.
const payloadLengths = [
    0,
    1,
    65_535,
    65_536,
    65_537,
    1 << 20,
    (3 << 20) + 5,
] as const;

describe('participant custody identities', () => {
    it('encode the custody identity framing as its pinned independent vector', () => {
        // SHAKE256 over the empty public-polynomial identity, computed outside
        // the module.
        expect(
            Buffer.from(
                independentIdentity(
                    'sealed-lattice/public-polynomial/v1',
                    new Uint8Array(),
                ),
            ).toString('hex'),
        ).toBe(
            'ae4e93421e5300b846a0f24f8a8f637b190afbdd215153a94708eedf948717a047815cfac7aa5e4a01c4d9a6c9daabacdf892ec65fe2e95befb100ca4497c2e2',
        );
    });

    it('return the identities the independent framing yields', async () => {
        const { module } = await instantiateParticipantModule(
            participantModule,
            noParallelHelpers,
        );
        expect(
            payloadLengths.map((length) =>
                custodyIdentity(
                    module,
                    custodyPurpose.root,
                    fixturePayload(length),
                ),
            ),
        ).toEqual(
            payloadLengths.map((length) =>
                independentIdentity(rootDomain, fixturePayload(length)),
            ),
        );
    });

    it('name the target, envelope and close response by their own domains', async () => {
        const { module } = await instantiateParticipantModule(
            participantModule,
            noParallelHelpers,
        );
        // The domains of the identities a certified target, a ballot
        // submission and a proposal's named response are addressed by.
        const domains = [
            [
                custodyPurpose.target,
                'sealed-lattice/evaluation-target-identity/v1',
            ],
            [
                custodyPurpose.envelope,
                'sealed-lattice/ballot-envelope-identity/v1',
            ],
            [custodyPurpose.closeResponse, 'sealed-lattice/close-response/v1'],
        ] as const;
        for (const [purpose, domain] of domains)
            for (const length of [0, 1, 65_537])
                expect(
                    custodyIdentity(module, purpose, fixturePayload(length)),
                ).toEqual(independentIdentity(domain, fixturePayload(length)));
    });
});
