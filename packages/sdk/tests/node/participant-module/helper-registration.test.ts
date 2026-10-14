import { createHash } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { custodyPurpose } from '#packages/sdk/src/participant/worker/module/custody-identity.js';
import {
    noParallelHelpers,
    startParallelHelpers,
} from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import type { ParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import {
    instantiateParticipantModule,
    readModuleMemory,
    writeInput,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { readParticipantLimits } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    concatenate,
    unsigned16,
    unsigned32,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import { ResourceFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import {
    registrationFile,
    registrationCandidateKey,
    streamRegistrations,
    verifiedRosterUsernames,
} from '#packages/sdk/src/participant/worker/stages/roster/roster.js';
import { dataKind } from '#packages/sdk/src/participant/worker/storage/root.js';
import { useHelperWorkers } from '#packages/sdk/tests/node/participant-module/helper-workers-fixture.js';
import {
    participantModule,
    failureOf,
    shake,
} from '#packages/sdk/tests/node/participant-module/packaged-participant-fixture.js';
import { participantRelayFixture } from '#packages/sdk/tests/participant-relay-fixture.js';
import {
    ascii,
    item,
    itemType,
    tuple,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';

const registrationHelpers = useHelperWorkers();

const runtimeIdentity = shake('runtime', 64);

type Enrollment = Readonly<{
    poll: Uint8Array;
    records: ReadonlyMap<number, Uint8Array>;
    requests: number;
}>;

type JoinedPoll = Readonly<{
    poll: Uint8Array;
    definition: Uint8Array;
    signature: Uint8Array;
}>;

type ParticipantInstance = Awaited<
    ReturnType<typeof instantiateParticipantModule>
>;

// Validates and prepares an enrollment in the instance.
const prepare = (
    { module, handlers }: ParticipantInstance,
    name: string,
    joining?: JoinedPoll,
): Enrollment => {
    const username = new TextEncoder().encode(name);
    const input =
        joining === undefined
            ? concatenate(
                  runtimeIdentity,
                  unsigned16(1),
                  unsigned16(3),
                  pollText,
                  unsigned32(username.length),
                  username,
              )
            : concatenate(
                  joining.poll,
                  runtimeIdentity,
                  unsigned32(joining.definition.length),
                  joining.definition,
                  joining.signature,
                  unsigned32(username.length),
                  username,
              );
    writeInput(module, input);
    expect(
        joining === undefined
            ? module.validate_organizer(input.length)
            : module.validate_joiner(input.length),
    ).toBe(0);
    const parts = new Map<number, Uint8Array[]>();
    handlers.staged = (kind, _offset, bytes) => {
        parts.set(kind, [...(parts.get(kind) ?? []), bytes.slice()]);
    };
    let requests = 0;
    handlers.random = (target) => {
        target.set(shake(name + '/' + String(requests), target.length));
        requests += 1;
    };
    writeInput(module, input);
    expect(
        joining === undefined
            ? module.prepare_organizer(input.length)
            : module.prepare_joiner(input.length),
    ).toBe(0);
    return {
        poll: readModuleMemory(module, module.poll_identity_pointer(), 64),
        records: new Map(
            [...parts].map(([kind, chunks]) => [kind, concatenate(...chunks)]),
        ),
        requests,
    };
};

const enroll = async (
    helpers: ParallelHelpers,
    name: string,
    joining?: JoinedPoll,
) =>
    prepare(
        await instantiateParticipantModule(participantModule, helpers),
        name,
        joining,
    );

// The poll's question and its two option labels as the organizer input frames
// them: each text after its four-byte length, the labels after their count.
const framedText = (value: string) => {
    const bytes = new TextEncoder().encode(value);
    return concatenate(unsigned32(bytes.length), bytes);
};

const pollText = concatenate(
    framedText('Which option leads?'),
    unsigned16(2),
    framedText('Option 0'),
    framedText('Option 1'),
);

// Independent foundation tuple framing of the exact signed registration body.
const registrationIdentity = (records: ReadonlyMap<number, Uint8Array>) =>
    createHash('shake256', { outputLength: 64 })
        .update(
            tuple([
                ascii('sealed-lattice/registration-body/v2'),
                item(
                    itemType.rawBytes,
                    variable(records.get(dataKind.header)!),
                ),
            ]),
        )
        .digest('hex');

// A roster verifier's verdict on the registrations, streamed as the worker
// streams them from its relay: the proposal body it accepts, or undefined
// when a step or the roster is refused.
const verifyRoster = async (
    helpers: ParallelHelpers,
    poll: JoinedPoll,
    registrations: readonly ReadonlyMap<number, Uint8Array>[],
    registrationBodyDigests: readonly string[],
) => {
    const { module } = await instantiateParticipantModule(
        participantModule,
        helpers,
    );
    const begin = concatenate(
        poll.poll,
        runtimeIdentity,
        unsigned16(registrations.length),
        unsigned32(poll.definition.length),
        poll.definition,
        poll.signature,
    );
    writeInput(module, begin);
    expect(module.roster_begin(begin.length)).toBe(0);
    const transport = participantRelayFixture();
    for (const [position, records] of registrations.entries()) {
        const files = new Map(
            [
                [registrationFile.header, dataKind.header],
                [registrationFile.signature, dataKind.signature],
                [registrationFile.publicKey, dataKind.publicKey],
            ].map(
                ([file, kind]) =>
                    [file as string, records.get(kind as number)!] as const,
            ),
        );
        const key = registrationCandidateKey(registrationBodyDigests[position]);
        // A complete transport manifest can still carry an incomplete key.
        // The owning verifier must discard that attempt and accept later bytes.
        transport.publish(
            key,
            new Map([
                ...files,
                [
                    registrationFile.publicKey,
                    records.get(dataKind.publicKey)!.subarray(0, 9),
                ],
            ]),
        );
        transport.publish(key, files);
    }
    const relay = { base: 'https://relay.test/' };
    const served = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation((request, options) =>
            transport.fetch(request as string, options),
        );
    try {
        await streamRegistrations(
            relay,
            registrationBodyDigests,
            readParticipantLimits(module).registration,
            module.roster_open_records(),
            (operation, position, bytes) => {
                writeInput(module, bytes);
                return (
                    module.roster_record(operation, position, bytes.length) ===
                    0
                );
            },
        );
    } catch {
        return undefined;
    } finally {
        served.mockRestore();
    }
    return module.roster_finish() === 0
        ? {
              body: readModuleMemory(
                  module,
                  module.roster_body_pointer(),
                  module.roster_body_length(),
              ),
              usernames: verifiedRosterUsernames(module),
          }
        : undefined;
};

// Runs an operation with three fresh helpers, as each operation's worker
// has its own.
const withHelpers = async <Value>(
    operation: (helpers: ParallelHelpers) => Promise<Value>,
) => {
    const helpers = await startParallelHelpers(
        participantModule,
        registrationHelpers.ports(3),
        false,
    );
    expect(helpers.count).toBe(3);
    try {
        return await operation(helpers);
    } finally {
        helpers.stop();
    }
};

// A copy of the registrations with one byte of one record changed.
const changed = (
    registrations: readonly ReadonlyMap<number, Uint8Array>[],
    position: number,
    kind: number,
    offset: number,
) =>
    registrations.map((records, index) => {
        if (index !== position) return records;
        const bytes = records.get(kind)!.slice();
        bytes[offset] ^= 1;
        return new Map([...records, [kind, bytes]]);
    });

describe('participant helpers with registration work', () => {
    it('generate the registration the worker generates alone, and verify true and false rosters as it does', async () => {
        const alone = await enroll(noParallelHelpers, 'Organizer');
        const organizer = await withHelpers((helpers) =>
            enroll(helpers, 'Organizer'),
        );
        expect(organizer.requests).toBe(alone.requests);
        expect(organizer.poll).toEqual(alone.poll);
        expect([...organizer.records.keys()].sort()).toEqual(
            [...alone.records.keys()].sort(),
        );
        for (const [kind, bytes] of alone.records)
            expect(
                Buffer.from(organizer.records.get(kind)!).equals(
                    Buffer.from(bytes),
                ),
                'staged record ' + String(kind),
            ).toBe(true);
        const poll = {
            poll: organizer.poll,
            definition: organizer.records.get(dataKind.pollDefinition)!,
            signature: organizer.records.get(dataKind.pollSignature)!,
        };
        const registrations = [organizer.records];
        for (const name of ['First voter', 'Second voter'])
            registrations.push(
                (await withHelpers((helpers) => enroll(helpers, name, poll)))
                    .records,
            );
        const registrationBodyDigests = registrations.map(registrationIdentity);
        // The true roster, a public key coefficient changed and a signature changed.
        for (const [candidate, accepted] of [
            [registrations, true],

            [changed(registrations, 2, dataKind.publicKey, 1000), false],
            [changed(registrations, 0, dataKind.signature, 7), false],
            [[registrations[0], registrations[2], registrations[1]], false],
        ] as const) {
            const verdictAlone = await verifyRoster(
                noParallelHelpers,
                poll,
                candidate,
                registrationBodyDigests,
            );
            expect(verdictAlone !== undefined).toBe(accepted);
            // The verified roster names its registrations' usernames in
            // roster order.
            expect(verdictAlone?.usernames).toEqual(
                accepted
                    ? ['Organizer', 'First voter', 'Second voter']
                    : undefined,
            );
            expect(
                await withHelpers((helpers) =>
                    verifyRoster(
                        helpers,
                        poll,
                        candidate,
                        registrationBodyDigests,
                    ),
                ),
            ).toEqual(verdictAlone);
        }
        // The poll admits at most three participants, so the roster
        // verifier refuses a roster of four before reading any record.
        const { module } = await instantiateParticipantModule(
            participantModule,
            noParallelHelpers,
        );
        for (const [count, refusal] of [
            [4, 1],
            [3, 0],
        ]) {
            const begin = concatenate(
                poll.poll,
                runtimeIdentity,
                unsigned16(count),
                unsigned32(poll.definition.length),
                poll.definition,
                poll.signature,
            );
            writeInput(module, begin);
            expect(module.roster_begin(begin.length)).toBe(refusal);
        }
    });

    it('end the call whose job failed, and its instance refuses every later call', async () => {
        const helpers = await startParallelHelpers(
            participantModule,
            registrationHelpers.ports(2),
            false,
        );
        expect(helpers.count).toBe(2);
        // Every job names a kind no helper runs.
        const failing: ParallelHelpers = {
            ...helpers,
            imports: (memory) => {
                const imports = helpers.imports(memory) as Record<
                    string,
                    (...values: number[]) => number
                >;
                return {
                    ...imports,
                    submit: (_kind: number, ...values: number[]) =>
                        imports.submit(0xffff, ...values),
                };
            },
        };
        try {
            const instance = await instantiateParticipantModule(
                participantModule,
                failing,
            );
            const failure = failureOf(() => prepare(instance, 'Organizer'));
            expect(failure).toBeInstanceOf(ResourceFailure);
            expect((failure as Error).message).toBe(
                'A participant helper failed.',
            );
            expect(
                failureOf(() =>
                    instance.module.custody_identity_input_capacity(),
                ),
            ).toBe(failure);
            expect(
                failureOf(() =>
                    instance.module.custody_identity_begin(
                        custodyPurpose.root,
                        0,
                    ),
                ),
            ).toBe(failure);
        } finally {
            helpers.stop();
        }
        // A later operation's fresh helpers and instance complete the
        // enrollment.
        await withHelpers((fresh) => enroll(fresh, 'Organizer'));
    });
});
