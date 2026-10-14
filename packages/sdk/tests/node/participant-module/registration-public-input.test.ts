import { describe, expect, it } from 'vitest';

import {
    readModuleMemory,
    writeInput,
    writeOwnRegistrationInput,
    writeSetupInput,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { chunkBytes } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    concatenate,
    encodeText,
    unsigned16,
    unsigned32,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import {
    instantiate,
    shake,
    draws,
    changedByte,
    call,
    framedText,
    organizerName,
    organizer,
    pollContext,
    minimumParticipants,
    joinInput,
    rosterBegin,
    recordBegin,
} from '#packages/sdk/tests/node/participant-module/public-input-fixture.js';

describe('participant module public input', () => {
    it('refuses every join and roster input with a changed byte, length or roster count', async () => {
        const { module } = await instantiate();
        const join = joinInput('First voter');
        // The username is the voter's own and may change to another valid
        // one; every earlier byte is the poll's or a length.
        const usernameStart = join.length - encodeText('First voter').length;
        const begin = rosterBegin(minimumParticipants);
        // The roster count is the verifier's request, not the poll's.
        const countOffset = 128;
        for (let index = 0; index < 48; index += 1) {
            const label = 'changed/' + String(index);
            const draw = draws(label);
            const changedJoin = changedByte(
                join,
                draw(usernameStart),
                1 + draw(255),
            );
            writeInput(module, changedJoin);
            expect(module.validate_joiner(changedJoin.length), label).toBe(1);
            const offset = draw(begin.length - 2);
            const changedBegin = changedByte(
                begin,
                offset < countOffset ? offset : offset + 2,
                1 + draw(255),
            );
            writeInput(module, changedBegin);
            expect(module.roster_begin(changedBegin.length), label).toBe(1);
            writeSetupInput(module, changedBegin);
            expect(module.setup_roster_begin(changedBegin.length), label).toBe(
                1,
            );
            // A shorter or longer length over the genuine bytes.
            const shift = 1 + draw(2048);
            writeInput(module, join);
            for (const length of [join.length - shift, join.length + shift])
                expect(module.validate_joiner(length), label).toBe(1);
            writeInput(module, begin);
            for (const length of [begin.length - shift, begin.length + shift])
                expect(module.roster_begin(length), label).toBe(1);
        }
        // The poll admits only the smallest roster.
        for (const count of [
            0,
            1,
            minimumParticipants - 1,
            minimumParticipants + 1,
            organizer.limits.participants.maximum,
            organizer.limits.participants.maximum + 1,
            0xffff,
        ].filter((value) => value !== minimumParticipants)) {
            const counted = rosterBegin(count);
            writeInput(module, counted);
            expect(module.roster_begin(counted.length), String(count)).toBe(1);
            writeSetupInput(module, counted);
            expect(
                module.setup_roster_begin(counted.length),
                String(count),
            ).toBe(1);
        }
        writeInput(module, join);
        expect(module.validate_joiner(join.length)).toBe(0);
        writeInput(module, begin);
        expect(module.roster_begin(begin.length)).toBe(0);
        writeSetupInput(module, begin);
        expect(module.setup_roster_begin(begin.length)).toBe(0);
    });

    it('takes the genuine registration record before and after arbitrary record steps that do not end the instance', async () => {
        const { module } = await instantiate();
        const begin = rosterBegin(minimumParticipants);
        // Each step of the genuine record in a new roster verification.
        const genuineRecord = () => {
            writeInput(module, begin);
            expect(module.roster_begin(begin.length)).toBe(0);
            const step = (
                operation: number,
                bytes: Uint8Array = new Uint8Array(),
            ) => {
                writeInput(module, bytes);
                return module.roster_record(operation, 0, bytes.length);
            };
            // The key in the worker's streamed parts.
            const streamed = (operation: number, bytes: Uint8Array) => {
                const results: number[] = [];
                for (
                    let offset = 0;
                    offset < bytes.length;
                    offset += chunkBytes
                )
                    results.push(
                        step(
                            operation,
                            bytes.subarray(offset, offset + chunkBytes),
                        ),
                    );
                return results;
            };
            const steps = [
                step(0, recordBegin),
                ...streamed(1, organizer.publicKey),
            ];
            steps.push(step(2));
            steps.push(step(4));
            return steps;
        };
        const accepted = genuineRecord();
        expect(accepted.every((result) => result === 0)).toBe(true);
        const pieces = [recordBegin, organizer.publicKey];
        const positions = [
            0,
            1,
            minimumParticipants - 1,
            minimumParticipants,
            0xffff,
            0xffff_ffff,
        ];
        for (let sequence = 0; sequence < 8; sequence += 1) {
            writeInput(module, begin);
            expect(module.roster_begin(begin.length)).toBe(0);
            for (let step = 0; step < 32; step += 1) {
                const label = `record/${String(sequence)}/${String(step)}`;
                const draw = draws(label);
                // A part of a genuine record, sometimes changed, or bytes no
                // record holds.
                const piece = pieces[draw(pieces.length)];
                const start = draw(piece.length);
                const part = piece.subarray(
                    start,
                    start + draw(Math.min(piece.length - start, 1 << 16) + 1),
                );
                const bytes =
                    draw(4) === 0
                        ? shake(label + '/bytes', part.length + 1)
                        : part.length > 0 && draw(2) === 0
                          ? changedByte(part, draw(part.length), 1 + draw(255))
                          : part;
                writeInput(module, bytes);
                call(
                    module,
                    'roster_record',
                    [draw(6), positions[draw(positions.length)], bytes.length],
                    label,
                );
            }
            expect(module.roster_finish()).toBe(1);
        }
        expect(genuineRecord()).toEqual(accepted);
    });

    it('refuses every changed registration record and a second begin in its own registration verification, and verifies the genuine record however it is divided', async () => {
        type RegistrationRecord = Readonly<{
            header: Uint8Array;
            signature: Uint8Array;
            publicKey: Uint8Array;
        }>;
        // Streams a record in parts of drawn sizes, the first few small so
        // that parts end inside encoded key coefficients; a fresh instance
        // verifies each record, as a verified registration is final.
        const verify = async (record: RegistrationRecord, label: string) => {
            const { module } = await instantiate();
            const draw = draws(label + '/parts');
            const parts = (bytes: Uint8Array) => {
                const divided: Uint8Array[] = [];
                for (let offset = 0; offset < bytes.length;) {
                    const size =
                        divided.length < 3
                            ? 1 + draw(64)
                            : 1 + draw(chunkBytes);
                    divided.push(bytes.subarray(offset, offset + size));
                    offset += size;
                }
                return divided;
            };
            const steps: (readonly [number, Uint8Array])[] = [
                [
                    0,
                    concatenate(
                        pollContext,
                        unsigned32(record.header.length),
                        record.header,
                        record.signature,
                    ),
                ],
                ...parts(record.publicKey).map((part) => [1, part] as const),
                [2, new Uint8Array()],
                [4, new Uint8Array()],
            ];
            // The poll the module verified the registration against, which
            // it reports only once the registration verifies.
            const verifiedPoll = () =>
                module.own_registration_poll() === 0
                    ? readModuleMemory(
                          module,
                          module.participant_output_pointer(),
                          module.participant_output_length(),
                      )
                    : undefined;
            // An accepted begin names the poll and the registration this
            // instance verifies, which a second begin cannot replace.
            const repeatedBegins: number[] = [];
            for (const [operation, bytes] of steps) {
                expect(verifiedPoll(), label).toBeUndefined();
                writeOwnRegistrationInput(module, bytes);
                if (
                    call(
                        module,
                        'own_registration_command',
                        [operation, bytes.length],
                        label,
                    ) !== 0
                )
                    return undefined;
                if (operation === 0) {
                    writeOwnRegistrationInput(module, bytes);
                    repeatedBegins.push(
                        call(
                            module,
                            'own_registration_command',
                            [0, bytes.length],
                            label,
                        ),
                    );
                }
            }
            expect(repeatedBegins, label).toEqual([1]);
            return {
                username: new TextDecoder().decode(
                    readModuleMemory(
                        module,
                        module.own_registration_username_pointer(),
                        module.own_registration_username_length(),
                    ),
                ),
                poll: verifiedPoll(),
            };
        };
        for (const [field, count] of [
            ['header', 2],
            ['signature', 1],
            ['publicKey', 1],
        ] as const)
            for (let index = 0; index < count; index += 1) {
                const label = `own/${field}/${String(index)}`;
                const draw = draws(label);
                const bytes = organizer[field];
                expect(
                    await verify(
                        {
                            ...organizer,
                            [field]: changedByte(
                                bytes,
                                draw(bytes.length),
                                1 + draw(255),
                            ),
                        },
                        label,
                    ),
                    label,
                ).toBeUndefined();
            }
        expect(
            await verify(
                {
                    ...organizer,
                    publicKey: organizer.publicKey.subarray(
                        0,
                        organizer.publicKey.length - 1,
                    ),
                },
                'own/shortened',
            ),
        ).toBeUndefined();
        // The verified poll is its result length, its question, its option
        // count and each option's identifier and label, the label in NFC.
        expect(await verify(organizer, 'own/genuine')).toEqual({
            username: organizerName,
            poll: concatenate(
                unsigned16(1),
                framedText('Which option leads?'),
                unsigned16(2),
                framedText('option-0'),
                framedText('Option 0'),
                framedText('option-1'),
                framedText('Caf\u00e9'),
            ),
        });
    });
});
