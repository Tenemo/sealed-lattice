import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { readParticipantLimits } from '#packages/sdk/src/participant/worker/bounds.js';
import {
    concatenate,
    encodeText,
    unsigned16,
    unsigned32,
} from '#packages/sdk/src/participant/worker/bytes.js';
import {
    instantiateParticipantKernel,
    moduleChunkBytes,
    readKernel,
    writeInput,
    writeOwnRegistrationInput,
    writeSetupInput,
} from '#packages/sdk/src/participant/worker/kernel.js';
import type { ParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import { dataKind } from '#packages/sdk/src/participant/worker/root.js';

// The packaged participant module, fed public input that no honest relay or
// participant produces. A command must refuse such input and return: a trap
// would end every visit that reads the same public bytes as pending.
const participantModule = await WebAssembly.compile(
    await readFile(
        new URL('../../../packages/sdk/dist/participant.wasm', import.meta.url),
    ),
);
const instantiate = () =>
    instantiateParticipantKernel(participantModule, noParallelHelpers);

// Every case derives its bytes and choices from its label, so a failing case
// replays from the label its failure names.
const shake = (label: string, length: number) =>
    new Uint8Array(
        createHash('shake256', { outputLength: length }).update(label).digest(),
    );
const draws = (label: string) => {
    let block = 0;
    let words = new DataView(new ArrayBuffer(0));
    let offset = 0;
    return (bound: number) => {
        if (offset === words.byteLength) {
            words = new DataView(
                shake(label + '#' + String(block), 256).buffer,
            );
            block += 1;
            offset = 0;
        }
        const value = words.getUint32(offset, true);
        offset += 4;
        return value % bound;
    };
};
const changedByte = (bytes: Uint8Array, offset: number, mask: number) => {
    const copy = bytes.slice();
    copy[offset] ^= mask;
    return copy;
};

type KernelCommand = Exclude<keyof ParticipantKernel, 'memory'>;
// Calls a command and names the case when the call does not return.
const call = (
    kernel: ParticipantKernel,
    name: KernelCommand,
    values: readonly number[],
    label: string,
) => {
    let failure: unknown;
    try {
        return kernel[name](...values);
    } catch (error) {
        failure = error;
    }
    throw new Error(
        `${label}: ${name}(${values.join(', ')}) did not return: ` +
            (failure instanceof Error ? failure.message : String(failure)),
    );
};

// The organizer's enrollment, whose public records every case changes.
const runtimeIdentity = shake('runtime', 64);
// The poll's question and its two option labels as the creator input frames
// them: each text after its four-byte length, the labels after their count.
// The second label is not in NFC, which the module applies once at ingress.
const framedText = (value: string) => {
    const bytes = encodeText(value);
    return concatenate(unsigned32(bytes.length), bytes);
};
const pollText = concatenate(
    framedText('Which option leads?'),
    unsigned16(2),
    framedText('Option 0'),
    framedText('Cafe\u0301'),
);
const organizerName = 'Organizer';
const organizer = await (async () => {
    const { kernel, handlers } = await instantiate();
    const limits = readParticipantLimits(kernel);
    const username = encodeText(organizerName);
    // The smallest roster the runtime supports is the poll's largest.
    const input = concatenate(
        runtimeIdentity,
        unsigned16(1),
        unsigned16(limits.participants.minimum),
        pollText,
        unsigned32(username.length),
        username,
    );
    writeInput(kernel, input);
    if (kernel.validate_creator(input.length) !== 0)
        throw new Error('The organizer input was refused.');
    const parts = new Map<number, Uint8Array[]>();
    handlers.staged = (kind, _offset, bytes) => {
        parts.set(kind, [...(parts.get(kind) ?? []), bytes.slice()]);
    };
    let requests = 0;
    handlers.random = (_source, target) => {
        target.set(
            shake(organizerName + '/' + String(requests), target.length),
        );
        requests += 1;
    };
    const control = concatenate(input, shake(organizerName + '/data-keys', 96));
    writeInput(kernel, control);
    if (kernel.prepare_creator(control.length) !== 0)
        throw new Error('The organizer enrollment was refused.');
    const record = (kind: number) => {
        const chunks = parts.get(kind);
        if (chunks === undefined)
            throw new Error('The enrollment staged no record ' + String(kind));
        return concatenate(...chunks);
    };
    return {
        limits,
        poll: readKernel(kernel, kernel.poll_identity_pointer(), 64),
        definition: record(dataKind.pollDefinition),
        definitionSignature: record(dataKind.pollSignature),
        header: record(dataKind.header),
        signature: record(dataKind.signature),
        publicKey: record(dataKind.publicKey),
        proof: record(dataKind.proof),
    };
})();
const pollContext = concatenate(
    organizer.poll,
    runtimeIdentity,
    unsigned32(organizer.definition.length),
    organizer.definition,
    organizer.definitionSignature,
);
const minimumParticipants = organizer.limits.participants.minimum;
const joinInput = (name: string) => {
    const username = encodeText(name);
    return concatenate(pollContext, unsigned32(username.length), username);
};
const rosterBegin = (count: number) =>
    concatenate(
        organizer.poll,
        runtimeIdentity,
        unsigned16(count),
        unsigned32(organizer.definition.length),
        organizer.definition,
        organizer.definitionSignature,
    );
const recordBegin = concatenate(
    unsigned16(0),
    unsigned32(organizer.header.length),
    organizer.header,
    organizer.signature,
);

// The module's input buffers and the commands that read public input from
// them. A command that reports acceptance with a nonzero value refuses with
// zero; every other command refuses with a nonzero value.
type InputBuffer = Readonly<{
    pointer: (kernel: ParticipantKernel) => number;
    capacity: (kernel: ParticipantKernel) => number;
}>;
const inputBuffers = {
    session: {
        pointer: (kernel) => kernel.input_pointer(),
        capacity: (kernel) => kernel.input_capacity(),
    },
    ownRegistration: {
        pointer: (kernel) => kernel.own_registration_input_pointer(),
        capacity: (kernel) => kernel.own_registration_input_capacity(),
    },
    setup: {
        pointer: (kernel) => kernel.setup_input_pointer(),
        capacity: (kernel) => kernel.setup_input_capacity(),
    },
    close: {
        pointer: (kernel) => kernel.close_input_pointer(),
        capacity: () => moduleChunkBytes,
    },
    ballot: {
        pointer: (kernel) => kernel.ballot_body_input_pointer(),
        capacity: () => moduleChunkBytes,
    },
    evaluation: {
        pointer: (kernel) => kernel.evaluation_target_input_pointer(),
        capacity: () => moduleChunkBytes,
    },
    completion: {
        pointer: (kernel) => kernel.completion_input_pointer(),
        capacity: () => moduleChunkBytes,
    },
} as const satisfies Record<string, InputBuffer>;
type Parameter = 'operation' | 'index' | 'length';
type PublicInputCommand = Readonly<{
    name: KernelCommand;
    buffer: keyof typeof inputBuffers;
    parameters: readonly Parameter[];
    acceptsWithNonzero?: true;
}>;
const publicInputCommands: readonly PublicInputCommand[] = [
    { name: 'validate_join', buffer: 'session', parameters: ['length'] },
    { name: 'roster_begin', buffer: 'session', parameters: ['length'] },
    {
        name: 'roster_record',
        buffer: 'session',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'roster_finish',
        buffer: 'session',
        parameters: [],
        acceptsWithNonzero: true,
    },
    {
        name: 'verify_roster_signature',
        buffer: 'session',
        parameters: ['length'],
        acceptsWithNonzero: true,
    },
    {
        name: 'participant_close_command',
        buffer: 'session',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'participant_finality_command',
        buffer: 'session',
        parameters: ['operation', 'length'],
    },
    {
        name: 'participant_release_command',
        buffer: 'session',
        parameters: ['operation', 'length'],
    },
    {
        name: 'own_registration_command',
        buffer: 'ownRegistration',
        parameters: ['operation', 'length'],
    },
    { name: 'setup_roster_begin', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_roster_record',
        buffer: 'setup',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'setup_roster_finish',
        buffer: 'setup',
        parameters: ['length'],
        acceptsWithNonzero: true,
    },
    { name: 'setup_offer_begin', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_offer_polynomial',
        buffer: 'setup',
        parameters: ['index', 'index', 'length'],
    },
    {
        name: 'setup_offer_proof',
        buffer: 'setup',
        parameters: ['index', 'length'],
    },
    {
        name: 'setup_offer_finish',
        buffer: 'setup',
        parameters: [],
        acceptsWithNonzero: true,
    },
    {
        name: 'setup_offer_available',
        buffer: 'setup',
        parameters: ['index', 'length'],
        acceptsWithNonzero: true,
    },
    { name: 'setup_selection_build', buffer: 'setup', parameters: ['length'] },
    { name: 'setup_selection_begin', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_selection_aggregate',
        buffer: 'setup',
        parameters: [],
        acceptsWithNonzero: true,
    },
    {
        name: 'setup_begin_selected_offer',
        buffer: 'setup',
        parameters: ['index'],
    },
    {
        name: 'setup_begin_selected_offer_verification',
        buffer: 'setup',
        parameters: ['length'],
    },
    {
        name: 'setup_polynomial',
        buffer: 'setup',
        parameters: ['index', 'index', 'length'],
    },
    {
        name: 'setup_selected_offer_proof',
        buffer: 'setup',
        parameters: ['index', 'length'],
    },
    {
        name: 'setup_finish_selected_offer',
        buffer: 'setup',
        parameters: [],
        acceptsWithNonzero: true,
    },
    {
        name: 'setup_selection_finish',
        buffer: 'setup',
        parameters: [],
        acceptsWithNonzero: true,
    },
    { name: 'setup_endorsement', buffer: 'setup', parameters: ['length'] },
    { name: 'setup_certificate_build', buffer: 'setup', parameters: [] },
    { name: 'setup_certificate', buffer: 'setup', parameters: ['length'] },
    {
        name: 'setup_finish_certificate',
        buffer: 'setup',
        parameters: [],
        acceptsWithNonzero: true,
    },
    {
        name: 'close_command',
        buffer: 'close',
        parameters: ['operation', 'length'],
    },
    {
        name: 'ballot_classification_begin',
        buffer: 'ballot',
        parameters: ['length'],
    },
    {
        name: 'ballot_classification_key_begin',
        buffer: 'ballot',
        parameters: ['index'],
    },
    {
        name: 'ballot_classification_key_chunk',
        buffer: 'ballot',
        parameters: ['length'],
    },
    {
        name: 'ballot_classification_key_finish',
        buffer: 'ballot',
        parameters: [],
    },
    {
        name: 'ballot_classification_chunk',
        buffer: 'ballot',
        parameters: ['length'],
    },
    {
        name: 'ballot_classification_finish',
        buffer: 'ballot',
        parameters: [],
        acceptsWithNonzero: true,
    },
    {
        name: 'evaluation_target_command',
        buffer: 'evaluation',
        parameters: ['operation', 'index', 'length'],
    },
    {
        name: 'completion_command',
        buffer: 'completion',
        parameters: ['operation', 'index', 'length'],
    },
];
// Values at and beyond the bounds the module checks, including those whose
// 32-bit sums wrap.
const boundaryValues = (capacity: number) => [
    0,
    1,
    2,
    3,
    4,
    6,
    8,
    64,
    132,
    3309,
    4096,
    65_535,
    65_536,
    capacity - 1,
    capacity,
    capacity + 1,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fff8,
    0xffff_ffff,
];
const drawArgument = (
    parameter: Parameter,
    draw: (bound: number) => number,
    capacity: number,
) => {
    const boundary = boundaryValues(capacity);
    if (draw(2) === 0) return boundary[draw(boundary.length)];
    if (parameter === 'operation') return draw(32);
    return draw(parameter === 'length' ? capacity + 1 : 64);
};
// The bytes each case writes before its call; a longer length also reads
// what earlier cases left in the buffer.
const writtenBytes = 16_384;

describe('participant module public input', () => {
    it('withholds offer and setup authority for partial carriers and proof bytes without a verified roster', async () => {
        const { kernel } = await instantiate();
        const signatureBytes = organizer.limits.registration.signatureBytes;
        const envelope = shake('unscoped-offer/envelope', 96);
        const selection = shake('unscoped-selection/body', 128);
        const carriers: readonly Readonly<{
            name:
                | 'setup_offer_begin'
                | 'setup_selection_begin'
                | 'setup_certificate';
            bytes: Uint8Array;
        }>[] = [
            { name: 'setup_offer_begin', bytes: unsigned32(0xffff_ffff) },
            {
                name: 'setup_offer_begin',
                bytes: concatenate(
                    unsigned32(envelope.length),
                    envelope,
                    new Uint8Array(signatureBytes - 1),
                ),
            },
            { name: 'setup_selection_begin', bytes: unsigned32(0xffff_ffff) },
            {
                name: 'setup_selection_begin',
                bytes: concatenate(
                    unsigned32(selection.length),
                    selection,
                    new Uint8Array(signatureBytes - 1),
                ),
            },
            { name: 'setup_certificate', bytes: encodeText('SSC1') },
            {
                name: 'setup_certificate',
                bytes: concatenate(encodeText('SSC1'), unsigned32(0xffff_ffff)),
            },
            {
                name: 'setup_certificate',
                bytes: concatenate(
                    encodeText('SSC1'),
                    unsigned32(selection.length),
                    selection,
                    new Uint8Array(signatureBytes),
                ),
            },
        ];
        // These are controls of the prerequisite boundary. Authenticated
        // roster/body/certificate controls run in the guarded complete cohort.
        for (const { name, bytes } of carriers) {
            writeSetupInput(kernel, bytes);
            expect(call(kernel, name, [bytes.length], name)).not.toBe(0);
            expect(kernel.setup_offer_finish()).toBe(0);
            expect(kernel.setup_selection_finish()).toBe(0);
            expect(kernel.setup_finish_certificate()).toBe(0);
            expect(kernel.setup_selection_count()).toBe(0);
            expect(kernel.setup_selection_position(0) >>> 0).toBe(0xffff_ffff);
            expect(kernel.setup_selection_body_identity_pointer(0)).toBe(0);
        }
        for (const length of [0, 1, 64, 4095]) {
            writeSetupInput(kernel, organizer.proof.subarray(0, length));
            expect(
                call(
                    kernel,
                    'setup_offer_proof',
                    [0, length],
                    `unscoped-proof/${String(length)}`,
                ),
            ).not.toBe(0);
            expect(kernel.setup_offer_finish()).toBe(0);
        }
        const begin = rosterBegin(minimumParticipants);
        writeSetupInput(kernel, begin);
        expect(kernel.setup_roster_begin(begin.length)).toBe(0);
    });

    it('refuses arbitrary arguments and bytes at every command that reads public input, and the instance stays usable', async () => {
        const { kernel } = await instantiate();
        // Open roster verifications give the record commands a verifier to
        // refuse in.
        const begin = rosterBegin(minimumParticipants);
        writeInput(kernel, begin);
        expect(kernel.roster_begin(begin.length)).toBe(0);
        writeSetupInput(kernel, begin);
        expect(kernel.setup_roster_begin(begin.length)).toBe(0);
        // Writes the case's bytes up to its length, the last argument, and
        // expects the command to refuse.
        const refuses = (
            command: PublicInputCommand,
            values: readonly number[],
            label: string,
        ) => {
            const buffer = inputBuffers[command.buffer];
            const length =
                values.length === 0
                    ? 0
                    : Math.min(
                          values[values.length - 1],
                          buffer.capacity(kernel),
                          writtenBytes,
                      );
            // The pointer call may grow the memory, so the view is taken
            // after it.
            const pointer = buffer.pointer(kernel) >>> 0;
            if (length > 0)
                new Uint8Array(kernel.memory.buffer, pointer, length).set(
                    shake(label + '/bytes', length),
                );
            const result = call(kernel, command.name, values, label);
            expect(
                command.acceptsWithNonzero === true
                    ? result === 0
                    : result !== 0,
                `${label}: ${command.name}(${values.join(', ')}) returned ${String(result)}`,
            ).toBe(true);
        };
        for (const command of publicInputCommands) {
            const capacity = inputBuffers[command.buffer].capacity(kernel);
            for (let index = 0; index < 64; index += 1) {
                const label = command.name + '/' + String(index);
                const draw = draws(label);
                refuses(
                    command,
                    command.parameters.map((parameter) =>
                        drawArgument(parameter, draw, capacity),
                    ),
                    label,
                );
            }
        }
        // Every operation of a command that takes one, at each small length
        // a command may require exactly.
        for (const command of publicInputCommands)
            if (command.parameters[0] === 'operation')
                for (let operation = 0; operation < 32; operation += 1)
                    for (let length = 0; length <= 40; length += 1)
                        for (const index of [0, 1])
                            refuses(
                                command,
                                command.parameters.map((parameter) =>
                                    parameter === 'operation'
                                        ? operation
                                        : parameter === 'length'
                                          ? length
                                          : index,
                                ),
                                `${command.name}/operation/${String(operation)}/${String(length)}/${String(index)}`,
                            );
        const join = joinInput('First voter');
        writeInput(kernel, join);
        expect(kernel.validate_join(join.length)).toBe(0);
        writeInput(kernel, begin);
        expect(kernel.roster_begin(begin.length)).toBe(0);
        writeSetupInput(kernel, begin);
        expect(kernel.setup_roster_begin(begin.length)).toBe(0);
    });

    it('refuses every join and roster input with a changed byte, length or roster count', async () => {
        const { kernel } = await instantiate();
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
            writeInput(kernel, changedJoin);
            expect(kernel.validate_join(changedJoin.length), label).toBe(1);
            const offset = draw(begin.length - 2);
            const changedBegin = changedByte(
                begin,
                offset < countOffset ? offset : offset + 2,
                1 + draw(255),
            );
            writeInput(kernel, changedBegin);
            expect(kernel.roster_begin(changedBegin.length), label).toBe(1);
            writeSetupInput(kernel, changedBegin);
            expect(kernel.setup_roster_begin(changedBegin.length), label).toBe(
                1,
            );
            // A shorter or longer length over the genuine bytes.
            const shift = 1 + draw(2048);
            writeInput(kernel, join);
            for (const length of [join.length - shift, join.length + shift])
                expect(kernel.validate_join(length), label).toBe(1);
            writeInput(kernel, begin);
            for (const length of [begin.length - shift, begin.length + shift])
                expect(kernel.roster_begin(length), label).toBe(1);
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
            writeInput(kernel, counted);
            expect(kernel.roster_begin(counted.length), String(count)).toBe(1);
            writeSetupInput(kernel, counted);
            expect(
                kernel.setup_roster_begin(counted.length),
                String(count),
            ).toBe(1);
        }
        writeInput(kernel, join);
        expect(kernel.validate_join(join.length)).toBe(0);
        writeInput(kernel, begin);
        expect(kernel.roster_begin(begin.length)).toBe(0);
        writeSetupInput(kernel, begin);
        expect(kernel.setup_roster_begin(begin.length)).toBe(0);
    });

    it('takes the genuine registration record before and after arbitrary record steps that do not end the instance', async () => {
        const { kernel } = await instantiate();
        const begin = rosterBegin(minimumParticipants);
        // Each step of the genuine record in a new roster verification.
        const genuineRecord = () => {
            writeInput(kernel, begin);
            expect(kernel.roster_begin(begin.length)).toBe(0);
            const step = (
                operation: number,
                bytes: Uint8Array = new Uint8Array(),
            ) => {
                writeInput(kernel, bytes);
                return kernel.roster_record(operation, 0, bytes.length);
            };
            // The key and proof in the worker's streamed parts.
            const streamed = (operation: number, bytes: Uint8Array) => {
                const results: number[] = [];
                for (
                    let offset = 0;
                    offset < bytes.length;
                    offset += moduleChunkBytes
                )
                    results.push(
                        step(
                            operation,
                            bytes.subarray(offset, offset + moduleChunkBytes),
                        ),
                    );
                return results;
            };
            const steps = [
                step(0, recordBegin),
                ...streamed(1, organizer.publicKey),
            ];
            steps.push(step(2), ...streamed(3, organizer.proof));
            steps.push(step(4));
            return steps;
        };
        const accepted = genuineRecord();
        expect(accepted.every((result) => result === 0)).toBe(true);
        const pieces = [recordBegin, organizer.publicKey, organizer.proof];
        const positions = [
            0,
            1,
            minimumParticipants - 1,
            minimumParticipants,
            0xffff,
            0xffff_ffff,
        ];
        for (let sequence = 0; sequence < 8; sequence += 1) {
            writeInput(kernel, begin);
            expect(kernel.roster_begin(begin.length)).toBe(0);
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
                writeInput(kernel, bytes);
                call(
                    kernel,
                    'roster_record',
                    [draw(6), positions[draw(positions.length)], bytes.length],
                    label,
                );
            }
            expect(kernel.roster_finish()).toBe(0);
        }
        expect(genuineRecord()).toEqual(accepted);
    });

    it('refuses every changed registration record in its own registration verification, and verifies the genuine record however it is divided', async () => {
        type RegistrationRecord = Readonly<{
            header: Uint8Array;
            signature: Uint8Array;
            publicKey: Uint8Array;
            proof: Uint8Array;
        }>;
        // Streams a record in parts of drawn sizes, the first few small so
        // that parts end inside the proof's leading header; a fresh instance
        // verifies each record, as a verified registration is final.
        const verify = async (record: RegistrationRecord, label: string) => {
            const { kernel } = await instantiate();
            const draw = draws(label + '/parts');
            const parts = (bytes: Uint8Array) => {
                const divided: Uint8Array[] = [];
                for (let offset = 0; offset < bytes.length;) {
                    const size =
                        divided.length < 3
                            ? 1 + draw(64)
                            : 1 + draw(moduleChunkBytes);
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
                ...parts(record.proof).map((part) => [3, part] as const),
                [4, new Uint8Array()],
            ];
            // The poll the module verified the registration against, which
            // it reports only once the registration verifies.
            const verifiedPoll = () =>
                kernel.own_registration_poll() === 0
                    ? readKernel(
                          kernel,
                          kernel.contribution_output_pointer(),
                          kernel.contribution_output_length(),
                      )
                    : undefined;
            for (const [operation, bytes] of steps) {
                expect(verifiedPoll(), label).toBeUndefined();
                writeOwnRegistrationInput(kernel, bytes);
                if (
                    call(
                        kernel,
                        'own_registration_command',
                        [operation, bytes.length],
                        label,
                    ) !== 0
                )
                    return undefined;
            }
            return {
                username: new TextDecoder().decode(
                    readKernel(
                        kernel,
                        kernel.own_registration_username_pointer(),
                        kernel.own_registration_username_length(),
                    ),
                ),
                poll: verifiedPoll(),
            };
        };
        for (const [field, count] of [
            ['header', 2],
            ['signature', 1],
            ['publicKey', 1],
            ['proof', 3],
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
                    proof: organizer.proof.subarray(
                        0,
                        organizer.proof.length - 1,
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

    it('refuses a creator input whose poll the module cannot frame', async () => {
        const { kernel } = await instantiate();
        const creatorInput = (
            question: string,
            labels: readonly string[],
            topCount: number,
        ) =>
            concatenate(
                runtimeIdentity,
                unsigned16(topCount),
                unsigned16(minimumParticipants),
                framedText(question),
                unsigned16(labels.length),
                ...labels.map(framedText),
                framedText(organizerName),
            );
        const validates = (input: Uint8Array) => {
            writeInput(kernel, input);
            return kernel.validate_creator(input.length) === 0;
        };
        const question = 'Which option leads?';
        const genuine = creatorInput(question, ['Option 0', 'Option 1'], 2);
        expect(validates(genuine)).toBe(true);
        const counted = (count: number) =>
            Array.from(
                { length: count },
                (_unused, index) => `Option ${String(index)}`,
            );
        expect(validates(creatorInput(question, counted(20), 20))).toBe(true);
        for (const [label, input] of [
            ['empty question', creatorInput('', counted(2), 1)],
            ['one option', creatorInput(question, counted(1), 1)],
            ['too many options', creatorInput(question, counted(21), 1)],
            ['empty label', creatorInput(question, ['Option 0', ''], 1)],
            [
                'repeated label',
                creatorInput(question, ['Option 0', 'Option 0'], 1),
            ],
            // Canonically equivalent labels are one label.
            [
                'equivalent labels',
                creatorInput(question, ['Caf\u00e9', 'Cafe\u0301'], 1),
            ],
            [
                'private-use label',
                creatorInput(question, ['Option 0', '\ue000'], 1),
            ],
            ['no result', creatorInput(question, counted(2), 0)],
            [
                'result longer than the options',
                creatorInput(question, counted(2), 3),
            ],
            ['truncated', genuine.subarray(0, -1)],
            ['extended', concatenate(genuine, Uint8Array.of(0))],
            [
                'label beyond the input',
                concatenate(
                    runtimeIdentity,
                    unsigned16(1),
                    unsigned16(minimumParticipants),
                    framedText(question),
                    unsigned16(3),
                    framedText('Option 0'),
                    framedText('Option 1'),
                ),
            ],
            [
                'invalid UTF-8 label',
                concatenate(
                    runtimeIdentity,
                    unsigned16(1),
                    unsigned16(minimumParticipants),
                    framedText(question),
                    unsigned16(2),
                    framedText('Option 0'),
                    unsigned32(1),
                    Uint8Array.of(0xff),
                    framedText(organizerName),
                ),
            ],
        ] as const)
            expect(validates(input), label).toBe(false);
    });
});
