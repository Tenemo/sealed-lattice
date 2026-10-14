import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import {
    instantiateParticipantModule,
    readModuleMemory,
    writeInput,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import type { ParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { readParticipantLimits } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    concatenate,
    encodeText,
    unsigned16,
    unsigned32,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import { dataKind } from '#packages/sdk/src/participant/worker/storage/root.js';
import {
    ascii,
    item,
    itemType,
    tuple,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';

// The packaged participant module, fed public input that no honest relay or
// participant produces. A command must refuse such input and return: a trap
// would end every visit that reads the same public bytes as pending.
const participantModule = await WebAssembly.compile(
    await readFile(
        new URL('../../../packages/sdk/dist/participant.wasm', import.meta.url),
    ),
);

export const instantiate = () =>
    instantiateParticipantModule(participantModule, noParallelHelpers);

// Every case derives its bytes and choices from its label, so a failing case
// replays from the label its failure names.
export const shake = (label: string, length: number) =>
    new Uint8Array(
        createHash('shake256', { outputLength: length }).update(label).digest(),
    );

export const draws = (label: string) => {
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

export const changedByte = (
    bytes: Uint8Array,
    offset: number,
    mask: number,
) => {
    const copy = bytes.slice();
    copy[offset] ^= mask;
    return copy;
};

export type ModuleCommand = Exclude<keyof ParticipantModule, 'memory'>;

// Calls a command and names the case when the call does not return.
export const call = (
    module: ParticipantModule,
    name: ModuleCommand,
    values: readonly number[],
    label: string,
) => {
    let failure: unknown;
    try {
        // Fuzzing deliberately bypasses the typed host signatures.
        const command: (...arguments_: readonly number[]) => number =
            module[name];
        return command(...values);
    } catch (error) {
        failure = error;
    }
    throw new Error(
        `${label}: ${name}(${values.join(', ')}) did not return: ` +
            (failure instanceof Error ? failure.message : String(failure)),
    );
};

// The organizer's enrollment, whose public records every case changes.
export const runtimeIdentity = shake('runtime', 64);

// The poll's question and its two option labels as the organizer input frames
// them: each text after its four-byte length, the labels after their count.
// The second label is not in NFC, which the module applies once at ingress.
export const framedText = (value: string) => {
    const bytes = encodeText(value);
    return concatenate(unsigned32(bytes.length), bytes);
};

const pollText = concatenate(
    framedText('Which option leads?'),
    unsigned16(2),
    framedText('Option 0'),
    framedText('Cafe\u0301'),
);

export const organizerName = 'Organizer';

export const organizer = await (async () => {
    const { module, handlers } = await instantiate();
    const limits = readParticipantLimits(module);
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
    writeInput(module, input);
    if (module.validate_organizer(input.length) !== 0)
        throw new Error('The organizer input was refused.');
    const parts = new Map<number, Uint8Array[]>();
    handlers.staged = (kind, _offset, bytes) => {
        parts.set(kind, [...(parts.get(kind) ?? []), bytes.slice()]);
    };
    let requests = 0;
    handlers.random = (target) => {
        target.set(
            shake(organizerName + '/' + String(requests), target.length),
        );
        requests += 1;
    };
    writeInput(module, input);
    if (module.prepare_organizer(input.length) !== 0)
        throw new Error('The organizer enrollment was refused.');
    const record = (kind: number) => {
        const chunks = parts.get(kind);
        if (chunks === undefined)
            throw new Error('The enrollment staged no record ' + String(kind));
        return concatenate(...chunks);
    };
    return {
        limits,
        poll: readModuleMemory(module, module.poll_identity_pointer(), 64),
        definition: record(dataKind.pollDefinition),
        definitionSignature: record(dataKind.pollSignature),
        header: record(dataKind.header),
        signature: record(dataKind.signature),
        publicKey: record(dataKind.publicKey),
    };
})();

export const pollContext = concatenate(
    organizer.poll,
    runtimeIdentity,
    unsigned32(organizer.definition.length),
    organizer.definition,
    organizer.definitionSignature,
);

export const minimumParticipants = organizer.limits.participants.minimum;

export const joinInput = (name: string) => {
    const username = encodeText(name);
    return concatenate(pollContext, unsigned32(username.length), username);
};

export const rosterBegin = (count: number) =>
    concatenate(
        organizer.poll,
        runtimeIdentity,
        unsigned16(count),
        unsigned32(organizer.definition.length),
        organizer.definition,
        organizer.definitionSignature,
    );

export const recordBegin = concatenate(
    unsigned16(0),
    createHash('shake256', { outputLength: 64 })
        .update(
            tuple([
                ascii('sealed-lattice/registration-body/v2'),
                item(itemType.rawBytes, variable(organizer.header)),
            ]),
        )
        .digest(),
    unsigned32(organizer.header.length),
    organizer.header,
    organizer.signature,
);
