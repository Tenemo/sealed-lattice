import { describe, expect, it } from 'vitest';

import {
    closeEventKind,
    closeRecordInventory,
    closeRecordLengths,
    collectingCloseState,
    decodeCloseState,
    encodeCloseState,
} from '#packages/sdk/src/participant/worker/close-state.js';
import type {
    CloseEvent,
    CloseState,
} from '#packages/sdk/src/participant/worker/close-state.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';

const profile = compileParticipantRuntimeProfile(3, 2);
const { close, ballot, registration } = profile;
const signatureBytes = registration.signatureBytes;

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const key = (value: number) => filled(32, value);
// A length-prefixed signed packet of one repeated byte.
const packet = (bodyLength: number, value: number) => {
    const bytes = filled(4 + bodyLength + signatureBytes, value);
    new DataView(bytes.buffer).setUint32(0, bodyLength, true);
    return bytes;
};

const heldRecords = 1 + Math.ceil(ballot.minimumBodyBytes / ballot.recordBytes);
const own: CloseEvent = {
    kind: closeEventKind.own,
    serial: 0,
    length: 0,
    keys: [],
};
const held: CloseEvent = {
    kind: closeEventKind.held,
    serial: 1,
    length: ballot.minimumBodyBytes,
    keys: Array.from({ length: heldRecords }, (_unused, index) =>
        key(20 + index),
    ),
};
const lock: CloseEvent = {
    kind: closeEventKind.lock,
    serial: 5,
    length: 0,
    keys: [],
};
const response: CloseEvent = {
    kind: closeEventKind.response,
    serial: 6,
    length:
        4 +
        close.minimumResponseBodyBytes +
        signatureBytes +
        close.submissionBytes,
    keys: [key(4)],
};
const collected = [own, held];
const responseBodyBytes = close.minimumResponseBodyBytes + 66;

const state = (fields: Partial<CloseState>): CloseState => ({
    ...collectingCloseState(),
    ...fields,
});
const locked = {
    intentPacket: packet(close.intentBodyBytes, 7),
};
const responded = {
    ...locked,
    responsePacket: packet(responseBodyBytes, 9),
};

// Each phase's state for the organizer or another participant.
const phases: readonly (readonly [number, boolean, CloseState])[] = [
    [12, false, state({ events: collected })],
    [17, true, state({ events: collected })],
    [
        18,
        true,
        state({
            events: collected,
            intentBody: filled(close.intentBodyBytes, 5),
        }),
    ],
    [19, false, state({ events: [...collected, lock], ...locked })],
    [19, true, state({ events: [...collected, lock, response], ...locked })],
    [
        20,
        false,
        state({
            events: [...collected, lock],
            ...locked,
            responseBody: filled(responseBodyBytes, 8),
        }),
    ],
    [21, false, state({ events: [...collected, lock], ...responded })],
    [
        21,
        true,
        state({
            events: [...collected, lock, response],
            ...responded,
            proposalBody: filled(close.proposalBodyBytes, 10),
        }),
    ],
    [
        22,
        true,
        state({
            events: [...collected, lock, response],
            ...responded,
            proposalPacket: packet(close.proposalBodyBytes, 11),
        }),
    ],
];

const decode = (generation: number, isOrganizer: boolean, bytes: Uint8Array) =>
    decodeCloseState(profile, generation, isOrganizer, bytes);

describe('participant close state', () => {
    it('decodes every phase it encodes', () => {
        for (const [generation, isOrganizer, value] of phases) {
            const bytes = encodeCloseState(generation, isOrganizer, value);
            expect(decode(generation, isOrganizer, bytes)).toEqual(value);
            // Truncated and extended encodings are refused.
            expect(() =>
                decode(generation, isOrganizer, bytes.subarray(0, -1)),
            ).toThrow();
            expect(() =>
                decode(generation, isOrganizer, Uint8Array.of(...bytes, 0)),
            ).toThrow();
        }
    });

    it('refuses a log that disagrees with its phase or role', () => {
        const encoded = (
            generation: number,
            isOrganizer: boolean,
            value: CloseState,
        ) => encodeCloseState(generation, isOrganizer, value);
        const lockedState = state({ events: [...collected, lock], ...locked });
        // The lock is present exactly from generation 19.
        expect(() =>
            decode(17, false, encoded(17, false, state({ events: [lock] }))),
        ).toThrow();
        expect(() =>
            decode(
                19,
                false,
                encoded(19, false, state({ events: collected, ...locked })),
            ),
        ).toThrow();
        expect(() =>
            decode(
                19,
                false,
                encoded(
                    19,
                    false,
                    state({ events: [...collected, lock, lock], ...locked }),
                ),
            ),
        ).toThrow();
        // Only the organizer takes responses, and only after its lock.
        expect(() =>
            decode(
                19,
                false,
                encoded(
                    19,
                    false,
                    state({
                        events: [...collected, lock, response],
                        ...locked,
                    }),
                ),
            ),
        ).toThrow();
        expect(() =>
            decode(
                19,
                true,
                encoded(
                    19,
                    true,
                    state({
                        events: [...collected, response, lock],
                        ...locked,
                    }),
                ),
            ),
        ).toThrow();
        // Only the organizer signs an intent or a proposal.
        for (const [generation, isOrganizer, value] of phases.filter(
            ([phase]) => phase === 18 || phase === 22,
        ))
            expect(() =>
                decode(
                    generation,
                    false,
                    encoded(generation, isOrganizer, value),
                ),
            ).toThrow();
        // Serials strictly ascend in arrival order.
        expect(() =>
            decode(
                12,
                false,
                encoded(12, false, state({ events: [held, own] })),
            ),
        ).toThrow();
        expect(() =>
            decode(
                12,
                false,
                encoded(
                    12,
                    false,
                    state({ events: [own, { ...held, serial: 0 }] }),
                ),
            ),
        ).toThrow();
        // Each kind has its record count and payload length.
        for (const event of [
            { ...held, keys: held.keys.slice(1) },
            { ...held, length: ballot.minimumBodyBytes - 1 },
            { ...own, keys: [key(1)] },
            { ...lock, length: 1 },
            { ...own, kind: 4 },
        ])
            expect(() =>
                decode(
                    12,
                    false,
                    encoded(12, false, state({ events: [event] })),
                ),
            ).toThrow();
        // A retained packet keeps its exact inner length.
        const shortIntent = packet(close.intentBodyBytes - 1, 7);
        expect(() =>
            decode(
                19,
                false,
                encoded(19, false, {
                    ...lockedState,
                    intentPacket: Uint8Array.of(...shortIntent, 0),
                }),
            ),
        ).toThrow();
        expect(() =>
            decode(
                20,
                false,
                encoded(20, false, {
                    ...lockedState,
                    responseBody: filled(close.minimumResponseBodyBytes - 1, 8),
                }),
            ),
        ).toThrow();
        // The log names at most its bound of events.
        const header = encodeCloseState(12, false, collectingCloseState());
        new DataView(header.buffer).setUint32(4, close.maximumEvents + 1, true);
        expect(() => decode(12, false, header)).toThrow();
        // Another marker is refused.
        const marked = encodeCloseState(12, false, collectingCloseState());
        marked[0] ^= 1;
        expect(() => decode(12, false, marked)).toThrow();
    });

    it('lists every record at its serial with its own binding', () => {
        const lengths = closeRecordLengths(profile, held);
        expect(lengths[0]).toBe(close.submissionBytes);
        expect(lengths.slice(1).reduce((total, value) => total + value)).toBe(
            ballot.minimumBodyBytes,
        );
        expect(
            lengths.slice(1, -1).every((value) => value === ballot.recordBytes),
        ).toBe(true);
        const context = {
            poll: filled(64, 1),
            runtime: filled(64, 2),
            setupIdentity: filled(64, 3),
            position: 1,
        };
        const records = closeRecordInventory(
            profile,
            context,
            state({ events: [...collected, lock, response] }),
        );
        expect(records.map((record) => record.key)).toEqual([
            ...held.keys.map((_key, index) => [held.serial, index]),
            [response.serial, 0],
        ]);
        expect(records.map((record) => record.byteLength)).toEqual([
            ...lengths.map((length) => length + 16),
            response.length + 16,
        ]);
        const bindings = new Set(
            records.map((record) =>
                Buffer.from(record.encryption!.additionalData).toString('hex'),
            ),
        );
        expect(bindings.size).toBe(records.length);
    });
});
