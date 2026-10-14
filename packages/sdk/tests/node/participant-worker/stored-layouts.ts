import { unsigned } from '#tests/node/protocol/reference/canonical-tuple.js';

// The participant's stored formats, written field by field. Nothing here
// comes from the SDK, so an encoder that changes a field's order, width or
// marker fails its test, and a deliberate format change edits the field it
// changes here.

const marker = (text: string) => Buffer.from(text, 'ascii');
const empty = Buffer.alloc(0);

type Reference = Readonly<{
    kind: number;
    offset: number;
    length: number;
    hash: Uint8Array;
}>;

// ERM9: the data keys, the poll, the reference count and each reference's
// kind, offset, length and identity, then each present suffix after its
// length.
export const rootManifestLayout = (
    manifest: Readonly<{
        dataKeys: Uint8Array;
        poll: Uint8Array;
        references: readonly Reference[];
        suffixes: readonly Uint8Array[];
    }>,
) =>
    Buffer.concat([
        marker('ERM9'),
        manifest.dataKeys,
        manifest.poll,
        unsigned(manifest.references.length, 4),
        ...manifest.references.flatMap((reference) => [
            unsigned(reference.kind, 1),
            unsigned(reference.offset, 4),
            unsigned(reference.length, 4),
            reference.hash,
        ]),
        ...manifest.suffixes.flatMap((suffix) => [
            unsigned(suffix.length, 4),
            suffix,
        ]),
    ]);

// BST3: the score count and scores, the ballot time until the signature is
// retained, the seed, the body length, the body key count and keys, the
// envelope and the signature.
export const ballotStateLayout = (
    state: Readonly<{
        scores: Uint8Array;
        ballotTime?: bigint;
        seed: Uint8Array;
        bodyLength: number;
        bodyKeys: readonly Uint8Array[];
        envelope: Uint8Array;
        signature: Uint8Array;
    }>,
) =>
    Buffer.concat([
        marker('BST3'),
        unsigned(state.scores.length, 1),
        state.scores,
        state.ballotTime === undefined ? empty : unsigned(state.ballotTime, 8),
        state.seed,
        unsigned(state.bodyLength, 4),
        unsigned(state.bodyKeys.length, 2),
        ...state.bodyKeys,
        state.envelope,
        state.signature,
    ]);

// The close messages a phase may retain, in their stored order.
export type CloseRetained = Readonly<{
    intentBody?: Uint8Array;
    intentPacket?: Uint8Array;
    responseBody?: Uint8Array;
    responsePacket?: Uint8Array;
    proposalBody?: Uint8Array;
    proposalPacket?: Uint8Array;
}>;

// CST2: the event count and each event's kind, key count, serial, payload
// length and keys, then the retained close messages. Only the response body
// carries its length.
export const closeStateLayout = (
    events: readonly Readonly<{
        kind: number;
        serial: number;
        length: number;
        keys: readonly Uint8Array[];
    }>[],
    retained: CloseRetained,
) =>
    Buffer.concat([
        marker('CST2'),
        unsigned(events.length, 4),
        ...events.flatMap((event) => [
            unsigned(event.kind, 1),
            unsigned(event.keys.length, 2),
            unsigned(event.serial, 4),
            unsigned(event.length, 4),
            ...event.keys,
        ]),
        retained.intentBody ?? empty,
        retained.intentPacket ?? empty,
        retained.responseBody === undefined
            ? empty
            : Buffer.concat([
                  unsigned(retained.responseBody.length, 4),
                  retained.responseBody,
              ]),
        retained.responsePacket ?? empty,
        retained.proposalBody ?? empty,
        retained.proposalPacket ?? empty,
    ]);

type StoredRecord = Readonly<{ key: Uint8Array; hash: Uint8Array }>;

// PCS5: the phase, the position, the header length and the public, private
// and signing record counts; then the header, each public record's object,
// offset, length, key and identity, each private record's key and identity,
// each signing record's object, length, key and identity, and the seed.
export const contributionStateLayout = (
    state: Readonly<{
        phase: number;
        position: number;
        header: Uint8Array;
        publicRecords: readonly (StoredRecord &
            Readonly<{ object: number; offset: number; length: number }>)[];
        privateRecords: readonly StoredRecord[];
        signingRecords: readonly (StoredRecord &
            Readonly<{ object: number; length: number }>)[];
        seed: Uint8Array;
    }>,
) =>
    Buffer.concat([
        marker('PCS5'),
        unsigned(state.phase, 1),
        unsigned(state.position, 2),
        unsigned(state.header.length, 4),
        unsigned(state.publicRecords.length, 4),
        unsigned(state.privateRecords.length, 4),
        unsigned(state.signingRecords.length, 4),
        state.header,
        ...state.publicRecords.flatMap((record) => [
            unsigned(record.object, 2),
            unsigned(record.offset, 4),
            unsigned(record.length, 4),
            record.key,
            record.hash,
        ]),
        ...state.privateRecords.flatMap((record) => [record.key, record.hash]),
        ...state.signingRecords.flatMap((record) => [
            unsigned(record.object, 2),
            unsigned(record.length, 4),
            record.key,
            record.hash,
        ]),
        state.seed,
    ]);

// PRE2: each field after its length.
export const preparationJournalLayout = (fields: readonly Uint8Array[]) =>
    Buffer.concat([
        marker('PRE2'),
        ...fields.flatMap((field) => [unsigned(field.length, 4), field]),
    ]);

type Signed = Readonly<{
    stage: 'intent' | 'signed';
    body: Uint8Array;
    signature?: Uint8Array;
}>;

// A signature field: its stage, 1 for an intent and 2 once signed, then the
// fields before its body, the body, and the signature once signed.
const signedField = (value: Signed, before: readonly Uint8Array[] = []) =>
    new Uint8Array(
        Buffer.concat([
            unsigned(value.stage === 'intent' ? 1 : 2, 1),
            ...before,
            value.body,
            value.stage === 'signed' ? value.signature! : empty,
        ]),
    );

// The preparation journal's fields: the own contribution, the selection,
// and the endorsement with the endorsed selection's body and signature and
// the selection reference before its own body. An absent field is empty.
// The fields are copies, so a test may corrupt one without changing another.
export const preparationJournalFields = (
    state: Readonly<{
        contribution?: Uint8Array;
        selection?: Signed;
        endorsement?: Signed &
            Readonly<{
                selection: Readonly<{
                    body: Uint8Array;
                    signature: Uint8Array;
                }>;
                reference: Uint8Array;
            }>;
    }>,
): Uint8Array[] => [
    Uint8Array.from(state.contribution ?? empty),
    state.selection === undefined
        ? new Uint8Array()
        : signedField(state.selection),
    state.endorsement === undefined
        ? new Uint8Array()
        : signedField(state.endorsement, [
              state.endorsement.selection.body,
              state.endorsement.selection.signature,
              state.endorsement.reference,
          ]),
];

export const preparationStateLayout = (
    state: Parameters<typeof preparationJournalFields>[0],
) => preparationJournalLayout(preparationJournalFields(state));

// The stored code of the own ballot's status in a target.
const inclusionCode = {
    'not cast': 0,
    late: 1,
    included: 2,
    omitted: 3,
} as const;

// RST4: the predecessor generation, the ballot status code, the target
// length, the body length and the body key count; then the target, the seed,
// the body keys, the envelope and the signature.
export const releaseStateLayout = (
    state: Readonly<{
        predecessor: number;
        ballotInclusion: keyof typeof inclusionCode;
        target: Uint8Array;
        seed: Uint8Array;
        bodyLength: number;
        bodyKeys: readonly Uint8Array[];
        envelope: Uint8Array;
        signature: Uint8Array;
    }>,
) =>
    Buffer.concat([
        marker('RST4'),
        unsigned(state.predecessor, 1),
        unsigned(inclusionCode[state.ballotInclusion], 1),
        unsigned(state.target.length, 2),
        unsigned(state.bodyLength, 4),
        unsigned(state.bodyKeys.length, 2),
        state.target,
        state.seed,
        ...state.bodyKeys,
        state.envelope,
        state.signature,
    ]);

// TST3: the predecessor generation, the ballot status code and the body
// length, then the body and, once signed, the vote.
export const targetStateLayout = (
    state: Readonly<{
        predecessor: number;
        ballotInclusion: keyof typeof inclusionCode;
        body: Uint8Array;
        vote?: Uint8Array;
    }>,
) =>
    Buffer.concat([
        marker('TST3'),
        unsigned(state.predecessor, 1),
        unsigned(inclusionCode[state.ballotInclusion], 1),
        unsigned(state.body.length, 2),
        state.body,
        state.vote ?? empty,
    ]);
