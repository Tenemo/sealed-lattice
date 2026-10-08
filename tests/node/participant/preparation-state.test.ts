import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    decodeContributionState,
    encodeContributionState,
} from '#packages/sdk/src/participant/worker/stages/contribution/contribution.js';
import type { ContributionState } from '#packages/sdk/src/participant/worker/stages/contribution/contribution.js';
import {
    decodePreparationState,
    encodePreparationState,
    unusedPreparationPurposes,
} from '#packages/sdk/src/participant/worker/stages/contribution/preparation-state.js';
import type {
    PreparationEndorsement,
    PreparationSignature,
    PreparationState,
} from '#packages/sdk/src/participant/worker/stages/contribution/preparation-state.js';
import { encodeManifest } from '#packages/sdk/src/participant/worker/storage/root.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';

// The SHA-256 digest of stored bytes, which pins their exact format.
const storedDigest = (bytes: Uint8Array) =>
    createHash('sha256').update(bytes).digest('hex');

const profile = compileParticipantRuntimeProfile(4, 2);
const bounds = profile.preparation;
const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const originalReference = () => {
    const bytes = filled(bounds.selectionReferenceBytes, 19);
    bytes.set(new TextEncoder().encode('SPI1'));
    return bytes;
};
const signatureAt = (
    stage: 'intent' | 'signed',
    length: number,
    fill: number,
): PreparationSignature =>
    stage === 'intent'
        ? { stage, body: filled(length, fill) }
        : {
              stage,
              body: filled(length, fill),
              signature: filled(profile.registration.signatureBytes, fill + 2),
          };
const selection = (stage: 'intent' | 'signed') =>
    signatureAt(stage, bounds.selectionBodyBytes, 29);
const endorsement = (stage: 'intent' | 'signed'): PreparationEndorsement => ({
    ...signatureAt(stage, bounds.endorsementBodyBytes, 43),
    selection: {
        body: filled(bounds.selectionBodyBytes, 29),
        signature: filled(profile.registration.signatureBytes, 31),
    },
    reference: originalReference(),
});

// Synthetic journal payloads for structural checks only: neither
// their opaque signatures nor SPI1 bytes establish a verified selection.
const unfinished = (phase: 4 | 5 | 6): ContributionState => ({
    phase,
    position: 2,
    header: phase === 4 ? new Uint8Array() : Uint8Array.of(70, 80, 67, 52, 7),
    publicRecords:
        phase === 4
            ? []
            : profile.contribution.publicRecords.map((location, index) => ({
                  ...location,
                  key: filled(32, index % 251),
                  hash: filled(64, (index + 1) % 251),
              })),
    privateRecords:
        phase === 4
            ? []
            : profile.contribution.checkpointLengths.map((_length, index) => ({
                  key: filled(32, (index + 5) % 251),
                  hash: filled(64, (index + 6) % 251),
              })),
    signingRecords: [],
    seed: filled(phase === 5 ? 0 : 64, 61),
});

// Independent PRE2 framing, useful for hostile inputs the encoder would
// never deliberately produce. Each of the three authorities has one length.
const journal = (fields: readonly Uint8Array[]) => {
    const bytes = new Uint8Array(
        4 + fields.reduce((total, value) => total + 4 + value.length, 0),
    );
    bytes.set(new TextEncoder().encode('PRE2'));
    let offset = 4;
    for (const field of fields) {
        new DataView(bytes.buffer).setUint32(offset, field.length, true);
        bytes.set(field, offset + 4);
        offset += 4 + field.length;
    }
    return bytes;
};
const fields = (state: PreparationState) => {
    const bytes = encodePreparationState(state);
    const output: Uint8Array[] = [];
    let offset = 4;
    for (let index = 0; index < 3; index++) {
        const length = new DataView(bytes.buffer).getUint32(offset, true);
        output.push(bytes.slice(offset + 4, offset + 4 + length));
        offset += 4 + length;
    }
    return output;
};

describe('independent preparation authority journal', () => {
    it('keeps selection and endorsement intents and signatures independent', () => {
        for (const selectionStage of [undefined, 'intent', 'signed'] as const) {
            for (const endorsementStage of [
                undefined,
                'intent',
                'signed',
            ] as const) {
                const state: PreparationState = {
                    ...(selectionStage === undefined
                        ? {}
                        : { selection: selection(selectionStage) }),
                    ...(endorsementStage === undefined
                        ? {}
                        : { endorsement: endorsement(endorsementStage) }),
                };
                const bytes = encodePreparationState(state);
                expect(decodePreparationState(bytes, profile)).toEqual(state);
                expect(bytes).toEqual(journal(fields(state)));
                expect(unusedPreparationPurposes(bytes)).toBe(
                    2 +
                        (selectionStage === 'signed' ? 0 : 4) +
                        (endorsementStage === 'signed' ? 0 : 8),
                );
            }
        }
    });

    it.each([4, 5, 6] as const)(
        'permits endorsement with original SPI1 while eligible own phase %i remains unfinished',
        (phase) => {
            const own = unfinished(phase);
            expect(own.position).toBeGreaterThanOrEqual(
                profile.setupContributorCount,
            );
            expect(own.position).toBeLessThan(profile.eligibleContributorCount);
            const contribution = encodeContributionState(own);
            const pending: PreparationState = {
                contribution,
                endorsement: endorsement('intent'),
            };
            const completed: PreparationState = {
                contribution,
                endorsement: endorsement('signed'),
            };
            for (const state of [pending, completed]) {
                const decoded = decodePreparationState(
                    encodePreparationState(state),
                    profile,
                );
                expect(decoded.contribution).toEqual(contribution);
                expect(
                    decodeContributionState(decoded.contribution!, profile),
                ).toEqual(own);
                expect(decoded.endorsement!.reference).toEqual(
                    originalReference(),
                );
                expect(
                    new TextDecoder().decode(
                        decoded.endorsement!.reference.subarray(0, 4),
                    ),
                ).toBe('SPI1');
                expect(decoded.endorsement!.selection).toEqual(
                    endorsement('signed').selection,
                );
                // The root stays at preparation generation four. Advancing an
                // independent authority needs no fake own-offer generation.
                const root = encodeManifest(
                    {
                        dataKeys: filled(96, 3),
                        poll: filled(64, 5),
                        references: [],
                        suffixes: {
                            preparation: encodePreparationState(state),
                        },
                    },
                    4,
                );
                expect(new TextDecoder().decode(root.subarray(0, 4))).toBe(
                    'ERM9',
                );
                expect(root.subarray(168 + 4)).toEqual(
                    encodePreparationState(state),
                );
            }
            expect(
                unusedPreparationPurposes(encodePreparationState(pending)),
            ).toBe(14);
            expect(
                unusedPreparationPurposes(encodePreparationState(completed)),
            ).toBe(6);
        },
    );

    it('does not require any own contribution or organizer selection to endorse', () => {
        const state = { endorsement: endorsement('signed') };
        const decoded = decodePreparationState(
            encodePreparationState(state),
            profile,
        );
        expect(decoded).toEqual(state);
        expect(decoded.contribution).toBeUndefined();
        expect(decoded.selection).toBeUndefined();
        // This helper is for active preparation; retirement generation burns
        // all preparation purposes in enrollment/root, not from empty PRE2.
        expect(
            decodePreparationState(encodePreparationState({}), profile),
        ).toEqual({});
        expect(unusedPreparationPurposes(encodePreparationState({}))).toBe(14);
    });

    it('burns only completed signing purposes across every independent phase combination', () => {
        for (const ownPhase of [undefined, 4, 5, 6, 7, 8, 9]) {
            for (const selected of [undefined, 'intent', 'signed'] as const) {
                for (const endorsed of [
                    undefined,
                    'intent',
                    'signed',
                ] as const) {
                    // The pre-profile mask reads only PCS5's authenticated
                    // structural phase; complete restore additionally decodes it.
                    const contribution =
                        ownPhase === undefined
                            ? new Uint8Array()
                            : Uint8Array.of(80, 67, 83, 53, ownPhase);
                    const state: PreparationState = {
                        ...(selected === undefined
                            ? {}
                            : { selection: selection(selected) }),
                        ...(endorsed === undefined
                            ? {}
                            : { endorsement: endorsement(endorsed) }),
                    };
                    const encodedFields = fields(state);
                    encodedFields[0] = contribution;
                    expect(
                        unusedPreparationPurposes(journal(encodedFields)),
                    ).toBe(
                        (ownPhase === 9 ? 0 : 2) +
                            (selected === 'signed' ? 0 : 4) +
                            (endorsed === 'signed' ? 0 : 8),
                    );
                }
            }
        }
    });

    it('refuses malformed slot lengths, unknown phases and stale signature tails', () => {
        const valid = fields({
            selection: selection('intent'),
            endorsement: endorsement('signed'),
        });
        for (const index of [1, 2]) {
            for (const changed of [
                valid[index].slice(0, -1),
                new Uint8Array([...valid[index], 0]),
                ...[0, 3, 255].map((phase) => {
                    const bytes = valid[index].slice();
                    bytes[0] = phase;
                    return bytes;
                }),
            ]) {
                const input = valid.map((value, position) =>
                    position === index ? changed : value,
                );
                expect(() =>
                    decodePreparationState(journal(input), profile),
                ).toThrow();
            }
            const changed = valid[index].slice();
            changed[0] = changed[0] === 1 ? 2 : 1;
            expect(() =>
                decodePreparationState(
                    journal(
                        valid.map((value, position) =>
                            position === index ? changed : value,
                        ),
                    ),
                    profile,
                ),
            ).toThrow();
            for (const stage of [0, 3, 255]) {
                const invalidPhase = valid[index].slice();
                invalidPhase[0] = stage;
                expect(() =>
                    unusedPreparationPurposes(
                        journal(
                            valid.map((value, position) =>
                                position === index ? invalidPhase : value,
                            ),
                        ),
                    ),
                ).toThrow();
            }
        }
        const corruptReference = endorsement('signed');
        for (const reference of [
            corruptReference.reference.slice(1),
            new Uint8Array([...corruptReference.reference, 0]),
        ])
            expect(() =>
                decodePreparationState(
                    encodePreparationState({
                        endorsement: { ...corruptReference, reference },
                    }),
                    profile,
                ),
            ).toThrow();
        expect(() =>
            decodePreparationState(
                journal([valid[0], valid[2], valid[1]]),
                profile,
            ),
        ).toThrow();
    });

    it('rejects malformed framing before using any authority phase', () => {
        const encoded = encodePreparationState({
            endorsement: endorsement('intent'),
        });
        for (const bad of [
            new Uint8Array(),
            encoded.slice(0, 3),
            encoded.slice(0, -1),
            new Uint8Array([...encoded, 0]),
        ]) {
            expect(() => decodePreparationState(bad, profile)).toThrow();
            expect(() => unusedPreparationPurposes(bad)).toThrow();
        }
        const badLength = encoded.slice();
        new DataView(badLength.buffer).setUint32(4, 0xffffffff, true);
        expect(() => decodePreparationState(badLength, profile)).toThrow();
        expect(() => unusedPreparationPurposes(badLength)).toThrow();
        for (const phase of [0, 3, 10, 255])
            expect(() =>
                unusedPreparationPurposes(
                    journal([
                        Uint8Array.of(80, 67, 83, 53, phase),
                        new Uint8Array(),
                        new Uint8Array(),
                    ]),
                ),
            ).toThrow();
    });

    it('does not let another journal phase hide malformed required own work', () => {
        const own = encodeContributionState(unfinished(5));
        own[4] = 4; // A generation intent cannot carry the checkpoint records.
        const decoded = decodePreparationState(
            encodePreparationState({
                contribution: own,
                endorsement: endorsement('signed'),
            }),
            profile,
        );
        expect(decoded.endorsement!.reference).toEqual(originalReference());
        expect(() =>
            decodeContributionState(decoded.contribution!, profile),
        ).toThrow();
    });

    it('pins the bytes of an empty, an intended and a signed journal', () => {
        expect(
            [
                {},
                {
                    contribution: encodeContributionState(unfinished(5)),
                    selection: selection('intent'),
                    endorsement: endorsement('intent'),
                },
                {
                    contribution: encodeContributionState(unfinished(6)),
                    selection: selection('signed'),
                    endorsement: endorsement('signed'),
                },
            ].map((state) => storedDigest(encodePreparationState(state))),
        ).toEqual([
            '336148d39032496ea4772e27e7f26f8d11c94dcc36c920e297e339976ec97359',
            '8bc5ce9c593e15110308dc1cb4f58d6da0ffa9faa1599cda55db84c46a98d002',
            '3a6b3862d77a809fdc26aed51f79a89730b843b6fa722f6950c9eb95679e74c3',
        ]);
    });
});
