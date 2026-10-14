import { describe, expect, it } from 'vitest';

import {
    writeInput,
    writeSetupInput,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import {
    concatenate,
    encodeText,
    unsigned16,
    unsigned32,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import {
    instantiate,
    shake,
    call,
    runtimeIdentity,
    framedText,
    organizerName,
    organizer,
    minimumParticipants,
    rosterBegin,
} from '#tests/node/participant-module/public-input-fixture.js';

describe('participant module public input', () => {
    it('withholds offer and setup authority for partial carriers and proof bytes without a verified roster', async () => {
        const { module } = await instantiate();
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
            writeSetupInput(module, bytes);
            expect(call(module, name, [bytes.length], name)).not.toBe(0);
            expect(module.setup_offer_finish()).toBe(1);
            expect(module.setup_selection_finish()).toBe(1);
            expect(module.setup_finish_certificate()).toBe(1);
            expect(module.setup_selection_output()).toBe(1);
        }
        for (const length of [0, 1, 64, 4095]) {
            writeSetupInput(module, organizer.publicKey.subarray(0, length));
            expect(
                call(
                    module,
                    'setup_offer_proof',
                    [0, length],
                    `unscoped-proof/${String(length)}`,
                ),
            ).not.toBe(0);
            expect(module.setup_offer_finish()).toBe(1);
        }
        const begin = rosterBegin(minimumParticipants);
        writeSetupInput(module, begin);
        expect(module.setup_roster_begin(begin.length)).toBe(0);
    });

    it('refuses an organizer input whose poll the module cannot frame', async () => {
        const { module } = await instantiate();
        const organizerInput = (
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
            writeInput(module, input);
            return module.validate_organizer(input.length) === 0;
        };
        const question = 'Which option leads?';
        const genuine = organizerInput(question, ['Option 0', 'Option 1'], 2);
        expect(validates(genuine)).toBe(true);
        const counted = (count: number) =>
            Array.from(
                { length: count },
                (_unused, index) => `Option ${String(index)}`,
            );
        expect(validates(organizerInput(question, counted(20), 20))).toBe(true);
        for (const [label, input] of [
            ['empty question', organizerInput('', counted(2), 1)],
            ['one option', organizerInput(question, counted(1), 1)],
            ['too many options', organizerInput(question, counted(21), 1)],
            ['empty label', organizerInput(question, ['Option 0', ''], 1)],
            [
                'repeated label',
                organizerInput(question, ['Option 0', 'Option 0'], 1),
            ],
            // Canonically equivalent labels are one label.
            [
                'equivalent labels',
                organizerInput(question, ['Caf\u00e9', 'Cafe\u0301'], 1),
            ],
            [
                'private-use label',
                organizerInput(question, ['Option 0', '\ue000'], 1),
            ],
            ['no result', organizerInput(question, counted(2), 0)],
            [
                'result longer than the options',
                organizerInput(question, counted(2), 3),
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
