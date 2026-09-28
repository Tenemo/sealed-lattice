import assert from 'node:assert/strict';
import {
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { layParticipantCeremony } from '#tools/ci/participant-public-ceremony.js';

const hexadecimal = (fill: number) => Buffer.alloc(64, fill).toString('hex');
// Roster order differs from the digests' name order.
const recordIds = [hexadecimal(0xc2), hexadecimal(0x0f), hexadecimal(0xa5)];
const poll = hexadecimal(0x11);
const runtimeIdentity = hexadecimal(0x22);
// Each submission's records sit under its author and envelope identity. The
// middle participant published no ballot and the last published two, whose
// identities differ from their arrival order; one pointer names one of them.
const submissions = [
    { author: 2, identity: hexadecimal(0xb0), fill: 3 },
    { author: 0, identity: hexadecimal(0xe1), fill: 1 },
    { author: 2, identity: hexadecimal(0x3c), fill: 5 },
];
const submissionDirectory = (author: number, identity: string) =>
    'ballot-' + String(author) + '/' + identity + '/';
const registrationFiles = [
    'polynomial-01.bin',
    'proof.bin',
    'registration-header.bin',
    'signature.bin',
];

describe('browser relay ceremony layout', () => {
    const temporaryRoot = path.resolve('temp');
    let root: string;
    let run: string;
    let relay: string;
    const write = async (name: string, bytes: Buffer | string) => {
        await mkdir(path.dirname(path.join(relay, name)), { recursive: true });
        await writeFile(path.join(relay, name), bytes);
    };
    const writeRun = (fields: Record<string, unknown> = {}) =>
        writeFile(
            path.join(run, 'result.json'),
            JSON.stringify({
                participantCount: 3,
                optionCount: 2,
                poll,
                recordIds,
                runtimeIdentity,
                result: {
                    kind: 'result',
                    identifiers: ['option-1', 'option-0'],
                },
                ...fields,
            }),
        );
    beforeEach(async () => {
        await mkdir(temporaryRoot, { recursive: true });
        root = await mkdtemp(path.join(temporaryRoot, 'relay-layout-test-'));
        // The run's diagnostics and its relay's records lie apart, as the
        // runner keeps them.
        run = path.join(root, 'run');
        relay = path.join(root, 'artifacts', 'public');
        await mkdir(run);
        await mkdir(relay, { recursive: true });
        await writeRun();
        for (const [position, id] of recordIds.entries())
            for (const file of registrationFiles)
                await write(
                    'registration/' + id + '/' + file,
                    file + ' of ' + String(position),
                );
        for (const name of [
            'poll-definition.bin',
            'poll-signature.bin',
            'proposal.bin',
            'proposal-signature.bin',
            'contribution-0/proof.bin',
            'contribution-2/polynomial-39.bin',
            'close/intent.bin',
            'close/response-1.bin',
            'close/proposal.bin',
            'completion/target.bin',
            'completion/release-envelope-2.bin',
        ])
            await write(name, name);
        for (const { author, identity, fill } of submissions) {
            const directory = submissionDirectory(author, identity);
            await write(directory + 'envelope.bin', Buffer.alloc(214, fill));
            await write(
                directory + 'signature.bin',
                Buffer.alloc(3309, fill + 7),
            );
            await write(directory + 'body.bin', 'body ' + String(fill));
        }
        await write(
            'ballot-2/submission.bin',
            Buffer.from(hexadecimal(0xb0), 'hex'),
        );
    });
    afterEach(async () => {
        assert.ok(root.startsWith(temporaryRoot + path.sep));
        await rm(root, { recursive: true, force: true });
    });

    it('orders registrations by roster position and indexes each submission', async () => {
        const ceremony = path.join(root, 'view', 'ceremony');
        const participant = await layParticipantCeremony(run, relay, ceremony);
        expect(participant.recordIds).toEqual(recordIds);
        expect(participant.result).toEqual({
            kind: 'result',
            identifiers: ['option-1', 'option-0'],
        });
        expect(await readFile(path.join(ceremony, 'context.bin'))).toEqual(
            Buffer.concat([
                Buffer.from(poll, 'hex'),
                Buffer.from(runtimeIdentity, 'hex'),
            ]),
        );
        expect((await readdir(ceremony)).sort()).toEqual([
            'ballot-0',
            'ballot-2',
            'close',
            'completion',
            'context.bin',
            'contribution-0',
            'contribution-2',
            'participant-0',
            'participant-1',
            'participant-2',
            'poll-definition.bin',
            'poll-signature.bin',
            'proposal-signature.bin',
            'proposal.bin',
        ]);
        for (const position of [0, 1, 2])
            for (const file of registrationFiles)
                expect(
                    await readFile(
                        path.join(
                            ceremony,
                            'participant-' + String(position),
                            file,
                        ),
                        'utf8',
                    ),
                ).toBe(file + ' of ' + String(position));
        for (const name of [
            'contribution-2/polynomial-39.bin',
            'close/response-1.bin',
            'completion/release-envelope-2.bin',
        ])
            expect(await readFile(path.join(ceremony, name), 'utf8')).toBe(
                name,
            );
        // Each body takes its author's directory and its ordinal in that
        // author's identity order, and no relayed identity or pointer is
        // carried.
        const bodies = [
            'ballot-0/0/body.bin',
            'ballot-2/0/body.bin',
            'ballot-2/1/body.bin',
        ];
        expect(
            await readFile(
                path.join(ceremony, 'close/submissions.txt'),
                'utf8',
            ),
        ).toBe(
            bodies
                .map(
                    (body, ordinal) =>
                        'submission-' + String(ordinal) + '.bin ' + body + '\n',
                )
                .join(''),
        );
        for (const [ordinal, fill] of [1, 5, 3].entries())
            expect(
                await readFile(path.join(ceremony, bodies[ordinal]), 'utf8'),
            ).toBe('body ' + String(fill));
        expect((await readdir(path.join(ceremony, 'ballot-2'))).sort()).toEqual(
            ['0', '1'],
        );
        for (const [ordinal, fill] of [1, 5, 3].entries())
            expect(
                await readFile(
                    path.join(
                        ceremony,
                        'close/submission-' + String(ordinal) + '.bin',
                    ),
                ),
            ).toEqual(
                Buffer.concat([
                    Buffer.alloc(214, fill),
                    Buffer.alloc(3309, fill + 7),
                ]),
            );
    });

    it('preserves absent bodies for the owning close verifier to require only usable slots', async () => {
        for (const submission of [submissions[0], submissions[1]])
            await rm(
                path.join(
                    relay,
                    submissionDirectory(submission.author, submission.identity),
                    'body.bin',
                ),
            );
        const ceremony = path.join(root, 'partial', 'ceremony');
        await layParticipantCeremony(run, relay, ceremony);
        const lines = (
            await readFile(path.join(ceremony, 'close/submissions.txt'), 'utf8')
        )
            .trimEnd()
            .split('\n');
        expect(lines).toHaveLength(3);
        for (const body of ['ballot-0/0/body.bin', 'ballot-2/1/body.bin'])
            await expect(
                readFile(path.join(ceremony, body)),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        expect(
            await readFile(path.join(ceremony, 'ballot-2/0/body.bin'), 'utf8'),
        ).toBe('body 5');
        // The envelopes remain present, including the absent usable body's
        // envelope: transport does not classify or silently omit a slot.
        for (let position = 0; position < 3; position++)
            expect(
                (
                    await readFile(
                        path.join(
                            ceremony,
                            `close/submission-${String(position)}.bin`,
                        ),
                    )
                ).length,
            ).toBe(214 + 3309);
    });

    it('carries a certified no-result terminal', async () => {
        await writeRun({ result: { kind: 'no-result' } });
        const participant = await layParticipantCeremony(
            run,
            relay,
            path.join(root, 'no-result'),
        );
        expect(participant.result).toEqual({ kind: 'no-result' });
    });

    it('refuses a malformed run, a colliding name and missing records', async () => {
        const lay = (name: string) =>
            layParticipantCeremony(run, relay, path.join(root, name));
        for (const fields of [
            { poll: 'A'.repeat(128) },
            { runtimeIdentity: runtimeIdentity.slice(2) },
            { recordIds: recordIds.slice(1) },
            { recordIds: [recordIds[0], recordIds[0], recordIds[2]] },
            { participantCount: 0, recordIds: [] },
            { result: ['option-1', 'option-0'] },
            { result: { kind: 'result', identifiers: [1] } },
            { result: { kind: 'result', identifiers: [] } },
            { result: { kind: 'no-result', identifiers: [] } },
            { result: { kind: 'other' } },
        ]) {
            await writeRun(fields);
            await expect(lay('malformed')).rejects.toThrow(/Malformed/u);
        }
        await writeRun();
        await mkdir(path.join(root, 'existing'));
        await expect(lay('existing')).rejects.toThrow();
        await write('close/submissions.txt', 'relayed index');
        await expect(lay('colliding-index')).rejects.toThrow();
        await rm(path.join(relay, 'close/submissions.txt'));
        await write('context.bin', 'relayed context');
        await expect(lay('colliding-context')).rejects.toThrow();
        await rm(path.join(relay, 'context.bin'));
        await write('participant-1/proof.bin', 'relayed proof');
        await expect(lay('colliding-participant')).rejects.toThrow(
            /derived name/u,
        );
        await rm(path.join(relay, 'participant-1'), { recursive: true });
        await write('ballot-3/envelope.bin', 'unrostered');
        await expect(lay('unrostered-ballot')).rejects.toThrow(
            /no roster position/u,
        );
        await rm(path.join(relay, 'ballot-3'), { recursive: true });
        const unsigned =
            submissionDirectory(2, hexadecimal(0x3c)) + 'signature.bin';
        await rm(path.join(relay, unsigned));
        await expect(lay('unsigned-ballot')).rejects.toThrow();
        await write(unsigned, Buffer.alloc(3309));
        await rm(path.join(relay, 'registration', recordIds[1]), {
            recursive: true,
        });
        await expect(lay('unregistered')).rejects.toThrow();
    });
});
