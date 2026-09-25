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
                result: ['option-1', 'option-0'],
                ...fields,
            }),
        );
    beforeEach(async () => {
        await mkdir(temporaryRoot, { recursive: true });
        root = await mkdtemp(path.join(temporaryRoot, 'relay-layout-test-'));
        run = path.join(root, 'run');
        relay = path.join(run, 'public');
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
        // The middle participant published no ballot.
        for (const author of [2, 0]) {
            await write(
                'ballot-' + String(author) + '/envelope.bin',
                Buffer.alloc(214, author + 1),
            );
            await write(
                'ballot-' + String(author) + '/signature.bin',
                Buffer.alloc(3309, author + 7),
            );
            await write(
                'ballot-' + String(author) + '/body.bin',
                'body of ' + String(author),
            );
        }
    });
    afterEach(async () => {
        assert.ok(root.startsWith(temporaryRoot + path.sep));
        await rm(root, { recursive: true, force: true });
    });

    it('orders registrations by roster position and indexes each ballot', async () => {
        const ceremony = path.join(root, 'view', 'ceremony');
        const participant = await layParticipantCeremony(run, ceremony);
        expect(participant.recordIds).toEqual(recordIds);
        expect(participant.result).toEqual(['option-1', 'option-0']);
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
        expect(
            await readFile(
                path.join(ceremony, 'close/submissions.txt'),
                'utf8',
            ),
        ).toBe(
            'submission-0.bin ballot-0/body.bin\nsubmission-1.bin ballot-2/body.bin\n',
        );
        for (const [ordinal, author] of [0, 2].entries())
            expect(
                await readFile(
                    path.join(
                        ceremony,
                        'close/submission-' + String(ordinal) + '.bin',
                    ),
                ),
            ).toEqual(
                Buffer.concat([
                    Buffer.alloc(214, author + 1),
                    Buffer.alloc(3309, author + 7),
                ]),
            );
        expect(
            await readFile(path.join(ceremony, 'ballot-2/body.bin'), 'utf8'),
        ).toBe('body of 2');
    });

    it('refuses a malformed run, a colliding name and missing records', async () => {
        const lay = (name: string) =>
            layParticipantCeremony(run, path.join(root, name));
        for (const fields of [
            { poll: 'A'.repeat(128) },
            { runtimeIdentity: runtimeIdentity.slice(2) },
            { recordIds: recordIds.slice(1) },
            { recordIds: [recordIds[0], recordIds[0], recordIds[2]] },
            { participantCount: 0, recordIds: [] },
            { result: [1] },
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
        await rm(path.join(relay, 'ballot-2/signature.bin'));
        await expect(lay('unsigned-ballot')).rejects.toThrow();
        await write('ballot-2/signature.bin', Buffer.alloc(3309));
        await rm(path.join(relay, 'registration', recordIds[1]), {
            recursive: true,
        });
        await expect(lay('unregistered')).rejects.toThrow();
    });
});
