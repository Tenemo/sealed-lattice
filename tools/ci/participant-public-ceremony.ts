import assert from 'node:assert/strict';
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

// A passed browser participant run: the poll and runtime identities a reader
// is given, the registration body digests in roster order, and the ranking
// the participants combined, or none for a certified no-result target.
export type ParticipantRun = Readonly<{
    participantCount: number;
    optionCount: number;
    poll: string;
    recordIds: readonly string[];
    runtimeIdentity: string;
    result: Readonly<
        | { kind: 'result'; identifiers: readonly string[] }
        | { kind: 'no-result' }
    >;
}>;

const identity = /^[0-9a-f]{128}$/u;
const ballotDirectory = /^ballot-(0|[1-9]\d*)$/u;

const isCount = (value: unknown): value is number =>
    Number.isSafeInteger(value) && (value as number) > 0;
const isIdentity = (value: unknown): value is string =>
    typeof value === 'string' && identity.test(value);
const isTerminal = (value: unknown): value is ParticipantRun['result'] => {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        return false;
    const fields = value as Record<string, unknown>;
    const { kind, identifiers } = fields;
    return kind === 'no-result'
        ? Object.keys(fields).length === 1
        : kind === 'result' &&
              Object.keys(fields).length === 2 &&
              Array.isArray(identifiers) &&
              identifiers.length > 0 &&
              identifiers.every((option) => typeof option === 'string');
};

const readParticipantRun = async (run: string): Promise<ParticipantRun> => {
    const value = JSON.parse(
        await readFile(path.join(run, 'result.json'), 'utf8'),
    ) as Partial<Record<keyof ParticipantRun, unknown>>;
    const { participantCount, optionCount, poll, runtimeIdentity } = value;
    const { recordIds, result } = value;
    assert.ok(
        isCount(participantCount) && isCount(optionCount),
        'Malformed participant run counts.',
    );
    assert.ok(
        isIdentity(poll) && isIdentity(runtimeIdentity),
        'Malformed participant run identities.',
    );
    assert.ok(
        Array.isArray(recordIds) &&
            recordIds.every(isIdentity) &&
            recordIds.length === participantCount &&
            new Set(recordIds).size === participantCount,
        'Malformed participant run roster.',
    );
    assert.ok(isTerminal(result), 'Malformed participant run result.');
    return {
        participantCount,
        optionCount,
        poll,
        recordIds,
        runtimeIdentity,
        result,
    };
};

// Lays out a browser cohort's relayed records as the native public reader
// takes them. The relay names each registration record by its body digest and
// each ballot submission by its author and envelope identity; the reader takes
// registrations in roster order and an index of submitted envelopes with their
// bodies. The context holds the
// poll and runtime identities the reader is given, and every other file is
// relayed bytes. Only the owning verifiers accept any of them.
export const layParticipantCeremony = async (
    run: string,
    ceremony: string,
): Promise<ParticipantRun> => {
    const participant = await readParticipantRun(run);
    const relay = path.join(run, 'public');
    const copy = (from: string, to: string) =>
        cp(from, to, { recursive: true, errorOnExist: true, force: false });
    await mkdir(path.dirname(ceremony), { recursive: true });
    await mkdir(ceremony);
    // Every other relayed record keeps its name. A relayed record under a
    // derived name is refused, here or when the derived file is written.
    for (const entry of await readdir(relay)) {
        assert.ok(
            !entry.startsWith('participant-'),
            'A relayed record takes a derived name.',
        );
        if (entry !== 'registration')
            await copy(path.join(relay, entry), path.join(ceremony, entry));
    }
    await writeFile(
        path.join(ceremony, 'context.bin'),
        Buffer.concat([
            Buffer.from(participant.poll, 'hex'),
            Buffer.from(participant.runtimeIdentity, 'hex'),
        ]),
        { flag: 'wx' },
    );
    for (const [position, id] of participant.recordIds.entries())
        await copy(
            path.join(relay, 'registration', id),
            path.join(ceremony, 'participant-' + String(position)),
        );
    // Each published submission in author and identity order, whether or not
    // its author's pointer names it; its body keeps its relayed path.
    const authors = (await readdir(relay))
        .map((entry) => ballotDirectory.exec(entry)?.[1])
        .filter((author) => author !== undefined)
        .map(Number)
        .sort((left, right) => left - right);
    assert.ok(
        authors.every((author) => author < participant.participantCount),
        'A relayed ballot names no roster position.',
    );
    const close = path.join(ceremony, 'close');
    await mkdir(close, { recursive: true });
    const lines: string[] = [];
    for (const author of authors) {
        const directory = 'ballot-' + String(author);
        const identities = (await readdir(path.join(relay, directory)))
            .filter((entry) => identity.test(entry))
            .sort();
        for (const envelopeIdentity of identities) {
            const submission = path.join(relay, directory, envelopeIdentity);
            const name = 'submission-' + String(lines.length) + '.bin';
            await writeFile(
                path.join(close, name),
                Buffer.concat([
                    await readFile(path.join(submission, 'envelope.bin')),
                    await readFile(path.join(submission, 'signature.bin')),
                ]),
                { flag: 'wx' },
            );
            lines.push(
                name + ' ' + directory + '/' + envelopeIdentity + '/body.bin\n',
            );
        }
    }
    await writeFile(path.join(close, 'submissions.txt'), lines.join(''), {
        flag: 'wx',
    });
    return participant;
};
