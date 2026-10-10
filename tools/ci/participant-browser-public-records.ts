import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import { runArtifactDirectoryPath } from '#tools/ci/local-run-log.js';
import type { ViewedRecord } from '#tools/ci/participant-browser-relay.js';

// The relay's layout: lower-case path segments of letters, digits, dots and
// hyphens, with no traversal.
const publicPath = /^(?:[a-z0-9][a-z0-9.-]*\/)*[a-z0-9][a-z0-9.-]*$/u;

type ForeignPoll = Readonly<{
    // The passed cohort's run directory, relative to the repository.
    run: string;
    poll: string;
    registrationBodyDigests: readonly string[];
    // The registration of the registrant its organizer left out of the
    // roster, when the other poll's run records one.
    leftOut: string | undefined;
    publicDirectory: string;
}>;

const identifierPattern = /^[0-9a-f]{128}$/u;

// Reads another passed cohort of this profile: its result names its poll and
// its roster's registrations, and its relay's records lie among its artifacts.
export const loadForeignPoll = async (
    run: string,
    settings: Readonly<{
        participantCount: number;
        optionCount: number;
        root: string;
    }>,
): Promise<ForeignPoll> => {
    const { participantCount, optionCount, root } = settings;
    const directory = path.resolve(run);
    const result = JSON.parse(
        await readFile(path.join(directory, 'result.json'), 'utf8'),
    ) as Readonly<Record<string, unknown>>;
    assert.ok(
        result.participantCount === participantCount &&
            result.optionCount === optionCount,
        'The foreign poll has another profile.',
    );
    const { poll } = result;
    const registrationBodyDigests: readonly unknown[] = Array.isArray(
        result.registrationBodyDigests,
    )
        ? (result.registrationBodyDigests as unknown[])
        : [];
    assert.ok(
        typeof poll === 'string' &&
            identifierPattern.test(poll) &&
            registrationBodyDigests.length === participantCount &&
            registrationBodyDigests.every(
                (id) => typeof id === 'string' && identifierPattern.test(id),
            ),
        'The foreign poll names a malformed poll or roster.',
    );
    const leftOutDigest = (
        result.leftOut as { registrationBodyDigest?: unknown } | undefined
    )?.registrationBodyDigest;
    assert.ok(
        leftOutDigest === undefined ||
            (typeof leftOutDigest === 'string' &&
                identifierPattern.test(leftOutDigest)),
        'The foreign poll names a malformed registrant left out of its roster.',
    );
    const publicDirectory = path.join(
        runArtifactDirectoryPath(directory),
        'public',
    );
    assert.ok(
        (await stat(publicDirectory)).isDirectory(),
        'The foreign poll has no public records.',
    );
    return {
        run: path.relative(root, directory).split(path.sep).join('/'),
        poll,
        registrationBodyDigests: registrationBodyDigests.map(String),
        leftOut: leftOutDigest,
        publicDirectory,
    };
};

// The names of the records a relay stored.
export const publicRecordNames = async (directory: string) =>
    (await readdir(directory, { recursive: true }))
        .map((name) => name.split(path.sep).join('/'))
        .filter((name) => publicPath.test(name) && name.endsWith('.bin'));

// The healthy fixture generates one immutable body per offered position.
// Discovery hints are deliberately not used as authority for this assertion.
export const generatedOfferIdentity = async (
    directory: string,
    position: number,
) => {
    const entries = await readdir(
        path.join(directory, 'contribution-' + String(position)),
        { withFileTypes: true },
    );
    const bodies = entries.filter(
        (entry) => entry.isDirectory() && /^[0-9a-f]{128}$/u.test(entry.name),
    );
    assert.equal(
        bodies.length,
        1,
        'The original contributor generated another body.',
    );
    return Buffer.from(bodies[0].name, 'hex');
};

// The record families a relay view replaces with another poll's, each with
// the details of the first of them a result visit reads. A result visit
// restores the verified setup and the evaluated target, so it reads no
// contribution or close record.
export const foreignFamilies = [
    {
        family: 'registrations',
        pattern: /^registration\//u,
        details: (
            registrationBodyDigests: readonly string[],
            foreignRecordIds: readonly string[],
        ) =>
            registrationBodyDigests
                .filter((id, position) => id !== foreignRecordIds[position])
                .map(
                    (id) =>
                        'No valid complete candidate is available: registration/' +
                        id,
                ),
    },
    {
        family: 'contributions',
        pattern: /^contribution-\d+\//u,
        details: undefined,
    },
    {
        family: 'close records',
        pattern: /^close\//u,
        details: undefined,
    },
    {
        family: 'target votes',
        pattern: /^completion\/target-vote-\d+\.bin$/u,
        details: () => ['The target votes are incomplete.'],
    },
    {
        family: 'release shares',
        pattern: /^completion\/release-(?:envelope-)?\d+\.bin$/u,
        details: () => ['The release shares are incomplete.'],
    },
] as const;

// Serves another poll's records of one family under this poll's names, and
// nothing where the other poll has none: its registrations by roster
// position under this poll's record identifiers, and its other records under
// their own names.
export const foreignRecordView = async (
    foreign: Pick<
        ForeignPoll,
        'publicDirectory' | 'registrationBodyDigests' | 'leftOut'
    >,
    publicDirectory: string,
    registrationBodyDigests: readonly string[],
    pattern: RegExp,
) => {
    const view = new Map<string, ViewedRecord>();
    for (const name of await publicRecordNames(publicDirectory))
        if (pattern.test(name)) view.set(name, undefined);
    let served = 0;
    for (const name of await publicRecordNames(foreign.publicDirectory)) {
        if (!pattern.test(name)) continue;
        const registration = /^registration\/([0-9a-f]{128})\/(.+)$/u.exec(
            name,
        );
        const position =
            registration === null
                ? undefined
                : foreign.registrationBodyDigests.indexOf(registration[1]);
        // The registrant the other poll's organizer left out of its roster
        // has no roster position to take in this poll.
        if (registration !== null && registration[1] === foreign.leftOut)
            continue;
        assert.ok(
            position === undefined || position >= 0,
            'A foreign registration is not in its roster.',
        );
        view.set(
            registration === null || position === undefined
                ? name
                : `registration/${registrationBodyDigests[position]}/${registration[2]}`,
            { file: path.join(foreign.publicDirectory, name) },
        );
        served++;
    }
    return { view, served };
};
