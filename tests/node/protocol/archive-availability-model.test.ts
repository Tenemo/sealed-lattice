import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    archiveHolderRequirements,
    createArchiveRecord,
    hasArchiveWriteQuorum,
    readArchiveClosure,
} from '#tests/archive-availability-model.js';

const setup = createArchiveRecord('setup', [], 'synthetic public setup');
const ballot = createArchiveRecord(
    'ballot',
    [setup.identity],
    'synthetic ciphertext',
);
const target = createArchiveRecord(
    'target',
    [setup.identity, ballot.identity],
    'synthetic close cut',
);
const signatures = Array.from({ length: 7 }, (_, position) =>
    createArchiveRecord(
        'target signature',
        [target.identity],
        `signer ${String(position)}`,
    ),
);
const certificate = createArchiveRecord(
    'certificate',
    signatures.map(({ identity }) => identity),
    'synthetic target certificate',
);
const archive = new Map(
    [setup, ballot, target, ...signatures, certificate].map(
        ({ identity, bytes }) => [identity, bytes],
    ),
);

describe('hybrid public archive availability model', () => {
    it('refuses malformed content-addressed records and dependencies without disrupting valid retrieval', () => {
        for (const encoded of [
            'not-json',
            '["purpose", []',
            'null',
            '["p",[],"x",0]',
            ' [ "p", [], "x" ] ',
        ]) {
            const bytes = Buffer.from(encoded);
            const identity = createHash('sha3-512').update(bytes).digest('hex');
            const store = new Map(archive);
            store.set(identity, bytes);
            expect(readArchiveClosure(identity, [store])).toBeUndefined();
            const parent = createArchiveRecord(
                'candidate',
                [identity],
                'malformed dependency',
            );
            store.set(parent.identity, parent.bytes);
            expect(
                readArchiveClosure(parent.identity, [store]),
            ).toBeUndefined();
            expect(readArchiveClosure(certificate.identity, [store])).toEqual(
                archive,
            );
        }
    });

    it('recovers all authorizing bytes after the original publisher disappears', () => {
        for (let failed = 0; failed < 3; failed++) {
            for (let omitted = 0; omitted < 3; omitted++) {
                const receipts = [0, 1, 2].filter(
                    (position) => position !== omitted,
                );
                expect(hasArchiveWriteQuorum(3, 1, receipts)).toBe(true);
                const stores = [0, 1, 2].map((position) =>
                    position === failed || !receipts.includes(position)
                        ? new Map()
                        : archive,
                );
                // Neither the publisher nor a collection of receipt signatures
                // participates in reading or verifying the dependency closure.
                expect(
                    readArchiveClosure(certificate.identity, stores),
                ).toEqual(archive);
            }
        }
    });

    it('does not mistake a root, partial certificate, or naked upload ACK for custody', () => {
        expect(hasArchiveWriteQuorum(3, 1, [0])).toBe(false);
        expect(hasArchiveWriteQuorum(3, 1, [0, 0])).toBe(false);
        expect(hasArchiveWriteQuorum(3, 1, [0, 3])).toBe(false);
        expect(
            readArchiveClosure(certificate.identity, [
                new Map([[certificate.identity, certificate.bytes]]),
            ]),
        ).toBeUndefined();
        const missingSignature = new Map(archive);
        missingSignature.delete(signatures[6].identity);
        expect(
            readArchiveClosure(certificate.identity, [missingSignature]),
        ).toBeUndefined();
        const missingPredecessor = new Map(archive);
        missingPredecessor.delete(ballot.identity);
        expect(
            readArchiveClosure(certificate.identity, [missingPredecessor]),
        ).toBeUndefined();
    });

    it('makes the infrastructure premise falsifiable rather than trusting receipts as bytes', () => {
        expect(hasArchiveWriteQuorum(3, 1, [0, 1])).toBe(true);
        // Both acknowledged replicas lose the record: the declared one-failure
        // premise is violated. Signed acknowledgements cannot restore bytes.
        expect(
            readArchiveClosure(certificate.identity, [
                new Map(),
                new Map(),
                new Map(),
            ]),
        ).toBeUndefined();
        // A participant holding the complete dependency closure can repair it.
        expect(readArchiveClosure(certificate.identity, [archive])).toEqual(
            archive,
        );
    });

    it('combines independently held records and ignores substitutions and fork unions', () => {
        const bad = new Map(archive);
        bad.set(ballot.identity, Buffer.from('replacement ballot bytes'));
        expect(readArchiveClosure(certificate.identity, [bad])).toBeUndefined();
        expect(
            readArchiveClosure(certificate.identity, [bad, archive]),
        ).toEqual(archive);
        const even = new Map(
            [...archive].filter((_, index) => index % 2 === 0),
        );
        const odd = new Map([...archive].filter((_, index) => index % 2 !== 0));
        const unrelated = createArchiveRecord('target', [], 'unrelated target');
        odd.set(unrelated.identity, unrelated.bytes);
        expect(readArchiveClosure(certificate.identity, [even, odd])).toEqual(
            archive,
        );
    });

    it('derives distinct full-copy and coded-retention holder requirements', () => {
        expect(archiveHolderRequirements(10, 3, 3, 1)).toEqual({
            requiredHolders: 7,
            possible: true,
        });
        expect(archiveHolderRequirements(10, 3, 3, 4)).toEqual({
            requiredHolders: 10,
            possible: true,
        });
        expect(archiveHolderRequirements(10, 3, 3, 5)).toEqual({
            requiredHolders: 11,
            possible: false,
        });
        // Independent named-set enumeration permits overlapping corruption and
        // departure sets and finds the worst case when their losses are disjoint.
        for (const holders of [7, 10]) {
            let minimumSurvivors = 10;
            const triples: number[][] = [];
            for (let first = 0; first < 10; first++)
                for (let second = first + 1; second < 10; second++)
                    for (let third = second + 1; third < 10; third++)
                        triples.push([first, second, third]);
            for (const corrupt of triples)
                for (const departed of triples) {
                    const surviving = Array.from(
                        { length: holders },
                        (_, i) => i,
                    ).filter(
                        (position) =>
                            !corrupt.includes(position) &&
                            !departed.includes(position),
                    );
                    minimumSurvivors = Math.min(
                        minimumSurvivors,
                        surviving.length,
                    );
                }
            expect(minimumSurvivors).toBe(holders === 7 ? 1 : 4);
        }
    });
});
