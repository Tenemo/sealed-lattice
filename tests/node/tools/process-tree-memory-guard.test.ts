import { describe, expect, it } from 'vitest';

import {
    parsePosixProcessRows,
    parseWindowsProcessRows,
    readProcessPrivateMemory,
    sumProcessTreeResidentBytes,
} from '#tools/ci/process-tree-memory-guard.js';

describe('process-tree memory guard', () => {
    it('parses Windows singleton and array inventories', () => {
        expect(
            parseWindowsProcessRows(
                '{"ProcessId":7,"ParentProcessId":3,"WorkingSetSize":11}',
            ),
        ).toEqual([
            {
                parentProcessIdentifier: 3,
                processIdentifier: 7,
                residentByteLength: 11,
            },
        ]);
        expect(
            parseWindowsProcessRows(
                '[{"ProcessId":7,"ParentProcessId":3,"WorkingSetSize":11},{"ProcessId":8,"ParentProcessId":7,"WorkingSetSize":13}]',
            ),
        ).toHaveLength(2);
    });

    it('parses POSIX KiB inventories into bytes', () => {
        expect(parsePosixProcessRows('7 3 11\n8 7 13\n')).toEqual([
            {
                parentProcessIdentifier: 3,
                processIdentifier: 7,
                residentByteLength: 11 * 1_024,
            },
            {
                parentProcessIdentifier: 7,
                processIdentifier: 8,
                residentByteLength: 13 * 1_024,
            },
        ]);
    });

    it('sums only the selected process tree and terminates on cycles', () => {
        expect(
            sumProcessTreeResidentBytes(
                [
                    {
                        parentProcessIdentifier: 1,
                        processIdentifier: 2,
                        residentByteLength: 20,
                    },
                    {
                        parentProcessIdentifier: 2,
                        processIdentifier: 3,
                        residentByteLength: 30,
                    },
                    {
                        parentProcessIdentifier: 3,
                        processIdentifier: 2,
                        residentByteLength: 20,
                    },
                    {
                        parentProcessIdentifier: 9,
                        processIdentifier: 10,
                        residentByteLength: 100,
                    },
                ],
                2,
            ),
        ).toBe(50);
    });

    it('refuses malformed or negative rows', () => {
        expect(() => parseWindowsProcessRows('{}')).toThrow();
        expect(() => parsePosixProcessRows('1 0 -1')).toThrow();
        expect(() => parsePosixProcessRows('not a row')).toThrow();
    });

    it('refuses an empty or invalid private-memory process inventory', async () => {
        await expect(readProcessPrivateMemory([])).rejects.toThrow();
        await expect(readProcessPrivateMemory([0])).rejects.toThrow();
    });

    it('tolerates a process that vanishes between discovery and sampling', async () => {
        const rows = await readProcessPrivateMemory([
            process.pid,
            2_147_483_647,
        ]);
        expect(
            rows.some(
                ({ processIdentifier }) => processIdentifier === process.pid,
            ),
        ).toBe(true);
    });
});
