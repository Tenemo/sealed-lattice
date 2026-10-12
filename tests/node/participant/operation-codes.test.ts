import { readdir, readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

type Codes = Readonly<Record<string, number>>;

const repositoryRoot = new URL('../../../', import.meta.url);

// The texts of the files with the extension below a directory, outside build
// output.
const sourceTexts = async (
    directory: URL,
    extension: string,
): Promise<string[]> => {
    const texts: string[] = [];
    for (const entry of await readdir(directory, { withFileTypes: true }))
        if (entry.isDirectory()) {
            if (entry.name !== 'target')
                texts.push(
                    ...(await sourceTexts(
                        new URL(entry.name + '/', directory),
                        extension,
                    )),
                );
        } else if (entry.name.endsWith(extension))
            texts.push(await readFile(new URL(entry.name, directory), 'utf8'));
    return texts;
};

const withoutComments = (text: string) => text.replace(/\/\/.*$/gm, '');

const lowerFirst = (name: string) => name[0].toLowerCase() + name.slice(1);

// The codes of an enum or table body whose every entry names its code.
const bodyCodes = (body: string, entry: RegExp): Codes => {
    const entries = withoutComments(body)
        .split(',')
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
    return Object.fromEntries(
        entries.map((part) => {
            const match = entry.exec(part);
            if (match === null)
                throw new Error('An entry names no code: ' + part);
            return [lowerFirst(match[1]), Number(match[2])];
        }),
    );
};

const variantCodes = (body: string) => bodyCodes(body, /^(\w+) = (\d+)$/);

// Every enum the module declares with its operation-codes macro, by name.
const moduleOperationCodes = (texts: readonly string[]) =>
    new Map(
        texts.flatMap((text) =>
            [
                ...text.matchAll(
                    /operation_codes! \{\s*(?:\/\/\/.*\s*)*(?:pub(?:\(\w+\))? )?enum (\w+) \{([^}]*)\}/g,
                ),
            ].map((match) => [match[1], variantCodes(match[2])] as const),
        ),
    );

// The codes of the one enum of the name the module declares outside the
// macro.
const moduleEnumCodes = (texts: readonly string[], name: string) => {
    const bodies = texts.flatMap((text) =>
        [...text.matchAll(new RegExp(`enum ${name} \\{([^}]*)\\}`, 'g'))].map(
            (match) => match[1],
        ),
    );
    expect(bodies, name).toHaveLength(1);
    return variantCodes(bodies[0]);
};

// Every worker table of a module command's operations or steps or of the
// module's purposes, by name.
const workerTables = (texts: readonly string[]) =>
    new Map(
        texts.flatMap((text) =>
            [
                ...text.matchAll(
                    /^(?:export )?const (\w+(?:Operation|Step|Purpose)) = \{([^}]*)\} as const;/gm,
                ),
            ].map(
                (match) =>
                    [match[1], bodyCodes(match[2], /^(\w+): (\d+)$/)] as const,
            ),
        ),
    );

// The single match of a pattern across the texts.
const onlyMatch = (texts: readonly string[], pattern: RegExp) => {
    const matches = texts.flatMap((text) => [...text.matchAll(pattern)]);
    expect(matches, pattern.source).toHaveLength(1);
    return matches[0];
};

const camelCase = (name: string) =>
    name
        .toLowerCase()
        .replace(/_(\w)/g, (_, letter: string) => letter.toUpperCase());

describe('participant module operation codes', () => {
    it('gives every worker code table the names and codes of its module enum', async () => {
        const moduleTexts = await sourceTexts(
            new URL('crates/protocol-research/', repositoryRoot),
            '.rs',
        );
        const operations = moduleOperationCodes(moduleTexts);
        const tables = workerTables(
            await sourceTexts(
                new URL('packages/sdk/src/participant/worker/', repositoryRoot),
                '.ts',
            ),
        );
        expect(operations.size).toBeGreaterThan(0);
        expect(tables.size).toBeGreaterThan(0);
        for (const name of operations.keys())
            expect(tables.has(lowerFirst(name)), name).toBe(true);
        for (const [table, codes] of tables) {
            const name = table[0].toUpperCase() + table.slice(1);
            expect(codes, table).toEqual(
                operations.get(name) ?? moduleEnumCodes(moduleTexts, name),
            );
        }
    });

    it('stages every enrollment record under the worker data kind of its name', async () => {
        const moduleTexts = await sourceTexts(
            new URL('crates/protocol-research/', repositoryRoot),
            '.rs',
        );
        const workerTexts = await sourceTexts(
            new URL('packages/sdk/src/participant/worker/', repositoryRoot),
            '.ts',
        );
        const moduleKinds = Object.fromEntries(
            [
                ...onlyMatch(
                    moduleTexts,
                    /pub mod data_kind \{([^}]*)\}/g,
                )[1].matchAll(/pub const (\w+): u32 = (\d+);/g),
            ].map((match) => [camelCase(match[1]), Number(match[2])]),
        );
        const workerKinds = bodyCodes(
            onlyMatch(
                workerTexts,
                /^export const dataKind = \{([^}]*)\} as const;/gm,
            )[1],
            /^(\w+): (\d+)$/,
        );
        expect(Object.keys(moduleKinds).length).toBeGreaterThan(0);
        for (const [name, kind] of Object.entries(moduleKinds))
            expect(workerKinds[name], name).toBe(kind);
        // The worker routes the staged capsule keys by their own kind, which
        // no record shares.
        const stagedDataKeys = Number(
            onlyMatch(workerTexts, /const stagedDataKeys = (\d+);/g)[1],
        );
        expect(
            Number(onlyMatch(moduleTexts, /const DATA_KEYS: u32 = (\d+);/g)[1]),
        ).toBe(stagedDataKeys);
        expect(Object.values(workerKinds)).not.toContain(stagedDataKeys);
    });
});
